const std = @import("std");
const Allocator = std.mem.Allocator;

/// Encode data using quoted-printable encoding (RFC 2045).
///
/// - Non-printable and non-ASCII bytes are encoded as =XX (uppercase hex).
/// - Printable ASCII (33-126) passes through, except '=' which becomes =3D.
/// - TAB (0x09) and SP (0x20) pass through except at end of line.
/// - Soft line breaks (=\r\n) are inserted to keep lines at most 76 characters.
pub fn encodeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var line_len: usize = 0;

    for (input, 0..) |byte, i| {
        const is_last = (i + 1 >= input.len);
        const next_is_newline = if (!is_last) (input[i + 1] == '\r' or input[i + 1] == '\n') else false;

        if (byte == '\r') {
            // Check for \r\n sequence (hard line break)
            if (!is_last and input[i + 1] == '\n') {
                try out.appendSlice("\r\n");
                line_len = 0;
                continue;
            }
            // Lone \r - encode it
            try ensureSoftBreak(&out, &line_len, 3);
            try appendEncoded(&out, byte);
            line_len += 3;
            continue;
        }

        if (byte == '\n') {
            // Lone \n (not preceded by \r) - pass through as line ending
            try out.append('\n');
            line_len = 0;
            continue;
        }

        if (byte == '\t' or byte == ' ') {
            // TAB and SP pass through except at end of line
            if (is_last or next_is_newline) {
                try ensureSoftBreak(&out, &line_len, 3);
                try appendEncoded(&out, byte);
                line_len += 3;
            } else {
                try ensureSoftBreak(&out, &line_len, 1);
                try out.append(byte);
                line_len += 1;
            }
            continue;
        }

        if (byte == '=') {
            try ensureSoftBreak(&out, &line_len, 3);
            try appendEncoded(&out, byte);
            line_len += 3;
            continue;
        }

        if (byte >= 33 and byte <= 126) {
            // Printable ASCII - pass through
            try ensureSoftBreak(&out, &line_len, 1);
            try out.append(byte);
            line_len += 1;
            continue;
        }

        // Non-printable or non-ASCII - encode
        try ensureSoftBreak(&out, &line_len, 3);
        try appendEncoded(&out, byte);
        line_len += 3;
    }

    return out.toOwnedSlice();
}

/// Decode quoted-printable encoded data.
///
/// - =XX sequences are decoded back to bytes.
/// - Soft line breaks (=\r\n) are removed.
/// - Other bytes pass through unchanged.
pub fn decodeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '=') {
            if (i + 2 < input.len) {
                // Check for soft line break =\r\n
                if (input[i + 1] == '\r' and input[i + 2] == '\n') {
                    i += 3;
                    continue;
                }
                // Decode =XX hex sequence
                const hi = hexDigitToValue(input[i + 1]);
                const lo = hexDigitToValue(input[i + 2]);
                if (hi != null and lo != null) {
                    try out.append((@as(u8, hi.?) << 4) | @as(u8, lo.?));
                    i += 3;
                    continue;
                }
            }
            // Check for soft line break =\n (without \r)
            if (i + 1 < input.len and input[i + 1] == '\n') {
                i += 2;
                continue;
            }
            // Not a valid sequence, pass through the '='
            try out.append('=');
            i += 1;
        } else {
            try out.append(input[i]);
            i += 1;
        }
    }

    return out.toOwnedSlice();
}

/// Insert a soft line break if adding `needed` chars would exceed 76 columns.
/// A soft break itself takes 3 chars (=\r\n), so we break when line_len + needed > 75
/// (the '=' of the soft break occupies column 76).
fn ensureSoftBreak(out: *std.array_list.Managed(u8), line_len: *usize, needed: usize) !void {
    // 76 chars max per line. The soft break "=" must fit on column 76 at most.
    // So if line_len + needed > 75, insert soft break first.
    if (line_len.* + needed > 75) {
        try out.appendSlice("=\r\n");
        line_len.* = 0;
    }
}

fn appendEncoded(out: *std.array_list.Managed(u8), byte: u8) !void {
    const hex_upper = "0123456789ABCDEF";
    try out.append('=');
    try out.append(hex_upper[byte >> 4]);
    try out.append(hex_upper[byte & 0x0F]);
}

fn hexDigitToValue(c: u8) ?u4 {
    if (c >= '0' and c <= '9') return @intCast(c - '0');
    if (c >= 'A' and c <= 'F') return @intCast(c - 'A' + 10);
    if (c >= 'a' and c <= 'f') return @intCast(c - 'a' + 10);
    return null;
}

test "encode basic ascii" {
    const allocator = std.testing.allocator;
    const result = try encodeAlloc(allocator, "Hello, World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "encode equals sign" {
    const allocator = std.testing.allocator;
    const result = try encodeAlloc(allocator, "a=b");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a=3Db", result);
}

test "decode basic" {
    const allocator = std.testing.allocator;
    const result = try decodeAlloc(allocator, "a=3Db=20c");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a=b c", result);
}

test "decode soft line break" {
    const allocator = std.testing.allocator;
    const result = try decodeAlloc(allocator, "hello=\r\nworld");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("helloworld", result);
}

test "roundtrip" {
    const allocator = std.testing.allocator;
    const original = "Subject: =?UTF-8?Q?Hello?= \xC3\xA9\xC3\xA0";
    const encoded = try encodeAlloc(allocator, original);
    defer allocator.free(encoded);
    const decoded = try decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}
