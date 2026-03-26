const std = @import("std");
const Allocator = std.mem.Allocator;

/// Encode data as Base64 with MIME line wrapping (76-character lines separated by \r\n).
pub fn encodeMimeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;

    // Calculate the base64 encoded length
    const encoded_len = encoder.calcSize(input.len);

    // Allocate buffer for the raw base64 output
    const raw = try allocator.alloc(u8, encoded_len);
    defer allocator.free(raw);

    // Encode
    _ = encoder.encode(raw, input);

    // Now wrap at 76 characters with \r\n
    const line_len: usize = 76;
    const num_full_lines = encoded_len / line_len;
    const remainder = encoded_len % line_len;
    const num_breaks = if (remainder > 0) num_full_lines else if (num_full_lines > 0) num_full_lines - 1 else 0;
    const total_len = encoded_len + (num_breaks * 2); // 2 bytes per \r\n

    var out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    var src_pos: usize = 0;
    var dst_pos: usize = 0;

    var line_idx: usize = 0;
    while (src_pos < encoded_len) {
        const chunk = @min(line_len, encoded_len - src_pos);
        @memcpy(out[dst_pos .. dst_pos + chunk], raw[src_pos .. src_pos + chunk]);
        src_pos += chunk;
        dst_pos += chunk;

        // Add line break after each line except the very last one
        line_idx += 1;
        if (src_pos < encoded_len) {
            out[dst_pos] = '\r';
            out[dst_pos + 1] = '\n';
            dst_pos += 2;
        }
    }

    return out[0..dst_pos];
}

/// Decode MIME Base64 data (strips whitespace/newlines before decoding).
pub fn decodeMimeAlloc(allocator: Allocator, input: []const u8) ![]u8 {
    // First, strip all whitespace characters
    var stripped = std.array_list.Managed(u8).init(allocator);
    defer stripped.deinit();

    for (input) |byte| {
        if (byte != ' ' and byte != '\t' and byte != '\r' and byte != '\n') {
            try stripped.append(byte);
        }
    }

    const clean = stripped.items;
    if (clean.len == 0) {
        return try allocator.alloc(u8, 0);
    }

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(clean) catch return error.InvalidBase64;
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);

    decoder.decode(out, clean) catch return error.InvalidBase64;

    return out;
}

test "encode mime base64 short" {
    const allocator = std.testing.allocator;
    const result = try encodeMimeAlloc(allocator, "Hello, World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("SGVsbG8sIFdvcmxkIQ==", result);
}

test "encode mime base64 wrapping" {
    const allocator = std.testing.allocator;
    // Create input that produces base64 longer than 76 chars
    const input = "This is a somewhat longer string that should produce base64 output exceeding seventy-six characters in length.";
    const result = try encodeMimeAlloc(allocator, input);
    defer allocator.free(result);

    // Verify no line exceeds 76 characters
    var iter = std.mem.splitSequence(u8, result, "\r\n");
    while (iter.next()) |line| {
        try std.testing.expect(line.len <= 76);
    }
}

test "decode mime base64" {
    const allocator = std.testing.allocator;
    const result = try decodeMimeAlloc(allocator, "SGVs\r\nbG8s\r\nIFdvcmxkIQ==");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "roundtrip base64" {
    const allocator = std.testing.allocator;
    const original = "Binary data: \x00\x01\x02\xFF\xFE\xFD";
    const encoded = try encodeMimeAlloc(allocator, original);
    defer allocator.free(encoded);
    const decoded = try decodeMimeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}
