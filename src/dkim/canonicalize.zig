const std = @import("std");

pub const CanonicalizationAlgo = enum {
    simple,
    relaxed,

    pub fn label(self: CanonicalizationAlgo) []const u8 {
        return switch (self) {
            .simple => "simple",
            .relaxed => "relaxed",
        };
    }
};

pub const Canonicalization = struct {
    header: CanonicalizationAlgo = .relaxed,
    body: CanonicalizationAlgo = .relaxed,

    pub fn label(self: Canonicalization, buf: *[15]u8) []const u8 {
        const h = self.header.label();
        const b = self.body.label();
        @memcpy(buf[0..h.len], h);
        buf[h.len] = '/';
        @memcpy(buf[h.len + 1 ..][0..b.len], b);
        return buf[0 .. h.len + 1 + b.len];
    }
};

/// Canonicalize a message body according to the specified algorithm.
pub fn canonicalizeBody(allocator: std.mem.Allocator, body: []const u8, algo: CanonicalizationAlgo) ![]u8 {
    return switch (algo) {
        .simple => canonicalizeBodySimple(allocator, body),
        .relaxed => canonicalizeBodyRelaxed(allocator, body),
    };
}

/// Canonicalize a single header line according to the specified algorithm.
pub fn canonicalizeHeader(allocator: std.mem.Allocator, header_line: []const u8, algo: CanonicalizationAlgo) ![]u8 {
    return switch (algo) {
        .simple => allocator.dupe(u8, header_line),
        .relaxed => canonicalizeHeaderRelaxed(allocator, header_line),
    };
}

/// Simple body canonicalization: strip trailing empty lines, ensure ends with single CRLF.
fn canonicalizeBodySimple(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    if (body.len == 0) {
        return allocator.dupe(u8, "\r\n");
    }

    // Find end of body excluding trailing CRLF sequences
    var end = body.len;
    while (end >= 2 and body[end - 2] == '\r' and body[end - 1] == '\n') {
        end -= 2;
    }

    // If entire body was empty lines, return single CRLF
    if (end == 0) {
        return allocator.dupe(u8, "\r\n");
    }

    // Allocate body + CRLF
    const result = try allocator.alloc(u8, end + 2);
    @memcpy(result[0..end], body[0..end]);
    result[end] = '\r';
    result[end + 1] = '\n';
    return result;
}

/// Relaxed body canonicalization:
/// 1. Reduce WSP sequences within lines to single space
/// 2. Remove trailing WSP on each line
/// 3. Remove trailing empty lines
/// 4. If non-empty, ensure ends with CRLF; if empty, return empty
fn canonicalizeBodyRelaxed(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < body.len) {
        // Find end of line
        const line_end = findCrlf(body, i);
        const line = body[i..line_end];

        // Process line: reduce WSP runs to single space, strip trailing WSP
        var line_buf: std.ArrayList(u8) = .empty;
        defer line_buf.deinit(allocator);

        var j: usize = 0;
        while (j < line.len) {
            if (line[j] == ' ' or line[j] == '\t') {
                // Skip all consecutive WSP, emit single space
                while (j < line.len and (line[j] == ' ' or line[j] == '\t')) : (j += 1) {}
                try line_buf.append(allocator, ' ');
            } else {
                try line_buf.append(allocator, line[j]);
                j += 1;
            }
        }

        // Strip trailing WSP
        while (line_buf.items.len > 0 and (line_buf.items[line_buf.items.len - 1] == ' ' or line_buf.items[line_buf.items.len - 1] == '\t')) {
            _ = line_buf.pop();
        }

        // Add line + CRLF
        try out.appendSlice(allocator, line_buf.items);
        try out.appendSlice(allocator, "\r\n");

        // Advance past CRLF
        if (line_end + 1 < body.len and body[line_end] == '\r' and body[line_end + 1] == '\n') {
            i = line_end + 2;
        } else if (line_end < body.len and body[line_end] == '\n') {
            i = line_end + 1;
        } else {
            i = body.len;
        }
    }

    // Remove trailing empty lines (lines that are just CRLF)
    while (out.items.len >= 2 and out.items[out.items.len - 2] == '\r' and out.items[out.items.len - 1] == '\n') {
        // Check if this CRLF is preceded by another CRLF (empty line) or is the only content
        if (out.items.len >= 4 and out.items[out.items.len - 4] == '\r' and out.items[out.items.len - 3] == '\n') {
            // Remove this trailing empty line
            _ = out.pop();
            _ = out.pop();
        } else if (out.items.len == 2) {
            // Body is just one CRLF = empty body in relaxed
            _ = out.pop();
            _ = out.pop();
        } else {
            break;
        }
    }

    return out.toOwnedSlice(allocator);
}

/// Relaxed header canonicalization:
/// 1. Lowercase header name
/// 2. Unfold continuation lines
/// 3. Compress WSP runs to single space
/// 4. Strip trailing WSP before CRLF
fn canonicalizeHeaderRelaxed(allocator: std.mem.Allocator, header_line: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    // Strip any trailing CRLF/LF for processing
    var input = header_line;
    if (std.mem.endsWith(u8, input, "\r\n")) {
        input = input[0 .. input.len - 2];
    } else if (std.mem.endsWith(u8, input, "\n")) {
        input = input[0 .. input.len - 1];
    }

    // Find the colon separating name from value
    const colon = std.mem.indexOfScalar(u8, input, ':') orelse {
        // No colon found, return as-is with CRLF
        try out.appendSlice(allocator, input);
        try out.appendSlice(allocator, "\r\n");
        return out.toOwnedSlice(allocator);
    };

    // Step 1: Lowercase the header name
    for (input[0..colon]) |c| {
        try out.append(allocator, std.ascii.toLower(c));
    }
    try out.append(allocator, ':');

    // Get the value portion (after the colon)
    var value = input[colon + 1 ..];

    // Step 2: Unfold continuation lines (remove CRLF followed by WSP)
    // Since we already stripped the outer CRLF, we need to handle embedded CRLF+WSP
    var unfolded: std.ArrayList(u8) = .empty;
    defer unfolded.deinit(allocator);
    {
        var k: usize = 0;
        while (k < value.len) {
            if (k + 2 < value.len and value[k] == '\r' and value[k + 1] == '\n' and (value[k + 2] == ' ' or value[k + 2] == '\t')) {
                // Unfold: replace CRLF+WSP with space
                try unfolded.append(allocator, ' ');
                k += 3;
            } else if (k + 1 < value.len and value[k] == '\n' and (value[k + 1] == ' ' or value[k + 1] == '\t')) {
                try unfolded.append(allocator, ' ');
                k += 2;
            } else {
                try unfolded.append(allocator, value[k]);
                k += 1;
            }
        }
        value = unfolded.items;
    }

    // Step 3: Compress WSP runs to single space
    var in_wsp = false;
    for (value) |c| {
        if (c == ' ' or c == '\t') {
            if (!in_wsp) {
                try out.append(allocator, ' ');
                in_wsp = true;
            }
        } else {
            try out.append(allocator, c);
            in_wsp = false;
        }
    }

    // Step 4: Strip trailing WSP
    while (out.items.len > 0 and (out.items[out.items.len - 1] == ' ' or out.items[out.items.len - 1] == '\t')) {
        _ = out.pop();
    }

    // Add trailing CRLF
    try out.appendSlice(allocator, "\r\n");

    return out.toOwnedSlice(allocator);
}

fn findCrlf(data: []const u8, start: usize) usize {
    var i = start;
    while (i < data.len) {
        if (data[i] == '\r' and i + 1 < data.len and data[i + 1] == '\n') return i;
        if (data[i] == '\n') return i;
        i += 1;
    }
    return data.len;
}

test "simple body canonicalization - strips trailing empty lines" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeBody(allocator, "Hello\r\n\r\n\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\n", result);
}

test "simple body canonicalization - empty body" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeBody(allocator, "", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\r\n", result);
}

test "relaxed body canonicalization - compress whitespace" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeBody(allocator, "Hello   World\r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World\r\n", result);
}

test "relaxed body canonicalization - empty body" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeBody(allocator, "", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "relaxed header canonicalization" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeHeader(allocator, "Subject:   Hello   World  \r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject: Hello World\r\n", result);
}

test "simple header canonicalization - no change" {
    const allocator = std.testing.allocator;
    const result = try canonicalizeHeader(allocator, "Subject: Hello\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subject: Hello\r\n", result);
}
