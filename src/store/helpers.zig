const std = @import("std");

/// Extract the header block from an email message body.
/// Headers end at the first empty line ("\r\n\r\n" or "\n\n").
pub fn extractHeaders(body: []const u8) []const u8 {
    if (std.mem.indexOf(u8, body, "\r\n\r\n")) |idx| {
        return body[0..idx];
    }
    if (std.mem.indexOf(u8, body, "\n\n")) |idx| {
        return body[0..idx];
    }
    // No blank line found; the entire body is treated as headers.
    return body;
}

/// Extract the text portion of an email message (everything after headers).
/// Returns the content after the first blank line separator.
pub fn extractText(body: []const u8) []const u8 {
    if (std.mem.indexOf(u8, body, "\r\n\r\n")) |idx| {
        return body[idx + 4 ..];
    }
    if (std.mem.indexOf(u8, body, "\n\n")) |idx| {
        return body[idx + 2 ..];
    }
    // No blank line found; no text portion.
    return "";
}

/// Extract the value of a specific header field from an email message body.
/// The comparison is case-insensitive. Returns the trimmed value, or an
/// empty string if the header is not found. The returned slice points into
/// the original body.
pub fn extractHeader(body: []const u8, header_name: []const u8) []const u8 {
    const headers = extractHeaders(body);
    var iter = LineIterator.init(headers);

    while (iter.next()) |line| {
        // Skip continuation lines (start with whitespace).
        if (line.len > 0 and (line[0] == ' ' or line[0] == '\t')) continue;

        if (std.mem.indexOfScalar(u8, line, ':')) |colon_idx| {
            const name = line[0..colon_idx];
            if (std.ascii.eqlIgnoreCase(name, header_name)) {
                return std.mem.trim(u8, line[colon_idx + 1 ..], " \t");
            }
        }
    }
    return "";
}

/// Extract multiple header fields from an email message body and return
/// them as a single allocated string, each on its own line.
/// The caller owns the returned memory.
pub fn extractHeaderFieldsAlloc(allocator: std.mem.Allocator, body: []const u8, fields: []const []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (fields) |field| {
        const value = extractHeader(body, field);
        if (value.len > 0) {
            try result.appendSlice(allocator, field);
            try result.appendSlice(allocator, ": ");
            try result.appendSlice(allocator, value);
            try result.append(allocator, '\n');
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Simple line iterator that handles both \r\n and \n line endings.
const LineIterator = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) LineIterator {
        return .{ .data = data, .pos = 0 };
    }

    fn next(self: *LineIterator) ?[]const u8 {
        if (self.pos >= self.data.len) return null;

        const start = self.pos;
        while (self.pos < self.data.len) : (self.pos += 1) {
            if (self.data[self.pos] == '\n') {
                const end = if (self.pos > start and self.data[self.pos - 1] == '\r')
                    self.pos - 1
                else
                    self.pos;
                self.pos += 1;
                return self.data[start..end];
            }
        }
        // Last line without trailing newline.
        return self.data[start..self.pos];
    }
};
