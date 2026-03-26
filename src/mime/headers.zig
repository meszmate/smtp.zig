const std = @import("std");
const Allocator = std.mem.Allocator;

/// Encode a header value using RFC 2047 encoded-word syntax if needed.
///
/// If the text is pure ASCII, it is returned as-is.
/// Otherwise, it is encoded as =?charset?B?base64-encoded?=.
/// Long encoded words are split across multiple lines.
pub fn encodeWordAlloc(allocator: Allocator, text: []const u8, charset: []const u8) ![]u8 {
    // Check if text is pure ASCII
    var all_ascii = true;
    for (text) |byte| {
        if (byte > 127) {
            all_ascii = false;
            break;
        }
    }

    if (all_ascii) {
        return try allocator.dupe(u8, text);
    }

    // Encode using =?charset?B?base64?= (RFC 2047)
    // Max encoded word length is 75 chars: =?charset?B?...?=
    // Overhead: =? + charset + ?B? + ?= = 7 + charset.len
    const overhead = 7 + charset.len;
    const max_encoded_word = 75;
    // Maximum base64 payload per word
    const max_b64_payload = max_encoded_word - overhead;
    // Each 3 bytes of input -> 4 base64 chars, so max input bytes per chunk:
    const max_input_per_chunk = (max_b64_payload / 4) * 3;

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var pos: usize = 0;
    var first = true;
    while (pos < text.len) {
        if (!first) {
            try out.appendSlice("\r\n ");
        }
        first = false;

        const chunk_end = @min(pos + max_input_per_chunk, text.len);
        const chunk = text[pos..chunk_end];

        // Base64 encode this chunk
        const encoder = std.base64.standard.Encoder;
        const b64_len = encoder.calcSize(chunk.len);
        const b64_buf = try allocator.alloc(u8, b64_len);
        defer allocator.free(b64_buf);
        _ = encoder.encode(b64_buf, chunk);

        try out.appendSlice("=?");
        try out.appendSlice(charset);
        try out.appendSlice("?B?");
        try out.appendSlice(b64_buf);
        try out.appendSlice("?=");

        pos = chunk_end;
    }

    return out.toOwnedSlice();
}

/// Format an email address with optional display name.
///
/// - If name is empty, returns just the email.
/// - If name contains non-ASCII, it is encoded using RFC 2047.
/// - Otherwise, returns "name <email>".
pub fn formatAddressAlloc(allocator: Allocator, name: []const u8, email: []const u8) ![]u8 {
    if (name.len == 0) {
        return try allocator.dupe(u8, email);
    }

    // Check if name needs encoding
    var needs_encoding = false;
    for (name) |byte| {
        if (byte > 127) {
            needs_encoding = true;
            break;
        }
    }

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    if (needs_encoding) {
        const encoded_name = try encodeWordAlloc(allocator, name, "UTF-8");
        defer allocator.free(encoded_name);
        try out.appendSlice(encoded_name);
        try out.appendSlice(" <");
        try out.appendSlice(email);
        try out.append('>');
    } else {
        try out.appendSlice(name);
        try out.appendSlice(" <");
        try out.appendSlice(email);
        try out.append('>');
    }

    return out.toOwnedSlice();
}

/// Format a list of addresses as a comma-separated string.
/// Each address is a [2][]const u8 where [0] is the name and [1] is the email.
pub fn formatAddressListAlloc(allocator: Allocator, addresses: []const [2][]const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    for (addresses, 0..) |addr, i| {
        if (i > 0) {
            try out.appendSlice(", ");
        }
        const formatted = try formatAddressAlloc(allocator, addr[0], addr[1]);
        defer allocator.free(formatted);
        try out.appendSlice(formatted);
    }

    return out.toOwnedSlice();
}

/// Generate a unique Message-ID for the given domain.
/// Format: <timestamp.random@domain>
pub fn formatMessageIdAlloc(allocator: Allocator, domain: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    const timestamp = std.time.milliTimestamp();
    var random_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    try out.append('<');

    // Append timestamp as decimal
    var ts_buf: [20]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{timestamp}) catch unreachable;
    try out.appendSlice(ts_str);

    try out.append('.');

    // Append random as hex
    for (random_bytes) |byte| {
        const hex = "0123456789abcdef";
        try out.append(hex[byte >> 4]);
        try out.append(hex[byte & 0x0F]);
    }

    try out.append('@');
    try out.appendSlice(domain);
    try out.append('>');

    return out.toOwnedSlice();
}

/// Format the current time as an RFC 5322 date string.
/// Example: "Thu, 26 Mar 2026 14:30:00 +0000"
pub fn formatDateAlloc(allocator: Allocator) ![]u8 {
    const timestamp = std.time.timestamp();
    return formatDateFromTimestamp(allocator, timestamp);
}

fn formatDateFromTimestamp(allocator: Allocator, timestamp: i64) ![]u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(@as(u64, @intCast(timestamp))) };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    const hour = day_seconds.getHoursIntoDay();
    const minute = day_seconds.getMinutesIntoHour();
    const second = day_seconds.getSecondsIntoMinute();

    // Compute day of week from epoch day.
    // Unix epoch (1970-01-01) was a Thursday (index 4 if Sun=0, or 3 if Mon=0).
    // We use: 0=Sun,1=Mon,...,6=Sat. 1970-01-01 is Thursday = 4.
    const raw_dow = @mod(@as(i64, @intCast(epoch_day.day)) + 4, 7);
    const dow_index: usize = @intCast(if (raw_dow < 0) raw_dow + 7 else raw_dow);

    const dow_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    const dow_str = dow_names[dow_index];
    const month_str = month_names[month_day.month.numeric() - 1];

    const year = year_day.year;
    const day = month_day.day_index + 1;

    var buf: [64]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000", .{
        dow_str,
        day,
        month_str,
        year,
        hour,
        minute,
        second,
    }) catch unreachable;

    return try allocator.dupe(u8, result);
}

test "encode word ascii" {
    const allocator = std.testing.allocator;
    const result = try encodeWordAlloc(allocator, "Hello World", "UTF-8");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World", result);
}

test "encode word non-ascii" {
    const allocator = std.testing.allocator;
    const result = try encodeWordAlloc(allocator, "H\xC3\xA9llo", "UTF-8");
    defer allocator.free(result);
    // Should start with =?UTF-8?B? and end with ?=
    try std.testing.expect(std.mem.startsWith(u8, result, "=?UTF-8?B?"));
    try std.testing.expect(std.mem.endsWith(u8, result, "?="));
}

test "format address with name" {
    const allocator = std.testing.allocator;
    const result = try formatAddressAlloc(allocator, "John Doe", "john@example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("John Doe <john@example.com>", result);
}

test "format address without name" {
    const allocator = std.testing.allocator;
    const result = try formatAddressAlloc(allocator, "", "john@example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john@example.com", result);
}

test "format address list" {
    const allocator = std.testing.allocator;
    const addresses = [_][2][]const u8{
        .{ "Alice", "alice@example.com" },
        .{ "", "bob@example.com" },
    };
    const result = try formatAddressListAlloc(allocator, &addresses);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Alice <alice@example.com>, bob@example.com", result);
}

test "format message id" {
    const allocator = std.testing.allocator;
    const result = try formatMessageIdAlloc(allocator, "example.com");
    defer allocator.free(result);
    try std.testing.expect(result[0] == '<');
    try std.testing.expect(result[result.len - 1] == '>');
    try std.testing.expect(std.mem.endsWith(u8, result, "@example.com>"));
}

test "format date" {
    const allocator = std.testing.allocator;
    // Test with a known timestamp: 2024-01-15 12:00:00 UTC = 1705320000
    const result = try formatDateFromTimestamp(allocator, 1705320000);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Mon, 15 Jan 2024 12:00:00 +0000", result);
}
