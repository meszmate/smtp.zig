const std = @import("std");

const base64 = std.base64.standard;

/// Base64-encodes the given text.
/// Caller owns the returned memory.
pub fn encodeAlloc(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]const u8 {
    const encoded_len = base64.Encoder.calcSize(text.len);
    const buf = try allocator.alloc(u8, encoded_len);
    _ = base64.Encoder.encode(buf, text);
    return buf;
}

/// Base64-decodes the given text.
/// Caller owns the returned memory.
pub fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    const decoded_len = base64.Decoder.calcSizeForSlice(text) catch return error.InvalidBase64;
    const buf = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(buf);
    base64.Decoder.decode(buf, text) catch return error.InvalidBase64;
    return buf;
}

/// Returns the base64-encoded "Username:" prompt.
pub fn usernamePrompt() []const u8 {
    return "VXNlcm5hbWU6";
}

/// Returns the base64-encoded "Password:" prompt.
pub fn passwordPrompt() []const u8 {
    return "UGFzc3dvcmQ6";
}

test "login: encode and decode round-trip" {
    const allocator = std.testing.allocator;
    const encoded = try encodeAlloc(allocator, "hello");
    defer allocator.free(encoded);

    const decoded = try decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, "hello", decoded);
}

test "login: username prompt" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAlloc(allocator, usernamePrompt());
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "Username:", decoded);
}

test "login: password prompt" {
    const allocator = std.testing.allocator;
    const decoded = try decodeAlloc(allocator, passwordPrompt());
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "Password:", decoded);
}
