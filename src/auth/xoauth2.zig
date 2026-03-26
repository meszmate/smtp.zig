const std = @import("std");

const base64 = std.base64.standard;

pub const DecodedXOAuth2 = struct {
    user: []const u8,
    access_token: []const u8,

    allocator: std.mem.Allocator,
    raw: []const u8,

    pub fn deinit(self: DecodedXOAuth2) void {
        self.allocator.free(self.raw);
    }
};

/// Builds and base64-encodes the XOAUTH2 initial response.
///
/// Format: "user=<user>\x01auth=Bearer <access_token>\x01\x01"
/// Caller owns the returned memory.
pub fn initialResponseAlloc(
    allocator: std.mem.Allocator,
    user: []const u8,
    access_token: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const prefix_user = "user=";
    const sep = "\x01";
    const prefix_auth = "auth=Bearer ";

    const total_len = prefix_user.len + user.len + sep.len +
        prefix_auth.len + access_token.len + sep.len + sep.len;

    const raw = try allocator.alloc(u8, total_len);
    defer allocator.free(raw);

    var offset: usize = 0;

    @memcpy(raw[offset .. offset + prefix_user.len], prefix_user);
    offset += prefix_user.len;

    @memcpy(raw[offset .. offset + user.len], user);
    offset += user.len;

    raw[offset] = '\x01';
    offset += 1;

    @memcpy(raw[offset .. offset + prefix_auth.len], prefix_auth);
    offset += prefix_auth.len;

    @memcpy(raw[offset .. offset + access_token.len], access_token);
    offset += access_token.len;

    raw[offset] = '\x01';
    offset += 1;

    raw[offset] = '\x01';

    return encodeBase64Alloc(allocator, raw);
}

/// Decodes a base64-encoded XOAUTH2 response and extracts the user and
/// access_token fields.
/// Caller must call `.deinit()` on the returned value to free memory.
pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    text: []const u8,
) !DecodedXOAuth2 {
    const raw = try decodeBase64Alloc(allocator, text);
    errdefer allocator.free(raw);

    const user = try extractFieldAlloc(raw, "user=");
    const token = try extractFieldAlloc(raw, "auth=Bearer ");

    return DecodedXOAuth2{
        .user = user,
        .access_token = token,
        .allocator = allocator,
        .raw = raw,
    };
}

/// Extracts the value of a field from the XOAUTH2 response string.
/// The returned slice points into `data` -- no allocation is performed.
fn extractFieldAlloc(data: []const u8, prefix: []const u8) ![]const u8 {
    const start_idx = std.mem.indexOf(u8, data, prefix) orelse return error.FieldNotFound;
    const value_start = start_idx + prefix.len;
    const remaining = data[value_start..];

    // Field value ends at the next \x01 or end of data.
    const end_idx = std.mem.indexOfScalar(u8, remaining, '\x01') orelse remaining.len;
    return remaining[0..end_idx];
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error![]const u8 {
    const encoded_len = base64.Encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, encoded_len);
    _ = base64.Encoder.encode(buf, data);
    return buf;
}

fn decodeBase64Alloc(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    const decoded_len = base64.Decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    const buf = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(buf);
    base64.Decoder.decode(buf, encoded) catch return error.InvalidBase64;
    return buf;
}

test "xoauth2: initial response encode and decode round-trip" {
    const allocator = std.testing.allocator;

    const encoded = try initialResponseAlloc(allocator, "testuser@example.com", "ya29.token123");
    defer allocator.free(encoded);

    const decoded = try decodeAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, "testuser@example.com", decoded.user);
    try std.testing.expectEqualSlices(u8, "ya29.token123", decoded.access_token);
}
