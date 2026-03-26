const std = @import("std");

const base64 = std.base64.standard;

pub const DecodedResponse = struct {
    authzid: []const u8,
    username: []const u8,
    password: []const u8,

    allocator: std.mem.Allocator,
    raw: []const u8,

    pub fn deinit(self: DecodedResponse) void {
        self.allocator.free(self.raw);
    }
};

/// Builds the raw PLAIN SASL initial response: "\0username\0password"
/// (with optional authzid prefix).
/// Caller owns the returned memory.
pub fn rawInitialResponseAlloc(
    allocator: std.mem.Allocator,
    authzid: ?[]const u8,
    username: []const u8,
    password: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const az = authzid orelse "";
    const total_len = az.len + 1 + username.len + 1 + password.len;

    const buf = try allocator.alloc(u8, total_len);
    errdefer allocator.free(buf);

    var offset: usize = 0;
    if (az.len > 0) {
        @memcpy(buf[offset .. offset + az.len], az);
        offset += az.len;
    }
    buf[offset] = 0;
    offset += 1;
    @memcpy(buf[offset .. offset + username.len], username);
    offset += username.len;
    buf[offset] = 0;
    offset += 1;
    @memcpy(buf[offset .. offset + password.len], password);

    return buf;
}

/// Builds and base64-encodes the PLAIN SASL initial response.
/// Caller owns the returned memory.
pub fn initialResponseAlloc(
    allocator: std.mem.Allocator,
    authzid: ?[]const u8,
    username: []const u8,
    password: []const u8,
) ![]const u8 {
    const raw = try rawInitialResponseAlloc(allocator, authzid, username, password);
    defer allocator.free(raw);

    return encodeBase64Alloc(allocator, raw);
}

/// Decodes a base64-encoded PLAIN SASL response and splits it into its
/// component parts: authzid, username, and password.
/// Caller must call `.deinit()` on the returned value to free memory.
pub fn decodeResponseAlloc(
    allocator: std.mem.Allocator,
    b64: []const u8,
) !DecodedResponse {
    const raw = try decodeBase64Alloc(allocator, b64);
    errdefer allocator.free(raw);

    // Format is: authzid \0 username \0 password
    // Find first null byte.
    const first_null = std.mem.indexOfScalar(u8, raw, 0) orelse return error.InvalidResponse;
    const rest = raw[first_null + 1 ..];

    // Find second null byte.
    const second_null = std.mem.indexOfScalar(u8, rest, 0) orelse return error.InvalidResponse;

    return DecodedResponse{
        .authzid = raw[0..first_null],
        .username = rest[0..second_null],
        .password = rest[second_null + 1 ..],
        .allocator = allocator,
        .raw = raw,
    };
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

test "plain: initial response without authzid" {
    const allocator = std.testing.allocator;
    const raw = try rawInitialResponseAlloc(allocator, null, "user", "pass");
    defer allocator.free(raw);
    try std.testing.expectEqualSlices(u8, "\x00user\x00pass", raw);
}

test "plain: initial response with authzid" {
    const allocator = std.testing.allocator;
    const raw = try rawInitialResponseAlloc(allocator, "admin", "user", "pass");
    defer allocator.free(raw);
    try std.testing.expectEqualSlices(u8, "admin\x00user\x00pass", raw);
}

test "plain: base64 encoded initial response" {
    const allocator = std.testing.allocator;
    const encoded = try initialResponseAlloc(allocator, null, "user", "pass");
    defer allocator.free(encoded);

    // Decode and verify round-trip.
    const decoded = try decodeResponseAlloc(allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, "", decoded.authzid);
    try std.testing.expectEqualSlices(u8, "user", decoded.username);
    try std.testing.expectEqualSlices(u8, "pass", decoded.password);
}
