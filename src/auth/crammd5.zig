const std = @import("std");

const base64 = std.base64.standard;
const HmacMd5 = std.crypto.auth.hmac.HmacMd5;

pub const VerifiedResponse = struct {
    username: []const u8,
    digest: []const u8,

    allocator: std.mem.Allocator,
    raw: []const u8,

    pub fn deinit(self: VerifiedResponse) void {
        self.allocator.free(self.raw);
    }
};

/// Computes the CRAM-MD5 response for the given credentials and challenge.
///
/// Decodes the base64-encoded challenge, computes HMAC-MD5 using the password
/// as the key, formats the result as "username hex_digest", and base64-encodes it.
/// Caller owns the returned memory.
pub fn responseAlloc(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    challenge_b64: []const u8,
) ![]const u8 {
    const challenge = try decodeBase64Alloc(allocator, challenge_b64);
    defer allocator.free(challenge);

    // Compute HMAC-MD5 digest.
    var mac: [HmacMd5.mac_length]u8 = undefined;
    HmacMd5.create(&mac, challenge, password);

    // Format the hex digest.
    const hex_digest = std.fmt.bytesToHex(mac, .lower);

    // Build "username hex_digest".
    const response_len = username.len + 1 + hex_digest.len;
    const response = try allocator.alloc(u8, response_len);
    defer allocator.free(response);

    @memcpy(response[0..username.len], username);
    response[username.len] = ' ';
    @memcpy(response[username.len + 1 ..], &hex_digest);

    return encodeBase64Alloc(allocator, response);
}

/// Decodes a base64-encoded CRAM-MD5 response and splits it into username
/// and hex digest parts.
/// Caller must call `.deinit()` on the returned value to free memory.
pub fn verifyResponseAlloc(
    allocator: std.mem.Allocator,
    response_b64: []const u8,
    challenge_b64: []const u8,
) !VerifiedResponse {
    _ = challenge_b64;

    const raw = try decodeBase64Alloc(allocator, response_b64);
    errdefer allocator.free(raw);

    // Format is "username hex_digest", split on last space.
    const space_idx = std.mem.lastIndexOfScalar(u8, raw, ' ') orelse return error.InvalidResponse;

    return VerifiedResponse{
        .username = raw[0..space_idx],
        .digest = raw[space_idx + 1 ..],
        .allocator = allocator,
        .raw = raw,
    };
}

/// Computes the expected HMAC-MD5 hex digest for the given password and challenge.
/// Caller owns the returned memory.
pub fn expectedDigestAlloc(
    allocator: std.mem.Allocator,
    password: []const u8,
    challenge_b64: []const u8,
) ![]const u8 {
    const challenge = try decodeBase64Alloc(allocator, challenge_b64);
    defer allocator.free(challenge);

    var mac: [HmacMd5.mac_length]u8 = undefined;
    HmacMd5.create(&mac, challenge, password);

    const hex_digest = std.fmt.bytesToHex(mac, .lower);
    const result = try allocator.alloc(u8, hex_digest.len);
    @memcpy(result, &hex_digest);
    return result;
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

test "crammd5: response and verify round-trip" {
    const allocator = std.testing.allocator;

    // Base64-encode a test challenge.
    const challenge = "test-challenge-12345";
    const challenge_b64 = try encodeBase64Alloc(allocator, challenge);
    defer allocator.free(challenge_b64);

    const response_b64 = try responseAlloc(allocator, "user", "pass", challenge_b64);
    defer allocator.free(response_b64);

    const verified = try verifyResponseAlloc(allocator, response_b64, challenge_b64);
    defer verified.deinit();

    try std.testing.expectEqualSlices(u8, "user", verified.username);

    // The digest should match the expected digest.
    const expected = try expectedDigestAlloc(allocator, "pass", challenge_b64);
    defer allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, verified.digest);
}
