const std = @import("std");
const smtp = @import("smtp");

const plain = smtp.auth.plain;
const login = smtp.auth.login;
const crammd5 = smtp.auth.crammd5;
const xoauth2 = smtp.auth.xoauth2;

// ---------------------------------------------------------------------------
// PLAIN auth tests
// ---------------------------------------------------------------------------

test "plain: raw initial response without authzid" {
    const allocator = std.testing.allocator;
    const raw = try plain.rawInitialResponseAlloc(allocator, null, "user", "pass");
    defer allocator.free(raw);
    try std.testing.expectEqualSlices(u8, "\x00user\x00pass", raw);
}

test "plain: raw initial response with authzid" {
    const allocator = std.testing.allocator;
    const raw = try plain.rawInitialResponseAlloc(allocator, "admin", "user", "pass");
    defer allocator.free(raw);
    try std.testing.expectEqualSlices(u8, "admin\x00user\x00pass", raw);
}

test "plain: base64 encode and decode roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try plain.initialResponseAlloc(allocator, null, "testuser", "testpass");
    defer allocator.free(encoded);

    const decoded = try plain.decodeResponseAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualStrings("", decoded.authzid);
    try std.testing.expectEqualStrings("testuser", decoded.username);
    try std.testing.expectEqualStrings("testpass", decoded.password);
}

test "plain: roundtrip with authzid" {
    const allocator = std.testing.allocator;
    const encoded = try plain.initialResponseAlloc(allocator, "admin", "user", "secret");
    defer allocator.free(encoded);

    const decoded = try plain.decodeResponseAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualStrings("admin", decoded.authzid);
    try std.testing.expectEqualStrings("user", decoded.username);
    try std.testing.expectEqualStrings("secret", decoded.password);
}

test "plain: decode invalid base64 returns error" {
    const allocator = std.testing.allocator;
    const result = plain.decodeResponseAlloc(allocator, "!!!invalid!!!");
    try std.testing.expectError(error.InvalidBase64, result);
}

test "plain: decode missing null separators returns error" {
    const allocator = std.testing.allocator;
    // base64 of "nonullbytes" -- no null separators
    const b64enc = std.base64.standard.Encoder;
    const input = "nonullbytes";
    var buf: [32]u8 = undefined;
    const encoded = buf[0..b64enc.calcSize(input.len)];
    _ = b64enc.encode(encoded, input);
    const result = plain.decodeResponseAlloc(allocator, encoded);
    try std.testing.expectError(error.InvalidResponse, result);
}

// ---------------------------------------------------------------------------
// LOGIN auth tests
// ---------------------------------------------------------------------------

test "login: encode and decode roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try login.encodeAlloc(allocator, "hello");
    defer allocator.free(encoded);

    const decoded = try login.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("hello", decoded);
}

test "login: encode username" {
    const allocator = std.testing.allocator;
    const encoded = try login.encodeAlloc(allocator, "testuser");
    defer allocator.free(encoded);

    const decoded = try login.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings("testuser", decoded);
}

test "login: username prompt decodes to Username:" {
    const allocator = std.testing.allocator;
    const decoded = try login.decodeAlloc(allocator, login.usernamePrompt());
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Username:", decoded);
}

test "login: password prompt decodes to Password:" {
    const allocator = std.testing.allocator;
    const decoded = try login.decodeAlloc(allocator, login.passwordPrompt());
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("Password:", decoded);
}

test "login: prompts are valid base64" {
    try std.testing.expectEqualStrings("VXNlcm5hbWU6", login.usernamePrompt());
    try std.testing.expectEqualStrings("UGFzc3dvcmQ6", login.passwordPrompt());
}

test "login: decode invalid base64 returns error" {
    const allocator = std.testing.allocator;
    const result = login.decodeAlloc(allocator, "!!!invalid!!!");
    try std.testing.expectError(error.InvalidBase64, result);
}

test "login: encode empty string" {
    const allocator = std.testing.allocator;
    const encoded = try login.encodeAlloc(allocator, "");
    defer allocator.free(encoded);

    const decoded = try login.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("", decoded);
}

// ---------------------------------------------------------------------------
// CRAM-MD5 auth tests
// ---------------------------------------------------------------------------

test "crammd5: response and verify roundtrip" {
    const allocator = std.testing.allocator;

    // Create a base64-encoded challenge.
    const challenge = "test-challenge-12345";
    const b64enc = std.base64.standard.Encoder;
    const challenge_b64_len = b64enc.calcSize(challenge.len);
    const challenge_b64 = try allocator.alloc(u8, challenge_b64_len);
    defer allocator.free(challenge_b64);
    _ = b64enc.encode(challenge_b64, challenge);

    const response_b64 = try crammd5.responseAlloc(allocator, "user", "pass", challenge_b64);
    defer allocator.free(response_b64);

    const verified = try crammd5.verifyResponseAlloc(allocator, response_b64, challenge_b64);
    defer verified.deinit();

    try std.testing.expectEqualStrings("user", verified.username);

    // Digest should match expected.
    const expected = try crammd5.expectedDigestAlloc(allocator, "pass", challenge_b64);
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, verified.digest);
}

test "crammd5: different passwords produce different digests" {
    const allocator = std.testing.allocator;

    const challenge = "challenge-abc";
    const b64enc = std.base64.standard.Encoder;
    const challenge_b64_len = b64enc.calcSize(challenge.len);
    const challenge_b64 = try allocator.alloc(u8, challenge_b64_len);
    defer allocator.free(challenge_b64);
    _ = b64enc.encode(challenge_b64, challenge);

    const digest1 = try crammd5.expectedDigestAlloc(allocator, "password1", challenge_b64);
    defer allocator.free(digest1);

    const digest2 = try crammd5.expectedDigestAlloc(allocator, "password2", challenge_b64);
    defer allocator.free(digest2);

    try std.testing.expect(!std.mem.eql(u8, digest1, digest2));
}

test "crammd5: response contains username" {
    const allocator = std.testing.allocator;

    const challenge = "test";
    const b64enc = std.base64.standard.Encoder;
    const challenge_b64_len = b64enc.calcSize(challenge.len);
    const challenge_b64 = try allocator.alloc(u8, challenge_b64_len);
    defer allocator.free(challenge_b64);
    _ = b64enc.encode(challenge_b64, challenge);

    const response_b64 = try crammd5.responseAlloc(allocator, "myuser", "mypass", challenge_b64);
    defer allocator.free(response_b64);

    const verified = try crammd5.verifyResponseAlloc(allocator, response_b64, challenge_b64);
    defer verified.deinit();

    try std.testing.expectEqualStrings("myuser", verified.username);
    // Digest should be 32 hex characters (MD5 = 16 bytes = 32 hex chars).
    try std.testing.expectEqual(@as(usize, 32), verified.digest.len);
}

// ---------------------------------------------------------------------------
// XOAUTH2 auth tests
// ---------------------------------------------------------------------------

test "xoauth2: initial response encode and decode roundtrip" {
    const allocator = std.testing.allocator;

    const encoded = try xoauth2.initialResponseAlloc(allocator, "testuser@example.com", "ya29.token123");
    defer allocator.free(encoded);

    const decoded = try xoauth2.decodeAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualStrings("testuser@example.com", decoded.user);
    try std.testing.expectEqualStrings("ya29.token123", decoded.access_token);
}

test "xoauth2: different users produce different encodings" {
    const allocator = std.testing.allocator;

    const enc1 = try xoauth2.initialResponseAlloc(allocator, "user1@example.com", "token");
    defer allocator.free(enc1);

    const enc2 = try xoauth2.initialResponseAlloc(allocator, "user2@example.com", "token");
    defer allocator.free(enc2);

    try std.testing.expect(!std.mem.eql(u8, enc1, enc2));
}

test "xoauth2: decode invalid base64 returns error" {
    const allocator = std.testing.allocator;
    const result = xoauth2.decodeAlloc(allocator, "!!!notbase64!!!");
    try std.testing.expectError(error.InvalidBase64, result);
}

test "xoauth2: encode with empty token" {
    const allocator = std.testing.allocator;
    const encoded = try xoauth2.initialResponseAlloc(allocator, "user@test.com", "");
    defer allocator.free(encoded);

    const decoded = try xoauth2.decodeAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualStrings("user@test.com", decoded.user);
    try std.testing.expectEqualStrings("", decoded.access_token);
}
