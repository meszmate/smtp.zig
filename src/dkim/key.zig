const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

const seed_length = Ed25519.KeyPair.seed_length;
const public_length = Ed25519.PublicKey.encoded_length;
const signature_length = Ed25519.Signature.encoded_length;

/// An Ed25519 key pair for DKIM signing.
pub const Ed25519Key = struct {
    seed: [seed_length]u8,
    key_pair: Ed25519.KeyPair,

    /// Get the public key bytes (32 bytes).
    pub fn publicKeyBytes(self: *const Ed25519Key) [public_length]u8 {
        return self.key_pair.public_key.bytes;
    }

    /// Get the public key as base64 for DNS record.
    pub fn publicKeyBase64(self: *const Ed25519Key, buf: *[44]u8) []const u8 {
        return std.base64.standard.Encoder.encode(buf, &self.key_pair.public_key.bytes);
    }

    /// Sign data using Ed25519.
    pub fn sign(self: *const Ed25519Key, msg: []const u8) [signature_length]u8 {
        const sig = self.key_pair.sign(msg, null) catch return .{0} ** signature_length;
        return sig.toBytes();
    }

    /// Verify a signature.
    pub fn verify(self: *const Ed25519Key, msg: []const u8, sig_bytes: [signature_length]u8) bool {
        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        sig.verify(msg, self.key_pair.public_key) catch return false;
        return true;
    }
};

/// An RSA key for DKIM signing via user-provided callback.
/// RSA operations require big-integer math not available in Zig stdlib,
/// so the actual signing is delegated to a user-supplied function.
pub const RsaKey = struct {
    /// User-provided signing function. Takes the raw message bytes to sign and
    /// must return an RSASSA-PKCS1-v1_5-SHA256 signature.
    sign_fn: *const fn (data: []const u8, ctx: ?*anyopaque) SignError!RsaSignature,
    /// Opaque context for the signing function.
    context: ?*anyopaque = null,
    /// Key size in bits (e.g. 2048).
    key_bits: u16 = 2048,

    pub const SignError = error{RsaSignFailed};
    pub const max_signature_len = 512; // 4096-bit RSA max

    pub const RsaSignature = struct {
        data: [max_signature_len]u8,
        len: usize,
    };

    pub fn sign(self: *const RsaKey, msg: []const u8) SignError!RsaSignature {
        return self.sign_fn(msg, self.context);
    }
};

/// Signature bytes that can hold either Ed25519 or RSA signatures.
pub const SignatureBytes = union(enum) {
    ed25519: [64]u8,
    rsa: RsaKey.RsaSignature,

    pub fn slice(self: *const SignatureBytes) []const u8 {
        return switch (self.*) {
            .ed25519 => |*s| s,
            .rsa => |*s| s.data[0..s.len],
        };
    }
};

/// A signing key that supports multiple algorithms.
pub const SigningKey = union(enum) {
    ed25519: Ed25519Key,
    rsa: RsaKey,

    pub fn sign(self: *const SigningKey, data: []const u8) ?SignatureBytes {
        return switch (self.*) {
            .ed25519 => |*k| .{ .ed25519 = k.sign(data) },
            .rsa => |*k| blk: {
                const result = k.sign(data) catch break :blk null;
                break :blk .{ .rsa = result };
            },
        };
    }

    pub fn algorithmLabel(self: *const SigningKey) []const u8 {
        return switch (self.*) {
            .ed25519 => "ed25519-sha256",
            .rsa => "rsa-sha256",
        };
    }

    pub fn keyTypeLabel(self: *const SigningKey) []const u8 {
        return switch (self.*) {
            .ed25519 => "ed25519",
            .rsa => "rsa",
        };
    }
};

/// Generate a new Ed25519 key pair for DKIM.
pub fn generateEd25519Key() Ed25519Key {
    var seed_bytes: [seed_length]u8 = undefined;
    std.crypto.random.bytes(&seed_bytes);
    return loadEd25519KeyFromSeed(seed_bytes);
}

/// Load an Ed25519 key from a 32-byte seed.
pub fn loadEd25519KeyFromSeed(seed_bytes: [seed_length]u8) Ed25519Key {
    const key_pair = Ed25519.KeyPair.generateDeterministic(seed_bytes) catch {
        // This should not happen with a valid seed
        @panic("Ed25519 key generation failed with identity element error");
    };
    return .{
        .seed = seed_bytes,
        .key_pair = key_pair,
    };
}

/// Load an Ed25519 key from a PEM-encoded PKCS#8 private key.
pub fn loadEd25519KeyFromPem(allocator: std.mem.Allocator, pem: []const u8) !Ed25519Key {
    const begin_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    const begin_pos = std.mem.indexOf(u8, pem, begin_marker) orelse return error.InvalidPem;
    const after_begin = begin_pos + begin_marker.len;
    const end_pos = std.mem.indexOfPos(u8, pem, after_begin, end_marker) orelse return error.InvalidPem;

    var b64_clean: std.ArrayList(u8) = .empty;
    defer b64_clean.deinit(allocator);
    for (pem[after_begin..end_pos]) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            try b64_clean.append(allocator, c);
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_clean.items) catch return error.InvalidBase64;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, b64_clean.items) catch return error.InvalidBase64;

    // Ed25519 PKCS#8 DER prefix (16 bytes) + 32 bytes seed = 48 bytes total
    const ed25519_prefix = [_]u8{ 0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20 };

    if (decoded.len == 48 and std.mem.startsWith(u8, decoded, &ed25519_prefix)) {
        var seed_bytes: [32]u8 = undefined;
        @memcpy(&seed_bytes, decoded[16..48]);
        return loadEd25519KeyFromSeed(seed_bytes);
    }

    return error.UnsupportedKeyFormat;
}

/// Check whether PEM-encoded PKCS#8 data contains an RSA key.
/// Returns true if the OID 1.2.840.113549.1.1.1 is found in the decoded DER.
pub fn isRsaPkcs8Pem(allocator: std.mem.Allocator, pem: []const u8) !bool {
    const begin_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    const begin_pos = std.mem.indexOf(u8, pem, begin_marker) orelse return error.InvalidPem;
    const after_begin = begin_pos + begin_marker.len;
    const end_pos = std.mem.indexOfPos(u8, pem, after_begin, end_marker) orelse return error.InvalidPem;

    var b64_clean: std.ArrayList(u8) = .empty;
    defer b64_clean.deinit(allocator);
    for (pem[after_begin..end_pos]) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            try b64_clean.append(allocator, c);
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64_clean.items) catch return error.InvalidBase64;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, b64_clean.items) catch return error.InvalidBase64;

    // RSA PKCS#8 OID: 1.2.840.113549.1.1.1 encoded as DER
    const rsa_oid = [_]u8{ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    return std.mem.indexOf(u8, decoded, &rsa_oid) != null;
}

test "generate ed25519 key" {
    const k = generateEd25519Key();
    const msg = "test message";
    const sig = k.sign(msg);
    try std.testing.expect(k.verify(msg, sig));
}

test "ed25519 public key base64" {
    const k = generateEd25519Key();
    var buf: [44]u8 = undefined;
    const b64 = k.publicKeyBase64(&buf);
    try std.testing.expect(b64.len > 0);
}

test "signing key union ed25519" {
    const k = generateEd25519Key();
    const sk = SigningKey{ .ed25519 = k };
    try std.testing.expectEqualStrings("ed25519-sha256", sk.algorithmLabel());
    try std.testing.expectEqualStrings("ed25519", sk.keyTypeLabel());
    const sig = sk.sign("test");
    try std.testing.expect(sig != null);
    try std.testing.expect(sig.?.slice().len == 64);
}

fn testRsaSignFn(data: []const u8, _: ?*anyopaque) RsaKey.SignError!RsaKey.RsaSignature {
    // Dummy RSA signer for testing: just SHA-256 hash the data as a stand-in
    var result: RsaKey.RsaSignature = .{ .data = undefined, .len = 32 };
    std.crypto.hash.sha2.Sha256.hash(data, result.data[0..32], .{});
    return result;
}

test "signing key union rsa" {
    const sk = SigningKey{ .rsa = .{
        .sign_fn = &testRsaSignFn,
        .key_bits = 2048,
    } };
    try std.testing.expectEqualStrings("rsa-sha256", sk.algorithmLabel());
    try std.testing.expectEqualStrings("rsa", sk.keyTypeLabel());
    const sig = sk.sign("test");
    try std.testing.expect(sig != null);
    try std.testing.expect(sig.?.slice().len == 32);
}

test "rsa key sign callback" {
    const rsa = RsaKey{
        .sign_fn = &testRsaSignFn,
        .key_bits = 2048,
    };
    const result = try rsa.sign("hello");
    try std.testing.expect(result.len == 32);
}
