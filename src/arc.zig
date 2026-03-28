const std = @import("std");

/// ARC chain validation result per RFC 8617 Section 5.2.
pub const ArcResult = enum {
    arc_pass,
    arc_fail,
    arc_none,

    pub fn label(self: ArcResult) []const u8 {
        return switch (self) {
            .arc_pass => "pass",
            .arc_fail => "fail",
            .arc_none => "none",
        };
    }
};

/// ARC-Seal header per RFC 8617 Section 4.1.3.
pub const ArcSeal = struct {
    instance: u32,
    algorithm: []const u8 = "ed25519-sha256",
    domain: []const u8,
    selector: []const u8,
    chain_validation: ArcResult,
    signature: []const u8 = "",
    timestamp: ?u64 = null,
};

/// ARC-Message-Signature header per RFC 8617 Section 4.1.2.
pub const ArcMessageSignature = struct {
    instance: u32,
    algorithm: []const u8 = "ed25519-sha256",
    domain: []const u8,
    selector: []const u8,
    signed_headers: []const u8 = "",
    body_hash: []const u8 = "",
    signature: []const u8 = "",
    canonicalization_header: []const u8 = "relaxed",
    canonicalization_body: []const u8 = "relaxed",
    timestamp: ?u64 = null,
};

/// ARC-Authentication-Results header per RFC 8617 Section 4.1.1.
pub const ArcAuthResults = struct {
    instance: u32,
    authserv_id: []const u8,
    results: []const u8 = "",
};

/// A complete ARC set (one instance of all three headers).
pub const ArcSet = struct {
    instance: u32,
    seal: ArcSeal,
    message_signature: ArcMessageSignature,
    auth_results: ArcAuthResults,
};

/// Options for signing a new ARC set.
pub const ArcSignOptions = struct {
    instance: u32,
    domain: []const u8,
    selector: []const u8,
    private_key: []const u8,
    authserv_id: []const u8,
    auth_results_text: []const u8,
    chain_validation: ArcResult,
    signed_headers: []const u8 = "From:To:Subject:Date",
    timestamp: ?u64 = null,
};

/// Build an ARC-Seal header string per RFC 8617 Section 4.1.3.
/// Caller owns the returned memory.
pub fn buildArcSealAlloc(allocator: std.mem.Allocator, seal: ArcSeal) ![]u8 {
    const instance_str = try std.fmt.allocPrint(allocator, "{d}", .{seal.instance});
    defer allocator.free(instance_str);

    var parts: std.ArrayList(u8) = .empty;
    defer parts.deinit(allocator);

    try parts.appendSlice(allocator, "ARC-Seal: i=");
    try parts.appendSlice(allocator, instance_str);
    try parts.appendSlice(allocator, "; a=");
    try parts.appendSlice(allocator, seal.algorithm);
    try parts.appendSlice(allocator, "; cv=");
    try parts.appendSlice(allocator, seal.chain_validation.label());
    try parts.appendSlice(allocator, "; d=");
    try parts.appendSlice(allocator, seal.domain);
    try parts.appendSlice(allocator, "; s=");
    try parts.appendSlice(allocator, seal.selector);

    if (seal.timestamp) |ts| {
        const ts_str = try std.fmt.allocPrint(allocator, "; t={d}", .{ts});
        defer allocator.free(ts_str);
        try parts.appendSlice(allocator, ts_str);
    }

    try parts.appendSlice(allocator, "; b=");
    try parts.appendSlice(allocator, seal.signature);

    return parts.toOwnedSlice(allocator);
}

/// Build an ARC-Message-Signature header string per RFC 8617 Section 4.1.2.
/// Caller owns the returned memory.
pub fn buildArcMessageSignatureAlloc(allocator: std.mem.Allocator, sig: ArcMessageSignature) ![]u8 {
    const instance_str = try std.fmt.allocPrint(allocator, "{d}", .{sig.instance});
    defer allocator.free(instance_str);

    var parts: std.ArrayList(u8) = .empty;
    defer parts.deinit(allocator);

    try parts.appendSlice(allocator, "ARC-Message-Signature: i=");
    try parts.appendSlice(allocator, instance_str);
    try parts.appendSlice(allocator, "; a=");
    try parts.appendSlice(allocator, sig.algorithm);
    try parts.appendSlice(allocator, "; c=");
    try parts.appendSlice(allocator, sig.canonicalization_header);
    try parts.appendSlice(allocator, "/");
    try parts.appendSlice(allocator, sig.canonicalization_body);
    try parts.appendSlice(allocator, "; d=");
    try parts.appendSlice(allocator, sig.domain);
    try parts.appendSlice(allocator, "; s=");
    try parts.appendSlice(allocator, sig.selector);

    if (sig.signed_headers.len > 0) {
        try parts.appendSlice(allocator, "; h=");
        try parts.appendSlice(allocator, sig.signed_headers);
    }

    if (sig.timestamp) |ts| {
        const ts_str = try std.fmt.allocPrint(allocator, "; t={d}", .{ts});
        defer allocator.free(ts_str);
        try parts.appendSlice(allocator, ts_str);
    }

    try parts.appendSlice(allocator, "; bh=");
    try parts.appendSlice(allocator, sig.body_hash);
    try parts.appendSlice(allocator, "; b=");
    try parts.appendSlice(allocator, sig.signature);

    return parts.toOwnedSlice(allocator);
}

/// Build an ARC-Authentication-Results header string per RFC 8617 Section 4.1.1.
/// Caller owns the returned memory.
pub fn buildArcAuthResultsAlloc(allocator: std.mem.Allocator, aar: ArcAuthResults) ![]u8 {
    const instance_str = try std.fmt.allocPrint(allocator, "{d}", .{aar.instance});
    defer allocator.free(instance_str);

    var parts: std.ArrayList(u8) = .empty;
    defer parts.deinit(allocator);

    try parts.appendSlice(allocator, "ARC-Authentication-Results: i=");
    try parts.appendSlice(allocator, instance_str);
    try parts.appendSlice(allocator, "; ");
    try parts.appendSlice(allocator, aar.authserv_id);

    if (aar.results.len > 0) {
        try parts.appendSlice(allocator, "; ");
        try parts.appendSlice(allocator, aar.results);
    }

    return parts.toOwnedSlice(allocator);
}

/// Parse an ARC-Seal header value into an ArcSeal struct.
pub fn parseArcSeal(value: []const u8) ArcSeal {
    var seal = ArcSeal{
        .instance = 0,
        .domain = "",
        .selector = "",
        .chain_validation = .arc_none,
    };

    var parts = std.mem.splitScalar(u8, value, ';');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t\r\n");
        if (part.len == 0) continue;

        const eq_pos = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const key = std.mem.trim(u8, part[0..eq_pos], " \t");
        const val = std.mem.trim(u8, part[eq_pos + 1 ..], " \t");

        if (std.mem.eql(u8, key, "i")) {
            seal.instance = std.fmt.parseInt(u32, val, 10) catch 0;
        } else if (std.mem.eql(u8, key, "a")) {
            seal.algorithm = val;
        } else if (std.mem.eql(u8, key, "cv")) {
            seal.chain_validation = parseChainValidation(val);
        } else if (std.mem.eql(u8, key, "d")) {
            seal.domain = val;
        } else if (std.mem.eql(u8, key, "s")) {
            seal.selector = val;
        } else if (std.mem.eql(u8, key, "t")) {
            seal.timestamp = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, key, "b")) {
            seal.signature = val;
        }
    }

    return seal;
}

/// Parse an ARC-Message-Signature header value into an ArcMessageSignature struct.
pub fn parseArcMessageSignature(value: []const u8) ArcMessageSignature {
    var sig = ArcMessageSignature{
        .instance = 0,
        .domain = "",
        .selector = "",
    };

    var parts = std.mem.splitScalar(u8, value, ';');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t\r\n");
        if (part.len == 0) continue;

        const eq_pos = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const key = std.mem.trim(u8, part[0..eq_pos], " \t");
        const val = std.mem.trim(u8, part[eq_pos + 1 ..], " \t");

        if (std.mem.eql(u8, key, "i")) {
            sig.instance = std.fmt.parseInt(u32, val, 10) catch 0;
        } else if (std.mem.eql(u8, key, "a")) {
            sig.algorithm = val;
        } else if (std.mem.eql(u8, key, "c")) {
            // Parse canonicalization: "relaxed/relaxed"
            if (std.mem.indexOfScalar(u8, val, '/')) |slash| {
                sig.canonicalization_header = val[0..slash];
                sig.canonicalization_body = val[slash + 1 ..];
            } else {
                sig.canonicalization_header = val;
            }
        } else if (std.mem.eql(u8, key, "d")) {
            sig.domain = val;
        } else if (std.mem.eql(u8, key, "s")) {
            sig.selector = val;
        } else if (std.mem.eql(u8, key, "h")) {
            sig.signed_headers = val;
        } else if (std.mem.eql(u8, key, "t")) {
            sig.timestamp = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, key, "bh")) {
            sig.body_hash = val;
        } else if (std.mem.eql(u8, key, "b")) {
            sig.signature = val;
        }
    }

    return sig;
}

/// Compute a SHA-256 hash encoded as base64.
fn computeBodyHashAlloc(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(body);
    const digest = hasher.finalResult();
    const encoded_len = std.base64.standard.Encoder.calcSize(digest.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, &digest);
    return encoded;
}

/// Sign a message with ARC headers, producing all three ARC headers for a new instance.
/// Returns the three ARC headers concatenated, ready to be prepended to the message.
/// Caller owns the returned memory.
///
/// Note: This produces a placeholder signature using HMAC-SHA256 with the provided
/// private_key bytes. For production use with Ed25519 or RSA, integrate with a
/// proper cryptographic signing module.
pub fn signArcSetAlloc(allocator: std.mem.Allocator, message: []const u8, options: ArcSignOptions) ![]u8 {
    // Separate headers from body
    const header_end = std.mem.indexOf(u8, message, "\r\n\r\n") orelse message.len;
    const body = if (header_end + 4 <= message.len) message[header_end + 4 ..] else "";

    // Compute body hash
    const body_hash = try computeBodyHashAlloc(allocator, body);
    defer allocator.free(body_hash);

    // Compute message signature using HMAC-SHA256
    const msg_sig = try computeHmacSignatureAlloc(allocator, options.private_key, message);
    defer allocator.free(msg_sig);

    // Build ARC-Authentication-Results
    const aar = ArcAuthResults{
        .instance = options.instance,
        .authserv_id = options.authserv_id,
        .results = options.auth_results_text,
    };
    const aar_header = try buildArcAuthResultsAlloc(allocator, aar);
    defer allocator.free(aar_header);

    // Build ARC-Message-Signature
    const ams = ArcMessageSignature{
        .instance = options.instance,
        .algorithm = "ed25519-sha256",
        .domain = options.domain,
        .selector = options.selector,
        .signed_headers = options.signed_headers,
        .body_hash = body_hash,
        .signature = msg_sig,
        .timestamp = options.timestamp,
    };
    const ams_header = try buildArcMessageSignatureAlloc(allocator, ams);
    defer allocator.free(ams_header);

    // Build seal input: AAR + AMS headers, then sign
    var seal_input: std.ArrayList(u8) = .empty;
    defer seal_input.deinit(allocator);
    try seal_input.appendSlice(allocator, aar_header);
    try seal_input.appendSlice(allocator, "\r\n");
    try seal_input.appendSlice(allocator, ams_header);

    const seal_sig = try computeHmacSignatureAlloc(allocator, options.private_key, seal_input.items);
    defer allocator.free(seal_sig);

    // Build ARC-Seal
    const as = ArcSeal{
        .instance = options.instance,
        .algorithm = "ed25519-sha256",
        .domain = options.domain,
        .selector = options.selector,
        .chain_validation = options.chain_validation,
        .signature = seal_sig,
        .timestamp = options.timestamp,
    };
    const as_header = try buildArcSealAlloc(allocator, as);
    defer allocator.free(as_header);

    // Concatenate all three headers per RFC 8617 ordering: AAR, AMS, AS
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);
    try result.appendSlice(allocator, aar_header);
    try result.appendSlice(allocator, "\r\n");
    try result.appendSlice(allocator, ams_header);
    try result.appendSlice(allocator, "\r\n");
    try result.appendSlice(allocator, as_header);
    try result.appendSlice(allocator, "\r\n");

    return result.toOwnedSlice(allocator);
}

/// Compute HMAC-SHA256 and return base64-encoded result.
fn computeHmacSignatureAlloc(allocator: std.mem.Allocator, key: []const u8, data: []const u8) ![]u8 {
    // Pad or hash the key to block size (64 bytes for SHA-256)
    var key_block: [64]u8 = @splat(0);
    if (key.len > 64) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(key);
        const key_hash = hasher.finalResult();
        @memcpy(key_block[0..key_hash.len], &key_hash);
    } else {
        @memcpy(key_block[0..key.len], key);
    }

    // Inner hash: H((key XOR ipad) || data)
    var ipad: [64]u8 = undefined;
    var opad: [64]u8 = undefined;
    for (0..64) |i| {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    var inner = std.crypto.hash.sha2.Sha256.init(.{});
    inner.update(&ipad);
    inner.update(data);
    const inner_hash = inner.finalResult();

    // Outer hash: H((key XOR opad) || inner_hash)
    var outer = std.crypto.hash.sha2.Sha256.init(.{});
    outer.update(&opad);
    outer.update(&inner_hash);
    const mac = outer.finalResult();

    const encoded_len = std.base64.standard.Encoder.calcSize(mac.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, &mac);
    return encoded;
}

fn parseChainValidation(val: []const u8) ArcResult {
    if (std.mem.eql(u8, val, "pass")) return .arc_pass;
    if (std.mem.eql(u8, val, "fail")) return .arc_fail;
    return .arc_none;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "ArcResult.label" {
    try std.testing.expectEqualStrings("pass", ArcResult.arc_pass.label());
    try std.testing.expectEqualStrings("fail", ArcResult.arc_fail.label());
    try std.testing.expectEqualStrings("none", ArcResult.arc_none.label());
}

test "buildArcSealAlloc basic" {
    const allocator = std.testing.allocator;
    const seal = ArcSeal{
        .instance = 1,
        .algorithm = "ed25519-sha256",
        .domain = "example.com",
        .selector = "sel1",
        .chain_validation = .arc_none,
        .signature = "dGVzdA==",
        .timestamp = 1234567890,
    };
    const header = try buildArcSealAlloc(allocator, seal);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "ARC-Seal: i=1; a=ed25519-sha256; cv=none; d=example.com; s=sel1; t=1234567890; b=dGVzdA==",
        header,
    );
}

test "buildArcSealAlloc without timestamp" {
    const allocator = std.testing.allocator;
    const seal = ArcSeal{
        .instance = 2,
        .domain = "example.com",
        .selector = "s1",
        .chain_validation = .arc_pass,
        .signature = "c2ln",
    };
    const header = try buildArcSealAlloc(allocator, seal);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "ARC-Seal: i=2; a=ed25519-sha256; cv=pass; d=example.com; s=s1; b=c2ln",
        header,
    );
}

test "buildArcMessageSignatureAlloc" {
    const allocator = std.testing.allocator;
    const sig = ArcMessageSignature{
        .instance = 1,
        .algorithm = "ed25519-sha256",
        .domain = "example.com",
        .selector = "sel1",
        .signed_headers = "From:To:Subject",
        .body_hash = "Ym9keWhhc2g=",
        .signature = "c2ln",
        .canonicalization_header = "relaxed",
        .canonicalization_body = "relaxed",
        .timestamp = 1234567890,
    };
    const header = try buildArcMessageSignatureAlloc(allocator, sig);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "ARC-Message-Signature: i=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=From:To:Subject; t=1234567890; bh=Ym9keWhhc2g=; b=c2ln",
        header,
    );
}

test "buildArcAuthResultsAlloc" {
    const allocator = std.testing.allocator;
    const aar = ArcAuthResults{
        .instance = 1,
        .authserv_id = "mx.example.com",
        .results = "dkim=pass header.d=example.com",
    };
    const header = try buildArcAuthResultsAlloc(allocator, aar);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "ARC-Authentication-Results: i=1; mx.example.com; dkim=pass header.d=example.com",
        header,
    );
}

test "buildArcAuthResultsAlloc no results" {
    const allocator = std.testing.allocator;
    const aar = ArcAuthResults{
        .instance = 1,
        .authserv_id = "mx.example.com",
    };
    const header = try buildArcAuthResultsAlloc(allocator, aar);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "ARC-Authentication-Results: i=1; mx.example.com",
        header,
    );
}

test "parseArcSeal parses header value" {
    const seal = parseArcSeal("i=1; a=ed25519-sha256; cv=pass; d=example.com; s=sel1; t=1234567890; b=dGVzdA==");
    try std.testing.expectEqual(@as(u32, 1), seal.instance);
    try std.testing.expectEqualStrings("ed25519-sha256", seal.algorithm);
    try std.testing.expectEqual(ArcResult.arc_pass, seal.chain_validation);
    try std.testing.expectEqualStrings("example.com", seal.domain);
    try std.testing.expectEqualStrings("sel1", seal.selector);
    try std.testing.expectEqual(@as(u64, 1234567890), seal.timestamp.?);
    try std.testing.expectEqualStrings("dGVzdA==", seal.signature);
}

test "parseArcSeal handles minimal value" {
    const seal = parseArcSeal("i=3; d=test.com; s=s1; cv=fail; b=abc");
    try std.testing.expectEqual(@as(u32, 3), seal.instance);
    try std.testing.expectEqualStrings("test.com", seal.domain);
    try std.testing.expectEqualStrings("s1", seal.selector);
    try std.testing.expectEqual(ArcResult.arc_fail, seal.chain_validation);
    try std.testing.expectEqualStrings("abc", seal.signature);
}

test "parseArcMessageSignature parses header value" {
    const sig = parseArcMessageSignature("i=1; a=ed25519-sha256; c=relaxed/simple; d=example.com; s=sel1; h=From:To; bh=hash; b=sig; t=999");
    try std.testing.expectEqual(@as(u32, 1), sig.instance);
    try std.testing.expectEqualStrings("ed25519-sha256", sig.algorithm);
    try std.testing.expectEqualStrings("relaxed", sig.canonicalization_header);
    try std.testing.expectEqualStrings("simple", sig.canonicalization_body);
    try std.testing.expectEqualStrings("example.com", sig.domain);
    try std.testing.expectEqualStrings("sel1", sig.selector);
    try std.testing.expectEqualStrings("From:To", sig.signed_headers);
    try std.testing.expectEqualStrings("hash", sig.body_hash);
    try std.testing.expectEqualStrings("sig", sig.signature);
    try std.testing.expectEqual(@as(u64, 999), sig.timestamp.?);
}

test "parseArcMessageSignature handles single canonicalization" {
    const sig = parseArcMessageSignature("i=1; c=simple; d=test.com; s=s1; bh=h; b=s");
    try std.testing.expectEqualStrings("simple", sig.canonicalization_header);
    try std.testing.expectEqualStrings("relaxed", sig.canonicalization_body);
}

test "signArcSetAlloc produces valid output" {
    const allocator = std.testing.allocator;

    const message = "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\n\r\nHello, World!";

    const result = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "relay.example.com",
        .selector = "arc1",
        .private_key = "test-key-material-for-hmac",
        .authserv_id = "relay.example.com",
        .auth_results_text = "dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com",
        .chain_validation = .arc_none,
        .signed_headers = "From:To:Subject:Date",
        .timestamp = 1735689600,
    });
    defer allocator.free(result);

    // Should contain all three headers
    try std.testing.expect(std.mem.indexOf(u8, result, "ARC-Authentication-Results:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "ARC-Message-Signature:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "ARC-Seal:") != null);

    // Should contain the instance number
    try std.testing.expect(std.mem.indexOf(u8, result, "i=1") != null);

    // Should contain the domain
    try std.testing.expect(std.mem.indexOf(u8, result, "relay.example.com") != null);

    // Should contain auth results text
    try std.testing.expect(std.mem.indexOf(u8, result, "dkim=pass") != null);
}

test "signArcSetAlloc with instance 2" {
    const allocator = std.testing.allocator;

    const message = "From: a@b.com\r\nTo: c@d.com\r\n\r\nBody";

    const result = try signArcSetAlloc(allocator, message, .{
        .instance = 2,
        .domain = "hop2.example.com",
        .selector = "s2",
        .private_key = "another-key",
        .authserv_id = "hop2.example.com",
        .auth_results_text = "arc=pass",
        .chain_validation = .arc_pass,
        .signed_headers = "From:To",
    });
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "i=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cv=pass") != null);
}

test "computeBodyHashAlloc produces consistent hash" {
    const allocator = std.testing.allocator;
    const hash1 = try computeBodyHashAlloc(allocator, "Hello, World!");
    defer allocator.free(hash1);
    const hash2 = try computeBodyHashAlloc(allocator, "Hello, World!");
    defer allocator.free(hash2);
    try std.testing.expectEqualStrings(hash1, hash2);
}

test "computeBodyHashAlloc different bodies produce different hashes" {
    const allocator = std.testing.allocator;
    const hash1 = try computeBodyHashAlloc(allocator, "Hello");
    defer allocator.free(hash1);
    const hash2 = try computeBodyHashAlloc(allocator, "World");
    defer allocator.free(hash2);
    try std.testing.expect(!std.mem.eql(u8, hash1, hash2));
}

test "computeHmacSignatureAlloc produces consistent signature" {
    const allocator = std.testing.allocator;
    const sig1 = try computeHmacSignatureAlloc(allocator, "key", "data");
    defer allocator.free(sig1);
    const sig2 = try computeHmacSignatureAlloc(allocator, "key", "data");
    defer allocator.free(sig2);
    try std.testing.expectEqualStrings(sig1, sig2);
}

test "computeHmacSignatureAlloc different keys produce different signatures" {
    const allocator = std.testing.allocator;
    const sig1 = try computeHmacSignatureAlloc(allocator, "key1", "data");
    defer allocator.free(sig1);
    const sig2 = try computeHmacSignatureAlloc(allocator, "key2", "data");
    defer allocator.free(sig2);
    try std.testing.expect(!std.mem.eql(u8, sig1, sig2));
}

test "parseChainValidation" {
    try std.testing.expectEqual(ArcResult.arc_pass, parseChainValidation("pass"));
    try std.testing.expectEqual(ArcResult.arc_fail, parseChainValidation("fail"));
    try std.testing.expectEqual(ArcResult.arc_none, parseChainValidation("none"));
    try std.testing.expectEqual(ArcResult.arc_none, parseChainValidation("unknown"));
}
