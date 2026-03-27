const std = @import("std");
const smtp = @import("smtp");

// --- Canonicalization Tests ---

test "simple body canonicalization - normal body" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "Hello\r\nWorld\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\nWorld\r\n", result);
}

test "simple body canonicalization - strips trailing empty lines" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "Hello\r\n\r\n\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\n", result);
}

test "simple body canonicalization - empty body becomes CRLF" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\r\n", result);
}

test "simple body canonicalization - only empty lines becomes CRLF" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "\r\n\r\n\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("\r\n", result);
}

test "relaxed body canonicalization - compress whitespace" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "Hello   World\r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World\r\n", result);
}

test "relaxed body canonicalization - strip trailing whitespace on line" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "Hello   \r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello\r\n", result);
}

test "relaxed body canonicalization - empty body becomes empty" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeBody(allocator, "", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "relaxed header canonicalization - lowercase name" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeHeader(allocator, "Subject: Hello\r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject: Hello\r\n", result);
}

test "relaxed header canonicalization - compress value whitespace" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeHeader(allocator, "Subject:   Hello   World  \r\n", .relaxed);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("subject: Hello World\r\n", result);
}

test "simple header canonicalization - no change" {
    const allocator = std.testing.allocator;
    const result = try smtp.dkim.canonicalizeHeader(allocator, "Subject: Hello\r\n", .simple);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subject: Hello\r\n", result);
}

test "canonicalization label" {
    var buf: [15]u8 = undefined;
    const c = smtp.dkim.Canonicalization{ .header = .relaxed, .body = .relaxed };
    const label = c.label(&buf);
    try std.testing.expectEqualStrings("relaxed/relaxed", label);
}

test "canonicalization label simple/simple" {
    var buf: [15]u8 = undefined;
    const c = smtp.dkim.Canonicalization{ .header = .simple, .body = .simple };
    const label = c.label(&buf);
    try std.testing.expectEqualStrings("simple/simple", label);
}

// --- Key Tests ---

test "generate and use ed25519 key" {
    const k = smtp.dkim.generateEd25519Key();
    const msg = "test message for signing";
    const sig = k.sign(msg);
    try std.testing.expect(k.verify(msg, sig));
}

test "ed25519 key - wrong message fails verification" {
    const k = smtp.dkim.generateEd25519Key();
    const sig = k.sign("correct message");
    try std.testing.expect(!k.verify("wrong message", sig));
}

test "ed25519 public key base64 encoding" {
    const k = smtp.dkim.generateEd25519Key();
    var buf: [44]u8 = undefined;
    const b64 = k.publicKeyBase64(&buf);
    try std.testing.expect(b64.len > 0);
    try std.testing.expect(b64.len <= 44);
}

test "signing key algorithm label" {
    const k = smtp.dkim.generateEd25519Key();
    const sk = smtp.dkim.SigningKey{ .ed25519 = k };
    try std.testing.expectEqualStrings("ed25519-sha256", sk.algorithmLabel());
    try std.testing.expectEqualStrings("ed25519", sk.keyTypeLabel());
}

test "load ed25519 key from seed - deterministic" {
    var seed1: [32]u8 = undefined;
    @memset(&seed1, 0xAA);
    const k1 = smtp.dkim.loadEd25519KeyFromSeed(seed1);
    const k2 = smtp.dkim.loadEd25519KeyFromSeed(seed1);
    try std.testing.expectEqual(k1.publicKeyBytes(), k2.publicKeyBytes());
}

test "different seeds produce different keys" {
    var seed1: [32]u8 = undefined;
    @memset(&seed1, 0xAA);
    var seed2: [32]u8 = undefined;
    @memset(&seed2, 0xBB);
    const k1 = smtp.dkim.loadEd25519KeyFromSeed(seed1);
    const k2 = smtp.dkim.loadEd25519KeyFromSeed(seed2);
    try std.testing.expect(!std.mem.eql(u8, &k1.publicKeyBytes(), &k2.publicKeyBytes()));
}

// --- Header Tests ---

test "build DKIM header" {
    const allocator = std.testing.allocator;
    const hdr = smtp.dkim.DkimHeader{
        .domain = "example.com",
        .selector = "sel1",
        .signed_headers = "From:To:Subject",
        .body_hash = "abcdef123456==",
        .timestamp = 1679900000,
    };
    const result = try smtp.dkim.buildDkimHeaderAlloc(allocator, hdr);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "DKIM-Signature:") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "v=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "d=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "s=sel1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "h=From:To:Subject") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bh=abcdef123456==") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "t=1679900000") != null);
}

test "build DKIM header with empty signature" {
    const allocator = std.testing.allocator;
    const hdr = smtp.dkim.DkimHeader{
        .domain = "test.com",
        .selector = "s",
        .signed_headers = "From",
        .body_hash = "hash==",
        .signature = "",
    };
    const result = try smtp.dkim.buildDkimHeaderAlloc(allocator, hdr);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "b=") != null);
}

test "parse DKIM header" {
    const hdr = smtp.dkim.parseDkimHeader("v=1; a=ed25519-sha256; d=example.com; s=sel1; h=From:To; bh=abc==; b=xyz==; t=12345");
    try std.testing.expectEqualStrings("1", hdr.version);
    try std.testing.expectEqualStrings("ed25519-sha256", hdr.algorithm);
    try std.testing.expectEqualStrings("example.com", hdr.domain);
    try std.testing.expectEqualStrings("sel1", hdr.selector);
    try std.testing.expectEqualStrings("From:To", hdr.signed_headers);
    try std.testing.expectEqualStrings("abc==", hdr.body_hash);
    try std.testing.expectEqualStrings("xyz==", hdr.signature);
    try std.testing.expectEqual(@as(u64, 12345), hdr.timestamp.?);
}

test "parse DKIM header with canonicalization" {
    const hdr = smtp.dkim.parseDkimHeader("v=1; c=relaxed/simple; d=test.com; s=s1; h=From; bh=x; b=y");
    try std.testing.expectEqual(smtp.dkim.CanonicalizationAlgo.relaxed, hdr.canonicalization.header);
    try std.testing.expectEqual(smtp.dkim.CanonicalizationAlgo.simple, hdr.canonicalization.body);
}

// --- DNS Record Tests ---

test "build DNS record" {
    const allocator = std.testing.allocator;
    const record = smtp.dkim.DnsRecord{
        .key_type = "ed25519",
        .public_key = "base64pubkey==",
    };
    const result = try smtp.dkim.buildDnsRecordAlloc(allocator, record);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "v=DKIM1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "k=ed25519") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "p=base64pubkey==") != null);
}

test "build DNS record with optional fields" {
    const allocator = std.testing.allocator;
    const record = smtp.dkim.DnsRecord{
        .key_type = "ed25519",
        .public_key = "key==",
        .hash_algorithms = "sha256",
        .service_type = "email",
        .flags = "y",
        .notes = "testing",
    };
    const result = try smtp.dkim.buildDnsRecordAlloc(allocator, record);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "h=sha256") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "s=email") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "t=y") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "n=testing") != null);
}

// --- Full Signer Tests ---

test "sign message produces valid DKIM-Signature header" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = smtp.dkim.loadEd25519KeyFromSeed(seed);

    var signer = smtp.dkim.Signer.init(allocator, .{
        .domain = "example.com",
        .selector = "sel1",
        .key = .{ .ed25519 = k },
        .signed_headers = "From:To:Subject",
        .timestamp = 1679900000,
    });

    const message =
        "From: sender@example.com\r\n" ++
        "To: recipient@example.com\r\n" ++
        "Subject: Test Email\r\n" ++
        "Date: Thu, 01 Jan 2023 00:00:00 +0000\r\n" ++
        "\r\n" ++
        "Hello, World!\r\n";

    const signed = try signer.signAlloc(message);
    defer allocator.free(signed);

    // Verify DKIM-Signature is prepended
    try std.testing.expect(std.mem.startsWith(u8, signed, "DKIM-Signature:"));

    // Verify required fields
    try std.testing.expect(std.mem.indexOf(u8, signed, "v=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "a=ed25519-sha256") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "d=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "s=sel1") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "h=From:To:Subject") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "bh=") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "t=1679900000") != null);

    // Verify original message is intact
    try std.testing.expect(std.mem.indexOf(u8, signed, "From: sender@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "Hello, World!") != null);
}

test "sign message is deterministic with same key and timestamp" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = smtp.dkim.loadEd25519KeyFromSeed(seed);

    const message = "From: a@test.com\r\n\r\nBody\r\n";

    var signer = smtp.dkim.Signer.init(allocator, .{
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .signed_headers = "From",
        .timestamp = 1000000,
    });

    const signed1 = try signer.signAlloc(message);
    defer allocator.free(signed1);
    const signed2 = try signer.signAlloc(message);
    defer allocator.free(signed2);

    try std.testing.expectEqualStrings(signed1, signed2);
}

test "different keys produce different signatures" {
    const allocator = std.testing.allocator;
    const message = "From: a@test.com\r\n\r\nBody\r\n";

    var seed1: [32]u8 = undefined;
    @memset(&seed1, 0x11);
    var seed2: [32]u8 = undefined;
    @memset(&seed2, 0x22);

    var signer1 = smtp.dkim.Signer.init(allocator, .{
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = smtp.dkim.loadEd25519KeyFromSeed(seed1) },
        .signed_headers = "From",
        .timestamp = 1000000,
    });

    var signer2 = smtp.dkim.Signer.init(allocator, .{
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = smtp.dkim.loadEd25519KeyFromSeed(seed2) },
        .signed_headers = "From",
        .timestamp = 1000000,
    });

    const signed1 = try signer1.signAlloc(message);
    defer allocator.free(signed1);
    const signed2 = try signer2.signAlloc(message);
    defer allocator.free(signed2);

    try std.testing.expect(!std.mem.eql(u8, signed1, signed2));
}

test "sign message with relaxed/relaxed canonicalization" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var signer = smtp.dkim.Signer.init(allocator, .{
        .domain = "example.com",
        .selector = "s1",
        .key = .{ .ed25519 = smtp.dkim.loadEd25519KeyFromSeed(seed) },
        .signed_headers = "From:Subject",
        .canonicalization = .{ .header = .relaxed, .body = .relaxed },
        .timestamp = 1000000,
    });

    const message =
        "From: test@example.com\r\n" ++
        "Subject: Hello\r\n" ++
        "\r\n" ++
        "Body text\r\n";

    const signed = try signer.signAlloc(message);
    defer allocator.free(signed);

    try std.testing.expect(std.mem.indexOf(u8, signed, "c=relaxed/relaxed") != null);
}

test "sign message with simple/simple canonicalization" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);

    var signer = smtp.dkim.Signer.init(allocator, .{
        .domain = "example.com",
        .selector = "s1",
        .key = .{ .ed25519 = smtp.dkim.loadEd25519KeyFromSeed(seed) },
        .signed_headers = "From",
        .canonicalization = .{ .header = .simple, .body = .simple },
        .timestamp = 1000000,
    });

    const message = "From: test@example.com\r\n\r\nBody\r\n";
    const signed = try signer.signAlloc(message);
    defer allocator.free(signed);

    try std.testing.expect(std.mem.indexOf(u8, signed, "c=simple/simple") != null);
}

test "end-to-end: sign, extract DNS record, verify components" {
    const allocator = std.testing.allocator;
    const k = smtp.dkim.generateEd25519Key();

    // Get public key for DNS
    var pub_buf: [44]u8 = undefined;
    const pub_b64 = k.publicKeyBase64(&pub_buf);

    // Build DNS record
    const dns_record = try smtp.dkim.buildDnsRecordAlloc(allocator, .{
        .key_type = "ed25519",
        .public_key = pub_b64,
    });
    defer allocator.free(dns_record);
    try std.testing.expect(std.mem.indexOf(u8, dns_record, "v=DKIM1") != null);
    try std.testing.expect(std.mem.indexOf(u8, dns_record, "k=ed25519") != null);

    // Sign a message
    var signer = smtp.dkim.Signer.init(allocator, .{
        .domain = "example.com",
        .selector = "default",
        .key = .{ .ed25519 = k },
        .signed_headers = "From:To:Subject:Date",
        .timestamp = 1700000000,
    });

    const message =
        "From: alice@example.com\r\n" ++
        "To: bob@example.com\r\n" ++
        "Subject: Important\r\n" ++
        "Date: Wed, 15 Nov 2023 00:00:00 +0000\r\n" ++
        "\r\n" ++
        "This is an important message.\r\n";

    const signed = try signer.signAlloc(message);
    defer allocator.free(signed);

    // Verify the signed message structure
    try std.testing.expect(std.mem.startsWith(u8, signed, "DKIM-Signature:"));
    try std.testing.expect(std.mem.indexOf(u8, signed, "d=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "s=default") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "t=1700000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "From: alice@example.com") != null);
}
