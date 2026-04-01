const std = @import("std");

/// TLSA certificate usage field (RFC 6698 Section 2.1.1).
pub const CertUsage = enum(u8) {
    /// CA constraint (PKIX-TA)
    pkix_ta = 0,
    /// Service certificate constraint (PKIX-EE)
    pkix_ee = 1,
    /// Trust anchor assertion (DANE-TA)
    dane_ta = 2,
    /// Domain-issued certificate (DANE-EE)
    dane_ee = 3,

    pub fn label(self: CertUsage) []const u8 {
        return switch (self) {
            .pkix_ta => "PKIX-TA",
            .pkix_ee => "PKIX-EE",
            .dane_ta => "DANE-TA",
            .dane_ee => "DANE-EE",
        };
    }
};

/// TLSA selector field.
pub const Selector = enum(u8) {
    /// Full certificate
    full_cert = 0,
    /// SubjectPublicKeyInfo
    spki = 1,

    pub fn label(self: Selector) []const u8 {
        return switch (self) {
            .full_cert => "Cert",
            .spki => "SPKI",
        };
    }
};

/// TLSA matching type field.
pub const MatchingType = enum(u8) {
    /// Exact match (no hash)
    exact = 0,
    /// SHA-256 hash
    sha256 = 1,
    /// SHA-512 hash
    sha512 = 2,

    pub fn label(self: MatchingType) []const u8 {
        return switch (self) {
            .exact => "Full",
            .sha256 => "SHA-256",
            .sha512 => "SHA-512",
        };
    }
};

/// A parsed TLSA record.
pub const TlsaRecord = struct {
    cert_usage: CertUsage,
    selector: Selector,
    matching_type: MatchingType,
    certificate_data: []const u8, // hex-encoded string

    pub fn eql(self: TlsaRecord, other: TlsaRecord) bool {
        return self.cert_usage == other.cert_usage and
            self.selector == other.selector and
            self.matching_type == other.matching_type and
            std.mem.eql(u8, self.certificate_data, other.certificate_data);
    }
};

/// DANE verification result.
pub const VerifyResult = enum {
    /// TLSA records found and certificate matches.
    pass,
    /// TLSA records found but certificate does not match.
    fail,
    /// No TLSA records found (DANE not configured).
    none,
    /// DNS lookup error (treat as if DANE not configured).
    temperror,
    /// Invalid TLSA record format.
    permerror,

    pub fn label(self: VerifyResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .none => "none",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn isPass(self: VerifyResult) bool {
        return self == .pass;
    }
};

/// Parse error for TLSA records.
pub const ParseError = error{
    InvalidFormat,
    InvalidUsage,
    InvalidSelector,
    InvalidMatchingType,
    InvalidHexData,
};

/// Parse a TLSA record from its text representation.
/// Format: "<usage> <selector> <matching_type> <hex_data>"
pub fn parseTlsaRecord(text: []const u8) ParseError!TlsaRecord {
    var it = std.mem.tokenizeScalar(u8, text, ' ');

    const usage_str = it.next() orelse return ParseError.InvalidFormat;
    const selector_str = it.next() orelse return ParseError.InvalidFormat;
    const matching_str = it.next() orelse return ParseError.InvalidFormat;
    const hex_data = it.rest();

    if (hex_data.len == 0) return ParseError.InvalidFormat;

    // Remove any remaining whitespace from hex data
    const usage_val = std.fmt.parseInt(u8, usage_str, 10) catch return ParseError.InvalidUsage;
    const selector_val = std.fmt.parseInt(u8, selector_str, 10) catch return ParseError.InvalidSelector;
    const matching_val = std.fmt.parseInt(u8, matching_str, 10) catch return ParseError.InvalidMatchingType;

    const cert_usage = std.meta.intToEnum(CertUsage, usage_val) catch return ParseError.InvalidUsage;
    const selector = std.meta.intToEnum(Selector, selector_val) catch return ParseError.InvalidSelector;
    const matching_type = std.meta.intToEnum(MatchingType, matching_val) catch return ParseError.InvalidMatchingType;

    // Validate hex data: must contain only hex characters
    for (hex_data) |c| {
        if (!std.ascii.isHex(c)) return ParseError.InvalidHexData;
    }

    return TlsaRecord{
        .cert_usage = cert_usage,
        .selector = selector,
        .matching_type = matching_type,
        .certificate_data = hex_data,
    };
}

/// Format the TLSA DNS record name for a given hostname and port.
/// Returns "_<port>._tcp.<hostname>"
pub fn formatTlsaNameAlloc(allocator: std.mem.Allocator, hostname: []const u8, port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator, "_{d}._tcp.{s}", .{ port, hostname });
}

/// Verify certificate data against a TLSA record.
/// `cert_data` is the DER-encoded certificate or SPKI depending on the selector.
/// `record.certificate_data` is the hex-encoded expected value.
pub fn verifyTlsa(record: TlsaRecord, cert_data: []const u8) VerifyResult {
    switch (record.matching_type) {
        .exact => {
            // Compare cert_data bytes against hex-encoded record data.
            // Each byte in cert_data corresponds to two hex characters.
            if (cert_data.len * 2 != record.certificate_data.len) return .fail;
            for (cert_data, 0..) |byte, i| {
                const hex_pair = [2]u8{
                    record.certificate_data[i * 2],
                    record.certificate_data[i * 2 + 1],
                };
                const expected = std.fmt.parseInt(u8, &hex_pair, 16) catch return .fail;
                if (byte != expected) return .fail;
            }
            return .pass;
        },
        .sha256 => {
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(cert_data, &hash, .{});
            const hex = std.fmt.bytesToHex(hash, .lower);
            if (std.ascii.eqlIgnoreCase(&hex, record.certificate_data)) {
                return .pass;
            }
            return .fail;
        },
        .sha512 => {
            var hash: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(cert_data, &hash, .{});
            const hex = std.fmt.bytesToHex(hash, .lower);
            if (std.ascii.eqlIgnoreCase(&hex, record.certificate_data)) {
                return .pass;
            }
            return .fail;
        },
    }
}

/// Verify certificate against multiple TLSA records.
/// Returns pass if ANY record matches (OR logic per RFC 6698).
pub fn verifyTlsaSet(records: []const TlsaRecord, cert_data: []const u8) VerifyResult {
    if (records.len == 0) return .none;

    for (records) |record| {
        if (verifyTlsa(record, cert_data) == .pass) {
            return .pass;
        }
    }

    return .fail;
}

/// Build a TLSA record string for publishing.
pub fn buildTlsaRecordAlloc(allocator: std.mem.Allocator, record: TlsaRecord) ![]u8 {
    return std.fmt.allocPrint(allocator, "{d} {d} {d} {s}", .{
        @intFromEnum(record.cert_usage),
        @intFromEnum(record.selector),
        @intFromEnum(record.matching_type),
        record.certificate_data,
    });
}

/// Compute SHA-256 hash of certificate data and return as hex string.
pub fn hashCertSha256Alloc(allocator: std.mem.Allocator, cert_data: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_data, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    return allocator.dupe(u8, &hex);
}

/// Compute SHA-512 hash of certificate data and return as hex string.
pub fn hashCertSha512Alloc(allocator: std.mem.Allocator, cert_data: []const u8) ![]u8 {
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(cert_data, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    return allocator.dupe(u8, &hex);
}

// --- Tests ---

test "parseTlsaRecord - DANE-EE SPKI SHA-256" {
    const record = try parseTlsaRecord("3 1 1 aabbccdd");
    try std.testing.expectEqual(CertUsage.dane_ee, record.cert_usage);
    try std.testing.expectEqual(Selector.spki, record.selector);
    try std.testing.expectEqual(MatchingType.sha256, record.matching_type);
    try std.testing.expectEqualStrings("aabbccdd", record.certificate_data);
}

test "parseTlsaRecord - PKIX-TA full cert exact" {
    const record = try parseTlsaRecord("0 0 0 deadbeef");
    try std.testing.expectEqual(CertUsage.pkix_ta, record.cert_usage);
    try std.testing.expectEqual(Selector.full_cert, record.selector);
    try std.testing.expectEqual(MatchingType.exact, record.matching_type);
    try std.testing.expectEqualStrings("deadbeef", record.certificate_data);
}

test "parseTlsaRecord - PKIX-EE SPKI SHA-512" {
    const record = try parseTlsaRecord("1 1 2 abcdef0123456789");
    try std.testing.expectEqual(CertUsage.pkix_ee, record.cert_usage);
    try std.testing.expectEqual(Selector.spki, record.selector);
    try std.testing.expectEqual(MatchingType.sha512, record.matching_type);
    try std.testing.expectEqualStrings("abcdef0123456789", record.certificate_data);
}

test "parseTlsaRecord - DANE-TA full cert SHA-256" {
    const record = try parseTlsaRecord("2 0 1 ff00ff00");
    try std.testing.expectEqual(CertUsage.dane_ta, record.cert_usage);
    try std.testing.expectEqual(Selector.full_cert, record.selector);
    try std.testing.expectEqual(MatchingType.sha256, record.matching_type);
    try std.testing.expectEqualStrings("ff00ff00", record.certificate_data);
}

test "parseTlsaRecord - invalid format missing fields" {
    try std.testing.expectError(ParseError.InvalidFormat, parseTlsaRecord("3 1"));
}

test "parseTlsaRecord - invalid format empty" {
    try std.testing.expectError(ParseError.InvalidFormat, parseTlsaRecord(""));
}

test "parseTlsaRecord - invalid usage value" {
    try std.testing.expectError(ParseError.InvalidUsage, parseTlsaRecord("9 1 1 aabb"));
}

test "parseTlsaRecord - invalid selector value" {
    try std.testing.expectError(ParseError.InvalidSelector, parseTlsaRecord("3 5 1 aabb"));
}

test "parseTlsaRecord - invalid matching type value" {
    try std.testing.expectError(ParseError.InvalidMatchingType, parseTlsaRecord("3 1 9 aabb"));
}

test "parseTlsaRecord - invalid hex data" {
    try std.testing.expectError(ParseError.InvalidHexData, parseTlsaRecord("3 1 1 xyz!"));
}

test "formatTlsaNameAlloc - SMTP default port" {
    const name = try formatTlsaNameAlloc(std.testing.allocator, "example.com", 25);
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("_25._tcp.example.com", name);
}

test "formatTlsaNameAlloc - submission port" {
    const name = try formatTlsaNameAlloc(std.testing.allocator, "mail.example.org", 587);
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("_587._tcp.mail.example.org", name);
}

test "formatTlsaNameAlloc - SMTPS port" {
    const name = try formatTlsaNameAlloc(std.testing.allocator, "smtp.example.com", 465);
    defer std.testing.allocator.free(name);
    try std.testing.expectEqualStrings("_465._tcp.smtp.example.com", name);
}

test "verifyTlsa - exact match pass" {
    const cert_data = "\xde\xad\xbe\xef";
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .full_cert,
        .matching_type = .exact,
        .certificate_data = "deadbeef",
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsa(record, cert_data));
}

test "verifyTlsa - exact match fail" {
    const cert_data = "\xde\xad\xbe\xef";
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .full_cert,
        .matching_type = .exact,
        .certificate_data = "aabbccdd",
    };
    try std.testing.expectEqual(VerifyResult.fail, verifyTlsa(record, cert_data));
}

test "verifyTlsa - SHA-256 match pass" {
    const cert_data = "hello";
    // SHA-256 of "hello"
    const expected_hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = expected_hex,
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsa(record, cert_data));
}

test "verifyTlsa - SHA-256 match fail" {
    const cert_data = "hello";
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = "0000000000000000000000000000000000000000000000000000000000000000",
    };
    try std.testing.expectEqual(VerifyResult.fail, verifyTlsa(record, cert_data));
}

test "verifyTlsa - SHA-512 match pass" {
    const cert_data = "hello";
    // SHA-512 of "hello"
    const expected_hex = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
    const record = TlsaRecord{
        .cert_usage = .pkix_ee,
        .selector = .full_cert,
        .matching_type = .sha512,
        .certificate_data = expected_hex,
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsa(record, cert_data));
}

test "verifyTlsa - SHA-512 match fail" {
    const cert_data = "hello";
    const record = TlsaRecord{
        .cert_usage = .pkix_ee,
        .selector = .full_cert,
        .matching_type = .sha512,
        .certificate_data = "0" ** 128,
    };
    try std.testing.expectEqual(VerifyResult.fail, verifyTlsa(record, cert_data));
}

test "verifyTlsa - case insensitive hex comparison" {
    const cert_data = "\xde\xad\xbe\xef";
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .full_cert,
        .matching_type = .exact,
        .certificate_data = "DEADBEEF",
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsa(record, cert_data));
}

test "verifyTlsaSet - empty records returns none" {
    const records = [_]TlsaRecord{};
    try std.testing.expectEqual(VerifyResult.none, verifyTlsaSet(&records, "hello"));
}

test "verifyTlsaSet - single matching record" {
    const cert_data = "\xde\xad\xbe\xef";
    const records = [_]TlsaRecord{
        .{
            .cert_usage = .dane_ee,
            .selector = .full_cert,
            .matching_type = .exact,
            .certificate_data = "deadbeef",
        },
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsaSet(&records, cert_data));
}

test "verifyTlsaSet - OR logic, second record matches" {
    const cert_data = "\xde\xad\xbe\xef";
    const records = [_]TlsaRecord{
        .{
            .cert_usage = .dane_ee,
            .selector = .full_cert,
            .matching_type = .exact,
            .certificate_data = "aabbccdd",
        },
        .{
            .cert_usage = .dane_ee,
            .selector = .full_cert,
            .matching_type = .exact,
            .certificate_data = "deadbeef",
        },
    };
    try std.testing.expectEqual(VerifyResult.pass, verifyTlsaSet(&records, cert_data));
}

test "verifyTlsaSet - no records match returns fail" {
    const cert_data = "\xde\xad\xbe\xef";
    const records = [_]TlsaRecord{
        .{
            .cert_usage = .dane_ee,
            .selector = .full_cert,
            .matching_type = .exact,
            .certificate_data = "aabbccdd",
        },
        .{
            .cert_usage = .dane_ee,
            .selector = .full_cert,
            .matching_type = .exact,
            .certificate_data = "11223344",
        },
    };
    try std.testing.expectEqual(VerifyResult.fail, verifyTlsaSet(&records, cert_data));
}

test "buildTlsaRecordAlloc" {
    const record = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = "aabbccdd",
    };
    const result = try buildTlsaRecordAlloc(std.testing.allocator, record);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("3 1 1 aabbccdd", result);
}

test "buildTlsaRecordAlloc - PKIX-TA exact" {
    const record = TlsaRecord{
        .cert_usage = .pkix_ta,
        .selector = .full_cert,
        .matching_type = .exact,
        .certificate_data = "deadbeef",
    };
    const result = try buildTlsaRecordAlloc(std.testing.allocator, record);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("0 0 0 deadbeef", result);
}

test "hashCertSha256Alloc" {
    const hex = try hashCertSha256Alloc(std.testing.allocator, "hello");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        hex,
    );
}

test "hashCertSha512Alloc" {
    const hex = try hashCertSha512Alloc(std.testing.allocator, "hello");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings(
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        hex,
    );
}

test "CertUsage labels" {
    try std.testing.expectEqualStrings("PKIX-TA", CertUsage.pkix_ta.label());
    try std.testing.expectEqualStrings("PKIX-EE", CertUsage.pkix_ee.label());
    try std.testing.expectEqualStrings("DANE-TA", CertUsage.dane_ta.label());
    try std.testing.expectEqualStrings("DANE-EE", CertUsage.dane_ee.label());
}

test "Selector labels" {
    try std.testing.expectEqualStrings("Cert", Selector.full_cert.label());
    try std.testing.expectEqualStrings("SPKI", Selector.spki.label());
}

test "MatchingType labels" {
    try std.testing.expectEqualStrings("Full", MatchingType.exact.label());
    try std.testing.expectEqualStrings("SHA-256", MatchingType.sha256.label());
    try std.testing.expectEqualStrings("SHA-512", MatchingType.sha512.label());
}

test "VerifyResult labels" {
    try std.testing.expectEqualStrings("pass", VerifyResult.pass.label());
    try std.testing.expectEqualStrings("fail", VerifyResult.fail.label());
    try std.testing.expectEqualStrings("none", VerifyResult.none.label());
    try std.testing.expectEqualStrings("temperror", VerifyResult.temperror.label());
    try std.testing.expectEqualStrings("permerror", VerifyResult.permerror.label());
}

test "VerifyResult isPass" {
    try std.testing.expect(VerifyResult.pass.isPass());
    try std.testing.expect(!VerifyResult.fail.isPass());
    try std.testing.expect(!VerifyResult.none.isPass());
}

test "TlsaRecord eql" {
    const a = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = "aabb",
    };
    const b = TlsaRecord{
        .cert_usage = .dane_ee,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = "aabb",
    };
    const c = TlsaRecord{
        .cert_usage = .pkix_ta,
        .selector = .spki,
        .matching_type = .sha256,
        .certificate_data = "aabb",
    };
    try std.testing.expect(a.eql(b));
    try std.testing.expect(!a.eql(c));
}

test "parseTlsaRecord roundtrip with buildTlsaRecordAlloc" {
    const original = "3 1 1 aabbccdd";
    const record = try parseTlsaRecord(original);
    const rebuilt = try buildTlsaRecordAlloc(std.testing.allocator, record);
    defer std.testing.allocator.free(rebuilt);
    try std.testing.expectEqualStrings(original, rebuilt);
}
