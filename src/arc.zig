const std = @import("std");
const dkim_key = @import("dkim/key.zig");
const dkim_canon = @import("dkim/canonicalize.zig");

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

/// Options for signing a new ARC set (deprecated, use ArcSigner instead).
pub const ArcSignOptions = struct {
    instance: u32,
    domain: []const u8,
    selector: []const u8,
    key: dkim_key.SigningKey,
    authserv_id: []const u8,
    auth_results_text: []const u8,
    chain_validation: ArcResult,
    signed_headers: []const u8 = "From:To:Subject:Date",
    timestamp: ?u64 = null,
};

/// ArcSigner provides a clean API for signing ARC sets with Ed25519.
pub const ArcSigner = struct {
    allocator: std.mem.Allocator,
    key: dkim_key.SigningKey,
    domain: []const u8,
    selector: []const u8,

    pub const SignOptions = struct {
        instance: u32,
        authserv_id: []const u8,
        auth_results_text: []const u8,
        chain_validation: ArcResult,
        signed_headers: []const u8 = "From:To:Subject:Date",
        timestamp: ?u64 = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        key: dkim_key.SigningKey,
        domain: []const u8,
        selector: []const u8,
    ) ArcSigner {
        return .{
            .allocator = allocator,
            .key = key,
            .domain = domain,
            .selector = selector,
        };
    }

    /// Sign a message, adding a new ARC set.
    /// Returns the three ARC headers (AAR, AMS, AS) to prepend.
    /// Caller owns the returned memory.
    pub fn signAlloc(self: *ArcSigner, message: []const u8, options: SignOptions) ![]u8 {
        return signArcSetEd25519(
            self.allocator,
            message,
            &self.key,
            self.domain,
            self.selector,
            options.instance,
            options.authserv_id,
            options.auth_results_text,
            options.chain_validation,
            options.signed_headers,
            options.timestamp,
        );
    }
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

/// Split a message into headers and body at the blank line.
fn splitMessage(message: []const u8) struct { headers: []const u8, body: []const u8 } {
    if (std.mem.indexOf(u8, message, "\r\n\r\n")) |sep| {
        return .{
            .headers = message[0 .. sep + 2], // Include trailing CRLF of last header
            .body = message[sep + 4 ..],
        };
    }
    // No blank line found - entire message is headers
    return .{ .headers = message, .body = "" };
}

/// Find a header by name in the headers section (case-insensitive).
/// Returns the full header line including continuation lines.
fn findHeader(headers: []const u8, name: []const u8) ?[]const u8 {
    var last_match: ?[]const u8 = null;
    var pos: usize = 0;

    while (pos < headers.len) {
        var end = pos;
        while (end < headers.len) {
            if (end + 1 < headers.len and headers[end] == '\r' and headers[end + 1] == '\n') {
                end += 2;
                if (end < headers.len and (headers[end] == ' ' or headers[end] == '\t')) {
                    continue;
                }
                break;
            }
            end += 1;
        }
        if (end == pos) break;

        const line = headers[pos..end];

        const colon = std.mem.indexOfScalar(u8, line, ':');
        if (colon) |c| {
            const hdr_name = std.mem.trim(u8, line[0..c], " \t");
            if (hdr_name.len == name.len and std.ascii.eqlIgnoreCase(hdr_name, name)) {
                last_match = line;
            }
        }

        pos = end;
    }

    return last_match;
}

/// Core Ed25519 ARC signing implementation used by both signArcSetAlloc and ArcSigner.
fn signArcSetEd25519(
    allocator: std.mem.Allocator,
    message: []const u8,
    key: *const dkim_key.SigningKey,
    domain: []const u8,
    selector: []const u8,
    instance: u32,
    authserv_id: []const u8,
    auth_results_text: []const u8,
    chain_validation: ArcResult,
    signed_headers: []const u8,
    timestamp: ?u64,
) ![]u8 {
    // Split message into headers and body
    const header_body = splitMessage(message);
    const headers_part = header_body.headers;
    const body_part = header_body.body;

    // Step 1: Canonicalize body (relaxed) and compute SHA-256 body hash
    const canon_body = try dkim_canon.canonicalizeBody(allocator, body_part, .relaxed);
    defer allocator.free(canon_body);

    var body_hash_raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canon_body, &body_hash_raw, .{});
    var body_hash_b64: [44]u8 = undefined;
    const body_hash = std.base64.standard.Encoder.encode(&body_hash_b64, &body_hash_raw);

    // Step 2: Build ARC-Authentication-Results
    const aar = ArcAuthResults{
        .instance = instance,
        .authserv_id = authserv_id,
        .results = auth_results_text,
    };
    const aar_header = try buildArcAuthResultsAlloc(allocator, aar);
    defer allocator.free(aar_header);

    // Step 3: Build ARC-Message-Signature with empty b= for signing
    const ams_empty = ArcMessageSignature{
        .instance = instance,
        .algorithm = "ed25519-sha256",
        .domain = domain,
        .selector = selector,
        .signed_headers = signed_headers,
        .body_hash = body_hash,
        .signature = "",
        .timestamp = timestamp,
    };
    const ams_header_empty = try buildArcMessageSignatureAlloc(allocator, ams_empty);
    defer allocator.free(ams_header_empty);

    // Step 4: Build AMS signing input - canonicalize selected headers + AMS header
    var ams_signing_input: std.ArrayList(u8) = .empty;
    defer ams_signing_input.deinit(allocator);

    // Collect and canonicalize selected headers from the message
    var header_names = std.mem.splitScalar(u8, signed_headers, ':');
    while (header_names.next()) |name| {
        const trimmed_name = std.mem.trim(u8, name, " \t");
        if (trimmed_name.len == 0) continue;

        if (findHeader(headers_part, trimmed_name)) |found_header| {
            const canon_hdr = try dkim_canon.canonicalizeHeader(allocator, found_header, .relaxed);
            defer allocator.free(canon_hdr);
            try ams_signing_input.appendSlice(allocator, canon_hdr);
        }
    }

    // Append canonicalized AMS header (without trailing CRLF) for signing
    const canon_ams = try dkim_canon.canonicalizeHeader(allocator, ams_header_empty, .relaxed);
    defer allocator.free(canon_ams);
    const ams_no_crlf = if (std.mem.endsWith(u8, canon_ams, "\r\n"))
        canon_ams[0 .. canon_ams.len - 2]
    else
        canon_ams;
    try ams_signing_input.appendSlice(allocator, ams_no_crlf);

    // Step 5: Sign AMS with Ed25519
    const ams_sig = key.sign(ams_signing_input.items) orelse return error.SigningFailed;
    const ams_sig_slice = ams_sig.slice();
    const ams_sig_b64_len = std.base64.standard.Encoder.calcSize(ams_sig_slice.len);
    const ams_sig_b64 = try allocator.alloc(u8, ams_sig_b64_len);
    defer allocator.free(ams_sig_b64);
    _ = std.base64.standard.Encoder.encode(ams_sig_b64, ams_sig_slice);

    // Step 6: Build final AMS with signature
    const ams_final = ArcMessageSignature{
        .instance = instance,
        .algorithm = "ed25519-sha256",
        .domain = domain,
        .selector = selector,
        .signed_headers = signed_headers,
        .body_hash = body_hash,
        .signature = ams_sig_b64,
        .timestamp = timestamp,
    };
    const ams_header = try buildArcMessageSignatureAlloc(allocator, ams_final);
    defer allocator.free(ams_header);

    // Step 7: Build ARC-Seal with empty b= for signing
    const as_empty = ArcSeal{
        .instance = instance,
        .algorithm = "ed25519-sha256",
        .domain = domain,
        .selector = selector,
        .chain_validation = chain_validation,
        .signature = "",
        .timestamp = timestamp,
    };
    const as_header_empty = try buildArcSealAlloc(allocator, as_empty);
    defer allocator.free(as_header_empty);

    // Step 8: Build seal signing input per RFC 8617:
    // Previous ARC-Seal headers (i=1..n-1) + current AAR + current AMS + current AS(empty b=)
    var seal_signing_input: std.ArrayList(u8) = .empty;
    defer seal_signing_input.deinit(allocator);

    // For instance > 1, previous ARC-Seal headers would be extracted from the message.
    // Extract previous ARC-Seal headers from the message if instance > 1.
    if (instance > 1) {
        var pos: usize = 0;
        while (pos < headers_part.len) {
            var end = pos;
            while (end < headers_part.len) {
                if (end + 1 < headers_part.len and headers_part[end] == '\r' and headers_part[end + 1] == '\n') {
                    end += 2;
                    if (end < headers_part.len and (headers_part[end] == ' ' or headers_part[end] == '\t')) {
                        continue;
                    }
                    break;
                }
                end += 1;
            }
            if (end == pos) break;

            const line = headers_part[pos..end];
            // Check if this is an ARC-Seal header
            const colon = std.mem.indexOfScalar(u8, line, ':');
            if (colon) |c| {
                const hdr_name = std.mem.trim(u8, line[0..c], " \t");
                if (std.ascii.eqlIgnoreCase(hdr_name, "ARC-Seal")) {
                    const canon_prev = try dkim_canon.canonicalizeHeader(allocator, line, .relaxed);
                    defer allocator.free(canon_prev);
                    try seal_signing_input.appendSlice(allocator, canon_prev);
                }
            }
            pos = end;
        }
    }

    // Add current AAR (canonicalized)
    const canon_aar = try dkim_canon.canonicalizeHeader(allocator, aar_header, .relaxed);
    defer allocator.free(canon_aar);
    try seal_signing_input.appendSlice(allocator, canon_aar);

    // Add current AMS (canonicalized)
    const canon_ams_final = try dkim_canon.canonicalizeHeader(allocator, ams_header, .relaxed);
    defer allocator.free(canon_ams_final);
    try seal_signing_input.appendSlice(allocator, canon_ams_final);

    // Add current AS with empty b= (canonicalized, without trailing CRLF)
    const canon_as = try dkim_canon.canonicalizeHeader(allocator, as_header_empty, .relaxed);
    defer allocator.free(canon_as);
    const as_no_crlf = if (std.mem.endsWith(u8, canon_as, "\r\n"))
        canon_as[0 .. canon_as.len - 2]
    else
        canon_as;
    try seal_signing_input.appendSlice(allocator, as_no_crlf);

    // Step 9: Sign the seal with Ed25519
    const seal_sig = key.sign(seal_signing_input.items) orelse return error.SigningFailed;
    const seal_sig_slice = seal_sig.slice();
    const seal_sig_b64_len = std.base64.standard.Encoder.calcSize(seal_sig_slice.len);
    const seal_sig_b64 = try allocator.alloc(u8, seal_sig_b64_len);
    defer allocator.free(seal_sig_b64);
    _ = std.base64.standard.Encoder.encode(seal_sig_b64, seal_sig_slice);

    // Step 10: Build final ARC-Seal with signature
    const as_final = ArcSeal{
        .instance = instance,
        .algorithm = "ed25519-sha256",
        .domain = domain,
        .selector = selector,
        .chain_validation = chain_validation,
        .signature = seal_sig_b64,
        .timestamp = timestamp,
    };
    const as_header = try buildArcSealAlloc(allocator, as_final);
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

/// Sign a message with ARC headers using Ed25519, producing all three ARC headers for a new instance.
/// Returns the three ARC headers concatenated, ready to be prepended to the message.
/// Caller owns the returned memory.
pub fn signArcSetAlloc(allocator: std.mem.Allocator, message: []const u8, options: ArcSignOptions) ![]u8 {
    return signArcSetEd25519(
        allocator,
        message,
        &options.key,
        options.domain,
        options.selector,
        options.instance,
        options.authserv_id,
        options.auth_results_text,
        options.chain_validation,
        options.signed_headers,
        options.timestamp,
    );
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

test "signArcSetAlloc produces valid Ed25519-signed output" {
    const allocator = std.testing.allocator;

    // Generate a deterministic Ed25519 key
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = dkim_key.loadEd25519KeyFromSeed(seed);

    const message = "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\n\r\nHello, World!";

    const result = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "relay.example.com",
        .selector = "arc1",
        .key = .{ .ed25519 = k },
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

    // Signatures should be base64 Ed25519 (88 chars for 64-byte signature)
    // Verify AMS signature is present and non-empty
    const ams_b_pos = std.mem.indexOf(u8, result, "ARC-Message-Signature:").?;
    const ams_line_end = std.mem.indexOfPos(u8, result, ams_b_pos, "\r\n") orelse result.len;
    const ams_line = result[ams_b_pos..ams_line_end];
    try std.testing.expect(std.mem.indexOf(u8, ams_line, "; b=") != null);
}

test "signArcSetAlloc with instance 2" {
    const allocator = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x55);
    const k = dkim_key.loadEd25519KeyFromSeed(seed);

    const message = "From: a@b.com\r\nTo: c@d.com\r\n\r\nBody";

    const result = try signArcSetAlloc(allocator, message, .{
        .instance = 2,
        .domain = "hop2.example.com",
        .selector = "s2",
        .key = .{ .ed25519 = k },
        .authserv_id = "hop2.example.com",
        .auth_results_text = "arc=pass",
        .chain_validation = .arc_pass,
        .signed_headers = "From:To",
    });
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "i=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "cv=pass") != null);
}

test "signArcSetAlloc deterministic with same key and timestamp" {
    const allocator = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = dkim_key.loadEd25519KeyFromSeed(seed);

    const message = "From: a@test.com\r\nTo: b@test.com\r\n\r\nBody\r\n";

    const result1 = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .authserv_id = "test.com",
        .auth_results_text = "none",
        .chain_validation = .arc_none,
        .signed_headers = "From:To",
        .timestamp = 1000000,
    });
    defer allocator.free(result1);

    const result2 = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .authserv_id = "test.com",
        .auth_results_text = "none",
        .chain_validation = .arc_none,
        .signed_headers = "From:To",
        .timestamp = 1000000,
    });
    defer allocator.free(result2);

    // Same key + same timestamp = same output (deterministic)
    try std.testing.expectEqualStrings(result1, result2);
}

test "signArcSetAlloc produces valid base64 Ed25519 signatures" {
    const allocator = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0xAB);
    const k = dkim_key.loadEd25519KeyFromSeed(seed);

    const message = "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: Test\r\n\r\nBody text\r\n";

    const result = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "example.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .authserv_id = "example.com",
        .auth_results_text = "spf=pass",
        .chain_validation = .arc_none,
        .signed_headers = "From:To:Subject",
        .timestamp = 1700000000,
    });
    defer allocator.free(result);

    // Extract the AMS signature from the result
    const ams_start = std.mem.indexOf(u8, result, "ARC-Message-Signature:").?;
    const ams_end = std.mem.indexOfPos(u8, result, ams_start, "\r\n").?;
    const ams_line = result[ams_start..ams_end];

    // Find the b= value in the AMS line (last "; b=" occurrence, after "; bh=")
    const b_tag = std.mem.lastIndexOf(u8, ams_line, "; b=").?;
    const sig_start = b_tag + 4;
    const sig_b64 = ams_line[sig_start..];

    // Ed25519 signature is 64 bytes, base64-encoded = 88 chars
    try std.testing.expectEqual(@as(usize, 88), sig_b64.len);

    // Verify the signature decodes as valid base64
    var sig_bytes: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(&sig_bytes, sig_b64) catch {
        return error.TestUnexpectedResult;
    };

    // Similarly check ARC-Seal signature
    const as_start = std.mem.indexOf(u8, result, "ARC-Seal:").?;
    const as_end = std.mem.indexOfPos(u8, result, as_start, "\r\n").?;
    const as_line = result[as_start..as_end];
    const as_b_tag = std.mem.lastIndexOf(u8, as_line, "; b=").?;
    const as_sig_b64 = as_line[as_b_tag + 4 ..];
    try std.testing.expectEqual(@as(usize, 88), as_sig_b64.len);

    var as_sig_bytes: [64]u8 = undefined;
    std.base64.standard.Decoder.decode(&as_sig_bytes, as_sig_b64) catch {
        return error.TestUnexpectedResult;
    };
}

test "ArcSigner produces same output as signArcSetAlloc" {
    const allocator = std.testing.allocator;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = dkim_key.loadEd25519KeyFromSeed(seed);

    const message = "From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello\r\n";

    // Use ArcSigner
    var signer = ArcSigner.init(allocator, .{ .ed25519 = k }, "example.com", "s1");
    const signer_result = try signer.signAlloc(message, .{
        .instance = 1,
        .authserv_id = "example.com",
        .auth_results_text = "none",
        .chain_validation = .arc_none,
        .signed_headers = "From:To",
        .timestamp = 1000000,
    });
    defer allocator.free(signer_result);

    // Use signArcSetAlloc
    const direct_result = try signArcSetAlloc(allocator, message, .{
        .instance = 1,
        .domain = "example.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .authserv_id = "example.com",
        .auth_results_text = "none",
        .chain_validation = .arc_none,
        .signed_headers = "From:To",
        .timestamp = 1000000,
    });
    defer allocator.free(direct_result);

    // Both should produce identical output
    try std.testing.expectEqualStrings(signer_result, direct_result);
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

test "parseChainValidation" {
    try std.testing.expectEqual(ArcResult.arc_pass, parseChainValidation("pass"));
    try std.testing.expectEqual(ArcResult.arc_fail, parseChainValidation("fail"));
    try std.testing.expectEqual(ArcResult.arc_none, parseChainValidation("none"));
    try std.testing.expectEqual(ArcResult.arc_none, parseChainValidation("unknown"));
}
