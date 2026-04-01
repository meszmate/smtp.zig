const std = @import("std");
const canonicalize = @import("canonicalize.zig");
const header_mod = @import("header.zig");
const key_mod = @import("key.zig");

pub const Algorithm = enum {
    ed25519_sha256,
    rsa_sha256,

    pub fn label(self: Algorithm) []const u8 {
        return switch (self) {
            .ed25519_sha256 => "ed25519-sha256",
            .rsa_sha256 => "rsa-sha256",
        };
    }
};

pub const SignerOptions = struct {
    domain: []const u8,
    selector: []const u8,
    key: key_mod.SigningKey,
    algorithm: Algorithm = .ed25519_sha256,
    canonicalization: canonicalize.Canonicalization = .{ .header = .relaxed, .body = .relaxed },
    signed_headers: []const u8 = "From:To:Subject:Date:Message-ID",
    timestamp: ?u64 = null,
    expiration: ?u64 = null,
    identity: ?[]const u8 = null,
    body_length: ?u64 = null,
};

pub const SignResult = struct {
    dkim_header: []u8,
    signed_message: []u8,
};

pub const Signer = struct {
    allocator: std.mem.Allocator,
    options: SignerOptions,

    pub fn init(allocator: std.mem.Allocator, options: SignerOptions) Signer {
        return .{ .allocator = allocator, .options = options };
    }

    /// Sign a complete email message and return the message with DKIM-Signature prepended.
    pub fn signAlloc(self: *Signer, message: []const u8) ![]u8 {
        // Split message into headers and body
        const header_body = splitMessage(message);
        const headers_part = header_body.headers;
        const body_part = header_body.body;

        // Step 1: Canonicalize and hash the body
        const canon_body = try canonicalize.canonicalizeBody(self.allocator, body_part, self.options.canonicalization.body);
        defer self.allocator.free(canon_body);

        // Apply body length limit if specified
        const hash_input = if (self.options.body_length) |l|
            canon_body[0..@min(l, canon_body.len)]
        else
            canon_body;

        // Step 2: Compute body hash (SHA-256)
        var body_hash_raw: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(hash_input, &body_hash_raw, .{});
        var body_hash_b64: [44]u8 = undefined;
        const body_hash = std.base64.standard.Encoder.encode(&body_hash_b64, &body_hash_raw);

        // Step 3: Build DKIM-Signature header with empty b=
        const timestamp = self.options.timestamp orelse @as(u64, @intCast(@divTrunc(std.time.milliTimestamp(), 1000)));

        const dkim_hdr = header_mod.DkimHeader{
            .algorithm = self.options.algorithm.label(),
            .domain = self.options.domain,
            .selector = self.options.selector,
            .signed_headers = self.options.signed_headers,
            .body_hash = body_hash,
            .signature = "",
            .canonicalization = self.options.canonicalization,
            .timestamp = timestamp,
            .expiration = self.options.expiration,
            .identity = self.options.identity,
            .body_length = self.options.body_length,
        };

        const dkim_header_empty_b = try header_mod.buildDkimHeaderAlloc(self.allocator, dkim_hdr);
        defer self.allocator.free(dkim_header_empty_b);

        // Step 4: Build signing input from selected headers
        var signing_input: std.ArrayList(u8) = .empty;
        defer signing_input.deinit(self.allocator);

        // Collect headers listed in h=
        var header_names = std.mem.splitScalar(u8, self.options.signed_headers, ':');
        while (header_names.next()) |name| {
            const trimmed_name = std.mem.trim(u8, name, " \t");
            if (trimmed_name.len == 0) continue;

            // Find this header in the message (case-insensitive, bottom-most first)
            if (findHeader(headers_part, trimmed_name)) |found_header| {
                const canon_hdr = try canonicalize.canonicalizeHeader(self.allocator, found_header, self.options.canonicalization.header);
                defer self.allocator.free(canon_hdr);
                try signing_input.appendSlice(self.allocator, canon_hdr);
            }
        }

        // Step 5: Append DKIM-Signature header (canonicalized, without trailing CRLF)
        const canon_dkim = try canonicalize.canonicalizeHeader(self.allocator, dkim_header_empty_b, self.options.canonicalization.header);
        defer self.allocator.free(canon_dkim);

        // Remove trailing CRLF from DKIM header for signing input
        const dkim_no_crlf = if (std.mem.endsWith(u8, canon_dkim, "\r\n"))
            canon_dkim[0 .. canon_dkim.len - 2]
        else
            canon_dkim;
        try signing_input.appendSlice(self.allocator, dkim_no_crlf);

        // Step 6: Sign
        const sig_result = self.options.key.sign(signing_input.items) orelse return error.SigningFailed;
        const sig_slice = sig_result.slice();

        // Base64 encode signature
        const sig_b64_len = std.base64.standard.Encoder.calcSize(sig_slice.len);
        const sig_b64 = try self.allocator.alloc(u8, sig_b64_len);
        defer self.allocator.free(sig_b64);
        _ = std.base64.standard.Encoder.encode(sig_b64, sig_slice);

        // Step 7: Build final DKIM-Signature header with signature
        const final_dkim_hdr_data = header_mod.DkimHeader{
            .algorithm = self.options.algorithm.label(),
            .domain = self.options.domain,
            .selector = self.options.selector,
            .signed_headers = self.options.signed_headers,
            .body_hash = body_hash,
            .signature = sig_b64,
            .canonicalization = self.options.canonicalization,
            .timestamp = timestamp,
            .expiration = self.options.expiration,
            .identity = self.options.identity,
            .body_length = self.options.body_length,
        };

        const final_dkim_header = try header_mod.buildDkimHeaderAlloc(self.allocator, final_dkim_hdr_data);
        errdefer self.allocator.free(final_dkim_header);

        // Step 8: Prepend DKIM-Signature to message
        const signed_msg = try self.allocator.alloc(u8, final_dkim_header.len + 2 + message.len);
        @memcpy(signed_msg[0..final_dkim_header.len], final_dkim_header);
        signed_msg[final_dkim_header.len] = '\r';
        signed_msg[final_dkim_header.len + 1] = '\n';
        @memcpy(signed_msg[final_dkim_header.len + 2 ..], message);

        self.allocator.free(final_dkim_header);

        return signed_msg;
    }

    /// Sign and return just the DKIM-Signature header (without prepending to message).
    pub fn signHeaderOnlyAlloc(self: *Signer, message: []const u8) ![]u8 {
        const signed = try self.signAlloc(message);
        defer self.allocator.free(signed);

        // Extract just the DKIM-Signature header line(s)
        const header_end = std.mem.indexOf(u8, signed, "\r\nDKIM-Signature:") orelse
            std.mem.indexOf(u8, signed, "\r\nFrom:") orelse
            std.mem.indexOf(u8, signed, "\r\nfrom:") orelse signed.len;

        // Find where the DKIM header ends (first line that doesn't start with tab/space after DKIM-Signature)
        var end = std.mem.indexOf(u8, signed, "\r\n") orelse signed.len;
        while (end + 2 < signed.len and (signed[end + 2] == '\t' or signed[end + 2] == ' ')) {
            end = std.mem.indexOfPos(u8, signed, end + 2, "\r\n") orelse signed.len;
        }

        _ = header_end;
        return self.allocator.dupe(u8, signed[0..end]);
    }
};

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
    // Search from bottom to top (last occurrence first per DKIM spec)
    var last_match: ?[]const u8 = null;
    var pos: usize = 0;

    while (pos < headers.len) {
        // Find end of this header (including continuation lines)
        var end = pos;
        // Find the first CRLF
        while (end < headers.len) {
            if (end + 1 < headers.len and headers[end] == '\r' and headers[end + 1] == '\n') {
                end += 2;
                // Check for continuation (next line starts with WSP)
                if (end < headers.len and (headers[end] == ' ' or headers[end] == '\t')) {
                    continue;
                }
                break;
            }
            end += 1;
        }
        if (end == pos) break;

        const line = headers[pos..end];

        // Check if this header matches the name
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

test "sign message with ed25519" {
    const allocator = std.testing.allocator;

    const k = key_mod.generateEd25519Key();
    var signer = Signer.init(allocator, .{
        .domain = "example.com",
        .selector = "sel1",
        .key = .{ .ed25519 = k },
        .signed_headers = "From:To:Subject",
        .timestamp = 1679900000,
    });

    const message =
        "From: sender@example.com\r\n" ++
        "To: recipient@example.com\r\n" ++
        "Subject: Test\r\n" ++
        "Date: Thu, 01 Jan 2023 00:00:00 +0000\r\n" ++
        "\r\n" ++
        "Hello, World!\r\n";

    const signed = try signer.signAlloc(message);
    defer allocator.free(signed);

    // Verify DKIM-Signature is prepended
    try std.testing.expect(std.mem.startsWith(u8, signed, "DKIM-Signature:"));

    // Verify original message is present
    try std.testing.expect(std.mem.indexOf(u8, signed, "From: sender@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "Hello, World!") != null);

    // Verify key fields are present
    try std.testing.expect(std.mem.indexOf(u8, signed, "d=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "s=sel1") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "a=ed25519-sha256") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "bh=") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "b=") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed, "t=1679900000") != null);
}

test "split message" {
    const result = splitMessage("From: a\r\nTo: b\r\n\r\nBody");
    try std.testing.expectEqualStrings("From: a\r\nTo: b\r\n", result.headers);
    try std.testing.expectEqualStrings("Body", result.body);
}

test "find header" {
    const headers = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n";
    const from = findHeader(headers, "From");
    try std.testing.expect(from != null);
    try std.testing.expect(std.mem.startsWith(u8, from.?, "From:"));

    const missing = findHeader(headers, "Cc");
    try std.testing.expect(missing == null);
}

test "sign deterministic with timestamp" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const k = key_mod.loadEd25519KeyFromSeed(seed);

    var signer = Signer.init(allocator, .{
        .domain = "test.com",
        .selector = "s1",
        .key = .{ .ed25519 = k },
        .signed_headers = "From",
        .timestamp = 1000000,
    });

    const msg = "From: a@test.com\r\n\r\nBody\r\n";
    const signed1 = try signer.signAlloc(msg);
    defer allocator.free(signed1);
    const signed2 = try signer.signAlloc(msg);
    defer allocator.free(signed2);

    // Same key + same timestamp = same signature
    try std.testing.expectEqualStrings(signed1, signed2);
}
