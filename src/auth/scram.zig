const std = @import("std");

const base64 = std.base64.standard;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Result of generating a client-first-message.
pub const ClientFirstResult = struct {
    message: []const u8,
    nonce: []const u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: ClientFirstResult) void {
        self.allocator.free(self.message);
        self.allocator.free(self.nonce);
    }
};

/// Result of generating a client-final-message.
pub const ClientFinalResult = struct {
    message: []const u8,
    server_signature: [32]u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: ClientFinalResult) void {
        self.allocator.free(self.message);
    }
};

/// Parsed fields from a client-first-message.
pub const ParsedClientFirst = struct {
    username: []const u8,
    client_nonce: []const u8,
};

/// Result of generating a server-first-message.
pub const ServerFirstResult = struct {
    message: []const u8,
    server_nonce: []const u8,

    allocator: std.mem.Allocator,

    pub fn deinit(self: ServerFirstResult) void {
        self.allocator.free(self.message);
        self.allocator.free(self.server_nonce);
    }
};

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/// Derives the salted password using PBKDF2-HMAC-SHA-256.
pub fn saltedPassword(password: []const u8, salt: []const u8, iterations: u32) [32]u8 {
    var dk: [32]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&dk, password, salt, iterations, HmacSha256) catch unreachable;
    return dk;
}

/// HMAC(salted_password, "Client Key")
pub fn clientKey(salted_pwd: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, "Client Key", &salted_pwd);
    return out;
}

/// SHA-256(client_key)
pub fn storedKey(client_key_val: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(&client_key_val, &out, .{});
    return out;
}

/// HMAC(salted_password, "Server Key")
pub fn serverKey(salted_pwd: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, "Server Key", &salted_pwd);
    return out;
}

/// HMAC(stored_key, auth_message)
pub fn clientSignature(stored_key_val: [32]u8, auth_message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, auth_message, &stored_key_val);
    return out;
}

/// client_key XOR client_signature
pub fn clientProof(client_key_val: [32]u8, client_sig: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (0..32) |i| {
        out[i] = client_key_val[i] ^ client_sig[i];
    }
    return out;
}

/// HMAC(server_key, auth_message)
pub fn serverSignature(server_key_val: [32]u8, auth_message: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, auth_message, &server_key_val);
    return out;
}

/// High-level helper: compute the full client proof from password, salt,
/// iteration count, and auth_message.
pub fn computeClientProof(password: []const u8, salt: []const u8, iterations: u32, auth_message: []const u8) [32]u8 {
    const sp = saltedPassword(password, salt, iterations);
    const ck = clientKey(sp);
    const sk = storedKey(ck);
    const cs = clientSignature(sk, auth_message);
    return clientProof(ck, cs);
}

// ---------------------------------------------------------------------------
// Client-side functions
// ---------------------------------------------------------------------------

/// Generates a client-first-message with a random nonce.
/// The message is the full GS2 header + client-first-message-bare:
///   n,,n=<username>,r=<client-nonce>
/// Returns the message and the generated nonce (both caller-owned).
pub fn clientFirstMessageAlloc(allocator: std.mem.Allocator, username: []const u8) !ClientFirstResult {
    // Generate 24 random bytes, base64-encode as nonce.
    var random_bytes: [24]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    const nonce_len = base64.Encoder.calcSize(random_bytes.len);
    const nonce = try allocator.alloc(u8, nonce_len);
    errdefer allocator.free(nonce);
    _ = base64.Encoder.encode(nonce, &random_bytes);

    // Build: n,,n=<username>,r=<nonce>
    const msg_len = 5 + username.len + 3 + nonce.len; // "n,,n=" + username + ",r=" + nonce
    const message = try allocator.alloc(u8, msg_len);
    errdefer allocator.free(message);

    var offset: usize = 0;
    @memcpy(message[offset .. offset + 5], "n,,n=");
    offset += 5;
    @memcpy(message[offset .. offset + username.len], username);
    offset += username.len;
    @memcpy(message[offset .. offset + 3], ",r=");
    offset += 3;
    @memcpy(message[offset .. offset + nonce.len], nonce);

    return ClientFirstResult{
        .message = message,
        .nonce = nonce,
        .allocator = allocator,
    };
}

/// Processes the server-first-message and produces the client-final-message.
///
/// Parameters:
///   - allocator: memory allocator
///   - username: the SCRAM username (same as used in client-first-message)
///   - password: the user's password
///   - client_nonce: the nonce generated during client-first-message
///   - server_response: the raw server-first-message
///
/// Returns the client-final-message and the expected server signature.
pub fn clientFinalMessageAlloc(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
    client_nonce: []const u8,
    server_response: []const u8,
) !ClientFinalResult {
    // Parse server-first-message fields.
    var combined_nonce: ?[]const u8 = null;
    var salt_b64: ?[]const u8 = null;
    var iterations: ?u32 = null;

    var field_iter = std.mem.splitScalar(u8, server_response, ',');
    while (field_iter.next()) |part| {
        if (part.len >= 2 and part[0] == 'r' and part[1] == '=') {
            combined_nonce = part[2..];
        } else if (part.len >= 2 and part[0] == 's' and part[1] == '=') {
            salt_b64 = part[2..];
        } else if (part.len >= 2 and part[0] == 'i' and part[1] == '=') {
            iterations = std.fmt.parseInt(u32, part[2..], 10) catch return error.InvalidIterationCount;
        }
    }

    const cn = combined_nonce orelse return error.InvalidServerMessage;
    const sb = salt_b64 orelse return error.InvalidServerMessage;
    const iters = iterations orelse return error.InvalidServerMessage;

    // Verify the combined nonce starts with our client nonce.
    if (cn.len <= client_nonce.len) return error.InvalidNonce;
    if (!std.mem.startsWith(u8, cn, client_nonce)) return error.InvalidNonce;

    // Decode the salt.
    const salt_len = base64.Decoder.calcSizeForSlice(sb) catch return error.InvalidBase64;
    const salt = try allocator.alloc(u8, salt_len);
    defer allocator.free(salt);
    base64.Decoder.decode(salt, sb) catch return error.InvalidBase64;

    // Build auth_message components.
    // client-first-message-bare = "n=<username>,r=<client_nonce>"
    const cfmb_len = 2 + username.len + 3 + client_nonce.len;
    const cfmb = try allocator.alloc(u8, cfmb_len);
    defer allocator.free(cfmb);
    {
        var off: usize = 0;
        @memcpy(cfmb[off .. off + 2], "n=");
        off += 2;
        @memcpy(cfmb[off .. off + username.len], username);
        off += username.len;
        @memcpy(cfmb[off .. off + 3], ",r=");
        off += 3;
        @memcpy(cfmb[off .. off + client_nonce.len], client_nonce);
    }

    // client-final-message-without-proof = "c=biws,r=<combined_nonce>"
    const cfm_wp_len = 9 + cn.len;
    const cfm_wp = try allocator.alloc(u8, cfm_wp_len);
    defer allocator.free(cfm_wp);
    @memcpy(cfm_wp[0..9], "c=biws,r=");
    @memcpy(cfm_wp[9..], cn);

    // auth_message = cfmb + "," + server_response + "," + cfm_wp
    const am_len = cfmb.len + 1 + server_response.len + 1 + cfm_wp.len;
    const auth_msg = try allocator.alloc(u8, am_len);
    defer allocator.free(auth_msg);
    {
        var off: usize = 0;
        @memcpy(auth_msg[off .. off + cfmb.len], cfmb);
        off += cfmb.len;
        auth_msg[off] = ',';
        off += 1;
        @memcpy(auth_msg[off .. off + server_response.len], server_response);
        off += server_response.len;
        auth_msg[off] = ',';
        off += 1;
        @memcpy(auth_msg[off .. off + cfm_wp.len], cfm_wp);
    }

    // Compute proof.
    const sp = saltedPassword(password, salt, iters);
    const ck = clientKey(sp);
    const sk_val = storedKey(ck);
    const cs = clientSignature(sk_val, auth_msg);
    const proof = clientProof(ck, cs);

    // Compute expected server signature.
    const skey = serverKey(sp);
    const server_sig = serverSignature(skey, auth_msg);

    // Base64-encode the proof.
    const proof_b64_len = base64.Encoder.calcSize(proof.len);
    const proof_b64 = try allocator.alloc(u8, proof_b64_len);
    defer allocator.free(proof_b64);
    _ = base64.Encoder.encode(proof_b64, &proof);

    // Build client-final-message = cfm_wp + ",p=" + proof_b64
    const msg_len = cfm_wp.len + 3 + proof_b64.len;
    const message = try allocator.alloc(u8, msg_len);
    errdefer allocator.free(message);
    {
        var off: usize = 0;
        @memcpy(message[off .. off + cfm_wp.len], cfm_wp);
        off += cfm_wp.len;
        @memcpy(message[off .. off + 3], ",p=");
        off += 3;
        @memcpy(message[off .. off + proof_b64.len], proof_b64);
    }

    return ClientFinalResult{
        .message = message,
        .server_signature = server_sig,
        .allocator = allocator,
    };
}

// ---------------------------------------------------------------------------
// Server-side functions
// ---------------------------------------------------------------------------

/// Parses a client-first-message and extracts the username and client nonce.
/// The input should be the full message including the GS2 header, e.g.:
///   n,,n=<username>,r=<client-nonce>
/// The returned slices point into the input message.
pub fn parseClientFirstMessage(message: []const u8) !ParsedClientFirst {
    // Strip GS2 header "n,," (or "y,," or "p=...,,")
    const bare = blk: {
        if (std.mem.startsWith(u8, message, "n,,")) {
            break :blk message[3..];
        } else if (std.mem.startsWith(u8, message, "y,,")) {
            break :blk message[3..];
        } else {
            // Check for "p=<something>,,"
            if (message.len > 0 and message[0] == 'p') {
                if (std.mem.indexOf(u8, message, ",,")) |idx| {
                    break :blk message[idx + 2 ..];
                }
            }
            return error.InvalidGS2Header;
        }
    };

    var username: ?[]const u8 = null;
    var client_nonce: ?[]const u8 = null;

    var iter = std.mem.splitScalar(u8, bare, ',');
    while (iter.next()) |part| {
        if (part.len >= 2 and part[0] == 'n' and part[1] == '=') {
            username = part[2..];
        } else if (part.len >= 2 and part[0] == 'r' and part[1] == '=') {
            client_nonce = part[2..];
        }
    }

    return ParsedClientFirst{
        .username = username orelse return error.MissingUsername,
        .client_nonce = client_nonce orelse return error.MissingNonce,
    };
}

/// Generates a server-first-message.
///
/// Parameters:
///   - client_nonce: the nonce from the client-first-message
///   - salt: raw salt bytes
///   - iterations: iteration count for PBKDF2
///
/// Returns the message and the generated server nonce (both caller-owned).
pub fn serverFirstMessageAlloc(
    allocator: std.mem.Allocator,
    client_nonce: []const u8,
    salt: []const u8,
    iterations: u32,
) !ServerFirstResult {
    // Generate server nonce.
    var random_bytes: [24]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);

    const server_nonce_len = base64.Encoder.calcSize(random_bytes.len);
    const server_nonce = try allocator.alloc(u8, server_nonce_len);
    errdefer allocator.free(server_nonce);
    _ = base64.Encoder.encode(server_nonce, &random_bytes);

    // Base64-encode the salt.
    const salt_b64_len = base64.Encoder.calcSize(salt.len);
    const salt_b64 = try allocator.alloc(u8, salt_b64_len);
    defer allocator.free(salt_b64);
    _ = base64.Encoder.encode(salt_b64, salt);

    // Format iteration count.
    var iter_buf: [20]u8 = undefined;
    const iter_str = std.fmt.bufPrint(&iter_buf, "{d}", .{iterations}) catch unreachable;

    // Build: r=<client_nonce><server_nonce>,s=<salt_b64>,i=<iterations>
    const msg_len = 2 + client_nonce.len + server_nonce.len + 3 + salt_b64.len + 3 + iter_str.len;
    const message = try allocator.alloc(u8, msg_len);
    errdefer allocator.free(message);
    {
        var off: usize = 0;
        @memcpy(message[off .. off + 2], "r=");
        off += 2;
        @memcpy(message[off .. off + client_nonce.len], client_nonce);
        off += client_nonce.len;
        @memcpy(message[off .. off + server_nonce.len], server_nonce);
        off += server_nonce.len;
        @memcpy(message[off .. off + 3], ",s=");
        off += 3;
        @memcpy(message[off .. off + salt_b64.len], salt_b64);
        off += salt_b64.len;
        @memcpy(message[off .. off + 3], ",i=");
        off += 3;
        @memcpy(message[off .. off + iter_str.len], iter_str);
    }

    return ServerFirstResult{
        .message = message,
        .server_nonce = server_nonce,
        .allocator = allocator,
    };
}

/// Verifies a client-final-message on the server side.
///
/// Parameters:
///   - message: the client-final-message
///   - stored_key_val: the stored key for the user (SHA-256 of client key)
///   - server_key_val: the server key for the user
///   - auth_message: the full auth_message (cfmb + "," + sfm + "," + cfm_without_proof)
///
/// Returns true if the client proof is valid.
pub fn verifyClientFinal(
    message: []const u8,
    stored_key_val: [32]u8,
    server_key_val: [32]u8,
    auth_message: []const u8,
) !bool {
    _ = server_key_val;

    // Extract the proof from the message: find ",p=" and decode what follows.
    const proof_prefix = ",p=";
    const proof_start = std.mem.indexOf(u8, message, proof_prefix) orelse return error.MissingProof;
    const proof_b64 = message[proof_start + proof_prefix.len ..];

    const proof_len = base64.Decoder.calcSizeForSlice(proof_b64) catch return error.InvalidBase64;
    if (proof_len != 32) return error.InvalidProofLength;
    var received_proof: [32]u8 = undefined;
    base64.Decoder.decode(&received_proof, proof_b64) catch return error.InvalidBase64;

    // Compute expected proof: client_key XOR client_signature
    // We have stored_key = SHA256(client_key), so we compute:
    //   client_signature = HMAC(stored_key, auth_message)
    //   received_client_key = received_proof XOR client_signature
    //   check: SHA256(received_client_key) == stored_key
    const cs = clientSignature(stored_key_val, auth_message);

    var recovered_ck: [32]u8 = undefined;
    for (0..32) |i| {
        recovered_ck[i] = received_proof[i] ^ cs[i];
    }

    const recovered_sk = storedKey(recovered_ck);
    return std.mem.eql(u8, &recovered_sk, &stored_key_val);
}

/// Generates the server-final-message containing the server signature.
/// Format: v=<server-signature-base64>
/// Caller owns the returned memory.
pub fn serverFinalMessageAlloc(allocator: std.mem.Allocator, server_sig: [32]u8) ![]const u8 {
    const sig_b64_len = base64.Encoder.calcSize(server_sig.len);
    const message = try allocator.alloc(u8, 2 + sig_b64_len);
    @memcpy(message[0..2], "v=");
    _ = base64.Encoder.encode(message[2..], &server_sig);
    return message;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "scram: crypto primitives - salted password" {
    // RFC 7677 test vector for SCRAM-SHA-256
    // password = "pencil", salt = "W22ZaJ0SNY7soEsUEjb6gQ==" (base64), i = 4096
    const salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
    var salt: [16]u8 = undefined;
    base64.Decoder.decode(&salt, salt_b64) catch unreachable;

    const sp = saltedPassword("pencil", &salt, 4096);

    // Verify by computing the full chain.
    const ck = clientKey(sp);
    const sk = storedKey(ck);
    _ = sk;
    const skey = serverKey(sp);
    _ = skey;

    // Just verify it doesn't crash and produces deterministic output.
    const sp2 = saltedPassword("pencil", &salt, 4096);
    try std.testing.expectEqualSlices(u8, &sp, &sp2);
}

test "scram: client key, stored key, server key" {
    const password = "pencil";
    const salt = "saltsalt";
    const sp = saltedPassword(password, salt, 4096);

    const ck = clientKey(sp);
    const sk = storedKey(ck);
    const skey = serverKey(sp);

    // Verify determinism.
    try std.testing.expectEqualSlices(u8, &clientKey(sp), &ck);
    try std.testing.expectEqualSlices(u8, &storedKey(ck), &sk);
    try std.testing.expectEqualSlices(u8, &serverKey(sp), &skey);
}

test "scram: client proof XOR properties" {
    const ck = [_]u8{0xAA} ** 32;
    const cs = [_]u8{0x55} ** 32;
    const proof = clientProof(ck, cs);
    // AA XOR 55 = FF
    try std.testing.expectEqualSlices(u8, &([_]u8{0xFF} ** 32), &proof);

    // XOR with proof should recover client_key.
    const recovered = clientProof(proof, cs);
    try std.testing.expectEqualSlices(u8, &ck, &recovered);
}

test "scram: parse client-first-message" {
    const parsed = try parseClientFirstMessage("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
    try std.testing.expectEqualSlices(u8, "user", parsed.username);
    try std.testing.expectEqualSlices(u8, "fyko+d2lbbFgONRv9qkxdawL", parsed.client_nonce);
}

test "scram: parse client-first-message with empty username" {
    const parsed = try parseClientFirstMessage("n,,n=,r=somenonce");
    try std.testing.expectEqualSlices(u8, "", parsed.username);
    try std.testing.expectEqualSlices(u8, "somenonce", parsed.client_nonce);
}

test "scram: parse client-first-message with special characters" {
    const parsed = try parseClientFirstMessage("n,,n=user@domain.com,r=abc123+/=");
    try std.testing.expectEqualSlices(u8, "user@domain.com", parsed.username);
    try std.testing.expectEqualSlices(u8, "abc123+/=", parsed.client_nonce);
}

test "scram: parse client-first-message invalid GS2 header" {
    const result = parseClientFirstMessage("x,,n=user,r=nonce");
    try std.testing.expectError(error.InvalidGS2Header, result);
}

test "scram: parse client-first-message missing nonce" {
    const result = parseClientFirstMessage("n,,n=user");
    try std.testing.expectError(error.MissingNonce, result);
}

test "scram: parse client-first-message missing username" {
    const result = parseClientFirstMessage("n,,r=nonce");
    try std.testing.expectError(error.MissingUsername, result);
}

test "scram: server final message" {
    const allocator = std.testing.allocator;
    const sig = [_]u8{0x01} ** 32;
    const msg = try serverFinalMessageAlloc(allocator, sig);
    defer allocator.free(msg);

    try std.testing.expect(std.mem.startsWith(u8, msg, "v="));

    // Decode and verify.
    const decoded_len = base64.Decoder.calcSizeForSlice(msg[2..]) catch unreachable;
    try std.testing.expectEqual(@as(usize, 32), decoded_len);
    var decoded: [32]u8 = undefined;
    base64.Decoder.decode(&decoded, msg[2..]) catch unreachable;
    try std.testing.expectEqualSlices(u8, &sig, &decoded);
}

test "scram: full round-trip exchange" {
    const allocator = std.testing.allocator;

    const username = "user";
    const password = "pencil";
    const salt = "serversalt123456"; // 16 bytes
    const iterations: u32 = 4096;

    // Step 1: Client generates first message.
    const client_first = try clientFirstMessageAlloc(allocator, username);
    defer client_first.deinit();

    // Verify format.
    try std.testing.expect(std.mem.startsWith(u8, client_first.message, "n,,n=user,r="));

    // Step 2: Server parses and generates response.
    const parsed = try parseClientFirstMessage(client_first.message);
    try std.testing.expectEqualSlices(u8, username, parsed.username);
    try std.testing.expectEqualSlices(u8, client_first.nonce, parsed.client_nonce);

    const server_first = try serverFirstMessageAlloc(allocator, parsed.client_nonce, salt, iterations);
    defer server_first.deinit();

    // Verify server message format.
    try std.testing.expect(std.mem.startsWith(u8, server_first.message, "r="));

    // Step 3: Client generates final message.
    const client_final = try clientFinalMessageAlloc(
        allocator,
        username,
        password,
        client_first.nonce,
        server_first.message,
    );
    defer client_final.deinit();

    // Verify format.
    try std.testing.expect(std.mem.startsWith(u8, client_final.message, "c=biws,r="));
    try std.testing.expect(std.mem.indexOf(u8, client_final.message, ",p=") != null);

    // Step 4: Server verifies.
    // Compute stored_key and server_key from the password and salt.
    const sp = saltedPassword(password, salt, iterations);
    const ck = clientKey(sp);
    const sk_val = storedKey(ck);
    const skey = serverKey(sp);

    // Build auth_message on server side.
    // client-first-message-bare
    const cfmb = client_first.message[3..]; // strip "n,,"

    // client-final-message-without-proof
    const proof_idx = std.mem.indexOf(u8, client_final.message, ",p=").?;
    const cfm_wp = client_final.message[0..proof_idx];

    // auth_message = cfmb + "," + server_first.message + "," + cfm_wp
    const am = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ cfmb, server_first.message, cfm_wp });
    defer allocator.free(am);

    const valid = try verifyClientFinal(client_final.message, sk_val, skey, am);
    try std.testing.expect(valid);

    // Step 5: Server sends final message, client verifies server signature.
    const server_sig = serverSignature(skey, am);
    const server_final = try serverFinalMessageAlloc(allocator, server_sig);
    defer allocator.free(server_final);

    try std.testing.expect(std.mem.startsWith(u8, server_final, "v="));

    // Verify server signature matches what client expects.
    var decoded_server_sig: [32]u8 = undefined;
    base64.Decoder.decode(&decoded_server_sig, server_final[2..]) catch unreachable;
    try std.testing.expectEqualSlices(u8, &client_final.server_signature, &decoded_server_sig);
}

test "scram: known test vector (RFC 7677 adapted)" {
    // RFC 7677 Section 3 provides a test vector for SCRAM-SHA-256.
    // Username: user
    // Password: pencil
    // Client nonce: rOprNGfwEbeRWgbNEkqO
    // Server nonce (appended): %hvYDpWUa2RaTCAfuxFIlj)hNlF$k0
    // Salt (base64): W22ZaJ0SNY7soEsUEjb6gQ==
    // Iteration count: 4096

    const allocator = std.testing.allocator;

    const client_nonce = "rOprNGfwEbeRWgbNEkqO";
    const server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    const client_final = try clientFinalMessageAlloc(
        allocator,
        "user",
        "pencil",
        client_nonce,
        server_first,
    );
    defer client_final.deinit();

    // Verify the message starts correctly.
    try std.testing.expect(std.mem.startsWith(u8, client_final.message, "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p="));

    // The expected client proof from RFC 7677:
    // client-final = c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
    const expected_proof_b64 = "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const proof_start = std.mem.indexOf(u8, client_final.message, ",p=").? + 3;
    const actual_proof_b64 = client_final.message[proof_start..];
    try std.testing.expectEqualSlices(u8, expected_proof_b64, actual_proof_b64);

    // Also verify server signature.
    // Expected server signature from RFC 7677: v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
    const expected_sig_b64 = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    var expected_sig: [32]u8 = undefined;
    base64.Decoder.decode(&expected_sig, expected_sig_b64) catch unreachable;
    try std.testing.expectEqualSlices(u8, &expected_sig, &client_final.server_signature);
}

test "scram: invalid nonce in server response" {
    const allocator = std.testing.allocator;
    const result = clientFinalMessageAlloc(
        allocator,
        "user",
        "pass",
        "clientnonce123",
        "r=differentnonce456,s=c2FsdA==,i=4096",
    );
    try std.testing.expectError(error.InvalidNonce, result);
}

test "scram: computeClientProof helper" {
    const salt = "saltsalt12345678";
    const auth_msg = "n=user,r=nonce,r=nonceserver,s=base64salt,i=4096,c=biws,r=nonceserver";

    const proof1 = computeClientProof("password", salt, 4096, auth_msg);

    // Should be deterministic.
    const proof2 = computeClientProof("password", salt, 4096, auth_msg);
    try std.testing.expectEqualSlices(u8, &proof1, &proof2);

    // Different password should give different proof.
    const proof3 = computeClientProof("different", salt, 4096, auth_msg);
    try std.testing.expect(!std.mem.eql(u8, &proof1, &proof3));
}

test "scram: verify rejects wrong password" {
    const allocator = std.testing.allocator;

    const username = "user";
    const password = "correct";
    const wrong_password = "wrong";
    const salt = "fixedsalt1234567";
    const iterations: u32 = 4096;
    const client_nonce = "testclientnonce1";

    // Build server-first-message with a fixed server nonce.
    const server_nonce = "testservernonce2";
    const salt_b64_len = base64.Encoder.calcSize(salt.len);
    const salt_b64 = try allocator.alloc(u8, salt_b64_len);
    defer allocator.free(salt_b64);
    _ = base64.Encoder.encode(salt_b64, salt);

    const sfm = try std.fmt.allocPrint(allocator, "r={s}{s},s={s},i={d}", .{ client_nonce, server_nonce, salt_b64, iterations });
    defer allocator.free(sfm);

    // Client uses wrong password.
    const client_final = try clientFinalMessageAlloc(
        allocator,
        username,
        wrong_password,
        client_nonce,
        sfm,
    );
    defer client_final.deinit();

    // Server has stored key from correct password.
    const sp = saltedPassword(password, salt, iterations);
    const ck = clientKey(sp);
    const sk_val = storedKey(ck);
    const skey = serverKey(sp);

    // Build auth_message.
    const cfmb = try std.fmt.allocPrint(allocator, "n={s},r={s}", .{ username, client_nonce });
    defer allocator.free(cfmb);

    const proof_idx = std.mem.indexOf(u8, client_final.message, ",p=").?;
    const cfm_wp = client_final.message[0..proof_idx];

    const am = try std.fmt.allocPrint(allocator, "{s},{s},{s}", .{ cfmb, sfm, cfm_wp });
    defer allocator.free(am);

    const valid = try verifyClientFinal(client_final.message, sk_val, skey, am);
    try std.testing.expect(!valid);
}
