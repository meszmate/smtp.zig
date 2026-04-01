const std = @import("std");
const types = @import("types.zig");
const wire = @import("wire/root.zig");
const response_mod = @import("response.zig");

const Transport = wire.Transport;
const LineReader = wire.LineReader;
const Encoder = wire.Encoder;
const SmtpResponse = types.SmtpResponse;

/// Per-recipient delivery result for LMTP DATA response.
/// In LMTP (RFC 2033), the DATA command returns one reply per accepted
/// RCPT TO recipient, indicating immediate delivery success or failure.
pub const RecipientResult = struct {
    recipient: []const u8,
    response: SmtpResponse,

    pub fn isSuccess(self: RecipientResult) bool {
        return self.response.isSuccess();
    }
};

/// LMTP client error set.
pub const LmtpClientError = error{
    /// Server greeting was not a 2xx code.
    BadGreeting,
    /// Server returned an unexpected response (e.g., DATA did not yield 354).
    UnexpectedResponse,
};

/// LMTP client for local mail delivery (RFC 2033).
///
/// LMTP is a variant of SMTP designed for final delivery to a mail store.
/// Key differences from SMTP:
/// - Uses LHLO instead of EHLO/HELO
/// - DATA returns one response per accepted recipient
/// - Must not queue for later delivery
pub const Client = struct {
    allocator: std.mem.Allocator,
    transport: Transport,
    reader: LineReader,

    /// Initialise a client around an already-connected Transport.
    /// Reads and validates the server greeting (must be 2xx).
    pub fn init(allocator: std.mem.Allocator, transport: Transport) !Client {
        var self = Client{
            .allocator = allocator,
            .transport = transport,
            .reader = LineReader.init(allocator, transport),
        };
        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            response_mod.freeResponse(allocator, &resp);
            return error.BadGreeting;
        }
        response_mod.freeResponse(allocator, &resp);
        return self;
    }

    /// Send LHLO (LMTP equivalent of EHLO).
    pub fn lhlo(self: *Client, domain: []const u8) !SmtpResponse {
        return try self.sendCommand("LHLO ", domain);
    }

    /// Send MAIL FROM.
    pub fn mailFrom(self: *Client, sender: []const u8) !SmtpResponse {
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("MAIL FROM:");
        try encoder.angleBracket(sender);
        try encoder.crlf();
        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);
        try self.transport.writeAll(cmd);
        return try self.readResponse();
    }

    /// Send RCPT TO.
    pub fn rcptTo(self: *Client, recipient: []const u8) !SmtpResponse {
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("RCPT TO:");
        try encoder.angleBracket(recipient);
        try encoder.crlf();
        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);
        try self.transport.writeAll(cmd);
        return try self.readResponse();
    }

    /// Send DATA with message body. Returns per-recipient results.
    ///
    /// In LMTP the server sends one response per accepted RCPT TO recipient
    /// after the final dot, rather than the single response SMTP uses.
    /// The caller must pass the number of accepted recipients so the client
    /// knows how many responses to read.
    ///
    /// The `recipients` slice is used to tag each result; its length also
    /// determines the number of responses to read.
    pub fn data(self: *Client, body: []const u8, recipients: []const []const u8) ![]RecipientResult {
        // Send DATA command
        try self.transport.writeAll("DATA\r\n");
        var resp = try self.readResponse();
        if (!resp.isIntermediate()) {
            response_mod.freeResponse(self.allocator, &resp);
            return error.UnexpectedResponse;
        }
        response_mod.freeResponse(self.allocator, &resp);

        // Send body with dot-stuffing
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.dotStuff(body);
        if (!std.mem.endsWith(u8, body, "\r\n")) {
            try encoder.crlf();
        }
        try encoder.dataTerminator();
        const encoded = try encoder.finish();
        defer self.allocator.free(encoded);
        try self.transport.writeAll(encoded);

        // Read one response per recipient
        const results = try self.allocator.alloc(RecipientResult, recipients.len);
        errdefer {
            for (results) |*r| {
                response_mod.freeResponse(self.allocator, &r.response);
            }
            self.allocator.free(results);
        }
        for (results, 0..) |*result, i| {
            result.* = .{
                .recipient = recipients[i],
                .response = try self.readResponse(),
            };
        }
        return results;
    }

    /// Free results returned by `data`.
    pub fn freeResults(self: *Client, results: []RecipientResult) void {
        for (results) |*r| {
            response_mod.freeResponse(self.allocator, &r.response);
        }
        self.allocator.free(results);
    }

    /// Send RSET.
    pub fn rset(self: *Client) !SmtpResponse {
        try self.transport.writeAll("RSET\r\n");
        return try self.readResponse();
    }

    /// Send QUIT.
    pub fn quit(self: *Client) !SmtpResponse {
        try self.transport.writeAll("QUIT\r\n");
        return try self.readResponse();
    }

    fn sendCommand(self: *Client, prefix: []const u8, arg: []const u8) !SmtpResponse {
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command(prefix);
        try encoder.atom(arg);
        try encoder.crlf();
        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);
        try self.transport.writeAll(cmd);
        return try self.readResponse();
    }

    fn readResponse(self: *Client) !SmtpResponse {
        return response_mod.readResponseAlloc(self.allocator, &self.reader);
    }

};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const PipeTransport = @import("smtptest.zig").PipeTransport;

test "LHLO command formatting" {
    const allocator = testing.allocator;

    var pipe = PipeTransport.init(allocator);
    defer pipe.deinit();

    // Greeting + LHLO response
    try pipe.feedInput(
        "220 localhost LMTP ready\r\n" ++
            "250 localhost\r\n",
    );

    var client = try Client.init(allocator, pipe.transport());

    var resp = try client.lhlo("myclient.local");
    defer freeResponse(allocator, &resp);

    try testing.expectEqual(@as(u16, 250), resp.code);

    // Verify the written output contains LHLO
    const output = pipe.output.items;
    try testing.expect(std.mem.indexOf(u8, output, "LHLO myclient.local\r\n") != null);
}

test "per-recipient DATA responses" {
    const allocator = testing.allocator;

    var pipe = PipeTransport.init(allocator);
    defer pipe.deinit();

    // Greeting + LHLO + MAIL FROM + 2x RCPT TO + DATA intermediate + 2 per-recipient results
    try pipe.feedInput(
        "220 localhost LMTP ready\r\n" ++
            "250 localhost\r\n" ++
            "250 OK\r\n" ++
            "250 OK\r\n" ++
            "250 OK\r\n" ++
            "354 Start mail input\r\n" ++
            "250 2.1.5 Delivered to alice@local\r\n" ++
            "550 5.1.1 bob@local: no such user\r\n",
    );

    var client = try Client.init(allocator, pipe.transport());

    var lhlo_resp = try client.lhlo("test.local");
    freeResponse(allocator, &lhlo_resp);

    var mail_resp = try client.mailFrom("sender@example.com");
    freeResponse(allocator, &mail_resp);

    var rcpt1 = try client.rcptTo("alice@local");
    freeResponse(allocator, &rcpt1);

    var rcpt2 = try client.rcptTo("bob@local");
    freeResponse(allocator, &rcpt2);

    const recipients = &[_][]const u8{ "alice@local", "bob@local" };
    const results = try client.data("Subject: Test\r\n\r\nHello\r\n", recipients);
    defer client.freeResults(results);

    try testing.expectEqual(@as(usize, 2), results.len);

    // First recipient: success
    try testing.expect(results[0].isSuccess());
    try testing.expectEqual(@as(u16, 250), results[0].response.code);
    try testing.expectEqualStrings("alice@local", results[0].recipient);

    // Second recipient: permanent failure
    try testing.expect(!results[1].isSuccess());
    try testing.expectEqual(@as(u16, 550), results[1].response.code);
    try testing.expectEqualStrings("bob@local", results[1].recipient);
}

test "RSET and QUIT" {
    const allocator = testing.allocator;

    var pipe = PipeTransport.init(allocator);
    defer pipe.deinit();

    try pipe.feedInput(
        "220 localhost LMTP ready\r\n" ++
            "250 OK\r\n" ++
            "221 Bye\r\n",
    );

    var client = try Client.init(allocator, pipe.transport());

    var rset_resp = try client.rset();
    defer freeResponse(allocator, &rset_resp);
    try testing.expectEqual(@as(u16, 250), rset_resp.code);

    var quit_resp = try client.quit();
    defer freeResponse(allocator, &quit_resp);
    try testing.expectEqual(@as(u16, 221), quit_resp.code);

    const output = pipe.output.items;
    try testing.expect(std.mem.indexOf(u8, output, "RSET\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, output, "QUIT\r\n") != null);
}

test "RecipientResult.isSuccess" {
    const result_ok = RecipientResult{
        .recipient = "user@local",
        .response = .{ .code = 250 },
    };
    try testing.expect(result_ok.isSuccess());

    const result_fail = RecipientResult{
        .recipient = "user@local",
        .response = .{ .code = 550 },
    };
    try testing.expect(!result_fail.isSuccess());
}

fn freeResponse(allocator: std.mem.Allocator, resp: *SmtpResponse) void {
    response_mod.freeResponse(allocator, resp);
}
