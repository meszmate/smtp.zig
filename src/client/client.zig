const std = @import("std");
const builtin = @import("builtin");
const types = @import("../types.zig");
const response_mod = @import("../response.zig");
const capability_mod = @import("../capability.zig");
const wire = @import("../wire/root.zig");
const auth_mod = @import("../auth/root.zig");
const options_mod = @import("options.zig");

const Transport = wire.Transport;
const TlsTransport = wire.TlsTransport;
const TlsOptions = wire.TlsOptions;
const LineReader = wire.LineReader;
const Encoder = wire.Encoder;

const CapabilitySet = capability_mod.CapabilitySet;
const caps = capability_mod.caps;

const ConnState = types.ConnState;
const SmtpResponse = types.SmtpResponse;
const MailOptions = types.MailOptions;
const RcptOptions = types.RcptOptions;
const DsnNotify = types.DsnNotify;

const Options = options_mod.Options;

/// SMTP client error set.
pub const SmtpClientError = error{
    /// Server returned an unexpected/failure response code.
    UnexpectedResponse,
    /// The client is not in the correct state for this operation.
    InvalidState,
    /// The server greeting was not a 220 code.
    BadGreeting,
    /// STARTTLS upgrade failed.
    StartTlsFailed,
    /// Authentication failed.
    AuthenticationFailed,
};

/// An SMTP client for sending email messages.
///
/// Wraps a `Transport` and provides high-level methods for the SMTP protocol
/// including connection management, authentication, and mail submission.
pub const Client = struct {
    allocator: std.mem.Allocator,
    transport: Transport,
    reader: LineReader,
    capabilities: CapabilitySet,
    state: ConnState,
    server_name: ?[]u8,
    max_size: ?u64,
    tls_state: ?*TlsTransport,
    is_tls: bool,
    owned_stream: ?std.net.Stream,
    /// Heap-allocated stream for plain TCP connections (so Transport's
    /// context pointer stays valid). Must be freed on deinit.
    heap_stream: ?*std.net.Stream,
    data_prev_byte: ?u8,
    data_last_byte: ?u8,
    options: Options,

    // -----------------------------------------------------------------------
    // Construction / Connection
    // -----------------------------------------------------------------------

    /// Initialise a client around an already-connected `Transport`.
    /// Reads the server greeting and transitions to the `greeted` state.
    pub fn init(allocator: std.mem.Allocator, transport: Transport, opts: Options) !Client {
        var self = Client{
            .allocator = allocator,
            .transport = transport,
            .reader = LineReader.init(allocator, transport),
            .capabilities = CapabilitySet.init(allocator),
            .state = .connect,
            .server_name = null,
            .max_size = null,
            .tls_state = null,
            .is_tls = false,
            .owned_stream = null,
            .heap_stream = null,
            .data_prev_byte = null,
            .data_last_byte = null,
            .options = opts,
        };
        self.reader.max_line_length = opts.max_response_line_length;

        try self.readGreeting();
        return self;
    }

    /// Connect over plain TCP to `host`:`port` and read the greeting.
    pub fn connectTcp(allocator: std.mem.Allocator, host: []const u8, port: u16) !Client {
        return connectTcpWithOptions(allocator, host, port, .{});
    }

    /// Connect over plain TCP to `host`:`port` using the provided client options.
    pub fn connectTcpWithOptions(allocator: std.mem.Allocator, host: []const u8, port: u16, opts: Options) !Client {
        const stream = try std.net.tcpConnectToHost(allocator, host, port);
        errdefer stream.close();

        // Heap-allocate the stream so the Transport's context pointer remains
        // valid after the Client is returned / moved.
        const heap_stream = try allocator.create(std.net.Stream);
        errdefer allocator.destroy(heap_stream);
        heap_stream.* = std.net.Stream{ .handle = stream.handle };
        try wire.applyStreamTimeouts(heap_stream.*, opts.read_timeout_ms, opts.write_timeout_ms);

        const transport = Transport.fromNetStream(heap_stream);

        var self = try init(allocator, transport, opts);
        self.owned_stream = heap_stream.*;
        self.heap_stream = heap_stream;
        return self;
    }

    /// Connect over implicit TLS (typically port 465).
    pub fn connectTls(allocator: std.mem.Allocator, host: []const u8, port: u16, tls_opts: TlsOptions) !Client {
        return connectTlsWithOptions(allocator, host, port, .{ .tls_options = tls_opts });
    }

    /// Connect over implicit TLS (typically port 465) using the provided client options.
    pub fn connectTlsWithOptions(allocator: std.mem.Allocator, host: []const u8, port: u16, opts: Options) !Client {
        const tls_opts = opts.tls_options orelse return error.TlsOptionsRequired;
        const stream = try std.net.tcpConnectToHost(allocator, host, port);
        errdefer stream.close();

        const net_stream = std.net.Stream{ .handle = stream.handle };
        try wire.applyStreamTimeouts(net_stream, opts.read_timeout_ms, opts.write_timeout_ms);

        const tls = try TlsTransport.init(allocator, net_stream, tls_opts);
        errdefer tls.deinitAndClose();

        const transport = tls.transport();

        var self = try init(allocator, transport, opts);
        self.tls_state = tls;
        self.is_tls = true;
        self.owned_stream = net_stream;
        return self;
    }

    /// Release all resources owned by this client.
    pub fn deinit(self: *Client) void {
        if (self.server_name) |name| {
            self.allocator.free(name);
            self.server_name = null;
        }
        self.capabilities.deinit();

        if (self.tls_state) |tls| {
            tls.deinit();
            self.tls_state = null;
        }

        if (self.owned_stream) |stream| {
            stream.close();
            self.owned_stream = null;
        }

        if (self.heap_stream) |hs| {
            self.allocator.destroy(hs);
            self.heap_stream = null;
        }
    }

    // -----------------------------------------------------------------------
    // EHLO / HELO
    // -----------------------------------------------------------------------

    /// Send EHLO, parse extensions, populate capabilities.
    pub fn ehlo(self: *Client, domain: []const u8) !SmtpResponse {
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("EHLO ");
        try encoder.atom(domain);
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: EHLO {s}\n", .{domain});

        var resp = try self.readResponse();

        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        // Parse EHLO response into capabilities.
        self.parseEhloResponse(resp);

        self.state = .ready;
        return resp;
    }

    /// Send HELO (fallback for servers that do not support EHLO).
    pub fn helo(self: *Client, domain: []const u8) !SmtpResponse {
        var resp = try self.sendCommand("HELO ", domain);
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }
        self.state = .ready;
        return resp;
    }

    // -----------------------------------------------------------------------
    // MAIL FROM / RCPT TO
    // -----------------------------------------------------------------------

    /// Send MAIL FROM with optional ESMTP parameters.
    pub fn mailFrom(self: *Client, sender: []const u8, opts: MailOptions) !SmtpResponse {
        if (self.state != .ready) return SmtpClientError.InvalidState;

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.command("MAIL FROM:");
        try encoder.angleBracket(sender);

        // Optional parameters
        if (opts.size) |size| {
            var buf: [20]u8 = undefined;
            const size_str = std.fmt.bufPrint(&buf, "{d}", .{size}) catch unreachable;
            try encoder.param("SIZE", size_str);
        }
        if (opts.body) |body| {
            try encoder.param("BODY", body.label());
        }
        if (opts.smtputf8) {
            try encoder.atom(" SMTPUTF8");
        }
        if (opts.ret) |ret| {
            try encoder.param("RET", ret.label());
        }
        if (opts.envid) |envid| {
            try encoder.param("ENVID", envid);
        }
        if (opts.auth) |auth_val| {
            try encoder.param("AUTH", auth_val);
        }
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: MAIL FROM:<{s}>\n", .{sender});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        self.state = .mail;
        return resp;
    }

    /// Send RCPT TO with optional DSN parameters.
    pub fn rcptTo(self: *Client, recipient: []const u8, opts: RcptOptions) !SmtpResponse {
        if (self.state != .mail and self.state != .rcpt) return SmtpClientError.InvalidState;

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();

        try encoder.command("RCPT TO:");
        try encoder.angleBracket(recipient);

        if (opts.notify.len > 0) {
            try encoder.atom(" NOTIFY=");
            for (opts.notify, 0..) |n, i| {
                if (i > 0) try encoder.atom(",");
                try encoder.atom(n.label());
            }
        }
        if (opts.orcpt) |orcpt| {
            try encoder.param("ORCPT", orcpt);
        }
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: RCPT TO:<{s}>\n", .{recipient});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        self.state = .rcpt;
        return resp;
    }

    // -----------------------------------------------------------------------
    // DATA
    // -----------------------------------------------------------------------

    /// Send the DATA command and wait for the 354 intermediate response.
    pub fn dataStart(self: *Client) !SmtpResponse {
        if (self.state != .rcpt) return SmtpClientError.InvalidState;

        try self.transport.writeAll("DATA\r\n");
        self.debugLog("C: DATA\n", .{});

        var resp = try self.readResponse();
        if (!resp.isIntermediate()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        self.state = .data;
        self.data_prev_byte = null;
        self.data_last_byte = null;
        return resp;
    }

    /// Write a raw chunk of data during the DATA phase.
    /// The caller is responsible for dot-stuffing if needed.
    pub fn dataWrite(self: *Client, chunk: []const u8) !void {
        if (self.state != .data) return SmtpClientError.InvalidState;
        try self.transport.writeAll(chunk);
        self.recordDataChunk(chunk);
    }

    /// Write body data with dot-stuffing applied automatically.
    pub fn dataWriteDotStuffed(self: *Client, body: []const u8) !void {
        if (self.state != .data) return SmtpClientError.InvalidState;

        var at_line_start = self.data_last_byte == null or self.data_last_byte.? == '\n';
        try self.dataWriteDotStuffedChunk(body, &at_line_start);
    }

    /// Send the DATA terminator (CRLF.CRLF), read the final response,
    /// and transition back to the `ready` state.
    pub fn dataEnd(self: *Client) !SmtpResponse {
        if (self.state != .data) return SmtpClientError.InvalidState;

        const ends_with_crlf = self.data_prev_byte == '\r' and self.data_last_byte == '\n';
        const terminator = if (self.data_last_byte == null or ends_with_crlf) ".\r\n" else "\r\n.\r\n";
        try self.transport.writeAll(terminator);
        self.debugLog("C: .\n", .{});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        self.state = .ready;
        self.data_prev_byte = null;
        self.data_last_byte = null;
        return resp;
    }

    /// Convenience: dataStart + dataWriteDotStuffed + dataEnd in one call.
    pub fn sendData(self: *Client, body: []const u8) !SmtpResponse {
        var start_resp = try self.dataStart();
        freeResp(self.allocator, &start_resp);

        try self.dataWriteDotStuffed(body);
        return try self.dataEnd();
    }

    /// Stream body data from a reader, applying dot-stuffing incrementally.
    pub fn sendDataReader(self: *Client, reader: anytype) !SmtpResponse {
        var start_resp = try self.dataStart();
        freeResp(self.allocator, &start_resp);

        var at_line_start = true;
        var buffer: [8192]u8 = undefined;
        while (true) {
            const read = try reader.read(&buffer);
            if (read == 0) break;
            try self.dataWriteDotStuffedChunk(buffer[0..read], &at_line_start);
        }

        return try self.dataEnd();
    }

    // -----------------------------------------------------------------------
    // BDAT (CHUNKING extension)
    // -----------------------------------------------------------------------

    /// Send a BDAT chunk. When `last` is true the LAST keyword is appended
    /// and the transaction is completed.
    pub fn bdat(self: *Client, data: []const u8, last: bool) !SmtpResponse {
        if (self.state != .rcpt and self.state != .data) return SmtpClientError.InvalidState;

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();

        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{data.len}) catch unreachable;

        try encoder.command("BDAT ");
        try encoder.atom(size_str);
        if (last) {
            try encoder.atom(" LAST");
        }
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        try self.transport.writeAll(data);

        self.debugLog("C: BDAT {s}{s}\n", .{ size_str, if (last) " LAST" else "" });

        self.state = if (last) .ready else .data;

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }
        return resp;
    }

    /// Stream a CHUNKING transaction from a reader using BDAT.
    pub fn sendBdatReader(self: *Client, reader: anytype) !SmtpResponse {
        var current: [8192]u8 = undefined;
        var next: [8192]u8 = undefined;

        var current_len = try reader.read(&current);
        if (current_len == 0) {
            return try self.bdat("", true);
        }

        while (true) {
            const next_len = try reader.read(&next);
            var resp = try self.bdat(current[0..current_len], next_len == 0);
            if (next_len == 0) {
                return resp;
            }

            freeResp(self.allocator, &resp);
            std.mem.swap([8192]u8, &current, &next);
            current_len = next_len;
        }
    }

    // -----------------------------------------------------------------------
    // Session commands
    // -----------------------------------------------------------------------

    /// RSET -- reset the session, discarding any pending mail transaction.
    pub fn rset(self: *Client) !SmtpResponse {
        try self.transport.writeAll("RSET\r\n");
        self.debugLog("C: RSET\n", .{});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }

        self.state = .ready;
        return resp;
    }

    /// NOOP -- keepalive / no-operation.
    pub fn noop(self: *Client) !SmtpResponse {
        try self.transport.writeAll("NOOP\r\n");
        self.debugLog("C: NOOP\n", .{});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.UnexpectedResponse;
        }
        return resp;
    }

    /// QUIT -- close the SMTP session.
    pub fn quit(self: *Client) !SmtpResponse {
        try self.transport.writeAll("QUIT\r\n");
        self.debugLog("C: QUIT\n", .{});

        const resp = try self.readResponse();
        self.state = .logout;
        return resp;
    }

    /// VRFY -- verify a mailbox.
    pub fn vrfy(self: *Client, address: []const u8) !SmtpResponse {
        return try self.sendCommand("VRFY ", address);
    }

    /// EXPN -- expand a mailing list.
    pub fn expn(self: *Client, list: []const u8) !SmtpResponse {
        return try self.sendCommand("EXPN ", list);
    }

    /// HELP -- request help from the server.
    pub fn help(self: *Client, topic: ?[]const u8) !SmtpResponse {
        if (topic) |t| {
            return try self.sendCommand("HELP ", t);
        }
        return try self.sendCommand("HELP", "");
    }

    // -----------------------------------------------------------------------
    // STARTTLS
    // -----------------------------------------------------------------------

    /// Upgrade the connection to TLS via STARTTLS, then re-issue EHLO.
    pub fn starttls(self: *Client, tls_opts: TlsOptions) !SmtpResponse {
        try self.transport.writeAll("STARTTLS\r\n");
        self.debugLog("C: STARTTLS\n", .{});

        var resp = try self.readResponse();
        if (!resp.isSuccess()) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.StartTlsFailed;
        }
        freeResp(self.allocator, &resp);

        // Upgrade the underlying stream to TLS.
        const stream = self.owned_stream orelse return SmtpClientError.StartTlsFailed;
        const tls = try TlsTransport.init(self.allocator, stream, tls_opts);

        self.tls_state = tls;
        self.is_tls = true;
        self.transport = tls.transport();
        self.reader = LineReader.init(self.allocator, self.transport);
        self.reader.max_line_length = self.options.max_response_line_length;

        // Capabilities must be re-discovered after STARTTLS.
        self.capabilities.clear();

        // Re-issue EHLO over the encrypted channel.
        const hostname = if (builtin.os.tag == .windows) "localhost" else blk: {
            var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
            break :blk std.posix.gethostname(&hostname_buf) catch "localhost";
        };
        return try self.ehlo(hostname);
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// AUTH PLAIN with initial response on the same line.
    pub fn authenticatePlain(self: *Client, username: []const u8, password: []const u8) !void {
        const initial = try auth_mod.plain.initialResponseAlloc(self.allocator, null, username, password);
        defer self.allocator.free(initial);

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("AUTH PLAIN ");
        try encoder.atom(initial);
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: AUTH PLAIN ***\n", .{});

        var resp = try self.readResponse();
        if (resp.code != response_mod.codes.auth_success) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp);
    }

    /// AUTH LOGIN multi-step (username prompt, then password prompt).
    pub fn authenticateLogin(self: *Client, username: []const u8, password: []const u8) !void {
        try self.transport.writeAll("AUTH LOGIN\r\n");
        self.debugLog("C: AUTH LOGIN\n", .{});

        // Expect 334 challenge with base64 "Username:"
        var resp1 = try self.readResponse();
        if (resp1.code != response_mod.codes.auth_continue) {
            freeResp(self.allocator, &resp1);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp1);

        // Send base64-encoded username.
        const user_b64 = try auth_mod.login.encodeAlloc(self.allocator, username);
        defer self.allocator.free(user_b64);
        try self.transport.writeAll(user_b64);
        try self.transport.writeAll("\r\n");

        // Expect 334 challenge with base64 "Password:"
        var resp2 = try self.readResponse();
        if (resp2.code != response_mod.codes.auth_continue) {
            freeResp(self.allocator, &resp2);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp2);

        // Send base64-encoded password.
        const pass_b64 = try auth_mod.login.encodeAlloc(self.allocator, password);
        defer self.allocator.free(pass_b64);
        try self.transport.writeAll(pass_b64);
        try self.transport.writeAll("\r\n");

        // Expect 235 Authentication successful.
        var resp3 = try self.readResponse();
        if (resp3.code != response_mod.codes.auth_success) {
            freeResp(self.allocator, &resp3);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp3);
    }

    /// AUTH CRAM-MD5 challenge-response.
    pub fn authenticateCramMd5(self: *Client, username: []const u8, password: []const u8) !void {
        try self.transport.writeAll("AUTH CRAM-MD5\r\n");
        self.debugLog("C: AUTH CRAM-MD5\n", .{});

        // Expect 334 with base64-encoded challenge.
        var resp1 = try self.readResponse();
        if (resp1.code != response_mod.codes.auth_continue) {
            freeResp(self.allocator, &resp1);
            return SmtpClientError.AuthenticationFailed;
        }
        const challenge = resp1.text;

        // Compute CRAM-MD5 response.
        const cram_resp = try auth_mod.crammd5.responseAlloc(self.allocator, username, password, challenge);
        defer self.allocator.free(cram_resp);
        freeResp(self.allocator, &resp1);

        try self.transport.writeAll(cram_resp);
        try self.transport.writeAll("\r\n");

        // Expect 235.
        var resp2 = try self.readResponse();
        if (resp2.code != response_mod.codes.auth_success) {
            freeResp(self.allocator, &resp2);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp2);
    }

    /// AUTH XOAUTH2 with initial response.
    pub fn authenticateXOAuth2(self: *Client, user: []const u8, access_token: []const u8) !void {
        const initial = try auth_mod.xoauth2.initialResponseAlloc(self.allocator, user, access_token);
        defer self.allocator.free(initial);

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("AUTH XOAUTH2 ");
        try encoder.atom(initial);
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: AUTH XOAUTH2 ***\n", .{});

        var resp = try self.readResponse();
        if (resp.code != response_mod.codes.auth_success) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp);
    }

    pub fn authenticateOAuthBearer(self: *Client, user: []const u8, access_token: []const u8, host: ?[]const u8, port: ?u16) !void {
        const initial = try auth_mod.oauthbearer.initialResponseAlloc(self.allocator, user, access_token, host, port);
        defer self.allocator.free(initial);

        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command("AUTH OAUTHBEARER ");
        try encoder.atom(initial);
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: AUTH OAUTHBEARER ***\n", .{});

        var resp = try self.readResponse();
        if (resp.code != response_mod.codes.auth_success) {
            freeResp(self.allocator, &resp);
            return SmtpClientError.AuthenticationFailed;
        }
        freeResp(self.allocator, &resp);
    }

    // -----------------------------------------------------------------------
    // High-level convenience
    // -----------------------------------------------------------------------

    /// Full send flow: MAIL FROM + RCPT TO (for each recipient) + DATA.
    pub fn sendMail(
        self: *Client,
        from: []const u8,
        recipients: []const []const u8,
        body: []const u8,
    ) !SmtpResponse {
        var mail_resp = try self.mailFrom(from, .{});
        freeResp(self.allocator, &mail_resp);

        for (recipients) |rcpt| {
            var rcpt_resp = try self.rcptTo(rcpt, .{});
            freeResp(self.allocator, &rcpt_resp);
        }

        return try self.sendData(body);
    }

    // -----------------------------------------------------------------------
    // Capability helpers
    // -----------------------------------------------------------------------

    /// Returns true if the server advertised the given capability.
    pub fn hasCap(self: *const Client, name: []const u8) bool {
        return self.capabilities.has(name);
    }

    pub fn supports8BitMime(self: *const Client) bool {
        return self.capabilities.has(caps.@"8bitmime");
    }

    pub fn supportsPipelining(self: *const Client) bool {
        return self.capabilities.has(caps.pipelining);
    }

    pub fn supportsChunking(self: *const Client) bool {
        return self.capabilities.has(caps.chunking);
    }

    pub fn supportsDsn(self: *const Client) bool {
        return self.capabilities.has(caps.dsn);
    }

    pub fn supportsSmtpUtf8(self: *const Client) bool {
        return self.capabilities.has(caps.smtputf8);
    }

    pub fn supportsStartTLS(self: *const Client) bool {
        return self.capabilities.has(caps.starttls);
    }

    /// Check whether a specific AUTH mechanism is advertised.
    pub fn supportsAuth(self: *const Client, mechanism: []const u8) bool {
        // AUTH mechanisms appear as "AUTH PLAIN", "AUTH LOGIN", etc.
        var buf: [128]u8 = undefined;
        const key = std.fmt.bufPrint(&buf, "AUTH {s}", .{mechanism}) catch return false;
        return self.capabilities.has(key);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Read the initial 220 greeting from the server and extract the server
    /// name (the first token of the greeting text).
    fn readGreeting(self: *Client) !void {
        var resp = try self.readResponse();
        defer freeResp(self.allocator, &resp);

        if (resp.code != response_mod.codes.service_ready) {
            return SmtpClientError.BadGreeting;
        }

        // Extract server name (first whitespace-delimited token).
        if (resp.text.len > 0) {
            const end = std.mem.indexOfScalar(u8, resp.text, ' ') orelse resp.text.len;
            self.server_name = try self.allocator.dupe(u8, resp.text[0..end]);
        }

        self.state = .greeted;
    }

    /// Read and parse a (potentially multi-line) SMTP response.
    fn readResponse(self: *Client) !SmtpResponse {
        const resp = try response_mod.readResponseAlloc(self.allocator, &self.reader);
        self.debugLog("S: {d} {s}\n", .{ resp.code, resp.text });
        return resp;
    }

    /// Check that a response has a 2xx success code; if not, return an error.
    fn ensureSuccess(_: *Client, resp: SmtpResponse) !void {
        if (!resp.isSuccess()) return SmtpClientError.UnexpectedResponse;
    }

    /// Send a simple command (verb + argument), read the response.
    fn sendCommand(self: *Client, verb: []const u8, argument: []const u8) !SmtpResponse {
        var encoder = Encoder.init(self.allocator);
        defer encoder.deinit();
        try encoder.command(verb);
        if (argument.len > 0) {
            try encoder.atom(argument);
        }
        try encoder.crlf();

        const cmd = try encoder.finish();
        defer self.allocator.free(cmd);

        try self.transport.writeAll(cmd);
        self.debugLog("C: {s}{s}\n", .{ verb, argument });

        return try self.readResponse();
    }

    /// Parse EHLO response lines into the capability set.
    /// The first line is the server greeting; subsequent lines are extensions.
    fn parseEhloResponse(self: *Client, resp: SmtpResponse) void {
        self.capabilities.clear();

        for (resp.lines, 0..) |line, i| {
            // Skip the first line (server greeting).
            if (i == 0) continue;

            // Each line is "250-KEYWORD [params]" or "250 KEYWORD [params]".
            // The response parser gives us the raw line including the code.
            if (line.len < 4) continue;
            const ext_text = line[4..];
            self.capabilities.add(ext_text) catch {};

            // Check for SIZE value.
            if (std.ascii.startsWithIgnoreCase(ext_text, "SIZE ") or
                std.ascii.startsWithIgnoreCase(ext_text, "SIZE\t"))
            {
                const size_str = std.mem.trimLeft(u8, ext_text[4..], " \t");
                self.max_size = std.fmt.parseInt(u64, size_str, 10) catch null;
            } else if (std.ascii.eqlIgnoreCase(ext_text, "SIZE")) {
                self.max_size = 0;
            }
        }
    }

    fn dataWriteDotStuffedChunk(self: *Client, chunk: []const u8, at_line_start: *bool) !void {
        var segment_start: usize = 0;

        for (chunk, 0..) |byte, index| {
            if (at_line_start.* and byte == '.') {
                if (segment_start < index) {
                    try self.transport.writeAll(chunk[segment_start..index]);
                    self.recordDataChunk(chunk[segment_start..index]);
                }

                try self.transport.writeAll(".");
                self.recordDataChunk(".");
                segment_start = index;
                at_line_start.* = false;
            }

            if (byte == '\n') {
                at_line_start.* = true;
            } else if (byte != '\r') {
                at_line_start.* = false;
            }
        }

        if (segment_start < chunk.len) {
            try self.transport.writeAll(chunk[segment_start..]);
            self.recordDataChunk(chunk[segment_start..]);
        }
    }

    fn recordDataChunk(self: *Client, chunk: []const u8) void {
        for (chunk) |byte| {
            self.data_prev_byte = self.data_last_byte;
            self.data_last_byte = byte;
        }
    }

    /// Conditionally log a debug message to stderr.
    fn debugLog(self: *const Client, comptime fmt: []const u8, args: anytype) void {
        if (self.options.debug_log) {
            std.debug.print(fmt, args);
        }
    }

    /// Helper to free a SmtpResponse using the shared response module.
    fn freeResp(allocator: std.mem.Allocator, resp: *SmtpResponse) void {
        response_mod.freeResponse(allocator, resp);
    }
};
