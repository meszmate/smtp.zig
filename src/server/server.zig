const std = @import("std");
const transport_mod = @import("../wire/transport.zig");
const line_reader_mod = @import("../wire/line_reader.zig");
const response_mod = @import("../response.zig");
const types = @import("../types.zig");
const auth_plain = @import("../auth/plain.zig");
const auth_login = @import("../auth/login.zig");
const auth_crammd5 = @import("../auth/crammd5.zig");
const auth_xoauth2 = @import("../auth/xoauth2.zig");
const conn_mod = @import("conn.zig");
const session_mod = @import("session.zig");
const options_mod = @import("options.zig");
const stream_mod = @import("stream.zig");
const store_mod = @import("../store/memstore.zig");

const Transport = transport_mod.Transport;
const LineReader = line_reader_mod.LineReader;
const Conn = conn_mod.Conn;
const Command = conn_mod.Command;
const SessionState = session_mod.SessionState;
const Options = options_mod.Options;
const Envelope = stream_mod.Envelope;
const MessageStream = stream_mod.MessageStream;
const MemStore = store_mod.MemStore;
const codes = response_mod.codes;

/// SMTP server that handles incoming connections.
pub const Server = struct {
    allocator: std.mem.Allocator,
    store: *MemStore,
    options: Options,
    is_shutdown: bool = false,

    /// Initialize a server with default options.
    pub fn init(allocator: std.mem.Allocator, store: *MemStore) Server {
        return .{
            .allocator = allocator,
            .store = store,
            .options = .{},
        };
    }

    /// Initialize a server with custom options.
    pub fn initWithOptions(allocator: std.mem.Allocator, store: *MemStore, opts: Options) Server {
        return .{
            .allocator = allocator,
            .store = store,
            .options = opts,
        };
    }

    /// Mark the server as shut down.
    pub fn shutdown(self: *Server) void {
        self.is_shutdown = true;
    }

    /// Check if the server is shut down.
    pub fn isShutdown(self: *const Server) bool {
        return self.is_shutdown;
    }

    fn hasTlsUpgrade(self: *const Server) bool {
        return self.options.tls_upgrade_fn != null and self.options.tls_upgrade_ctx != null;
    }

    fn canAdvertiseStarttls(self: *const Server, conn: *const Conn) bool {
        return self.options.enable_starttls and self.hasTlsUpgrade() and !conn.session.is_tls;
    }

    /// Serve a single SMTP connection. This is the main session loop.
    pub fn serveConnection(self: *Server, transport: Transport, stream: std.net.Stream, is_tls: bool) void {
        var connection = Conn.init(self.allocator, transport);
        defer connection.deinit();
        connection.stream = stream;

        connection.session.is_tls = is_tls;

        // Send greeting.
        connection.writeGreeting(self.options.hostname, self.options.greeting_text) catch return;

        // Main command loop.
        while (!self.is_shutdown and connection.session.state != .logout) {
            const result = connection.readCommandAlloc() catch |err| {
                switch (err) {
                    error.EndOfStream => return,
                    else => return,
                }
            };
            defer self.allocator.free(result.raw);

            self.handleCommand(&connection, result.command) catch {
                connection.writeError(451, "4.0.0 Internal server error") catch return;
            };
        }
    }

    fn handleCommand(self: *Server, conn: *Conn, cmd: Command) !void {
        // Normalize verb to uppercase for comparison.
        var upper_buf: [64]u8 = undefined;
        const verb_len = @min(cmd.verb.len, upper_buf.len);
        for (cmd.verb[0..verb_len], 0..) |c, i| {
            upper_buf[i] = std.ascii.toUpper(c);
        }
        const verb = upper_buf[0..verb_len];

        // Check if command is allowed in current state.
        if (!conn.session.canExecute(verb)) {
            try conn.writeError(503, "5.5.1 Bad sequence of commands");
            return;
        }

        if (std.mem.eql(u8, verb, "EHLO")) {
            try self.handleEhlo(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "HELO")) {
            try self.handleHelo(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "STARTTLS")) {
            try self.handleStarttls(conn);
        } else if (std.mem.eql(u8, verb, "AUTH")) {
            try self.handleAuth(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "MAIL FROM")) {
            try self.handleMailFrom(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "RCPT TO")) {
            try self.handleRcptTo(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "DATA")) {
            try self.handleData(conn);
        } else if (std.mem.eql(u8, verb, "BDAT")) {
            try self.handleBdat(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "RSET")) {
            try self.handleRset(conn);
        } else if (std.mem.eql(u8, verb, "NOOP")) {
            try conn.writeOk("2.0.0 OK");
        } else if (std.mem.eql(u8, verb, "QUIT")) {
            try self.handleQuit(conn);
        } else if (std.mem.eql(u8, verb, "VRFY")) {
            try self.handleVrfy(conn, cmd.args);
        } else if (std.mem.eql(u8, verb, "EXPN")) {
            try conn.writeError(codes.command_not_implemented, "5.5.1 EXPN not supported");
        } else if (std.mem.eql(u8, verb, "HELP")) {
            try self.handleHelp(conn);
        } else {
            try conn.writeError(codes.command_not_implemented, "5.5.1 Command not recognized");
        }
    }

    fn handleEhlo(self: *Server, conn: *Conn, args: []const u8) !void {
        if (args.len == 0) {
            try conn.writeError(codes.param_syntax_error, "5.5.4 EHLO requires a domain");
            return;
        }

        try conn.session.setClientDomain(args);

        // Build EHLO response lines.
        var lines: std.ArrayList([]const u8) = .empty;
        defer {
            for (lines.items) |line| {
                self.allocator.free(@constCast(line));
            }
            lines.deinit(self.allocator);
        }

        // First line is the hostname greeting.
        const greeting = try std.fmt.allocPrint(self.allocator, "{s} Hello {s}", .{ self.options.hostname, args });
        try lines.append(self.allocator, greeting);

        // Add SIZE extension.
        if (self.options.max_message_size > 0) {
            const size_cap = try std.fmt.allocPrint(self.allocator, "SIZE {d}", .{self.options.max_message_size});
            try lines.append(self.allocator, size_cap);
        }

        // Add capabilities.
        const caps = if (self.options.capabilities) |c|
            c
        else if (self.canAdvertiseStarttls(conn))
            Options.starttlsCapabilities()
        else
            Options.defaultCapabilities();

        for (caps) |cap| {
            if (!self.canAdvertiseStarttls(conn) and std.ascii.eqlIgnoreCase(cap, "STARTTLS")) continue;
            const cap_owned = try self.allocator.dupe(u8, cap);
            try lines.append(self.allocator, cap_owned);
        }

        // Add AUTH capabilities if authentication is available.
        if (conn.session.is_tls or self.options.allow_insecure_auth) {
            const auth_cap = try self.allocator.dupe(u8, "AUTH PLAIN LOGIN CRAM-MD5 XOAUTH2");
            try lines.append(self.allocator, auth_cap);
        }

        try conn.writeMultiline(codes.ok, lines.items);
    }

    fn handleHelo(self: *Server, conn: *Conn, args: []const u8) !void {
        if (args.len == 0) {
            try conn.writeError(codes.param_syntax_error, "5.5.4 HELO requires a domain");
            return;
        }

        try conn.session.setClientDomain(args);
        const msg = try std.fmt.allocPrint(self.allocator, "{s} Hello {s}", .{ self.options.hostname, args });
        defer self.allocator.free(msg);
        try conn.writeOk(msg);
    }

    fn handleStarttls(self: *Server, conn: *Conn) !void {
        if (!self.options.enable_starttls or !self.hasTlsUpgrade()) {
            try conn.writeError(codes.command_not_implemented, "5.5.1 STARTTLS not available");
            return;
        }

        if (conn.session.is_tls) {
            try conn.writeError(codes.bad_sequence, "5.5.1 TLS already active");
            return;
        }

        try conn.writeResponse(codes.service_ready, "2.0.0 Ready to start TLS");

        // Perform TLS upgrade via callback.
        // The upgrade function is responsible for replacing the transport layer
        // on the connection. It receives the opaque context that was configured
        // in the server options.
        const stream = conn.stream orelse {
            try conn.writeError(codes.local_error, "4.7.0 No underlying stream for TLS upgrade");
            return;
        };
        self.options.tls_upgrade_fn.?(self.options.tls_upgrade_ctx.?, stream) catch {
            try conn.writeError(codes.local_error, "4.7.0 TLS negotiation failed");
            return;
        };

        conn.session.is_tls = true;
        // Reset session state after TLS upgrade (per RFC 3207).
        conn.session.reset();
        conn.session.state = .connect;
    }

    fn handleAuth(self: *Server, conn: *Conn, args: []const u8) !void {
        if (conn.session.authenticated) {
            try conn.writeError(codes.bad_sequence, "5.5.1 Already authenticated");
            return;
        }

        if (!conn.session.is_tls and !self.options.allow_insecure_auth) {
            try conn.writeError(530, "5.7.11 Encryption required for authentication");
            return;
        }

        // Parse mechanism and optional initial response.
        var it = std.mem.tokenizeScalar(u8, args, ' ');
        const mechanism = it.next() orelse {
            try conn.writeError(codes.param_syntax_error, "5.5.4 AUTH requires a mechanism");
            return;
        };
        const initial_response = it.next();

        // Normalize mechanism to uppercase.
        var mech_buf: [32]u8 = undefined;
        const mech_len = @min(mechanism.len, mech_buf.len);
        for (mechanism[0..mech_len], 0..) |c, i| {
            mech_buf[i] = std.ascii.toUpper(c);
        }
        const mech = mech_buf[0..mech_len];

        if (std.mem.eql(u8, mech, "PLAIN")) {
            try self.handleAuthPlain(conn, initial_response);
        } else if (std.mem.eql(u8, mech, "LOGIN")) {
            try self.handleAuthLogin(conn, initial_response);
        } else if (std.mem.eql(u8, mech, "CRAM-MD5")) {
            try self.handleAuthCramMd5(conn);
        } else if (std.mem.eql(u8, mech, "XOAUTH2")) {
            try self.handleAuthXOAuth2(conn, initial_response);
        } else {
            try conn.writeError(codes.param_not_recognized, "5.5.4 Unrecognized authentication mechanism");
        }
    }

    fn handleAuthPlain(self: *Server, conn: *Conn, initial_response: ?[]const u8) !void {
        var allocated_line: ?[]u8 = null;
        defer if (allocated_line) |l| self.allocator.free(l);

        const b64_response = if (initial_response) |ir|
            ir
        else blk: {
            // Send challenge (empty for PLAIN).
            try conn.writeResponse(codes.auth_continue, "");
            const line = try conn.reader.readLineAlloc();
            allocated_line = line;
            break :blk @as([]const u8, line);
        };

        // Check for auth cancel.
        if (std.mem.eql(u8, b64_response, "*")) {
            try conn.writeError(codes.param_syntax_error, "5.7.0 Authentication cancelled");
            return;
        }

        const decoded = auth_plain.decodeResponseAlloc(self.allocator, b64_response) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer decoded.deinit();

        if (self.store.authenticate(decoded.username, decoded.password)) |_| {
            try conn.session.setAuthenticated(decoded.username);
            try conn.writeResponse(codes.auth_success, "2.7.0 Authentication successful");
        } else {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication credentials invalid");
        }
    }

    fn handleAuthLogin(self: *Server, conn: *Conn, initial_response: ?[]const u8) !void {
        // Get username.
        var allocated_uname: ?[]u8 = null;
        defer if (allocated_uname) |l| self.allocator.free(l);

        const username_b64 = if (initial_response) |ir|
            ir
        else blk: {
            try conn.writeResponse(codes.auth_continue, auth_login.usernamePrompt());
            const line = try conn.reader.readLineAlloc();
            allocated_uname = line;
            break :blk @as([]const u8, line);
        };

        if (std.mem.eql(u8, username_b64, "*")) {
            try conn.writeError(codes.param_syntax_error, "5.7.0 Authentication cancelled");
            return;
        }

        const username = auth_login.decodeAlloc(self.allocator, username_b64) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer self.allocator.free(username);

        // Get password.
        try conn.writeResponse(codes.auth_continue, auth_login.passwordPrompt());
        const password_b64 = try conn.reader.readLineAlloc();
        defer self.allocator.free(password_b64);

        if (std.mem.eql(u8, password_b64, "*")) {
            try conn.writeError(codes.param_syntax_error, "5.7.0 Authentication cancelled");
            return;
        }

        const password = auth_login.decodeAlloc(self.allocator, password_b64) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer self.allocator.free(password);

        if (self.store.authenticate(username, password)) |_| {
            try conn.session.setAuthenticated(username);
            try conn.writeResponse(codes.auth_success, "2.7.0 Authentication successful");
        } else {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication credentials invalid");
        }
    }

    fn handleAuthCramMd5(self: *Server, conn: *Conn) !void {
        // Generate and send challenge.
        const timestamp: u64 = @intCast(std.time.timestamp());
        const challenge = try std.fmt.allocPrint(self.allocator, "<{d}.{d}@{s}>", .{
            timestamp,
            @as(u64, @intCast(std.time.milliTimestamp())) % 100000,
            self.options.hostname,
        });
        defer self.allocator.free(challenge);

        // Base64 encode the challenge.
        const b64_encoder = std.base64.standard.Encoder;
        const challenge_b64_len = b64_encoder.calcSize(challenge.len);
        const challenge_b64 = try self.allocator.alloc(u8, challenge_b64_len);
        defer self.allocator.free(challenge_b64);
        _ = b64_encoder.encode(challenge_b64, challenge);

        try conn.writeResponse(codes.auth_continue, challenge_b64);

        // Read response.
        const response_b64 = try conn.reader.readLineAlloc();
        defer self.allocator.free(response_b64);

        if (std.mem.eql(u8, response_b64, "*")) {
            try conn.writeError(codes.param_syntax_error, "5.7.0 Authentication cancelled");
            return;
        }

        // Verify the response.
        const verified = auth_crammd5.verifyResponseAlloc(self.allocator, response_b64, challenge_b64) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer verified.deinit();

        // Look up the user and verify the digest.
        const user = self.store.users.get(verified.username) orelse {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication credentials invalid");
            return;
        };

        const expected = auth_crammd5.expectedDigestAlloc(self.allocator, user.password, challenge_b64) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer self.allocator.free(expected);

        if (std.mem.eql(u8, verified.digest, expected)) {
            try conn.session.setAuthenticated(verified.username);
            try conn.writeResponse(codes.auth_success, "2.7.0 Authentication successful");
        } else {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication credentials invalid");
        }
    }

    fn handleAuthXOAuth2(self: *Server, conn: *Conn, initial_response: ?[]const u8) !void {
        var allocated_line: ?[]u8 = null;
        defer if (allocated_line) |l| self.allocator.free(l);

        const b64_response = if (initial_response) |ir|
            ir
        else blk: {
            try conn.writeResponse(codes.auth_continue, "");
            const line = try conn.reader.readLineAlloc();
            allocated_line = line;
            break :blk @as([]const u8, line);
        };

        if (std.mem.eql(u8, b64_response, "*")) {
            try conn.writeError(codes.param_syntax_error, "5.7.0 Authentication cancelled");
            return;
        }

        const decoded = auth_xoauth2.decodeAlloc(self.allocator, b64_response) catch {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication failed");
            return;
        };
        defer decoded.deinit();

        if (self.store.authenticateToken(decoded.user, decoded.access_token)) |_| {
            try conn.session.setAuthenticated(decoded.user);
            try conn.writeResponse(codes.auth_success, "2.7.0 Authentication successful");
        } else {
            try conn.writeError(codes.auth_failed, "5.7.8 Authentication credentials invalid");
        }
    }

    fn handleMailFrom(self: *Server, conn: *Conn, args: []const u8) !void {
        // Parse the sender address from angle brackets.
        const addr = extractAddress(args) orelse {
            try conn.writeError(codes.param_syntax_error, "5.5.4 Invalid sender address");
            return;
        };

        // Check message size parameter if present.
        if (self.options.max_message_size > 0) {
            if (extractParam(args, "SIZE")) |size_str| {
                const size = std.fmt.parseInt(u64, size_str, 10) catch {
                    try conn.writeError(codes.param_syntax_error, "5.5.4 Invalid SIZE parameter");
                    return;
                };
                if (size > self.options.max_message_size) {
                    try conn.writeError(codes.exceeded_storage, "5.3.4 Message too big");
                    return;
                }
            }
        }

        try conn.session.setFrom(addr);
        try conn.writeOk("2.1.0 Sender OK");
    }

    fn handleRcptTo(self: *Server, conn: *Conn, args: []const u8) !void {
        const addr = extractAddress(args) orelse {
            try conn.writeError(codes.param_syntax_error, "5.5.4 Invalid recipient address");
            return;
        };

        // Check recipient limit.
        if (conn.session.recipients.items.len >= self.options.max_recipients) {
            try conn.writeError(codes.insufficient_storage, "4.5.3 Too many recipients");
            return;
        }

        try conn.session.addRecipient(addr);
        try conn.writeOk("2.1.5 Recipient OK");
    }

    fn handleData(self: *Server, conn: *Conn) !void {
        if (self.options.message_stream_factory != null) {
            try self.handleDataStream(conn);
            return;
        }

        try conn.writeResponse(codes.start_mail_input, "Start mail input; end with <CRLF>.<CRLF>");

        // Read message body until lone dot.
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        while (true) {
            const line = conn.reader.readLineAlloc() catch |err| {
                switch (err) {
                    error.EndOfStream => return,
                    else => return,
                }
            };
            defer self.allocator.free(line);

            // Check for terminating dot.
            if (std.mem.eql(u8, line, ".")) {
                break;
            }

            // Handle dot-stuffing: remove leading dot.
            const actual_line = if (line.len > 0 and line[0] == '.') line[1..] else line;

            // Check message size.
            if (self.options.max_message_size > 0 and body.items.len + actual_line.len + 2 > self.options.max_message_size) {
                try conn.writeError(codes.exceeded_storage, "5.3.4 Message too big");
                // Drain remaining data.
                while (true) {
                    const drain = conn.reader.readLineAlloc() catch return;
                    defer self.allocator.free(drain);
                    if (std.mem.eql(u8, drain, ".")) break;
                }
                return;
            }

            try body.appendSlice(self.allocator, actual_line);
            try body.appendSlice(self.allocator, "\r\n");
        }

        // Deliver the message.
        const from = conn.session.from orelse "";
        const recipients = conn.session.recipients.items;
        _ = self.store.deliverMessage(from, recipients, body.items) catch {
            try conn.writeError(codes.local_error, "4.0.0 Delivery failed");
            return;
        };

        try conn.writeOk("2.6.0 Message accepted for delivery");
        conn.session.reset();
    }

    fn handleBdat(self: *Server, conn: *Conn, args: []const u8) !void {
        // Parse chunk size and optional LAST flag.
        var it = std.mem.tokenizeScalar(u8, args, ' ');
        const size_str = it.next() orelse {
            try conn.writeError(codes.param_syntax_error, "5.5.4 BDAT requires a chunk size");
            return;
        };
        const chunk_size = std.fmt.parseInt(usize, size_str, 10) catch {
            try conn.writeError(codes.param_syntax_error, "5.5.4 Invalid chunk size");
            return;
        };

        var is_last = false;
        if (it.next()) |flag| {
            var flag_upper: [4]u8 = undefined;
            const flag_len = @min(flag.len, 4);
            for (flag[0..flag_len], 0..) |c, i| {
                flag_upper[i] = std.ascii.toUpper(c);
            }
            if (std.mem.eql(u8, flag_upper[0..flag_len], "LAST")) {
                is_last = true;
            }
        }

        // Read the exact number of bytes.
        const chunk_data = conn.reader.readExactAlloc(chunk_size) catch {
            try conn.writeError(codes.local_error, "4.0.0 Failed to read chunk data");
            return;
        };
        defer self.allocator.free(chunk_data);

        // Read trailing CRLF.
        conn.reader.readCrlf() catch {};

        if (self.options.message_stream_factory != null) {
            try self.handleBdatStream(conn, chunk_data, is_last);
            return;
        }

        if (!is_last) {
            try conn.session.appendBdatChunk(chunk_data);
            try conn.writeOk("2.0.0 Chunk received");
            return;
        }

        const body = if (conn.session.bdat_buffer.items.len > 0) blk: {
            try conn.session.appendBdatChunk(chunk_data);
            break :blk conn.session.bdat_buffer.items;
        } else chunk_data;

        const from = conn.session.from orelse "";
        const recipients = conn.session.recipients.items;
        _ = self.store.deliverMessage(from, recipients, body) catch {
            try conn.writeError(codes.local_error, "4.0.0 Delivery failed");
            return;
        };

        try conn.writeOk("2.6.0 Message accepted for delivery");
        conn.session.reset();
    }

    fn handleDataStream(self: *Server, conn: *Conn) !void {
        try conn.writeResponse(codes.start_mail_input, "Start mail input; end with <CRLF>.<CRLF>");

        var stream = self.openMessageStream(conn) catch {
            try conn.writeError(codes.local_error, "4.0.0 Failed to initialize message stream");
            return;
        };
        var finished = false;
        defer if (!finished) stream.abort();

        var body_size: usize = 0;

        while (true) {
            const line = conn.reader.readLineAlloc() catch |err| {
                switch (err) {
                    error.EndOfStream => return,
                    else => return,
                }
            };
            defer self.allocator.free(line);

            if (std.mem.eql(u8, line, ".")) {
                break;
            }

            const actual_line = if (line.len > 0 and line[0] == '.') line[1..] else line;
            const next_size = body_size + actual_line.len + 2;
            if (self.options.max_message_size > 0 and next_size > self.options.max_message_size) {
                try conn.writeError(codes.exceeded_storage, "5.3.4 Message too big");
                while (true) {
                    const drain = conn.reader.readLineAlloc() catch return;
                    defer self.allocator.free(drain);
                    if (std.mem.eql(u8, drain, ".")) break;
                }
                return;
            }

            try stream.write(actual_line);
            try stream.write("\r\n");
            body_size = next_size;
        }

        stream.finish() catch {
            try conn.writeError(codes.local_error, "4.0.0 Delivery failed");
            return;
        };
        finished = true;

        try conn.writeOk("2.6.0 Message accepted for delivery");
        conn.session.reset();
    }

    fn handleBdatStream(self: *Server, conn: *Conn, chunk_data: []const u8, is_last: bool) !void {
        const stream = if (conn.session.active_message_stream) |existing|
            existing
        else blk: {
            const opened = self.openMessageStream(conn) catch {
                try conn.writeError(codes.local_error, "4.0.0 Failed to initialize message stream");
                return;
            };
            conn.session.setActiveMessageStream(opened);
            break :blk opened;
        };

        errdefer {
            if (conn.session.active_message_stream != null) {
                conn.session.active_message_stream.?.abort();
                conn.session.clearActiveMessageStream();
            }
        }

        try stream.write(chunk_data);

        if (!is_last) {
            try conn.writeOk("2.0.0 Chunk received");
            return;
        }

        stream.finish() catch {
            try conn.writeError(codes.local_error, "4.0.0 Delivery failed");
            return;
        };
        conn.session.clearActiveMessageStream();

        try conn.writeOk("2.6.0 Message accepted for delivery");
        conn.session.reset();
    }

    fn handleRset(_: *Server, conn: *Conn) !void {
        conn.session.reset();
        try conn.writeOk("2.0.0 Reset OK");
    }

    fn handleQuit(_: *Server, conn: *Conn) !void {
        try conn.writeResponse(codes.service_closing, "2.0.0 Bye");
        conn.session.logout();
    }

    fn handleVrfy(_: *Server, conn: *Conn, _: []const u8) !void {
        try conn.writeResponse(codes.cannot_vrfy, "2.5.2 Cannot VRFY user");
    }

    fn handleHelp(_: *Server, conn: *Conn) !void {
        const help_lines = [_][]const u8{
            "Supported commands:",
            "EHLO HELO MAIL RCPT DATA BDAT",
            "RSET NOOP QUIT VRFY HELP",
            "AUTH STARTTLS",
        };
        try conn.writeMultiline(codes.help_message, &help_lines);
    }

    fn openMessageStream(self: *Server, conn: *const Conn) !MessageStream {
        const factory = self.options.message_stream_factory orelse return error.NoMessageStreamFactory;
        return try factory.open(self.allocator, envelopeFromSession(&conn.session));
    }
};

fn envelopeFromSession(session: *const SessionState) Envelope {
    return .{
        .from = session.from orelse "",
        .recipients = session.recipients.items,
        .username = session.username,
        .client_domain = session.client_domain,
        .is_tls = session.is_tls,
    };
}

/// Extract an email address from angle brackets: <addr> -> addr.
fn extractAddress(text: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, text, '<') orelse return null;
    const end = std.mem.indexOfScalar(u8, text[start..], '>') orelse return null;
    return text[start + 1 .. start + end];
}

/// Extract a parameter value from SMTP command arguments.
/// Looks for "KEY=VALUE" pattern.
fn extractParam(text: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    while (it.next()) |token| {
        if (std.mem.indexOfScalar(u8, token, '=')) |eq_idx| {
            var key_buf: [32]u8 = undefined;
            const klen = @min(eq_idx, key_buf.len);
            for (token[0..klen], 0..) |c, i| {
                key_buf[i] = std.ascii.toUpper(c);
            }
            if (std.mem.eql(u8, key_buf[0..klen], key)) {
                return token[eq_idx + 1 ..];
            }
        }
    }
    return null;
}
