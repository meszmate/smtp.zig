const std = @import("std");

pub const Options = struct {
    psql_path: []const u8 = "psql",
    database_url: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    username: ?[]const u8 = null,
    database: ?[]const u8 = null,
};

pub const ExecFn = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, options: Options, sql: []const u8) anyerror![]u8;

pub const PgStore = struct {
    allocator: std.mem.Allocator,
    options: Options,
    exec_ctx: *anyopaque,
    exec_fn: ExecFn,

    pub fn init(allocator: std.mem.Allocator, options: Options) PgStore {
        return .{
            .allocator = allocator,
            .options = options,
            .exec_ctx = undefined,
            .exec_fn = execViaPsql,
        };
    }

    pub fn initWithExecutor(allocator: std.mem.Allocator, options: Options, exec_ctx: *anyopaque, exec_fn: ExecFn) PgStore {
        return .{
            .allocator = allocator,
            .options = options,
            .exec_ctx = exec_ctx,
            .exec_fn = exec_fn,
        };
    }

    pub fn deinit(_: *PgStore) void {}

    pub fn schemaSql() []const u8 {
        return
            \\CREATE TABLE IF NOT EXISTS smtp_users (
            \\    username TEXT PRIMARY KEY,
            \\    password TEXT NOT NULL
            \\);
            \\
            \\CREATE TABLE IF NOT EXISTS smtp_messages (
            \\    id BIGSERIAL PRIMARY KEY,
            \\    username TEXT NOT NULL,
            \\    mail_from TEXT NOT NULL,
            \\    recipients TEXT NOT NULL,
            \\    body TEXT NOT NULL,
            \\    size BIGINT NOT NULL DEFAULT 0,
            \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            \\    FOREIGN KEY (username) REFERENCES smtp_users(username) ON DELETE CASCADE
            \\);
            \\
            \\CREATE INDEX IF NOT EXISTS idx_smtp_messages_user ON smtp_messages(username);
        ;
    }

    pub fn ensureSchema(self: *PgStore) !void {
        const out = try self.execSqlAlloc(schemaSql());
        self.allocator.free(out);
    }

    pub fn addUser(self: *PgStore, username: []const u8, password: []const u8) !void {
        const esc_user = try sqlEscapeAlloc(self.allocator, username);
        defer self.allocator.free(esc_user);
        const esc_password = try sqlEscapeAlloc(self.allocator, password);
        defer self.allocator.free(esc_password);
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "INSERT INTO smtp_users (username, password) VALUES ('{s}', '{s}') ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password;",
            .{ esc_user, esc_password },
        );
        defer self.allocator.free(sql);
        const out = try self.execSqlAlloc(sql);
        self.allocator.free(out);
    }

    pub fn authenticate(self: *PgStore, username: []const u8, password: []const u8) !PgUser {
        const esc_user = try sqlEscapeAlloc(self.allocator, username);
        defer self.allocator.free(esc_user);
        const esc_password = try sqlEscapeAlloc(self.allocator, password);
        defer self.allocator.free(esc_password);
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT username FROM smtp_users WHERE username = '{s}' AND password = '{s}' LIMIT 1;",
            .{ esc_user, esc_password },
        );
        defer self.allocator.free(sql);
        const out = try self.execSqlAlloc(sql);
        defer self.allocator.free(out);
        if (std.mem.trim(u8, out, " \r\n\t").len == 0) return error.InvalidCredentials;

        return .{
            .allocator = self.allocator,
            .store = self,
            .username = try self.allocator.dupe(u8, username),
        };
    }

    /// Deliver a message to all recipient users that exist in the store.
    /// Returns the number of successful deliveries.
    pub fn deliverMessage(self: *PgStore, from: []const u8, recipients: []const []u8, body: []const u8) !u32 {
        var delivered: u32 = 0;
        for (recipients) |rcpt| {
            const local = extractLocal(rcpt);
            // Check if user exists
            const esc_local = try sqlEscapeAlloc(self.allocator, local);
            defer self.allocator.free(esc_local);
            const check_sql = try std.fmt.allocPrint(
                self.allocator,
                "SELECT username FROM smtp_users WHERE username = '{s}' LIMIT 1;",
                .{esc_local},
            );
            defer self.allocator.free(check_sql);
            const check_out = try self.execSqlAlloc(check_sql);
            defer self.allocator.free(check_out);
            if (std.mem.trim(u8, check_out, " \r\n\t").len == 0) continue;

            // Build recipients text
            var rcpt_text: std.ArrayList(u8) = .empty;
            defer rcpt_text.deinit(self.allocator);
            for (recipients, 0..) |r, i| {
                if (i != 0) try rcpt_text.appendSlice(self.allocator, ", ");
                try rcpt_text.appendSlice(self.allocator, r);
            }

            const esc_from = try sqlEscapeAlloc(self.allocator, from);
            defer self.allocator.free(esc_from);
            const esc_rcpts = try sqlEscapeAlloc(self.allocator, rcpt_text.items);
            defer self.allocator.free(esc_rcpts);
            const esc_body = try sqlEscapeAlloc(self.allocator, body);
            defer self.allocator.free(esc_body);
            const sql = try std.fmt.allocPrint(
                self.allocator,
                "INSERT INTO smtp_messages (username, mail_from, recipients, body, size) VALUES ('{s}', '{s}', '{s}', '{s}', {d});",
                .{ esc_local, esc_from, esc_rcpts, esc_body, body.len },
            );
            defer self.allocator.free(sql);
            const out = try self.execSqlAlloc(sql);
            self.allocator.free(out);
            delivered += 1;
        }
        return delivered;
    }

    fn execSqlAlloc(self: *PgStore, sql: []const u8) ![]u8 {
        return self.exec_fn(self.exec_ctx, self.allocator, self.options, sql);
    }

    fn extractLocal(addr: []const u8) []const u8 {
        if (std.mem.indexOfScalar(u8, addr, '@')) |idx| {
            return addr[0..idx];
        }
        return addr;
    }
};

pub const PgUser = struct {
    allocator: std.mem.Allocator,
    store: *PgStore,
    username: []u8,

    pub fn deinit(self: *PgUser) void {
        self.allocator.free(self.username);
        self.* = undefined;
    }

    /// List message IDs for this user.
    pub fn listMessagesAlloc(self: *PgUser) ![][]u8 {
        const esc_user = try sqlEscapeAlloc(self.allocator, self.username);
        defer self.allocator.free(esc_user);
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT id FROM smtp_messages WHERE username = '{s}' ORDER BY id;",
            .{esc_user},
        );
        defer self.allocator.free(sql);
        const out = try self.store.execSqlAlloc(sql);
        defer self.allocator.free(out);
        return splitLinesAlloc(self.allocator, out);
    }

    /// Delete a message by its ID.
    pub fn deleteMessage(self: *PgUser, message_id: []const u8) !void {
        const esc_user = try sqlEscapeAlloc(self.allocator, self.username);
        defer self.allocator.free(esc_user);
        const esc_id = try sqlEscapeAlloc(self.allocator, message_id);
        defer self.allocator.free(esc_id);
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "DELETE FROM smtp_messages WHERE username = '{s}' AND id = {s};",
            .{ esc_user, esc_id },
        );
        defer self.allocator.free(sql);
        const out = try self.store.execSqlAlloc(sql);
        self.allocator.free(out);
    }

    /// Get the number of messages for this user.
    pub fn getMessageCount(self: *PgUser) !u32 {
        const esc_user = try sqlEscapeAlloc(self.allocator, self.username);
        defer self.allocator.free(esc_user);
        const sql = try std.fmt.allocPrint(
            self.allocator,
            "SELECT COUNT(*) FROM smtp_messages WHERE username = '{s}';",
            .{esc_user},
        );
        defer self.allocator.free(sql);
        const out = try self.store.execSqlAlloc(sql);
        defer self.allocator.free(out);
        const trimmed = std.mem.trim(u8, out, " \r\n\t");
        return std.fmt.parseInt(u32, trimmed, 10) catch 0;
    }
};

fn execViaPsql(_: *anyopaque, allocator: std.mem.Allocator, options: Options, sql: []const u8) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    var port_text: ?[]u8 = null;
    defer if (port_text) |value| allocator.free(value);

    try argv.append(allocator, options.psql_path);
    try argv.append(allocator, "-X");
    try argv.append(allocator, "-A");
    try argv.append(allocator, "-t");
    try argv.append(allocator, "-v");
    try argv.append(allocator, "ON_ERROR_STOP=1");
    if (options.host) |host| {
        try argv.append(allocator, "-h");
        try argv.append(allocator, host);
    }
    if (options.port) |port| {
        const rendered = try std.fmt.allocPrint(allocator, "{d}", .{port});
        port_text = rendered;
        try argv.append(allocator, "-p");
        try argv.append(allocator, rendered);
    }
    if (options.username) |username| {
        try argv.append(allocator, "-U");
        try argv.append(allocator, username);
    }
    if (options.database) |database| {
        try argv.append(allocator, "-d");
        try argv.append(allocator, database);
    } else if (options.database_url) |url| {
        try argv.append(allocator, url);
    }
    try argv.append(allocator, "-c");
    try argv.append(allocator, sql);

    const run = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.PsqlNotAvailable,
        else => return err,
    };
    defer allocator.free(run.stdout);
    defer allocator.free(run.stderr);

    switch (run.term) {
        .Exited => |code| if (code == 0) return allocator.dupe(u8, run.stdout),
        else => {},
    }
    return error.PsqlCommandFailed;
}

fn splitLinesAlloc(allocator: std.mem.Allocator, text: []const u8) ![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |item| allocator.free(item);
        out.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trimRight(u8, line, "\r");
        if (trimmed.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, trimmed));
    }
    return out.toOwnedSlice(allocator);
}

fn sqlEscapeAlloc(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (value) |byte| {
        if (byte == '\'') {
            try out.append(allocator, '\'');
            try out.append(allocator, '\'');
        } else {
            try out.append(allocator, byte);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn parseUidList(allocator: std.mem.Allocator, text: []const u8) ![]u32 {
    var out: std.ArrayList(u32) = .empty;
    errdefer out.deinit(allocator);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (trimmed.len == 0) continue;
        const uid = std.fmt.parseInt(u32, trimmed, 10) catch continue;
        try out.append(allocator, uid);
    }
    return out.toOwnedSlice(allocator);
}
