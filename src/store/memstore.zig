const std = @import("std");

/// A stored email message.
pub const Message = struct {
    allocator: std.mem.Allocator,
    from: []u8,
    recipients: std.ArrayList([]u8),
    body: []u8,
    timestamp: u64,

    pub fn init(allocator: std.mem.Allocator, from: []const u8, body: []const u8) !Message {
        const from_owned = try allocator.dupe(u8, from);
        errdefer allocator.free(from_owned);

        const body_owned = try allocator.dupe(u8, body);
        errdefer allocator.free(body_owned);

        return .{
            .allocator = allocator,
            .from = from_owned,
            .recipients = .empty,
            .body = body_owned,
            .timestamp = @intCast(std.time.timestamp()),
        };
    }

    pub fn addRecipient(self: *Message, rcpt: []const u8) !void {
        const owned = try self.allocator.dupe(u8, rcpt);
        errdefer self.allocator.free(owned);
        try self.recipients.append(self.allocator, owned);
    }

    pub fn deinit(self: *Message) void {
        self.allocator.free(self.from);
        self.allocator.free(self.body);
        for (self.recipients.items) |r| {
            self.allocator.free(r);
        }
        self.recipients.deinit(self.allocator);
    }
};

/// A user account in the in-memory store.
pub const User = struct {
    allocator: std.mem.Allocator,
    username: []u8,
    password: []u8,
    messages: std.ArrayList(Message),

    pub fn init(allocator: std.mem.Allocator, username: []const u8, password: []const u8) !User {
        const user_owned = try allocator.dupe(u8, username);
        errdefer allocator.free(user_owned);

        const pass_owned = try allocator.dupe(u8, password);
        errdefer allocator.free(pass_owned);

        return .{
            .allocator = allocator,
            .username = user_owned,
            .password = pass_owned,
            .messages = .empty,
        };
    }

    pub fn deinit(self: *User) void {
        for (self.messages.items) |*msg| {
            msg.deinit();
        }
        self.messages.deinit(self.allocator);
        self.allocator.free(self.username);
        self.allocator.free(self.password);
    }

    pub fn appendMessage(self: *User, msg: Message) !void {
        try self.messages.append(self.allocator, msg);
    }
};

/// In-memory mail store for testing and simple deployments.
pub const MemStore = struct {
    allocator: std.mem.Allocator,
    users: std.StringHashMap(*User),

    pub fn init(allocator: std.mem.Allocator) MemStore {
        return .{
            .allocator = allocator,
            .users = std.StringHashMap(*User).init(allocator),
        };
    }

    pub fn deinit(self: *MemStore) void {
        var it = self.users.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.users.deinit();
    }

    /// Add a new user with the given credentials.
    pub fn addUser(self: *MemStore, username: []const u8, password: []const u8) !void {
        if (self.users.get(username)) |existing| {
            const new_password = try self.allocator.dupe(u8, password);
            self.allocator.free(existing.password);
            existing.password = new_password;
            return;
        }

        const user = try self.allocator.create(User);
        errdefer self.allocator.destroy(user);

        user.* = try User.init(self.allocator, username, password);
        errdefer user.deinit();

        const key = try self.allocator.dupe(u8, username);
        errdefer self.allocator.free(key);

        try self.users.put(key, user);
    }

    /// Authenticate with username/password. Returns the user on success.
    pub fn authenticate(self: *MemStore, username: []const u8, password: []const u8) ?*User {
        const user = self.users.get(username) orelse return null;
        if (std.mem.eql(u8, user.password, password)) {
            return user;
        }
        return null;
    }

    /// Authenticate by username only (for external/certificate-based auth).
    pub fn authenticateExternal(self: *MemStore, username: []const u8) ?*User {
        return self.users.get(username);
    }

    /// Authenticate with a token (for XOAUTH2). In this simple store,
    /// the token is treated as the password.
    pub fn authenticateToken(self: *MemStore, username: []const u8, token: []const u8) ?*User {
        return self.authenticate(username, token);
    }

    /// Deliver a message to all recipient users that exist in the store.
    /// Returns the number of successful deliveries.
    pub fn deliverMessage(self: *MemStore, from: []const u8, recipients: []const []u8, body: []const u8) !u32 {
        var delivered: u32 = 0;

        for (recipients) |rcpt| {
            // Extract local part if the recipient is a full email address.
            const local = extractLocal(rcpt);
            const user = self.users.get(local) orelse continue;

            var msg = try Message.init(self.allocator, from, body);
            errdefer msg.deinit();

            for (recipients) |r| {
                try msg.addRecipient(r);
            }

            try user.appendMessage(msg);
            delivered += 1;
        }

        return delivered;
    }

    /// Extract the local part from an email address (before the @).
    fn extractLocal(addr: []const u8) []const u8 {
        if (std.mem.indexOfScalar(u8, addr, '@')) |idx| {
            return addr[0..idx];
        }
        return addr;
    }
};
