const std = @import("std");
const smtp = @import("smtp");

const MemStore = smtp.store.MemStore;
const PgStore = smtp.store.PgStore;
const PgUser = smtp.store.PgUser;

const ExecCapture = struct {
    allocator: std.mem.Allocator,
    last_sql: ?[]u8 = null,

    fn deinit(self: *ExecCapture) void {
        if (self.last_sql) |sql| {
            self.allocator.free(sql);
            self.last_sql = null;
        }
    }

    fn exec(ctx: *anyopaque, allocator: std.mem.Allocator, _: smtp.store.PgStoreOptions, sql: []const u8) anyerror![]u8 {
        const self: *ExecCapture = @ptrCast(@alignCast(ctx));
        if (self.last_sql) |prev| allocator.free(prev);
        self.last_sql = try allocator.dupe(u8, sql);
        return try allocator.dupe(u8, "");
    }
};

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

test "memstore: addUser creates a user" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "password123");
    const user = store.users.get("alice");
    try std.testing.expect(user != null);
    try std.testing.expectEqualStrings("alice", user.?.username);
    try std.testing.expectEqualStrings("password123", user.?.password);
}

test "memstore: addUser multiple users" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "pass1");
    try store.addUser("bob", "pass2");
    try store.addUser("charlie", "pass3");

    try std.testing.expect(store.users.get("alice") != null);
    try std.testing.expect(store.users.get("bob") != null);
    try std.testing.expect(store.users.get("charlie") != null);
}

test "memstore: addUser updates an existing password" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "old-password");
    try store.addUser("alice", "new-password");

    try std.testing.expect(store.authenticate("alice", "old-password") == null);
    try std.testing.expect(store.authenticate("alice", "new-password") != null);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

test "memstore: authenticate with correct credentials succeeds" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "secret");
    const user = store.authenticate("alice", "secret");
    try std.testing.expect(user != null);
    try std.testing.expectEqualStrings("alice", user.?.username);
}

test "memstore: authenticate with wrong password fails" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "secret");
    const user = store.authenticate("alice", "wrong");
    try std.testing.expect(user == null);
}

test "memstore: authenticate with nonexistent user fails" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "secret");
    const user = store.authenticate("bob", "secret");
    try std.testing.expect(user == null);
}

test "memstore: authenticateExternal with existing user succeeds" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "anything");
    const user = store.authenticateExternal("alice");
    try std.testing.expect(user != null);
}

test "memstore: authenticateExternal with nonexistent user fails" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    const user = store.authenticateExternal("nobody");
    try std.testing.expect(user == null);
}

test "memstore: authenticateToken delegates to authenticate" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "token123");
    const user = store.authenticateToken("alice", "token123");
    try std.testing.expect(user != null);

    const bad = store.authenticateToken("alice", "wrongtoken");
    try std.testing.expect(bad == null);
}

// ---------------------------------------------------------------------------
// Message delivery
// ---------------------------------------------------------------------------

test "memstore: deliverMessage to existing user" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("bob", "pass");

    var recipients = [_][]u8{
        @constCast("bob@example.com"),
    };
    const delivered = try store.deliverMessage("alice@example.com", &recipients, "Hello, Bob!");
    try std.testing.expectEqual(@as(u32, 1), delivered);

    // Verify message was stored.
    const user = store.users.get("bob").?;
    try std.testing.expectEqual(@as(usize, 1), user.messages.items.len);
    try std.testing.expectEqualStrings("alice@example.com", user.messages.items[0].from);
    try std.testing.expectEqualStrings("Hello, Bob!", user.messages.items[0].body);
}

test "memstore: deliverMessage to nonexistent user returns 0" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    var recipients = [_][]u8{
        @constCast("nobody@example.com"),
    };
    const delivered = try store.deliverMessage("alice@example.com", &recipients, "Hello!");
    try std.testing.expectEqual(@as(u32, 0), delivered);
}

test "memstore: deliverMessage to local part without domain" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("bob", "pass");

    var recipients = [_][]u8{
        @constCast("bob"),
    };
    const delivered = try store.deliverMessage("alice", &recipients, "Hello!");
    try std.testing.expectEqual(@as(u32, 1), delivered);
}

test "memstore: deliverMessage multiple recipients" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("bob", "pass");
    try store.addUser("charlie", "pass");

    var recipients = [_][]u8{
        @constCast("bob@example.com"),
        @constCast("charlie@example.com"),
    };
    const delivered = try store.deliverMessage("alice@example.com", &recipients, "Hello all!");
    try std.testing.expectEqual(@as(u32, 2), delivered);

    const bob = store.users.get("bob").?;
    try std.testing.expectEqual(@as(usize, 1), bob.messages.items.len);

    const charlie = store.users.get("charlie").?;
    try std.testing.expectEqual(@as(usize, 1), charlie.messages.items.len);
}

test "memstore: deliverMessage partial recipients (one exists, one not)" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("bob", "pass");

    var recipients = [_][]u8{
        @constCast("bob@example.com"),
        @constCast("nobody@example.com"),
    };
    const delivered = try store.deliverMessage("alice@example.com", &recipients, "Hello!");
    try std.testing.expectEqual(@as(u32, 1), delivered);
}

// ---------------------------------------------------------------------------
// Message struct
// ---------------------------------------------------------------------------

test "memstore: Message addRecipient" {
    const allocator = std.testing.allocator;
    var msg = try smtp.store.Message.init(allocator, "sender@test.com", "body text");
    defer msg.deinit();

    try msg.addRecipient("rcpt1@test.com");
    try msg.addRecipient("rcpt2@test.com");

    try std.testing.expectEqual(@as(usize, 2), msg.recipients.items.len);
    try std.testing.expectEqualStrings("rcpt1@test.com", msg.recipients.items[0]);
    try std.testing.expectEqualStrings("rcpt2@test.com", msg.recipients.items[1]);
}

test "memstore: User appendMessage" {
    const allocator = std.testing.allocator;
    var user = try smtp.store.User.init(allocator, "testuser", "testpass");
    defer user.deinit();

    const msg = try smtp.store.Message.init(allocator, "from@test.com", "test body");
    // Note: appendMessage takes ownership of msg, so no defer deinit on msg.
    try user.appendMessage(msg);

    try std.testing.expectEqual(@as(usize, 1), user.messages.items.len);
    try std.testing.expectEqualStrings("from@test.com", user.messages.items[0].from);
}

test "pgstore: deleteMessage renders a numeric id safely" {
    const allocator = std.testing.allocator;
    var capture = ExecCapture{ .allocator = allocator };
    defer capture.deinit();

    var store = PgStore.initWithExecutor(allocator, .{}, @ptrCast(&capture), ExecCapture.exec);
    var user = PgUser{
        .allocator = allocator,
        .store = &store,
        .username = try allocator.dupe(u8, "alice"),
    };
    defer user.deinit();

    try user.deleteMessage("42");

    try std.testing.expect(capture.last_sql != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.last_sql.?, "id = 42;") != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.last_sql.?, "'42'") == null);
}

test "pgstore: deleteMessage rejects non-numeric ids" {
    const allocator = std.testing.allocator;
    var capture = ExecCapture{ .allocator = allocator };
    defer capture.deinit();

    var store = PgStore.initWithExecutor(allocator, .{}, @ptrCast(&capture), ExecCapture.exec);
    var user = PgUser{
        .allocator = allocator,
        .store = &store,
        .username = try allocator.dupe(u8, "alice"),
    };
    defer user.deinit();

    try std.testing.expectError(error.InvalidMessageId, user.deleteMessage("42 OR 1=1"));
    try std.testing.expect(capture.last_sql == null);
}
