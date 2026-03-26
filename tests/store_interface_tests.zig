const std = @import("std");
const smtp = @import("smtp");

const MemStore = smtp.store.MemStore;
const Backend = smtp.store.Backend;
const DeliveryBackend = smtp.store.DeliveryBackend;

// ---------------------------------------------------------------------------
// Backend interface from MemStore
// ---------------------------------------------------------------------------

test "interface: Backend.fromMemStore authenticate success" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "secret");

    const backend = Backend.fromMemStore(&store);
    const result = backend.authenticate("alice", "secret");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(true, result.?);
}

test "interface: Backend.fromMemStore authenticate failure" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "secret");

    const backend = Backend.fromMemStore(&store);
    const result = backend.authenticate("alice", "wrong");
    try std.testing.expect(result == null);
}

test "interface: Backend.fromMemStore authenticate nonexistent user" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    const backend = Backend.fromMemStore(&store);
    const result = backend.authenticate("nobody", "pass");
    try std.testing.expect(result == null);
}

test "interface: Backend.fromMemStore authenticateExternal" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "pass");

    const backend = Backend.fromMemStore(&store);
    const result = backend.authenticateExternal("alice");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(true, result.?);

    const bad = backend.authenticateExternal("nobody");
    try std.testing.expect(bad == null);
}

test "interface: Backend.fromMemStore authenticateToken" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("alice", "token123");

    const backend = Backend.fromMemStore(&store);
    const result = backend.authenticateToken("alice", "token123");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(true, result.?);

    const bad = backend.authenticateToken("alice", "wrongtoken");
    try std.testing.expect(bad == null);
}

test "interface: Backend.fromMemStore addUser" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    const backend = Backend.fromMemStore(&store);
    try backend.addUser("newuser", "newpass");

    // Verify through direct store access.
    const user = store.authenticate("newuser", "newpass");
    try std.testing.expect(user != null);
}

// ---------------------------------------------------------------------------
// DeliveryBackend interface from MemStore
// ---------------------------------------------------------------------------

test "interface: DeliveryBackend.fromMemStore deliverMessage" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    try store.addUser("bob", "pass");

    const delivery = DeliveryBackend.fromMemStore(&store);

    var recipients = [_][]u8{
        @constCast("bob@example.com"),
    };
    const delivered = try delivery.deliverMessage("alice@example.com", &recipients, "Hello from interface!");
    try std.testing.expectEqual(@as(u32, 1), delivered);

    // Verify message was stored.
    const user = store.users.get("bob").?;
    try std.testing.expectEqual(@as(usize, 1), user.messages.items.len);
    try std.testing.expectEqualStrings("Hello from interface!", user.messages.items[0].body);
}

test "interface: DeliveryBackend.fromMemStore no matching recipients" {
    const allocator = std.testing.allocator;
    var store = MemStore.init(allocator);
    defer store.deinit();

    const delivery = DeliveryBackend.fromMemStore(&store);

    var recipients = [_][]u8{
        @constCast("nobody@example.com"),
    };
    const delivered = try delivery.deliverMessage("alice@example.com", &recipients, "Hello!");
    try std.testing.expectEqual(@as(u32, 0), delivered);
}
