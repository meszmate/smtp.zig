const std = @import("std");

/// Status of a queued message.
pub const MessageStatus = enum {
    pending,
    sending,
    sent,
    failed,
    deferred, // temporary failure, will retry
};

/// A message stored in the queue.
pub const QueuedMessage = struct {
    id: u64,
    from: []u8,
    recipients: [][]u8,
    body: []u8,
    status: MessageStatus = .pending,
    attempts: u32 = 0,
    max_attempts: u32 = 5,
    created_at: i64,
    next_retry_at: i64 = 0,
    last_error: ?[]u8 = null,

    /// Free all owned memory.
    pub fn deinit(self: *QueuedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.from);
        for (self.recipients) |r| allocator.free(r);
        allocator.free(self.recipients);
        allocator.free(self.body);
        if (self.last_error) |e| {
            allocator.free(e);
            self.last_error = null;
        }
    }
};

/// Options for creating a Queue.
pub const QueueOptions = struct {
    max_queue_size: usize = 10000,
    default_max_attempts: u32 = 5,
    flush_interval_ms: u64 = 60_000,
};

/// In-memory message queue with thread-safe access.
pub const Queue = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayList(QueuedMessage),
    next_id: u64 = 1,
    options: QueueOptions,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, options: QueueOptions) Queue {
        return .{
            .allocator = allocator,
            .messages = .empty,
            .next_id = 1,
            .options = options,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Queue) void {
        for (self.messages.items) |*msg| {
            msg.deinit(self.allocator);
        }
        self.messages.deinit(self.allocator);
    }

    /// Add a message to the queue. Returns the assigned message ID.
    pub fn enqueue(self: *Queue, from: []const u8, recipients: []const []const u8, body: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len >= self.options.max_queue_size) {
            return error.QueueFull;
        }

        const id = self.next_id;
        self.next_id += 1;

        // Duplicate all data so the queue owns it.
        const owned_from = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(owned_from);

        const owned_recipients = try self.allocator.alloc([]u8, recipients.len);
        var initialized: usize = 0;
        errdefer {
            for (owned_recipients[0..initialized]) |r| self.allocator.free(r);
            self.allocator.free(owned_recipients);
        }
        for (recipients, 0..) |r, i| {
            owned_recipients[i] = try self.allocator.dupe(u8, r);
            initialized = i + 1;
        }

        const owned_body = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(owned_body);

        const now = std.time.timestamp();

        try self.messages.append(self.allocator, .{
            .id = id,
            .from = owned_from,
            .recipients = owned_recipients,
            .body = owned_body,
            .status = .pending,
            .attempts = 0,
            .max_attempts = self.options.default_max_attempts,
            .created_at = now,
            .next_retry_at = 0,
            .last_error = null,
        });

        return id;
    }

    /// Get a pointer to the next pending message that is ready for sending.
    /// Returns null if no messages are available.
    pub fn dequeue(self: *Queue) ?*QueuedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();

        for (self.messages.items) |*msg| {
            if (msg.status == .pending or
                (msg.status == .deferred and msg.next_retry_at <= now))
            {
                msg.status = .sending;
                return msg;
            }
        }
        return null;
    }

    /// Mark a message as successfully sent.
    pub fn markSent(self: *Queue, id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findById(id)) |msg| {
            msg.status = .sent;
        }
    }

    /// Mark a message as permanently failed.
    pub fn markFailed(self: *Queue, id: u64, error_msg: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findById(id)) |msg| {
            msg.status = .failed;
            msg.attempts += 1;
            if (msg.last_error) |e| self.allocator.free(e);
            msg.last_error = self.allocator.dupe(u8, error_msg) catch null;
        }
    }

    /// Mark a message as deferred (temporary failure); schedule next retry.
    pub fn markDeferred(self: *Queue, id: u64, error_msg: []const u8, next_retry_at: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findById(id)) |msg| {
            msg.status = .deferred;
            msg.attempts += 1;
            msg.next_retry_at = next_retry_at;
            if (msg.last_error) |e| self.allocator.free(e);
            msg.last_error = self.allocator.dupe(u8, error_msg) catch null;
        }
    }

    /// Count messages in the pending or deferred state.
    pub fn pendingCount(self: *Queue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.messages.items) |msg| {
            if (msg.status == .pending or msg.status == .deferred) {
                count += 1;
            }
        }
        return count;
    }

    /// Remove messages that have exhausted their retries (failed with attempts >= max_attempts).
    /// Returns the number of messages removed.
    pub fn removeExpired(self: *Queue) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.messages.items.len) {
            var msg = &self.messages.items[i];
            if ((msg.status == .failed or msg.status == .deferred) and
                msg.attempts >= msg.max_attempts)
            {
                msg.deinit(self.allocator);
                _ = self.messages.orderedRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    /// Look up the status of a message by ID.
    pub fn getStatus(self: *Queue, id: u64) ?MessageStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findById(id)) |msg| {
            return msg.status;
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn findById(self: *Queue, id: u64) ?*QueuedMessage {
        for (self.messages.items) |*msg| {
            if (msg.id == id) return msg;
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Queue enqueue and dequeue" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{ .max_queue_size = 100, .default_max_attempts = 3 });
    defer q.deinit();

    const recipients = &[_][]const u8{ "bob@example.com", "carol@example.com" };
    const id = try q.enqueue("alice@example.com", recipients, "Hello, world!");

    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(usize, 1), q.pendingCount());

    const msg = q.dequeue().?;
    try std.testing.expectEqual(MessageStatus.sending, msg.status);
    try std.testing.expectEqualStrings("alice@example.com", msg.from);
    try std.testing.expectEqual(@as(usize, 2), msg.recipients.len);
    try std.testing.expectEqualStrings("bob@example.com", msg.recipients[0]);
    try std.testing.expectEqualStrings("Hello, world!", msg.body);
}

test "Queue markSent" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    _ = q.dequeue();
    q.markSent(id);

    try std.testing.expectEqual(MessageStatus.sent, q.getStatus(id).?);
    try std.testing.expectEqual(@as(usize, 0), q.pendingCount());
}

test "Queue markFailed" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    _ = q.dequeue();
    q.markFailed(id, "connection refused");

    try std.testing.expectEqual(MessageStatus.failed, q.getStatus(id).?);
}

test "Queue markDeferred" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    _ = q.dequeue();
    q.markDeferred(id, "temp failure", std.time.timestamp() + 60);

    try std.testing.expectEqual(MessageStatus.deferred, q.getStatus(id).?);
    try std.testing.expectEqual(@as(usize, 1), q.pendingCount());
}

test "Queue removeExpired" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{ .default_max_attempts = 2 });
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    _ = q.dequeue();
    q.markFailed(id, "err1");
    // Attempt 1, change back to sending
    if (q.findById(id)) |msg| {
        msg.status = .sending;
    }
    q.markFailed(id, "err2");
    // Now attempts == 2, which equals max_attempts

    const removed = q.removeExpired();
    try std.testing.expectEqual(@as(usize, 1), removed);
    try std.testing.expect(q.getStatus(id) == null);
}

test "Queue max size enforcement" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{ .max_queue_size = 2 });
    defer q.deinit();

    _ = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "1");
    _ = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "2");

    const result = q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "3");
    try std.testing.expectError(error.QueueFull, result);
}

test "Queue getStatus returns null for unknown id" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    try std.testing.expect(q.getStatus(999) == null);
}

test "Queue dequeue returns null when empty" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    try std.testing.expect(q.dequeue() == null);
}

test "Queue multiple enqueue assigns incrementing IDs" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id1 = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "1");
    const id2 = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "2");
    const id3 = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "3");

    try std.testing.expectEqual(@as(u64, 1), id1);
    try std.testing.expectEqual(@as(u64, 2), id2);
    try std.testing.expectEqual(@as(u64, 3), id3);
}

test "QueuedMessage deinit frees all fields" {
    const allocator = std.testing.allocator;

    const recipients = try allocator.alloc([]u8, 1);
    recipients[0] = try allocator.dupe(u8, "bob@example.com");

    var msg = QueuedMessage{
        .id = 1,
        .from = try allocator.dupe(u8, "alice@example.com"),
        .recipients = recipients,
        .body = try allocator.dupe(u8, "test body"),
        .created_at = 0,
        .last_error = try allocator.dupe(u8, "some error"),
    };
    msg.deinit(allocator);
}
