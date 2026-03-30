const std = @import("std");
const server_stream = @import("../server/stream.zig");
const retry_mod = @import("retry.zig");

const Envelope = server_stream.Envelope;
const MessageStream = server_stream.MessageStream;
const MessageStreamFactory = server_stream.MessageStreamFactory;
const RetryPolicy = retry_mod.RetryPolicy;

/// Message body storage that can live in memory or in a temporary file.
pub const QueuedBody = union(enum) {
    memory: []u8,
    file_path: []u8,

    pub fn deinit(self: *QueuedBody, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .memory => |bytes| allocator.free(bytes),
            .file_path => |path| {
                std.fs.cwd().deleteFile(path) catch {};
                allocator.free(path);
            },
        }
    }

    pub fn readAllAlloc(self: QueuedBody, allocator: std.mem.Allocator) ![]u8 {
        return switch (self) {
            .memory => |bytes| allocator.dupe(u8, bytes),
            .file_path => |path| blk: {
                const stat = try std.fs.cwd().statFile(path);
                break :blk try std.fs.cwd().readFileAlloc(allocator, path, @intCast(stat.size));
            },
        };
    }

    pub fn size(self: QueuedBody) !usize {
        return switch (self) {
            .memory => |bytes| bytes.len,
            .file_path => |path| blk: {
                const stat = try std.fs.cwd().statFile(path);
                break :blk @intCast(stat.size);
            },
        };
    }

    pub fn isOnDisk(self: QueuedBody) bool {
        return switch (self) {
            .memory => false,
            .file_path => true,
        };
    }
};

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
    body: QueuedBody,
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
        self.body.deinit(allocator);
        if (self.last_error) |e| {
            allocator.free(e);
            self.last_error = null;
        }
    }

    pub fn readBodyAlloc(self: *const QueuedMessage, allocator: std.mem.Allocator) ![]u8 {
        return try self.body.readAllAlloc(allocator);
    }
};

/// Options for creating a Queue.
pub const QueueOptions = struct {
    max_queue_size: usize = 10000,
    default_max_attempts: u32 = 5,
    flush_interval_ms: u64 = 60_000,
    streaming_memory_limit: usize = 64 * 1024,
    streaming_temp_dir: []const u8 = ".smtp-queue",
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
        const owned_body = try self.allocator.dupe(u8, body);
        return try self.enqueueOwnedBody(from, recipients, .{ .memory = owned_body });
    }

    /// Add a message to the queue by reading it incrementally from a reader.
    pub fn enqueueReader(self: *Queue, from: []const u8, recipients: []const []const u8, reader: anytype) !u64 {
        var accumulator = BodyAccumulator.init(
            self.allocator,
            self.options.streaming_memory_limit,
            self.options.streaming_temp_dir,
        );
        defer accumulator.deinit();

        var buffer: [8192]u8 = undefined;
        while (true) {
            const read = try reader.read(&buffer);
            if (read == 0) break;
            try accumulator.write(buffer[0..read]);
        }

        return try self.enqueueOwnedBody(from, recipients, try accumulator.finish());
    }

    fn enqueueOwnedBody(self: *Queue, from: []const u8, recipients: []const []const u8, body: QueuedBody) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.messages.items.len >= self.options.max_queue_size) {
            var owned_body = body;
            owned_body.deinit(self.allocator);
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

        var owned_body = body;
        errdefer owned_body.deinit(self.allocator);

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
            self.setLastError(msg, error_msg);
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
            self.setLastError(msg, error_msg);
        }
    }

    /// Mark a message as deferred using a retry policy expressed in milliseconds.
    /// If no further retries remain, the message is marked as permanently failed.
    pub fn markDeferredWithPolicy(self: *Queue, id: u64, error_msg: []const u8, policy: RetryPolicy) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findById(id)) |msg| {
            msg.max_attempts = policy.max_attempts;
            if (!policy.shouldRetry(msg.attempts)) {
                msg.status = .failed;
                msg.attempts += 1;
                self.setLastError(msg, error_msg);
                return;
            }

            const retry_attempt = msg.attempts + 1;
            const delay_ms = policy.nextRetryDelay(retry_attempt);
            const delay_seconds = @as(i64, @intCast(std.math.divCeil(u64, delay_ms, std.time.ms_per_s) catch unreachable));

            msg.status = .deferred;
            msg.attempts = retry_attempt;
            msg.next_retry_at = std.time.timestamp() + delay_seconds;
            self.setLastError(msg, error_msg);
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

    fn setLastError(self: *Queue, msg: *QueuedMessage, error_msg: []const u8) void {
        if (msg.last_error) |e| self.allocator.free(e);
        msg.last_error = self.allocator.dupe(u8, error_msg) catch null;
    }
};

pub const StreamFactory = struct {
    queue: *Queue,

    pub fn init(queue: *Queue) StreamFactory {
        return .{ .queue = queue };
    }

    pub fn messageStreamFactory(self: *StreamFactory) MessageStreamFactory {
        return .{
            .context = @ptrCast(self),
            .open_fn = openFn,
        };
    }

    fn openFn(ctx: *anyopaque, allocator: std.mem.Allocator, envelope: Envelope) !MessageStream {
        const self: *StreamFactory = @ptrCast(@alignCast(ctx));
        const writer = try allocator.create(QueueMessageStream);
        errdefer allocator.destroy(writer);

        writer.* = .{
            .allocator = allocator,
            .queue = self.queue,
            .from = envelope.from,
            .recipients = envelope.recipients,
            .accumulator = BodyAccumulator.init(
                allocator,
                self.queue.options.streaming_memory_limit,
                self.queue.options.streaming_temp_dir,
            ),
        };

        return .{
            .context = @ptrCast(writer),
            .write_fn = QueueMessageStream.writeFn,
            .finish_fn = QueueMessageStream.finishFn,
            .abort_fn = QueueMessageStream.abortFn,
        };
    }
};

const QueueMessageStream = struct {
    allocator: std.mem.Allocator,
    queue: *Queue,
    from: []const u8,
    recipients: []const []u8,
    accumulator: BodyAccumulator,

    fn writeFn(ctx: *anyopaque, chunk: []const u8) !void {
        const self: *QueueMessageStream = @ptrCast(@alignCast(ctx));
        try self.accumulator.write(chunk);
    }

    fn finishFn(ctx: *anyopaque) !void {
        const self: *QueueMessageStream = @ptrCast(@alignCast(ctx));
        defer self.allocator.destroy(self);

        var accumulator = self.accumulator;
        self.accumulator = BodyAccumulator.init(
            self.allocator,
            self.queue.options.streaming_memory_limit,
            self.queue.options.streaming_temp_dir,
        );
        errdefer accumulator.deinit();

        _ = try self.queue.enqueueOwnedBody(self.from, self.recipients, try accumulator.finish());
    }

    fn abortFn(ctx: *anyopaque) void {
        const self: *QueueMessageStream = @ptrCast(@alignCast(ctx));
        self.accumulator.deinit();
        self.allocator.destroy(self);
    }
};

const BodyAccumulator = struct {
    allocator: std.mem.Allocator,
    memory_limit: usize,
    temp_dir: []const u8,
    buffer: std.ArrayList(u8) = .empty,
    temp_file: ?std.fs.File = null,
    temp_path: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator, memory_limit: usize, temp_dir: []const u8) BodyAccumulator {
        return .{
            .allocator = allocator,
            .memory_limit = memory_limit,
            .temp_dir = temp_dir,
        };
    }

    fn deinit(self: *BodyAccumulator) void {
        if (self.temp_file) |file| {
            file.close();
            self.temp_file = null;
        }
        if (self.temp_path) |path| {
            std.fs.cwd().deleteFile(path) catch {};
            self.allocator.free(path);
            self.temp_path = null;
        }
        self.buffer.deinit(self.allocator);
    }

    fn write(self: *BodyAccumulator, chunk: []const u8) !void {
        if (self.temp_file == null and self.buffer.items.len + chunk.len > self.memory_limit) {
            try self.spillToDisk();
        }

        if (self.temp_file) |*file| {
            try file.writeAll(chunk);
        } else {
            try self.buffer.appendSlice(self.allocator, chunk);
        }
    }

    fn finish(self: *BodyAccumulator) !QueuedBody {
        if (self.temp_file) |file| {
            file.close();
            self.temp_file = null;
            const path = self.temp_path orelse unreachable;
            self.temp_path = null;
            self.buffer.deinit(self.allocator);
            self.buffer = .empty;
            return .{ .file_path = path };
        }

        const bytes = try self.buffer.toOwnedSlice(self.allocator);
        self.buffer = .empty;
        return .{ .memory = bytes };
    }

    fn spillToDisk(self: *BodyAccumulator) !void {
        try std.fs.cwd().makePath(self.temp_dir);
        const path = try tempPathAlloc(self.allocator, self.temp_dir);
        errdefer self.allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        errdefer {
            file.close();
            std.fs.cwd().deleteFile(path) catch {};
        }

        if (self.buffer.items.len > 0) {
            try file.writeAll(self.buffer.items);
            self.buffer.clearRetainingCapacity();
        }

        self.temp_file = file;
        self.temp_path = path;
    }
};

fn tempPathAlloc(allocator: std.mem.Allocator, temp_dir: []const u8) ![]u8 {
    const random_value = std.crypto.random.int(u64);
    const filename = try std.fmt.allocPrint(allocator, "queue-{d}-{x}.eml", .{ std.time.milliTimestamp(), random_value });
    defer allocator.free(filename);

    return try std.fs.path.join(allocator, &.{ temp_dir, filename });
}

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
    const body = try msg.readBodyAlloc(allocator);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("Hello, world!", body);
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
        .body = .{ .memory = try allocator.dupe(u8, "test body") },
        .created_at = 0,
        .last_error = try allocator.dupe(u8, "some error"),
    };
    msg.deinit(allocator);
}

test "Queue enqueueReader stores large bodies on disk" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{
        .streaming_memory_limit = 8,
        .streaming_temp_dir = ".smtp-queue-test",
    });
    defer q.deinit();

    var stream = std.io.fixedBufferStream("this body is larger than eight bytes");
    const id = try q.enqueueReader("a@b.com", &[_][]const u8{"c@d.com"}, stream.reader());

    const msg = q.findById(id).?;
    try std.testing.expect(msg.body.isOnDisk());

    const body = try msg.readBodyAlloc(allocator);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("this body is larger than eight bytes", body);
}

test "Queue markDeferredWithPolicy converts retry delay to absolute queue time" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    _ = q.dequeue();

    const before = std.time.timestamp();
    q.markDeferredWithPolicy(id, "temp failure", .{
        .max_attempts = 3,
        .initial_delay_ms = 1500,
        .max_delay_ms = 1500,
    });
    const after = std.time.timestamp();

    const msg = q.findById(id).?;
    try std.testing.expectEqual(MessageStatus.deferred, msg.status);
    try std.testing.expectEqual(@as(u32, 1), msg.attempts);
    try std.testing.expect(msg.next_retry_at >= before + 2);
    try std.testing.expect(msg.next_retry_at <= after + 2);
}

test "Queue markDeferredWithPolicy marks exhausted retries as failed" {
    const allocator = std.testing.allocator;
    var q = Queue.init(allocator, .{});
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    const msg = q.dequeue().?;
    msg.attempts = 2;

    q.markDeferredWithPolicy(id, "still failing", .{
        .max_attempts = 2,
        .initial_delay_ms = 1000,
        .max_delay_ms = 1000,
    });

    try std.testing.expectEqual(MessageStatus.failed, q.getStatus(id).?);
}
