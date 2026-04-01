const std = @import("std");
const queue_mod = @import("queue.zig");

const MessageStatus = queue_mod.MessageStatus;

pub const PersistentQueueOptions = struct {
    base_path: []const u8 = ".smtp-queue",
    max_queue_size: usize = 10000,
    default_max_attempts: u32 = 5,
};

pub const PersistedMessage = struct {
    id: u64,
    from: []u8,
    recipients: [][]u8,
    body_path: []u8,
    status: MessageStatus,
    attempts: u32,
    max_attempts: u32,
    created_at: i64,
    next_retry_at: i64,
    last_error: ?[]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PersistedMessage) void {
        self.allocator.free(self.from);
        for (self.recipients) |r| self.allocator.free(r);
        self.allocator.free(self.recipients);
        self.allocator.free(self.body_path);
        if (self.last_error) |e| self.allocator.free(e);
    }

    pub fn readBodyAlloc(self: *const PersistedMessage, allocator: std.mem.Allocator) ![]u8 {
        const stat = try std.fs.cwd().statFile(self.body_path);
        return try std.fs.cwd().readFileAlloc(allocator, self.body_path, @intCast(stat.size));
    }
};

pub const PersistentQueue = struct {
    allocator: std.mem.Allocator,
    base_path: []const u8,
    options: PersistentQueueOptions,
    next_id: u64,
    mutex: std.Thread.Mutex,

    const status_dirs = [_][]const u8{ "pending", "deferred", "failed", "sent" };

    pub fn init(allocator: std.mem.Allocator, options: PersistentQueueOptions) PersistentQueue {
        return .{
            .allocator = allocator,
            .base_path = options.base_path,
            .options = options,
            .next_id = 1,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *PersistentQueue) void {
        _ = self;
    }

    /// Ensure all required subdirectories exist.
    fn ensureDirs(self: *PersistentQueue) !void {
        for (status_dirs) |dir| {
            const path = try std.fs.path.join(self.allocator, &.{ self.base_path, dir });
            defer self.allocator.free(path);
            try std.fs.cwd().makePath(path);
        }
    }

    /// Enqueue a message, writing it to disk immediately. Returns the assigned ID.
    pub fn enqueue(self: *PersistentQueue, from: []const u8, recipients: []const []const u8, body: []const u8) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check queue size
        const count = try self.pendingCountLocked();
        if (count >= self.options.max_queue_size) return error.QueueFull;

        const id = self.next_id;
        self.next_id += 1;

        try self.ensureDirs();

        // Create message directory: <base>/pending/<id>/
        const id_str = try std.fmt.allocPrint(self.allocator, "{d}", .{id});
        defer self.allocator.free(id_str);
        const msg_dir = try std.fs.path.join(self.allocator, &.{ self.base_path, "pending", id_str });
        defer self.allocator.free(msg_dir);
        try std.fs.cwd().makePath(msg_dir);

        // Write body.eml
        const body_path = try std.fs.path.join(self.allocator, &.{ msg_dir, "body.eml" });
        defer self.allocator.free(body_path);
        const body_file = try std.fs.cwd().createFile(body_path, .{ .truncate = true });
        defer body_file.close();
        try body_file.writeAll(body);

        // Write envelope.txt
        const envelope_path = try std.fs.path.join(self.allocator, &.{ msg_dir, "envelope.txt" });
        defer self.allocator.free(envelope_path);

        const now = std.time.timestamp();
        const recipients_joined = try joinRecipients(self.allocator, recipients);
        defer self.allocator.free(recipients_joined);

        const envelope_content = try std.fmt.allocPrint(self.allocator,
            \\id={d}
            \\from={s}
            \\recipients={s}
            \\status=pending
            \\attempts=0
            \\max_attempts={d}
            \\created_at={d}
            \\next_retry_at=0
            \\last_error=
        , .{ id, from, recipients_joined, self.options.default_max_attempts, now });
        defer self.allocator.free(envelope_content);

        const env_file = try std.fs.cwd().createFile(envelope_path, .{ .truncate = true });
        defer env_file.close();
        try env_file.writeAll(envelope_content);

        return id;
    }

    /// Get the next pending message ready for delivery.
    pub fn dequeue(self: *PersistentQueue) !?PersistedMessage {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();

        // Check pending directory
        if (try self.dequeueFromDir("pending", now)) |msg| return msg;
        // Check deferred directory
        if (try self.dequeueFromDir("deferred", now)) |msg| return msg;

        return null;
    }

    fn dequeueFromDir(self: *PersistentQueue, status_dir: []const u8, now: i64) !?PersistedMessage {
        const dir_path = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir });
        defer self.allocator.free(dir_path);

        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;

            const envelope_path = try std.fs.path.join(self.allocator, &.{ dir_path, entry.name, "envelope.txt" });
            defer self.allocator.free(envelope_path);

            var msg = try self.readEnvelope(envelope_path, dir_path, entry.name);
            errdefer msg.deinit();

            if (msg.status == .pending or (msg.status == .deferred and msg.next_retry_at <= now)) {
                // Update status to sending on disk
                msg.status = .sending;
                try self.writeEnvelopeFromMessage(&msg);
                return msg;
            } else {
                msg.deinit();
            }
        }
        return null;
    }

    /// Mark a message as sent - move to sent directory.
    pub fn markSent(self: *PersistentQueue, id: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.moveMessage(id, "sent", null, null);
    }

    /// Mark a message as permanently failed.
    pub fn markFailed(self: *PersistentQueue, id: u64, error_msg: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.moveMessage(id, "failed", error_msg, null);
    }

    /// Mark a message as deferred with a next retry time.
    pub fn markDeferred(self: *PersistentQueue, id: u64, error_msg: []const u8, next_retry: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.moveMessage(id, "deferred", error_msg, next_retry);
    }

    /// Count pending/deferred messages by scanning disk.
    pub fn pendingCount(self: *PersistentQueue) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return try self.pendingCountLocked();
    }

    fn pendingCountLocked(self: *PersistentQueue) !usize {
        var count: usize = 0;
        const dirs_to_check = [_][]const u8{ "pending", "deferred" };
        for (dirs_to_check) |status_dir| {
            const dir_path = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir });
            defer self.allocator.free(dir_path);

            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind == .directory) count += 1;
            }
        }
        return count;
    }

    /// Remove expired/exhausted messages (failed with attempts >= max_attempts).
    pub fn removeExpired(self: *PersistentQueue) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var removed: usize = 0;
        const dirs_to_check = [_][]const u8{ "failed", "deferred" };

        for (dirs_to_check) |status_dir| {
            const dir_path = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir });
            defer self.allocator.free(dir_path);

            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            defer dir.close();

            // Collect entries first since we modify the directory during iteration
            var entries: std.ArrayList([]u8) = .empty;
            defer {
                for (entries.items) |e| self.allocator.free(e);
                entries.deinit(self.allocator);
            }

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind == .directory) {
                    try entries.append(self.allocator, try self.allocator.dupe(u8, entry.name));
                }
            }

            for (entries.items) |entry_name| {
                const envelope_path = try std.fs.path.join(self.allocator, &.{ dir_path, entry_name, "envelope.txt" });
                defer self.allocator.free(envelope_path);

                var msg = self.readEnvelope(envelope_path, dir_path, entry_name) catch continue;
                defer msg.deinit();

                if ((msg.status == .failed or msg.status == .deferred) and msg.attempts >= msg.max_attempts) {
                    const msg_dir = try std.fs.path.join(self.allocator, &.{ dir_path, entry_name });
                    defer self.allocator.free(msg_dir);
                    deleteDirectory(msg_dir) catch {};
                    removed += 1;
                }
            }
        }
        return removed;
    }

    /// Recover queue state from disk on startup. Returns the number of recovered messages.
    pub fn recover(self: *PersistentQueue) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        var max_id: u64 = 0;

        for (status_dirs) |status_dir| {
            const dir_path = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir });
            defer self.allocator.free(dir_path);

            var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| {
                if (err == error.FileNotFound) continue;
                return err;
            };
            defer dir.close();

            var iter = dir.iterate();
            while (try iter.next()) |entry| {
                if (entry.kind != .directory) continue;

                const envelope_path = try std.fs.path.join(self.allocator, &.{ dir_path, entry.name, "envelope.txt" });
                defer self.allocator.free(envelope_path);

                var msg = self.readEnvelope(envelope_path, dir_path, entry.name) catch continue;
                defer msg.deinit();

                if (msg.id >= max_id) max_id = msg.id;

                // Reset "sending" messages back to pending
                if (msg.status == .sending) {
                    msg.status = .pending;
                    // Move back to pending directory
                    const id_str = try std.fmt.allocPrint(self.allocator, "{d}", .{msg.id});
                    defer self.allocator.free(id_str);
                    const src_dir = try std.fs.path.join(self.allocator, &.{ dir_path, entry.name });
                    defer self.allocator.free(src_dir);
                    const dst_dir = try std.fs.path.join(self.allocator, &.{ self.base_path, "pending", id_str });
                    defer self.allocator.free(dst_dir);

                    if (!std.mem.eql(u8, src_dir, dst_dir)) {
                        std.fs.cwd().rename(src_dir, dst_dir) catch {};
                    }
                    // Update envelope on disk
                    const new_envelope_path = try std.fs.path.join(self.allocator, &.{ self.base_path, "pending", id_str, "envelope.txt" });
                    defer self.allocator.free(new_envelope_path);
                    self.writeEnvelopeToPath(new_envelope_path, &msg) catch {};
                }

                count += 1;
            }
        }

        if (max_id >= self.next_id) {
            self.next_id = max_id + 1;
        }

        return count;
    }

    /// Get the status of a message by ID.
    pub fn getStatus(self: *PersistentQueue, id: u64) !?MessageStatus {
        self.mutex.lock();
        defer self.mutex.unlock();

        const id_str = try std.fmt.allocPrint(self.allocator, "{d}", .{id});
        defer self.allocator.free(id_str);

        for (status_dirs) |status_dir| {
            const envelope_path = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir, id_str, "envelope.txt" });
            defer self.allocator.free(envelope_path);

            var msg = self.readEnvelope(envelope_path, "", id_str) catch continue;
            defer msg.deinit();
            return msg.status;
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn moveMessage(self: *PersistentQueue, id: u64, target_status: []const u8, error_msg: ?[]const u8, next_retry: ?i64) !void {
        try self.ensureDirs();

        const id_str = try std.fmt.allocPrint(self.allocator, "{d}", .{id});
        defer self.allocator.free(id_str);

        // Find the message in any status directory
        var source_dir: ?[]u8 = null;
        defer if (source_dir) |sd| self.allocator.free(sd);

        for (status_dirs) |status_dir| {
            const msg_dir = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir, id_str });
            defer self.allocator.free(msg_dir);
            std.fs.cwd().access(msg_dir, .{}) catch continue;
            source_dir = try std.fs.path.join(self.allocator, &.{ self.base_path, status_dir });
            break;
        }

        const src_status_dir = source_dir orelse return error.MessageNotFound;

        // Read current envelope
        const src_envelope_path = try std.fs.path.join(self.allocator, &.{ src_status_dir, id_str, "envelope.txt" });
        defer self.allocator.free(src_envelope_path);
        var msg = try self.readEnvelope(src_envelope_path, src_status_dir, id_str);
        defer msg.deinit();

        // Update message fields
        msg.status = statusFromString(target_status);
        msg.attempts += 1;
        if (error_msg) |e| {
            if (msg.last_error) |old| self.allocator.free(old);
            msg.last_error = try self.allocator.dupe(u8, e);
        }
        if (next_retry) |nr| {
            msg.next_retry_at = nr;
        }

        // Move directory
        const src_msg_dir = try std.fs.path.join(self.allocator, &.{ src_status_dir, id_str });
        defer self.allocator.free(src_msg_dir);
        const dst_msg_dir = try std.fs.path.join(self.allocator, &.{ self.base_path, target_status, id_str });
        defer self.allocator.free(dst_msg_dir);

        if (!std.mem.eql(u8, src_msg_dir, dst_msg_dir)) {
            try std.fs.cwd().rename(src_msg_dir, dst_msg_dir);
        }

        // Rewrite envelope
        const dst_envelope_path = try std.fs.path.join(self.allocator, &.{ dst_msg_dir, "envelope.txt" });
        defer self.allocator.free(dst_envelope_path);

        // Update body_path in msg for the new location
        const new_body_path = try std.fs.path.join(self.allocator, &.{ dst_msg_dir, "body.eml" });
        defer self.allocator.free(new_body_path);
        self.allocator.free(msg.body_path);
        msg.body_path = try self.allocator.dupe(u8, new_body_path);

        try self.writeEnvelopeToPath(dst_envelope_path, &msg);
    }

    fn readEnvelope(self: *PersistentQueue, envelope_path: []const u8, dir_path: []const u8, entry_name: []const u8) !PersistedMessage {
        _ = dir_path;
        const stat = try std.fs.cwd().statFile(envelope_path);
        const content = try std.fs.cwd().readFileAlloc(self.allocator, envelope_path, @intCast(stat.size));
        defer self.allocator.free(content);

        return try parseEnvelope(self.allocator, content, self.base_path, entry_name);
    }

    fn writeEnvelopeFromMessage(self: *PersistentQueue, msg: *PersistedMessage) !void {
        // Derive envelope path from body_path by replacing body.eml with envelope.txt
        const dir = std.fs.path.dirname(msg.body_path) orelse return error.InvalidPath;
        const envelope_path = try std.fs.path.join(self.allocator, &.{ dir, "envelope.txt" });
        defer self.allocator.free(envelope_path);
        try self.writeEnvelopeToPath(envelope_path, msg);
    }

    fn writeEnvelopeToPath(self: *PersistentQueue, path: []const u8, msg: *const PersistedMessage) !void {
        const recipients_joined = try joinRecipientsOwned(self.allocator, msg.recipients);
        defer self.allocator.free(recipients_joined);

        const last_err = msg.last_error orelse "";

        const envelope_content = try std.fmt.allocPrint(self.allocator,
            \\id={d}
            \\from={s}
            \\recipients={s}
            \\status={s}
            \\attempts={d}
            \\max_attempts={d}
            \\created_at={d}
            \\next_retry_at={d}
            \\last_error={s}
        , .{
            msg.id,
            msg.from,
            recipients_joined,
            statusToString(msg.status),
            msg.attempts,
            msg.max_attempts,
            msg.created_at,
            msg.next_retry_at,
            last_err,
        });
        defer self.allocator.free(envelope_content);

        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(envelope_content);
    }

    fn deleteDirectory(path: []const u8) !void {
        var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .directory) {
                const sub_path = std.fs.path.join(std.heap.page_allocator, &.{ path, entry.name }) catch continue;
                defer std.heap.page_allocator.free(sub_path);
                deleteDirectory(sub_path) catch {};
            } else {
                dir.deleteFile(entry.name) catch {};
            }
        }
        dir.close();
        try std.fs.cwd().deleteDir(path);
    }
};

// -----------------------------------------------------------------------
// Envelope parsing helpers
// -----------------------------------------------------------------------

fn parseEnvelope(allocator: std.mem.Allocator, content: []const u8, base_path: []const u8, entry_name: []const u8) !PersistedMessage {
    var id: u64 = 0;
    var from: ?[]u8 = null;
    errdefer if (from) |f| allocator.free(f);
    var recipients: ?[][]u8 = null;
    errdefer if (recipients) |rs| {
        for (rs) |r| allocator.free(r);
        allocator.free(rs);
    };
    var status: MessageStatus = .pending;
    var attempts: u32 = 0;
    var max_attempts: u32 = 5;
    var created_at: i64 = 0;
    var next_retry_at: i64 = 0;
    var last_error: ?[]u8 = null;
    errdefer if (last_error) |e| allocator.free(e);

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
            const key = line[0..eq_pos];
            const value = line[eq_pos + 1 ..];

            if (std.mem.eql(u8, key, "id")) {
                id = std.fmt.parseInt(u64, value, 10) catch 0;
            } else if (std.mem.eql(u8, key, "from")) {
                from = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "recipients")) {
                recipients = try parseRecipients(allocator, value);
            } else if (std.mem.eql(u8, key, "status")) {
                status = statusFromString(value);
            } else if (std.mem.eql(u8, key, "attempts")) {
                attempts = std.fmt.parseInt(u32, value, 10) catch 0;
            } else if (std.mem.eql(u8, key, "max_attempts")) {
                max_attempts = std.fmt.parseInt(u32, value, 10) catch 5;
            } else if (std.mem.eql(u8, key, "created_at")) {
                created_at = std.fmt.parseInt(i64, value, 10) catch 0;
            } else if (std.mem.eql(u8, key, "next_retry_at")) {
                next_retry_at = std.fmt.parseInt(i64, value, 10) catch 0;
            } else if (std.mem.eql(u8, key, "last_error")) {
                if (value.len > 0) {
                    last_error = try allocator.dupe(u8, value);
                }
            }
        }
    }

    // Determine the status directory from the parsed status
    const status_dir = statusToDir(status);

    const body_path = try std.fs.path.join(allocator, &.{ base_path, status_dir, entry_name, "body.eml" });
    errdefer allocator.free(body_path);

    return .{
        .id = id,
        .from = from orelse return error.InvalidEnvelope,
        .recipients = recipients orelse return error.InvalidEnvelope,
        .body_path = body_path,
        .status = status,
        .attempts = attempts,
        .max_attempts = max_attempts,
        .created_at = created_at,
        .next_retry_at = next_retry_at,
        .last_error = last_error,
        .allocator = allocator,
    };
}

fn parseRecipients(allocator: std.mem.Allocator, value: []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, value, ',');
    while (iter.next()) |r| {
        if (r.len > 0) {
            try list.append(allocator, try allocator.dupe(u8, r));
        }
    }
    return try list.toOwnedSlice(allocator);
}

fn joinRecipients(allocator: std.mem.Allocator, recipients: []const []const u8) ![]u8 {
    if (recipients.len == 0) return try allocator.dupe(u8, "");

    var total_len: usize = 0;
    for (recipients) |r| total_len += r.len;
    total_len += recipients.len - 1; // commas

    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (recipients, 0..) |r, i| {
        @memcpy(result[pos .. pos + r.len], r);
        pos += r.len;
        if (i < recipients.len - 1) {
            result[pos] = ',';
            pos += 1;
        }
    }
    return result;
}

fn joinRecipientsOwned(allocator: std.mem.Allocator, recipients: []const []u8) ![]u8 {
    if (recipients.len == 0) return try allocator.dupe(u8, "");

    var total_len: usize = 0;
    for (recipients) |r| total_len += r.len;
    total_len += recipients.len - 1;

    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (recipients, 0..) |r, i| {
        @memcpy(result[pos .. pos + r.len], r);
        pos += r.len;
        if (i < recipients.len - 1) {
            result[pos] = ',';
            pos += 1;
        }
    }
    return result;
}

fn statusToString(status: MessageStatus) []const u8 {
    return switch (status) {
        .pending => "pending",
        .sending => "sending",
        .sent => "sent",
        .failed => "failed",
        .deferred => "deferred",
    };
}

/// Map a status to the directory it lives in on disk.
fn statusToDir(status: MessageStatus) []const u8 {
    return switch (status) {
        .pending, .sending => "pending", // sending messages stay in the pending directory
        .sent => "sent",
        .failed => "failed",
        .deferred => "deferred",
    };
}

fn statusFromString(s: []const u8) MessageStatus {
    if (std.mem.eql(u8, s, "pending")) return .pending;
    if (std.mem.eql(u8, s, "sending")) return .sending;
    if (std.mem.eql(u8, s, "sent")) return .sent;
    if (std.mem.eql(u8, s, "failed")) return .failed;
    if (std.mem.eql(u8, s, "deferred")) return .deferred;
    return .pending;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn cleanupTestDir(path: []const u8) void {
    std.fs.cwd().deleteTree(path) catch {};
}

test "PersistentQueue enqueue and dequeue round-trip" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-roundtrip";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{
        .base_path = test_path,
        .max_queue_size = 100,
        .default_max_attempts = 5,
    });
    defer q.deinit();

    const recipients = &[_][]const u8{ "bob@example.com", "carol@example.com" };
    const id = try q.enqueue("alice@example.com", recipients, "Hello, world!");

    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(usize, 1), try q.pendingCount());

    var msg = (try q.dequeue()).?;
    defer msg.deinit();

    try std.testing.expectEqualStrings("alice@example.com", msg.from);
    try std.testing.expectEqual(@as(usize, 2), msg.recipients.len);
    try std.testing.expectEqualStrings("bob@example.com", msg.recipients[0]);
    try std.testing.expectEqualStrings("carol@example.com", msg.recipients[1]);

    const body = try msg.readBodyAlloc(allocator);
    defer allocator.free(body);
    try std.testing.expectEqualStrings("Hello, world!", body);
}

test "PersistentQueue persistence and recovery" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-recovery";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    // Enqueue with first queue instance
    {
        var q = PersistentQueue.init(allocator, .{
            .base_path = test_path,
            .default_max_attempts = 5,
        });
        defer q.deinit();
        _ = try q.enqueue("alice@example.com", &[_][]const u8{"bob@example.com"}, "Message 1");
        _ = try q.enqueue("carol@example.com", &[_][]const u8{"dave@example.com"}, "Message 2");
    }

    // Create new queue and recover
    {
        var q2 = PersistentQueue.init(allocator, .{
            .base_path = test_path,
            .default_max_attempts = 5,
        });
        defer q2.deinit();

        const recovered = try q2.recover();
        try std.testing.expectEqual(@as(usize, 2), recovered);
        try std.testing.expectEqual(@as(u64, 3), q2.next_id); // next_id should be max+1

        // Should be able to dequeue both
        var msg1 = (try q2.dequeue()).?;
        defer msg1.deinit();
        var msg2 = (try q2.dequeue()).?;
        defer msg2.deinit();

        // Verify we got both (order not guaranteed with directory iteration)
        const got_alice = std.mem.eql(u8, msg1.from, "alice@example.com") or std.mem.eql(u8, msg2.from, "alice@example.com");
        const got_carol = std.mem.eql(u8, msg1.from, "carol@example.com") or std.mem.eql(u8, msg2.from, "carol@example.com");
        try std.testing.expect(got_alice);
        try std.testing.expect(got_carol);
    }
}

test "PersistentQueue markSent" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-sent";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{ .base_path = test_path });
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    var msg = (try q.dequeue()).?;
    msg.deinit();

    try q.markSent(id);

    const status = try q.getStatus(id);
    try std.testing.expectEqual(MessageStatus.sent, status.?);
    try std.testing.expectEqual(@as(usize, 0), try q.pendingCount());
}

test "PersistentQueue markFailed" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-failed";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{ .base_path = test_path });
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    var msg = (try q.dequeue()).?;
    msg.deinit();

    try q.markFailed(id, "connection refused");

    const status = try q.getStatus(id);
    try std.testing.expectEqual(MessageStatus.failed, status.?);
}

test "PersistentQueue markDeferred" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-deferred";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{ .base_path = test_path });
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    var msg = (try q.dequeue()).?;
    msg.deinit();

    const future_time = std.time.timestamp() + 3600;
    try q.markDeferred(id, "temp failure", future_time);

    const status = try q.getStatus(id);
    try std.testing.expectEqual(MessageStatus.deferred, status.?);
    // Still counts as pending
    try std.testing.expectEqual(@as(usize, 1), try q.pendingCount());
}

test "PersistentQueue removeExpired" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-expired";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{
        .base_path = test_path,
        .default_max_attempts = 2,
    });
    defer q.deinit();

    const id = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "body");
    var msg = (try q.dequeue()).?;
    msg.deinit();

    // Mark failed twice to exhaust attempts
    try q.markFailed(id, "err1");
    // markFailed increments attempts. After first call: attempts=1. Need attempts >= max_attempts=2
    // Re-read and mark failed again. But markFailed moves to failed dir and increments.
    // After first markFailed: attempts=1, status=failed
    // After second markFailed: attempts=2, status=failed
    try q.markFailed(id, "err2");

    const removed = try q.removeExpired();
    try std.testing.expectEqual(@as(usize, 1), removed);

    const status = try q.getStatus(id);
    try std.testing.expect(status == null);
}

test "PersistentQueue max queue size enforcement" {
    const allocator = std.testing.allocator;
    const test_path = ".smtp-queue-test-maxsize";
    cleanupTestDir(test_path);
    defer cleanupTestDir(test_path);

    var q = PersistentQueue.init(allocator, .{
        .base_path = test_path,
        .max_queue_size = 2,
    });
    defer q.deinit();

    _ = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "1");
    _ = try q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "2");

    const result = q.enqueue("a@b.com", &[_][]const u8{"c@d.com"}, "3");
    try std.testing.expectError(error.QueueFull, result);
}
