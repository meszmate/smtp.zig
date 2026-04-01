const std = @import("std");

/// Log severity levels.
pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
    fatal = 4,

    pub fn label(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }
};

/// A structured log entry.
pub const Entry = struct {
    level: Level,
    message: []const u8,
    timestamp_ms: i64,
    /// Optional structured fields as key-value pairs.
    fields: []const Field = &.{},
};

pub const Field = struct {
    key: []const u8,
    value: []const u8,
};

/// Log output backend interface.
pub const Writer = struct {
    context: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, entry: Entry) void,

    pub fn write(self: Writer, entry: Entry) void {
        self.write_fn(self.context, entry);
    }
};

/// The main logger.
pub const Logger = struct {
    allocator: std.mem.Allocator,
    min_level: Level = .info,
    writers: std.ArrayList(Writer),
    /// Prefix fields added to every log entry.
    prefix_fields: std.ArrayList(Field),

    pub fn init(allocator: std.mem.Allocator) Logger {
        return .{
            .allocator = allocator,
            .writers = .empty,
            .prefix_fields = .empty,
        };
    }

    pub fn deinit(self: *Logger) void {
        self.writers.deinit(self.allocator);
        self.prefix_fields.deinit(self.allocator);
    }

    /// Add an output writer.
    pub fn addWriter(self: *Logger, writer: Writer) !void {
        try self.writers.append(self.allocator, writer);
    }

    /// Set minimum log level.
    pub fn setLevel(self: *Logger, level: Level) void {
        self.min_level = level;
    }

    /// Add a prefix field to all future log entries.
    pub fn addField(self: *Logger, key: []const u8, value: []const u8) !void {
        try self.prefix_fields.append(self.allocator, .{ .key = key, .value = value });
    }

    /// Log a message at the given level.
    pub fn log(self: *Logger, level: Level, message: []const u8, fields: []const Field) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;

        const entry = Entry{
            .level = level,
            .message = message,
            .timestamp_ms = std.time.milliTimestamp(),
            .fields = fields,
        };

        for (self.writers.items) |writer| {
            writer.write(entry);
        }
    }

    // Convenience methods
    pub fn debug(self: *Logger, msg: []const u8, fields: []const Field) void {
        self.log(.debug, msg, fields);
    }
    pub fn info(self: *Logger, msg: []const u8, fields: []const Field) void {
        self.log(.info, msg, fields);
    }
    pub fn warn(self: *Logger, msg: []const u8, fields: []const Field) void {
        self.log(.warn, msg, fields);
    }
    pub fn err(self: *Logger, msg: []const u8, fields: []const Field) void {
        self.log(.err, msg, fields);
    }
};

/// Built-in writer: writes to stderr in a human-readable format.
pub const StderrWriter = struct {
    var instance: StderrWriter = .{};

    pub fn writer() Writer {
        return .{
            .context = @ptrCast(&instance),
            .write_fn = writeFn,
        };
    }

    fn writeFn(_: *anyopaque, entry: Entry) void {
        const ts = formatTimestamp(entry.timestamp_ms);
        std.debug.print("{s} [{s}] {s}", .{
            @as([]const u8, &ts),
            entry.level.label(),
            entry.message,
        });
        for (entry.fields) |field| {
            std.debug.print(" {s}={s}", .{ field.key, field.value });
        }
        std.debug.print("\n", .{});
    }

    fn formatTimestamp(ms: i64) [23]u8 {
        // Format as "YYYY-MM-DD HH:MM:SS.mmm"
        var buf: [23]u8 = undefined;
        const secs: u64 = @intCast(@divTrunc(ms, 1000));
        const millis: u64 = @intCast(@mod(ms, 1000));
        const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
        const day = epoch.getEpochDay();
        const yd = day.calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = epoch.getDaySeconds();
        _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}", .{
            yd.year,
            md.month.numeric(),
            @as(u8, md.day_index) + 1,
            ds.getHoursIntoDay(),
            ds.getMinutesIntoHour(),
            ds.getSecondsIntoMinute(),
            millis,
        }) catch {};
        return buf;
    }
};

/// Built-in writer: buffers entries in memory (useful for testing).
pub const BufferWriter = struct {
    entries: std.ArrayList(StoredEntry),
    allocator: std.mem.Allocator,

    pub const StoredEntry = struct {
        level: Level,
        message: []u8,
        timestamp_ms: i64,
    };

    pub fn init(allocator: std.mem.Allocator) BufferWriter {
        return .{
            .entries = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BufferWriter) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.message);
        }
        self.entries.deinit(self.allocator);
    }

    pub fn writer(self: *BufferWriter) Writer {
        return .{
            .context = @ptrCast(self),
            .write_fn = writeFn,
        };
    }

    fn writeFn(ctx: *anyopaque, entry: Entry) void {
        const self: *BufferWriter = @ptrCast(@alignCast(ctx));
        const msg = self.allocator.dupe(u8, entry.message) catch return;
        self.entries.append(self.allocator, .{
            .level = entry.level,
            .message = msg,
            .timestamp_ms = entry.timestamp_ms,
        }) catch {
            self.allocator.free(msg);
        };
    }

    pub fn count(self: *const BufferWriter) usize {
        return self.entries.items.len;
    }

    pub fn clear(self: *BufferWriter) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.message);
        }
        self.entries.clearRetainingCapacity();
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

test "logger with buffer writer captures entries" {
    const allocator = std.testing.allocator;
    var buf = BufferWriter.init(allocator);
    defer buf.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    try logger.addWriter(buf.writer());

    logger.info("hello world", &.{});
    try std.testing.expectEqual(@as(usize, 1), buf.count());
    try std.testing.expectEqualStrings("hello world", buf.entries.items[0].message);
    try std.testing.expectEqual(Level.info, buf.entries.items[0].level);
}

test "level filtering works" {
    const allocator = std.testing.allocator;
    var buf = BufferWriter.init(allocator);
    defer buf.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    logger.setLevel(.warn);
    try logger.addWriter(buf.writer());

    logger.debug("should be filtered", &.{});
    logger.info("should be filtered", &.{});
    logger.warn("should pass", &.{});
    logger.err("should pass", &.{});

    try std.testing.expectEqual(@as(usize, 2), buf.count());
    try std.testing.expectEqualStrings("should pass", buf.entries.items[0].message);
    try std.testing.expectEqual(Level.warn, buf.entries.items[0].level);
    try std.testing.expectEqual(Level.err, buf.entries.items[1].level);
}

test "multiple writers receive same entry" {
    const allocator = std.testing.allocator;
    var buf1 = BufferWriter.init(allocator);
    defer buf1.deinit();
    var buf2 = BufferWriter.init(allocator);
    defer buf2.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    try logger.addWriter(buf1.writer());
    try logger.addWriter(buf2.writer());

    logger.info("broadcast", &.{});

    try std.testing.expectEqual(@as(usize, 1), buf1.count());
    try std.testing.expectEqual(@as(usize, 1), buf2.count());
    try std.testing.expectEqualStrings("broadcast", buf1.entries.items[0].message);
    try std.testing.expectEqualStrings("broadcast", buf2.entries.items[0].message);
}

test "convenience methods log at correct levels" {
    const allocator = std.testing.allocator;
    var buf = BufferWriter.init(allocator);
    defer buf.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    logger.setLevel(.debug);
    try logger.addWriter(buf.writer());

    logger.debug("d", &.{});
    logger.info("i", &.{});
    logger.warn("w", &.{});
    logger.err("e", &.{});

    try std.testing.expectEqual(@as(usize, 4), buf.count());
    try std.testing.expectEqual(Level.debug, buf.entries.items[0].level);
    try std.testing.expectEqual(Level.info, buf.entries.items[1].level);
    try std.testing.expectEqual(Level.warn, buf.entries.items[2].level);
    try std.testing.expectEqual(Level.err, buf.entries.items[3].level);
}

test "buffer writer count and clear" {
    const allocator = std.testing.allocator;
    var buf = BufferWriter.init(allocator);
    defer buf.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    try logger.addWriter(buf.writer());

    logger.info("one", &.{});
    logger.info("two", &.{});
    logger.info("three", &.{});

    try std.testing.expectEqual(@as(usize, 3), buf.count());

    buf.clear();
    try std.testing.expectEqual(@as(usize, 0), buf.count());

    // Ensure we can still log after clearing.
    logger.info("four", &.{});
    try std.testing.expectEqual(@as(usize, 1), buf.count());
    try std.testing.expectEqualStrings("four", buf.entries.items[0].message);
}

test "log with structured fields" {
    const allocator = std.testing.allocator;
    var buf = BufferWriter.init(allocator);
    defer buf.deinit();

    var logger = Logger.init(allocator);
    defer logger.deinit();
    try logger.addWriter(buf.writer());

    logger.info("connection opened", &.{
        .{ .key = "remote", .value = "127.0.0.1" },
        .{ .key = "port", .value = "25" },
    });

    try std.testing.expectEqual(@as(usize, 1), buf.count());
    try std.testing.expectEqualStrings("connection opened", buf.entries.items[0].message);
}

test "level labels" {
    try std.testing.expectEqualStrings("DEBUG", Level.debug.label());
    try std.testing.expectEqualStrings("INFO", Level.info.label());
    try std.testing.expectEqualStrings("WARN", Level.warn.label());
    try std.testing.expectEqualStrings("ERROR", Level.err.label());
    try std.testing.expectEqualStrings("FATAL", Level.fatal.label());
}

test "stderr writer format timestamp" {
    const buf = StderrWriter.formatTimestamp(1700000000000);
    try std.testing.expectEqualStrings("2023-11-14 22:13:20.000", &buf);
}
