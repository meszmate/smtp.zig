const std = @import("std");

/// Immutable transaction metadata exposed to streaming handlers.
pub const Envelope = struct {
    from: []const u8,
    recipients: []const []u8,
    username: ?[]const u8 = null,
    client_domain: ?[]const u8 = null,
    is_tls: bool = false,
};

/// A sink for incrementally receiving a message body.
pub const MessageStream = struct {
    context: *anyopaque,
    write_fn: *const fn (ctx: *anyopaque, chunk: []const u8) anyerror!void,
    finish_fn: *const fn (ctx: *anyopaque) anyerror!void,
    abort_fn: *const fn (ctx: *anyopaque) void,

    pub fn write(self: MessageStream, chunk: []const u8) !void {
        try self.write_fn(self.context, chunk);
    }

    pub fn finish(self: MessageStream) !void {
        try self.finish_fn(self.context);
    }

    pub fn abort(self: MessageStream) void {
        self.abort_fn(self.context);
    }
};

/// Opens a streaming sink for a single SMTP transaction.
pub const MessageStreamFactory = struct {
    context: *anyopaque,
    open_fn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, envelope: Envelope) anyerror!MessageStream,

    pub fn open(self: MessageStreamFactory, allocator: std.mem.Allocator, envelope: Envelope) !MessageStream {
        return try self.open_fn(self.context, allocator, envelope);
    }
};
