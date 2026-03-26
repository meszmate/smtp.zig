const std = @import("std");
const smtp = @import("root.zig");
const memstore = @import("store/memstore.zig");
const wire = @import("wire/root.zig");

/// Harness provides an in-process SMTP server and client for integration testing.
/// It uses a pair of connected transports so no real TCP is needed.
pub const Harness = struct {
    allocator: std.mem.Allocator,
    store: memstore.MemStore,
    server_transport: PipeTransport,
    client_transport: PipeTransport,

    pub fn init(allocator: std.mem.Allocator) Harness {
        const pipe = PipePair.init(allocator);
        return .{
            .allocator = allocator,
            .store = memstore.MemStore.init(allocator),
            .server_transport = pipe.server,
            .client_transport = pipe.client,
        };
    }

    pub fn deinit(self: *Harness) void {
        self.server_transport.deinit();
        self.client_transport.deinit();
        self.store.deinit();
    }

    pub fn addUser(self: *Harness, username: []const u8, password: []const u8) !void {
        try self.store.addUser(username, password);
    }

    pub fn getUser(self: *Harness, username: []const u8) ?*memstore.User {
        return self.store.users.get(username);
    }

    pub fn writeClientLine(self: *Harness, line: []const u8) !void {
        const t = self.client_transport.transport();
        try t.writeAll(line);
    }

    pub fn serverOutput(self: *Harness) []const u8 {
        return self.server_transport.output.items;
    }
};

const PipePair = struct {
    server: PipeTransport,
    client: PipeTransport,

    fn init(allocator: std.mem.Allocator) PipePair {
        return .{
            .server = PipeTransport.init(allocator),
            .client = PipeTransport.init(allocator),
        };
    }
};

/// PipeTransport is a simple in-memory transport for testing.
pub const PipeTransport = struct {
    allocator: std.mem.Allocator,
    input: std.ArrayList(u8) = .empty,
    output: std.ArrayList(u8) = .empty,
    read_pos: usize = 0,

    pub fn init(allocator: std.mem.Allocator) PipeTransport {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PipeTransport) void {
        self.input.deinit(self.allocator);
        self.output.deinit(self.allocator);
    }

    pub fn feedInput(self: *PipeTransport, data: []const u8) !void {
        try self.input.appendSlice(self.allocator, data);
    }

    pub fn transport(self: *PipeTransport) wire.Transport {
        return .{
            .context = @ptrCast(self),
            .read_fn = readFn,
            .write_fn = writeFn,
            .close_fn = closeFn,
        };
    }

    fn readFn(ctx: *anyopaque, buffer: []u8) wire.Transport.ReadError!usize {
        const self: *PipeTransport = @ptrCast(@alignCast(ctx));
        if (self.read_pos >= self.input.items.len) return 0;
        const available = self.input.items[self.read_pos..];
        const to_read = @min(buffer.len, available.len);
        @memcpy(buffer[0..to_read], available[0..to_read]);
        self.read_pos += to_read;
        return to_read;
    }

    fn writeFn(ctx: *anyopaque, data: []const u8) wire.Transport.WriteError!usize {
        const self: *PipeTransport = @ptrCast(@alignCast(ctx));
        self.output.appendSlice(self.allocator, data) catch return error.Unexpected;
        return data.len;
    }

    fn closeFn(_: *anyopaque) void {}
};

/// MockSession provides a minimal mock session for testing.
pub const MockSession = struct {
    connected: bool = false,
    authenticated: bool = false,
    username: ?[]const u8 = null,
    from: ?[]const u8 = null,
    recipients: std.ArrayList([]const u8) = .empty,
    message_body: ?[]const u8 = null,
    closed: bool = false,

    pub fn connect(self: *MockSession) void {
        self.connected = true;
    }

    pub fn authenticate(self: *MockSession, user: []const u8) void {
        self.authenticated = true;
        self.username = user;
    }

    pub fn setFrom(self: *MockSession, from: []const u8) void {
        self.from = from;
    }

    pub fn close(self: *MockSession) void {
        self.closed = true;
    }
};
