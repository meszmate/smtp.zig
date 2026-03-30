const std = @import("std");

pub const Transport = struct {
    context: *anyopaque,
    read_fn: ReadFn,
    write_fn: WriteFn,
    close_fn: CloseFn,

    pub const ReadFn = *const fn (context: *anyopaque, buffer: []u8) ReadError!usize;
    pub const WriteFn = *const fn (context: *anyopaque, buffer: []const u8) WriteError!usize;
    pub const CloseFn = *const fn (context: *anyopaque) void;

    pub const ReadError = std.net.Stream.ReadError;
    pub const WriteError = std.net.Stream.WriteError;

    pub fn fromNetStream(stream: *std.net.Stream) Transport {
        return .{
            .context = @ptrCast(stream),
            .read_fn = netStreamRead,
            .write_fn = netStreamWrite,
            .close_fn = netStreamClose,
        };
    }

    pub fn read(self: Transport, buffer: []u8) ReadError!usize {
        return self.read_fn(self.context, buffer);
    }

    pub fn write(self: Transport, buffer: []const u8) WriteError!usize {
        return self.write_fn(self.context, buffer);
    }

    pub fn writeAll(self: Transport, buffer: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < buffer.len) {
            index += try self.write(buffer[index..]);
        }
    }

    pub fn close(self: Transport) void {
        self.close_fn(self.context);
    }

    pub fn print(self: Transport, comptime fmt: []const u8, args: anytype) WriteError!void {
        var buf: [4096]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch return error.Unexpected;
        try self.writeAll(slice);
    }

    fn netStreamRead(context: *anyopaque, buffer: []u8) ReadError!usize {
        const stream: *std.net.Stream = @ptrCast(@alignCast(context));
        return @errorCast(std.posix.recv(stream.handle, buffer, 0));
    }

    fn netStreamWrite(context: *anyopaque, buffer: []const u8) WriteError!usize {
        const stream: *std.net.Stream = @ptrCast(@alignCast(context));
        return @errorCast(std.posix.send(stream.handle, buffer, 0));
    }

    fn netStreamClose(context: *anyopaque) void {
        const stream: *std.net.Stream = @ptrCast(@alignCast(context));
        stream.close();
    }
};
