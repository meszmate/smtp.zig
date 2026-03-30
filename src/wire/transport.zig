const std = @import("std");
const builtin = @import("builtin");

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
        if (builtin.os.tag == .windows) {
            return winSockRead(stream.handle, buffer);
        }
        return stream.read(buffer);
    }

    fn netStreamWrite(context: *anyopaque, buffer: []const u8) WriteError!usize {
        const stream: *std.net.Stream = @ptrCast(@alignCast(context));
        if (builtin.os.tag == .windows) {
            return winSockWrite(stream.handle, buffer);
        }
        return stream.write(buffer);
    }

    fn netStreamClose(context: *anyopaque) void {
        const stream: *std.net.Stream = @ptrCast(@alignCast(context));
        stream.close();
    }

    fn winSockRead(handle: std.net.Stream.Handle, buffer: []u8) ReadError!usize {
        const ws2_32 = std.os.windows.ws2_32;
        const len: i32 = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(i32))));
        const rc = ws2_32.recv(handle, buffer.ptr, len, 0);
        if (rc != ws2_32.SOCKET_ERROR) return @intCast(rc);

        return switch (ws2_32.WSAGetLastError()) {
            .WSAECONNRESET => error.ConnectionResetByPeer,
            .WSAEINVAL => error.SocketNotBound,
            .WSAEMSGSIZE => error.MessageTooBig,
            .WSAENETDOWN => error.NetworkSubsystemFailed,
            .WSAENOTCONN => error.SocketNotConnected,
            .WSAETIMEDOUT => error.ConnectionTimedOut,
            .WSAEWOULDBLOCK => error.WouldBlock,
            else => |err| std.os.windows.unexpectedWSAError(err),
        };
    }

    fn winSockWrite(handle: std.net.Stream.Handle, buffer: []const u8) WriteError!usize {
        const ws2_32 = std.os.windows.ws2_32;
        const len: i32 = @intCast(@min(buffer.len, @as(usize, std.math.maxInt(i32))));
        const rc = ws2_32.send(handle, buffer.ptr, len, 0);
        if (rc != ws2_32.SOCKET_ERROR) return @intCast(rc);

        return switch (ws2_32.WSAGetLastError()) {
            .WSAECONNRESET => error.ConnectionResetByPeer,
            .WSAEINVAL => error.SocketNotBound,
            .WSAEMSGSIZE => error.MessageTooBig,
            .WSAENETDOWN => error.NetworkSubsystemFailed,
            .WSAENOBUFS => error.SystemResources,
            .WSAENOTCONN => error.SocketNotConnected,
            else => |err| std.os.windows.unexpectedWSAError(err),
        };
    }
};

pub fn applyStreamTimeouts(stream: std.net.Stream, read_timeout_ms: u64, write_timeout_ms: u64) std.posix.SetSockOptError!void {
    if (!isValidStream(stream)) return;

    if (read_timeout_ms > 0) {
        try setStreamTimeout(stream.handle, std.posix.SO.RCVTIMEO, read_timeout_ms);
    }
    if (write_timeout_ms > 0) {
        try setStreamTimeout(stream.handle, std.posix.SO.SNDTIMEO, write_timeout_ms);
    }
}

fn isValidStream(stream: std.net.Stream) bool {
    if (builtin.os.tag == .windows) {
        return stream.handle != std.os.windows.ws2_32.INVALID_SOCKET;
    }
    return stream.handle >= 0;
}

fn setStreamTimeout(handle: std.net.Stream.Handle, optname: u32, timeout_ms: u64) std.posix.SetSockOptError!void {
    if (builtin.os.tag == .windows) {
        const timeout: u32 = @intCast(@min(timeout_ms, @as(u64, std.math.maxInt(u32))));
        try std.posix.setsockopt(handle, std.posix.SOL.SOCKET, optname, std.mem.asBytes(&timeout));
        return;
    }

    const timeout = std.posix.timeval{
        .sec = @intCast(timeout_ms / std.time.ms_per_s),
        .usec = @intCast((timeout_ms % std.time.ms_per_s) * std.time.us_per_ms),
    };
    try std.posix.setsockopt(handle, std.posix.SOL.SOCKET, optname, std.mem.asBytes(&timeout));
}
