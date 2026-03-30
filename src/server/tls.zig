const std = @import("std");
const wire = @import("../wire/root.zig");

pub const Transport = wire.Transport;

pub const ConnectionMode = enum {
    plaintext,
    implicit_tls,
};

/// Owns the server-side TLS state for a single connection.
pub const TlsSession = struct {
    context: *anyopaque,
    transport_fn: *const fn (ctx: *anyopaque) Transport,
    deinit_fn: *const fn (ctx: *anyopaque) void,

    pub fn transport(self: *TlsSession) Transport {
        return self.transport_fn(self.context);
    }

    pub fn deinit(self: *TlsSession) void {
        self.deinit_fn(self.context);
    }
};

/// User-supplied TLS integration for implicit TLS and STARTTLS upgrades.
pub const TlsProvider = struct {
    context: *anyopaque,
    accept_fn: ?*const fn (ctx: *anyopaque, allocator: std.mem.Allocator, stream: std.net.Stream) anyerror!*TlsSession = null,
    upgrade_fn: ?*const fn (ctx: *anyopaque, allocator: std.mem.Allocator, stream: std.net.Stream) anyerror!*TlsSession = null,

    pub fn canAcceptImplicit(self: TlsProvider) bool {
        return self.accept_fn != null;
    }

    pub fn canUpgrade(self: TlsProvider) bool {
        return self.upgrade_fn != null;
    }

    pub fn acceptImplicit(self: TlsProvider, allocator: std.mem.Allocator, stream: std.net.Stream) !*TlsSession {
        const accept_fn = self.accept_fn orelse return error.TlsAcceptUnavailable;
        return try accept_fn(self.context, allocator, stream);
    }

    pub fn upgrade(self: TlsProvider, allocator: std.mem.Allocator, stream: std.net.Stream) !*TlsSession {
        const upgrade_fn = self.upgrade_fn orelse return error.TlsUpgradeUnavailable;
        return try upgrade_fn(self.context, allocator, stream);
    }
};
