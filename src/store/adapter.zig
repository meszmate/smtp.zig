const std = @import("std");
const memstore = @import("memstore.zig");
const interface = @import("interface.zig");

/// SessionAdapter bridges a memstore backend to the SMTP server protocol.
/// It wraps a single user and provides message delivery and query operations.
pub const SessionAdapter = struct {
    allocator: std.mem.Allocator,
    user: *memstore.User,

    pub fn init(allocator: std.mem.Allocator, user: *memstore.User) SessionAdapter {
        return .{ .allocator = allocator, .user = user };
    }

    /// Deliver a message to this user's mailbox.
    pub fn deliverMessage(self: *SessionAdapter, from: []const u8, recipients: []const []const u8, body: []const u8) !void {
        var msg = try memstore.Message.init(self.allocator, from, body);
        errdefer msg.deinit();

        for (recipients) |rcpt| {
            try msg.addRecipient(rcpt);
        }

        try self.user.appendMessage(msg);
    }

    /// Return the number of messages stored for this user.
    pub fn getMessageCount(self: *const SessionAdapter) usize {
        return self.user.messages.items.len;
    }

    /// Return the username associated with this session.
    pub fn getUsername(self: *const SessionAdapter) []const u8 {
        return self.user.username;
    }
};

/// ProtocolAdapter bridges a store Backend and DeliveryBackend to the
/// full SMTP server protocol, providing login and delivery operations
/// through the type-erased interface.
pub const ProtocolAdapter = struct {
    allocator: std.mem.Allocator,
    backend: interface.Backend,
    delivery_backend: ?interface.DeliveryBackend = null,
    authenticated: bool = false,

    pub fn init(allocator: std.mem.Allocator, backend: interface.Backend) ProtocolAdapter {
        return .{ .allocator = allocator, .backend = backend };
    }

    /// Attach a delivery backend for message routing.
    pub fn setDeliveryBackend(self: *ProtocolAdapter, delivery: interface.DeliveryBackend) void {
        self.delivery_backend = delivery;
    }

    pub fn deinit(self: *ProtocolAdapter) void {
        _ = self;
    }

    /// Authenticate a user with username and password.
    pub fn login(self: *ProtocolAdapter, username: []const u8, password: []const u8) !void {
        const result = self.backend.authenticate(username, password);
        if (result == null or result.? == false) {
            return error.AuthenticationFailed;
        }
        self.authenticated = true;
    }

    /// Deliver a message through the delivery backend.
    pub fn deliverMessage(self: *ProtocolAdapter, from: []const u8, recipients: []const []u8, body: []const u8) !void {
        const delivery = self.delivery_backend orelse return error.NoDeliveryBackend;
        _ = try delivery.deliverMessage(from, recipients, body);
    }
};

/// Parse an email address string like "Display Name <user@host>" or "user@host".
/// Returns the component parts. All returned slices point into the original input.
pub fn parseAddress(raw: []const u8) struct { name: []const u8, mailbox: []const u8, host: []const u8 } {
    const trimmed = std.mem.trim(u8, raw, " \t");

    // Check for angle-bracket form: "Display Name <user@host>"
    if (std.mem.indexOfScalar(u8, trimmed, '<')) |open| {
        if (std.mem.indexOfScalar(u8, trimmed, '>')) |close| {
            if (close > open + 1) {
                const addr = trimmed[open + 1 .. close];
                const display = std.mem.trim(u8, trimmed[0..open], " \t\"");
                const local = localPart(addr);
                const domain = domainPart(addr);
                return .{ .name = display, .mailbox = local, .host = domain };
            }
        }
    }

    // Plain address: "user@host"
    const local = localPart(trimmed);
    const domain = domainPart(trimmed);
    return .{ .name = "", .mailbox = local, .host = domain };
}

/// Extract the local part from an email address (before @).
pub fn localPart(email: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, email, '@')) |idx| {
        return email[0..idx];
    }
    return email;
}

/// Extract the domain from an email address (after @).
pub fn domainPart(email: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, email, '@')) |idx| {
        return email[idx + 1 ..];
    }
    return "";
}
