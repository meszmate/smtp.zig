const std = @import("std");
const types = @import("../types.zig");
const state_mod = @import("../state/machine.zig");

pub const ConnState = types.ConnState;

/// Tracks the state of an SMTP session/transaction.
pub const SessionState = struct {
    allocator: std.mem.Allocator,

    /// Current connection state.
    state: ConnState = .connect,

    /// Whether the client has authenticated.
    authenticated: bool = false,

    /// Authenticated username.
    username: ?[]const u8 = null,

    /// MAIL FROM sender address for the current transaction.
    from: ?[]const u8 = null,

    /// RCPT TO recipients for the current transaction.
    recipients: std.ArrayList([]u8),

    /// Whether the connection is using TLS.
    is_tls: bool = false,

    /// Client-provided EHLO/HELO domain.
    client_domain: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator) SessionState {
        return .{
            .allocator = allocator,
            .recipients = .empty,
        };
    }

    pub fn deinit(self: *SessionState) void {
        self.freeFrom();
        self.freeRecipients();
        self.freeUsername();
        self.freeClientDomain();
    }

    /// Check if the given command verb is allowed in the current state.
    pub fn canExecute(self: *const SessionState, command: []const u8) bool {
        const allowed = state_mod.commandAllowedStates(command);
        for (allowed) |s| {
            if (self.state == s) return true;
        }
        return false;
    }

    /// Set the MAIL FROM address for the current transaction.
    pub fn setFrom(self: *SessionState, from: []const u8) !void {
        self.freeFrom();
        const owned = try self.allocator.dupe(u8, from);
        self.from = owned;
        self.state = .mail;
    }

    /// Add a recipient to the current transaction.
    pub fn addRecipient(self: *SessionState, rcpt: []const u8) !void {
        const owned = try self.allocator.dupe(u8, rcpt);
        errdefer self.allocator.free(owned);
        try self.recipients.append(self.allocator, owned);
        self.state = .rcpt;
    }

    /// Reset the transaction state (RSET), keeping connection state.
    pub fn reset(self: *SessionState) void {
        self.freeFrom();
        self.freeRecipients();
        self.from = null;
        if (self.state != .connect and self.state != .greeted) {
            self.state = .ready;
        }
    }

    /// Transition to logout state.
    pub fn logout(self: *SessionState) void {
        self.state = .logout;
    }

    /// Mark the session as authenticated.
    pub fn setAuthenticated(self: *SessionState, user: []const u8) !void {
        self.freeUsername();
        self.username = try self.allocator.dupe(u8, user);
        self.authenticated = true;
    }

    /// Set the client domain from EHLO/HELO.
    pub fn setClientDomain(self: *SessionState, domain: []const u8) !void {
        self.freeClientDomain();
        self.client_domain = try self.allocator.dupe(u8, domain);
        if (self.state == .connect) {
            self.state = .greeted;
        }
        // After EHLO/HELO the session is ready for mail transactions.
        self.state = .ready;
    }

    /// Get the number of recipients.
    pub fn recipientCount(self: *const SessionState) usize {
        return self.recipients.items.len;
    }

    /// Get recipient at index.
    pub fn getRecipient(self: *const SessionState, index: usize) []const u8 {
        return self.recipients.items[index];
    }

    fn freeFrom(self: *SessionState) void {
        if (self.from) |f| {
            self.allocator.free(f);
            self.from = null;
        }
    }

    fn freeRecipients(self: *SessionState) void {
        for (self.recipients.items) |r| {
            self.allocator.free(r);
        }
        self.recipients.clearRetainingCapacity();
    }

    fn freeUsername(self: *SessionState) void {
        if (self.username) |u| {
            self.allocator.free(@constCast(u));
            self.username = null;
        }
    }

    fn freeClientDomain(self: *SessionState) void {
        if (self.client_domain) |d| {
            self.allocator.free(@constCast(d));
            self.client_domain = null;
        }
    }
};
