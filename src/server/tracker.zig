const std = @import("std");

/// SessionTracker tracks a single SMTP session/connection.
/// Records per-connection statistics such as messages received and bytes transferred.
pub const SessionTracker = struct {
    allocator: std.mem.Allocator,
    client_addr: ?[]u8 = null,
    client_domain: ?[]u8 = null,
    messages_received: u32 = 0,
    bytes_received: u64 = 0,
    authenticated: bool = false,
    tls_active: bool = false,

    pub fn init(allocator: std.mem.Allocator) SessionTracker {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionTracker) void {
        if (self.client_addr) |addr| {
            self.allocator.free(addr);
            self.client_addr = null;
        }
        if (self.client_domain) |domain| {
            self.allocator.free(domain);
            self.client_domain = null;
        }
    }

    /// Record that a message of the given size was received.
    pub fn recordMessage(self: *SessionTracker, size: u64) void {
        self.messages_received += 1;
        self.bytes_received += size;
    }

    /// Set the client domain (from EHLO/HELO). Frees any previously stored domain.
    pub fn setClientDomain(self: *SessionTracker, domain: []const u8) !void {
        if (self.client_domain) |old| {
            self.allocator.free(old);
        }
        self.client_domain = try self.allocator.dupe(u8, domain);
    }

    /// Set the client address. Frees any previously stored address.
    pub fn setClientAddr(self: *SessionTracker, addr: []const u8) !void {
        if (self.client_addr) |old| {
            self.allocator.free(old);
        }
        self.client_addr = try self.allocator.dupe(u8, addr);
    }

    /// Set the TLS status.
    pub fn setTls(self: *SessionTracker, active: bool) void {
        self.tls_active = active;
    }

    /// Set the authentication status.
    pub fn setAuthenticated(self: *SessionTracker, auth: bool) void {
        self.authenticated = auth;
    }
};

/// ServerTracker tracks all active connections to an SMTP server.
/// Thread-safe via an internal mutex.
pub const ServerTracker = struct {
    allocator: std.mem.Allocator,
    sessions: std.ArrayList(*SessionTracker),
    total_connections: u64 = 0,
    total_messages: u64 = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) ServerTracker {
        return .{
            .allocator = allocator,
            .sessions = .empty,
        };
    }

    pub fn deinit(self: *ServerTracker) void {
        self.sessions.deinit(self.allocator);
    }

    /// Register a new session with the tracker.
    pub fn addSession(self: *ServerTracker, session: *SessionTracker) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sessions.append(self.allocator, session) catch return;
        self.total_connections += 1;
    }

    /// Remove a session from the tracker.
    pub fn removeSession(self: *ServerTracker, session: *SessionTracker) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.sessions.items, 0..) |s, i| {
            if (s == session) {
                _ = self.sessions.orderedRemove(i);
                return;
            }
        }
    }

    /// Return the number of currently active connections.
    pub fn activeConnectionCount(self: *ServerTracker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.sessions.items.len;
    }

    /// Record that a message was received (server-wide counter).
    pub fn recordMessage(self: *ServerTracker) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.total_messages += 1;
    }
};
