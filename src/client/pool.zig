const std = @import("std");
const builtin = @import("builtin");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const options_mod = @import("options.zig");
const Options = options_mod.Options;

/// Options for the connection pool.
pub const PoolOptions = struct {
    /// SMTP server hostname.
    host: []const u8,

    /// SMTP server port.
    port: u16 = 25,

    /// Maximum number of idle connections to keep in the pool.
    max_idle: u16 = 4,

    /// Username for authentication (optional).
    username: ?[]const u8 = null,

    /// Password for authentication (optional).
    password: ?[]const u8 = null,

    /// Client options (timeouts, TLS, debug).
    client_options: Options = .{},

    /// Custom dial function. If null, uses default TCP connect.
    /// When set, the pool calls this to obtain a connected Client.
    dial_fn: ?*const fn (allocator: std.mem.Allocator, host: []const u8, port: u16) anyerror!*Client = null,
};

/// A pool of reusable SMTP client connections.
///
/// Connections are acquired from the pool and returned when no longer needed.
/// If no idle connection is available, a new one is created. Connections are
/// automatically authenticated if credentials are provided in the pool options.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    opts: PoolOptions,
    idle: std.ArrayList(*Client),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, opts: PoolOptions) Pool {
        return .{
            .allocator = allocator,
            .opts = opts,
            .idle = .empty,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.idle.items) |c| {
            _ = c.quit() catch {};
            c.deinit();
            self.allocator.destroy(c);
        }
        self.idle.deinit(self.allocator);
    }

    /// Acquire a connection from the pool. Returns an existing idle connection
    /// if one is available, otherwise creates and authenticates a new one.
    pub fn acquire(self: *Pool) !*Client {
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.idle.items.len > 0) {
                const c = self.idle.pop().?;
                // Validate the connection with a NOOP before returning.
                _ = c.noop() catch {
                    // Connection is stale, discard it.
                    c.deinit();
                    self.allocator.destroy(c);
                    return self.dialNew();
                };
                return c;
            }
        }

        return self.dialNew();
    }

    /// Release a connection back to the pool. If the pool is full the
    /// connection is closed instead.
    pub fn release(self: *Pool, c: *Client) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.idle.items.len >= self.opts.max_idle) {
            _ = c.quit() catch {};
            c.deinit();
            self.allocator.destroy(c);
            return;
        }

        self.idle.append(self.allocator, c) catch {
            _ = c.quit() catch {};
            c.deinit();
            self.allocator.destroy(c);
        };
    }

    /// Create a new connection, perform EHLO, and authenticate if credentials
    /// are configured.
    fn dialNew(self: *Pool) !*Client {
        const c = try self.allocator.create(Client);
        errdefer self.allocator.destroy(c);

        if (self.opts.dial_fn) |dial| {
            const dialed = try dial(self.allocator, self.opts.host, self.opts.port);
            c.* = dialed.*;
            // The dial function allocated its own Client; we've copied the
            // fields into our heap-allocated one, so free the original shell.
            self.allocator.destroy(dialed);
        } else {
            if (self.opts.client_options.tls_options) |tls_opts| {
                _ = tls_opts;
                c.* = try Client.connectTlsWithOptions(self.allocator, self.opts.host, self.opts.port, self.opts.client_options);
            } else {
                c.* = try Client.connectTcpWithOptions(self.allocator, self.opts.host, self.opts.port, self.opts.client_options);
            }
        }

        // EHLO with our hostname.
        const hostname = if (builtin.os.tag == .windows) "localhost" else blk: {
            var hostname_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
            break :blk std.posix.gethostname(&hostname_buf) catch "localhost";
        };
        _ = try c.ehlo(hostname);

        // Authenticate if credentials are provided.
        if (self.opts.username) |user| {
            if (self.opts.password) |pass| {
                try c.authenticatePlain(user, pass);
            }
        }

        return c;
    }
};
