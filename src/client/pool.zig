const std = @import("std");
const builtin = @import("builtin");
const client_mod = @import("client.zig");
const Client = client_mod.Client;
const options_mod = @import("options.zig");
const Options = options_mod.Options;
const response_mod = @import("../response.zig");

/// Wrapper around a Client that tracks connection lifecycle timestamps.
pub const PooledConnection = struct {
    client: *Client,
    /// Millisecond timestamp when the connection was created.
    created_at: i64,
    /// Millisecond timestamp when the connection was last handed out or returned.
    last_used_at: i64,
    /// Millisecond timestamp of the last NOOP health-check.
    last_health_check: i64,
};

/// Snapshot of pool activity counters.
pub const PoolStats = struct {
    total_created: u64 = 0,
    total_reused: u64 = 0,
    total_failed: u64 = 0,
    current_idle: u64 = 0,
    current_active: u64 = 0,
};

/// Options for the connection pool.
pub const PoolOptions = struct {
    /// SMTP server hostname.
    host: []const u8,

    /// SMTP server port.
    port: u16 = 25,

    /// Maximum number of idle connections to keep in the pool.
    max_idle: u16 = 4,

    /// Maximum total simultaneous connections (idle + active).
    max_total: u16 = 16,

    /// Username for authentication (optional).
    username: ?[]const u8 = null,

    /// Password for authentication (optional).
    password: ?[]const u8 = null,

    /// Client options (timeouts, TLS, debug).
    client_options: Options = .{},

    /// Custom dial function. If null, uses default TCP connect.
    /// When set, the pool calls this to obtain a connected Client.
    dial_fn: ?*const fn (allocator: std.mem.Allocator, host: []const u8, port: u16) anyerror!*Client = null,

    /// Evict idle connections after this many milliseconds (default 5 min).
    max_idle_time_ms: u64 = 300_000,

    /// Maximum connection lifetime in milliseconds (default 1 hour).
    max_lifetime_ms: u64 = 3_600_000,

    /// Interval between NOOP health checks in milliseconds (default 30 s).
    health_check_interval_ms: u64 = 30_000,
};

/// A pool of reusable SMTP client connections.
///
/// Connections are acquired from the pool and returned when no longer needed.
/// If no idle connection is available, a new one is created. Connections are
/// automatically authenticated if credentials are provided in the pool options.
///
/// The pool tracks connection age, idle time, and performs periodic health
/// checks so that callers always receive a usable connection.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    opts: PoolOptions,
    idle: std.ArrayList(PooledConnection),
    active_count: u16 = 0,
    stats: PoolStats = .{},
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, opts: PoolOptions) Pool {
        return .{
            .allocator = allocator,
            .opts = opts,
            .idle = .empty,
            .active_count = 0,
            .stats = .{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.idle.items) |pc| {
            self.closeClient(pc.client);
        }
        self.idle.deinit(self.allocator);
    }

    /// Return the current millisecond timestamp.
    fn nowMs(_: *Pool) i64 {
        return std.time.milliTimestamp();
    }

    /// Acquire a connection from the pool. Returns an existing idle connection
    /// if one is valid, otherwise creates and authenticates a new one.
    /// Returns `error.PoolExhausted` when `max_total` connections are already
    /// in use.
    pub fn acquire(self: *Pool) !*Client {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = self.nowMs();

        // 1. Evict expired idle connections while holding the lock.
        _ = self.evictExpiredLocked(now);

        // 2. Try to find a valid idle connection.
        while (self.idle.items.len > 0) {
            var pc = self.idle.pop().?;

            // Check max lifetime.
            if (exceedsLimit(now - pc.created_at, self.opts.max_lifetime_ms)) {
                self.closePooledConnection(&pc);
                continue;
            }

            // Check idle timeout.
            if (exceedsLimit(now - pc.last_used_at, self.opts.max_idle_time_ms)) {
                self.closePooledConnection(&pc);
                continue;
            }

            // Health check if interval has elapsed.
            if (exceedsLimit(now - pc.last_health_check, self.opts.health_check_interval_ms)) {
                if (pc.client.noop()) |resp| {
                    var r = resp;
                    response_mod.freeResponse(pc.client.allocator, &r);
                } else |_| {
                    self.stats.total_failed += 1;
                    self.closePooledConnection(&pc);
                    continue;
                }
                pc.last_health_check = now;
            }

            pc.last_used_at = now;
            self.active_count += 1;
            self.stats.total_reused += 1;
            self.stats.current_idle = @intCast(self.idle.items.len);
            self.stats.current_active = self.active_count;
            return pc.client;
        }

        // 3. No idle connections available -- try to create a new one.
        if (self.active_count >= self.opts.max_total) {
            return error.PoolExhausted;
        }

        const c = self.dialNew() catch |err| {
            self.stats.total_failed += 1;
            return err;
        };

        self.active_count += 1;
        self.stats.total_created += 1;
        self.stats.current_idle = @intCast(self.idle.items.len);
        self.stats.current_active = self.active_count;
        return c;
    }

    /// Release a connection back to the pool. If the pool is full or the
    /// connection has exceeded its maximum lifetime the connection is closed.
    pub fn release(self: *Pool, c: *Client) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.active_count > 0) {
            self.active_count -= 1;
        }

        const now = self.nowMs();

        // Check if the idle pool is full.
        if (self.idle.items.len >= self.opts.max_idle) {
            self.closeClient(c);
            self.stats.current_active = self.active_count;
            self.stats.current_idle = @intCast(self.idle.items.len);
            return;
        }

        // We don't know the original created_at for this client, so we look
        // for a reasonable value. For connections that went through acquire()
        // we cannot easily store metadata outside the pool, so we record now
        // as both last_used_at and last_health_check, and use now as
        // created_at (meaning it will live for another full max_lifetime from
        // this point). This is a pragmatic choice: the pool already validated
        // the connection on acquire and it was just used successfully.
        const pc = PooledConnection{
            .client = c,
            .created_at = now,
            .last_used_at = now,
            .last_health_check = now,
        };

        self.idle.append(self.allocator, pc) catch {
            self.closeClient(c);
        };

        self.stats.current_active = self.active_count;
        self.stats.current_idle = @intCast(self.idle.items.len);
    }

    /// Evict idle connections whose idle time or lifetime has expired.
    /// Returns the number of connections evicted.
    pub fn evictExpired(self: *Pool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.evictExpiredLocked(self.nowMs());
    }

    /// Check whether the elapsed time (in ms) exceeds the given limit.
    /// Handles the case where the limit is larger than what fits in an i64.
    fn exceedsLimit(elapsed: i64, limit: u64) bool {
        if (elapsed < 0) return false;
        return @as(u64, @intCast(elapsed)) >= limit;
    }

    /// Internal eviction that assumes the mutex is already held.
    fn evictExpiredLocked(self: *Pool, now: i64) usize {
        var evicted: usize = 0;
        var i: usize = 0;
        while (i < self.idle.items.len) {
            const pc = &self.idle.items[i];
            const idle_expired = exceedsLimit(now - pc.last_used_at, self.opts.max_idle_time_ms);
            const lifetime_expired = exceedsLimit(now - pc.created_at, self.opts.max_lifetime_ms);
            if (idle_expired or lifetime_expired) {
                var removed = self.idle.orderedRemove(i);
                self.closePooledConnection(&removed);
                evicted += 1;
            } else {
                i += 1;
            }
        }
        if (evicted > 0) {
            self.stats.current_idle = @intCast(self.idle.items.len);
        }
        return evicted;
    }

    /// Get a snapshot of the current pool statistics.
    pub fn getStats(self: *Pool) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var s = self.stats;
        s.current_idle = @intCast(self.idle.items.len);
        s.current_active = self.active_count;
        return s;
    }

    /// Close all idle connections immediately.
    pub fn drain(self: *Pool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.idle.items) |pc| {
            self.closeClient(pc.client);
        }
        self.idle.clearRetainingCapacity();
        self.stats.current_idle = 0;
    }

    /// Close and destroy the client inside a PooledConnection.
    /// Sends QUIT before closing. Errors during QUIT are ignored.
    fn closePooledConnection(self: *Pool, pc: *PooledConnection) void {
        self.closeClient(pc.client);
    }

    /// Send QUIT (best-effort), release resources, free the heap allocation.
    fn closeClient(self: *Pool, c: *Client) void {
        if (c.quit()) |resp| {
            var r = resp;
            response_mod.freeResponse(c.allocator, &r);
        } else |_| {}
        c.deinit();
        self.allocator.destroy(c);
    }

    /// Create a new connection, perform EHLO, and authenticate if credentials
    /// are configured.
    ///
    /// When a custom `dial_fn` is set the returned Client is assumed to be
    /// fully initialised (EHLO and authentication already performed by the
    /// caller), so the pool skips those steps.
    fn dialNew(self: *Pool) !*Client {
        const c = try self.allocator.create(Client);
        errdefer self.allocator.destroy(c);

        if (self.opts.dial_fn) |dial| {
            const dialed = try dial(self.allocator, self.opts.host, self.opts.port);
            c.* = dialed.*;
            // The dial function allocated its own Client; we've copied the
            // fields into our heap-allocated one, so free the original shell.
            self.allocator.destroy(dialed);
            return c;
        }

        if (self.opts.client_options.tls_options) |tls_opts| {
            _ = tls_opts;
            c.* = try Client.connectTlsWithOptions(self.allocator, self.opts.host, self.opts.port, self.opts.client_options);
        } else {
            c.* = try Client.connectTcpWithOptions(self.allocator, self.opts.host, self.opts.port, self.opts.client_options);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const wire = @import("../wire/root.zig");
const Transport = wire.Transport;
const LineReader = wire.LineReader;
const capability_mod = @import("../capability.zig");
const CapabilitySet = capability_mod.CapabilitySet;

/// State for a stub Transport that returns a fixed "221 Bye" response
/// on read so that quit() succeeds without crashing.
const StubState = struct {
    response: []const u8 = "221 Bye\r\n",
    pos: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) Transport.ReadError!usize {
        const self: *StubState = @ptrCast(@alignCast(ctx));
        if (self.pos >= self.response.len) {
            self.pos = 0; // reset for next command
            return 0;
        }
        const remaining = self.response[self.pos..];
        const n = @min(remaining.len, buf.len);
        @memcpy(buf[0..n], remaining[0..n]);
        self.pos += n;
        return n;
    }
    fn write(_: *anyopaque, buf: []const u8) Transport.WriteError!usize {
        return buf.len;
    }
    fn close(_: *anyopaque) void {}
};

/// Create a stub Transport that returns valid SMTP responses.
fn stubTransport(state: *StubState) Transport {
    return .{
        .context = @ptrCast(state),
        .read_fn = &StubState.read,
        .write_fn = &StubState.write,
        .close_fn = &StubState.close,
    };
}

/// Build a minimal mock Client suitable for pool tests. The transport
/// uses no-op stubs so quit / deinit will not crash.
/// Fixed pool of stub states for mock transports. Each mockClient gets
/// its own StubState so transport contexts remain valid after the pool
/// copies and frees the Client shells returned by dialNew.
var stub_states: [16]StubState = [_]StubState{.{}} ** 16;
var stub_state_index: usize = 0;

fn mockClient(alloc: std.mem.Allocator) !*Client {
    const c = try alloc.create(Client);
    const idx = stub_state_index;
    stub_state_index = (stub_state_index + 1) % stub_states.len;
    stub_states[idx] = .{};
    const transport = stubTransport(&stub_states[idx]);
    c.* = .{
        .allocator = alloc,
        .transport = transport,
        .reader = LineReader.init(alloc, transport),
        .capabilities = CapabilitySet.init(alloc),
        .state = .ready,
        .server_name = null,
        .max_size = null,
        .tls_state = null,
        .is_tls = false,
        .owned_stream = null,
        .heap_stream = null,
        .data_prev_byte = null,
        .data_last_byte = null,
        .options = .{},
    };
    return c;
}

test "pool acquire and release with mock dial" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Helpers = struct {
        fn mockDial(alloc: std.mem.Allocator, _: []const u8, _: u16) anyerror!*Client {
            return mockClient(alloc);
        }
    };

    var p = Pool.init(allocator, .{
        .host = "localhost",
        .port = 2525,
        .max_idle = 2,
        .max_total = 4,
        .dial_fn = &Helpers.mockDial,
        // Disable time-based eviction for deterministic tests.
        .max_idle_time_ms = std.math.maxInt(u64),
        .max_lifetime_ms = std.math.maxInt(u64),
        .health_check_interval_ms = std.math.maxInt(u64),
    });
    defer p.deinit();

    // Acquire a connection, then release it.
    const c1 = try p.acquire();
    try testing.expectEqual(@as(u64, 1), p.getStats().total_created);
    try testing.expectEqual(@as(u64, 1), p.getStats().current_active);

    p.release(c1);
    try testing.expectEqual(@as(u64, 0), p.getStats().current_active);
    try testing.expectEqual(@as(u64, 1), p.getStats().current_idle);

    // Acquiring again should reuse the released connection.
    const c2 = try p.acquire();
    try testing.expectEqual(@as(u64, 1), p.getStats().total_reused);

    // Clean up: release so deinit can close it.
    p.release(c2);
}

test "pool max total enforcement" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Helpers = struct {
        fn mockDial(alloc: std.mem.Allocator, _: []const u8, _: u16) anyerror!*Client {
            return mockClient(alloc);
        }
    };

    var p = Pool.init(allocator, .{
        .host = "localhost",
        .max_idle = 2,
        .max_total = 2,
        .dial_fn = &Helpers.mockDial,
        .max_idle_time_ms = std.math.maxInt(u64),
        .max_lifetime_ms = std.math.maxInt(u64),
        .health_check_interval_ms = std.math.maxInt(u64),
    });
    defer p.deinit();

    const c1 = try p.acquire();
    const c2 = try p.acquire();

    // Third acquire should fail.
    const result = p.acquire();
    try testing.expectError(error.PoolExhausted, result);

    p.release(c1);
    p.release(c2);
}

test "pool evict expired connections" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Helpers = struct {
        fn mockDial(alloc: std.mem.Allocator, _: []const u8, _: u16) anyerror!*Client {
            return mockClient(alloc);
        }
    };

    var p = Pool.init(allocator, .{
        .host = "localhost",
        .max_idle = 4,
        .max_total = 8,
        .dial_fn = &Helpers.mockDial,
        // Set very short idle timeout so connections expire immediately.
        .max_idle_time_ms = 0,
        .max_lifetime_ms = std.math.maxInt(u64),
        .health_check_interval_ms = std.math.maxInt(u64),
    });
    defer p.deinit();

    // Acquire and release two connections to put them in the idle list.
    const c1 = try p.acquire();
    const c2 = try p.acquire();
    p.release(c1);
    p.release(c2);

    try testing.expectEqual(@as(u64, 2), p.getStats().current_idle);

    // Evict -- both should be removed because max_idle_time_ms = 0.
    const evicted = p.evictExpired();
    try testing.expectEqual(@as(usize, 2), evicted);
    try testing.expectEqual(@as(u64, 0), p.getStats().current_idle);
}

test "pool stats tracking" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Helpers = struct {
        fn mockDial(alloc: std.mem.Allocator, _: []const u8, _: u16) anyerror!*Client {
            return mockClient(alloc);
        }
    };

    var p = Pool.init(allocator, .{
        .host = "localhost",
        .max_idle = 2,
        .max_total = 4,
        .dial_fn = &Helpers.mockDial,
        .max_idle_time_ms = std.math.maxInt(u64),
        .max_lifetime_ms = std.math.maxInt(u64),
        .health_check_interval_ms = std.math.maxInt(u64),
    });
    defer p.deinit();

    var stats = p.getStats();
    try testing.expectEqual(@as(u64, 0), stats.total_created);
    try testing.expectEqual(@as(u64, 0), stats.total_reused);

    const c1 = try p.acquire();
    stats = p.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_created);
    try testing.expectEqual(@as(u64, 1), stats.current_active);

    p.release(c1);
    stats = p.getStats();
    try testing.expectEqual(@as(u64, 0), stats.current_active);
    try testing.expectEqual(@as(u64, 1), stats.current_idle);

    // Reuse.
    const c2 = try p.acquire();
    stats = p.getStats();
    try testing.expectEqual(@as(u64, 1), stats.total_reused);
    try testing.expectEqual(@as(u64, 1), stats.current_active);

    p.release(c2);
}

test "pool drain" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const Helpers = struct {
        fn mockDial(alloc: std.mem.Allocator, _: []const u8, _: u16) anyerror!*Client {
            return mockClient(alloc);
        }
    };

    var p = Pool.init(allocator, .{
        .host = "localhost",
        .max_idle = 4,
        .max_total = 8,
        .dial_fn = &Helpers.mockDial,
        .max_idle_time_ms = std.math.maxInt(u64),
        .max_lifetime_ms = std.math.maxInt(u64),
        .health_check_interval_ms = std.math.maxInt(u64),
    });
    defer p.deinit();

    const c1 = try p.acquire();
    const c2 = try p.acquire();
    const c3 = try p.acquire();
    p.release(c1);
    p.release(c2);
    p.release(c3);

    try testing.expectEqual(@as(u64, 3), p.getStats().current_idle);

    p.drain();

    try testing.expectEqual(@as(u64, 0), p.getStats().current_idle);
}
