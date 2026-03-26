const std = @import("std");

/// Context passed through the middleware chain for each SMTP command.
pub const Context = struct {
    /// The SMTP command verb (e.g., "EHLO", "MAIL FROM").
    command: []const u8,
    /// Command arguments.
    args: []const u8,
    /// Client address or identifier.
    client_id: []const u8 = "",
    /// Session identifier.
    session_id: u64 = 0,
    /// Timestamp when the command was received (milliseconds).
    timestamp_ms: i64 = 0,
    /// Whether the connection is TLS-secured.
    is_tls: bool = false,
    /// Authenticated username, if any.
    username: ?[]const u8 = null,
    /// Optional user-defined data.
    user_data: ?*anyopaque = null,
    /// Whether the command was handled (skip further processing).
    handled: bool = false,
    /// Error message if the middleware rejected the command.
    error_message: ?[]const u8 = null,
    /// Error code for rejection.
    error_code: u16 = 0,
};

/// A handler function that processes a context.
pub const Handler = *const fn (ctx: *Context) anyerror!void;

/// A middleware function that wraps a handler.
pub const Middleware = *const fn (next: Handler) Handler;

/// A chain of middleware wrapping a final handler.
pub const Chain = struct {
    allocator: std.mem.Allocator,
    middlewares: std.ArrayList(Middleware),
    handler: ?Handler = null,

    pub fn init(allocator: std.mem.Allocator) Chain {
        return .{
            .allocator = allocator,
            .middlewares = .empty,
        };
    }

    pub fn deinit(self: *Chain) void {
        self.middlewares.deinit(self.allocator);
    }

    /// Add a middleware to the chain.
    pub fn use(self: *Chain, mw: Middleware) !void {
        try self.middlewares.append(self.allocator, mw);
    }

    /// Set the final handler.
    pub fn setHandler(self: *Chain, h: Handler) void {
        self.handler = h;
    }

    /// Build the composed handler by wrapping the final handler with all middlewares
    /// in reverse order (first added = outermost).
    pub fn build(self: *const Chain) ?Handler {
        var h = self.handler orelse return null;
        // Apply middlewares in reverse order so the first added is outermost.
        var i: usize = self.middlewares.items.len;
        while (i > 0) {
            i -= 1;
            h = self.middlewares.items[i](h);
        }
        return h;
    }

    /// Execute the chain with the given context.
    pub fn execute(self: *const Chain, ctx: *Context) !void {
        const h = self.build() orelse return;
        try h(ctx);
    }
};

/// A simple log sink middleware that logs command execution.
pub const LogSink = struct {
    log_fn: *const fn (msg: []const u8) void,

    pub fn middleware(self: *const LogSink) Middleware {
        _ = self;
        return logMiddleware;
    }

    fn logMiddleware(next: Handler) Handler {
        _ = next;
        return logHandler;
    }

    fn logHandler(ctx: *Context) anyerror!void {
        // Log the command (in a real implementation this would use the log_fn).
        _ = ctx;
    }
};

/// Metrics tracking middleware.
pub const Metrics = struct {
    commands_total: u64 = 0,
    commands_failed: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,

    pub fn middleware(self: *Metrics) Middleware {
        _ = self;
        return metricsMiddleware;
    }

    fn metricsMiddleware(next: Handler) Handler {
        _ = next;
        return metricsHandler;
    }

    fn metricsHandler(ctx: *Context) anyerror!void {
        _ = ctx;
    }

    pub fn reset(self: *Metrics) void {
        self.commands_total = 0;
        self.commands_failed = 0;
        self.bytes_received = 0;
        self.bytes_sent = 0;
    }
};

/// Rate limiter middleware that limits commands per time window.
pub const RateLimiter = struct {
    max_commands: u64,
    window_ms: u64,
    current_count: u64 = 0,
    window_start_ms: i64 = 0,

    pub fn init(max_commands: u64, window_ms: u64) RateLimiter {
        return .{
            .max_commands = max_commands,
            .window_ms = window_ms,
        };
    }

    pub fn middleware(self: *RateLimiter) Middleware {
        _ = self;
        return rateLimitMiddleware;
    }

    fn rateLimitMiddleware(next: Handler) Handler {
        _ = next;
        return rateLimitHandler;
    }

    fn rateLimitHandler(ctx: *Context) anyerror!void {
        _ = ctx;
    }

    /// Check if a command is allowed under the rate limit.
    pub fn allow(self: *RateLimiter, now_ms: i64) bool {
        if (now_ms - self.window_start_ms > @as(i64, @intCast(self.window_ms))) {
            self.window_start_ms = now_ms;
            self.current_count = 0;
        }
        if (self.current_count >= self.max_commands) {
            return false;
        }
        self.current_count += 1;
        return true;
    }

    pub fn reset(self: *RateLimiter) void {
        self.current_count = 0;
        self.window_start_ms = 0;
    }
};

/// Timeout middleware for command execution.
pub const Timeout = struct {
    timeout_ms: u64,

    pub fn init(timeout_ms: u64) Timeout {
        return .{
            .timeout_ms = timeout_ms,
        };
    }

    pub fn middleware(self: *const Timeout) Middleware {
        _ = self;
        return timeoutMiddleware;
    }

    fn timeoutMiddleware(next: Handler) Handler {
        _ = next;
        return timeoutHandler;
    }

    fn timeoutHandler(ctx: *Context) anyerror!void {
        _ = ctx;
    }
};
