const std = @import("std");
const smtp = @import("smtp");

const Chain = smtp.middleware.Chain;
const Context = smtp.middleware.Context;
const Handler = smtp.middleware.Handler;
const Middleware = smtp.middleware.Middleware;
const Metrics = smtp.middleware.Metrics;
const RateLimiter = smtp.middleware.RateLimiter;
const Timeout = smtp.middleware.Timeout;
const LogSink = smtp.middleware.LogSink;

// ---------------------------------------------------------------------------
// Chain execution
// ---------------------------------------------------------------------------

var test_handler_called: bool = false;

fn testHandler(ctx: *Context) anyerror!void {
    _ = ctx;
    test_handler_called = true;
}

test "chain: execute calls the handler" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    test_handler_called = false;
    chain.setHandler(testHandler);

    var ctx = Context{
        .command = "EHLO",
        .args = "example.com",
    };
    try chain.execute(&ctx);
    try std.testing.expect(test_handler_called);
}

test "chain: execute with no handler does nothing" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    var ctx = Context{
        .command = "EHLO",
        .args = "example.com",
    };
    // Should not panic or error.
    try chain.execute(&ctx);
}

test "chain: build returns null with no handler" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    try std.testing.expect(chain.build() == null);
}

test "chain: build returns handler when set" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    chain.setHandler(testHandler);
    try std.testing.expect(chain.build() != null);
}

// ---------------------------------------------------------------------------
// Middleware wrapping
// ---------------------------------------------------------------------------

fn noopMiddleware(next: Handler) Handler {
    _ = next;
    return testHandler;
}

test "chain: use adds middleware" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    try chain.use(noopMiddleware);
    chain.setHandler(testHandler);

    const built = chain.build();
    try std.testing.expect(built != null);
}

test "chain: middleware wraps handler" {
    const allocator = std.testing.allocator;
    var chain = Chain.init(allocator);
    defer chain.deinit();

    try chain.use(noopMiddleware);
    chain.setHandler(testHandler);

    test_handler_called = false;
    var ctx = Context{
        .command = "NOOP",
        .args = "",
    };
    try chain.execute(&ctx);
    try std.testing.expect(test_handler_called);
}

// ---------------------------------------------------------------------------
// Context fields
// ---------------------------------------------------------------------------

test "context: default values" {
    const ctx = Context{
        .command = "MAIL FROM",
        .args = "<user@example.com>",
    };
    try std.testing.expectEqualStrings("MAIL FROM", ctx.command);
    try std.testing.expectEqualStrings("<user@example.com>", ctx.args);
    try std.testing.expectEqualStrings("", ctx.client_id);
    try std.testing.expectEqual(@as(u64, 0), ctx.session_id);
    try std.testing.expect(!ctx.is_tls);
    try std.testing.expect(ctx.username == null);
    try std.testing.expect(!ctx.handled);
    try std.testing.expect(ctx.error_message == null);
    try std.testing.expectEqual(@as(u16, 0), ctx.error_code);
}

test "context: setting fields" {
    var ctx = Context{
        .command = "AUTH",
        .args = "PLAIN",
        .client_id = "192.168.1.1",
        .session_id = 42,
        .is_tls = true,
        .username = "alice",
    };
    try std.testing.expectEqualStrings("192.168.1.1", ctx.client_id);
    try std.testing.expectEqual(@as(u64, 42), ctx.session_id);
    try std.testing.expect(ctx.is_tls);
    try std.testing.expectEqualStrings("alice", ctx.username.?);

    // Simulate rejection.
    ctx.error_code = 550;
    ctx.error_message = "Access denied";
    ctx.handled = true;
    try std.testing.expect(ctx.handled);
    try std.testing.expectEqual(@as(u16, 550), ctx.error_code);
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

test "metrics: initial values are zero" {
    const m = Metrics{};
    try std.testing.expectEqual(@as(u64, 0), m.commands_total);
    try std.testing.expectEqual(@as(u64, 0), m.commands_failed);
    try std.testing.expectEqual(@as(u64, 0), m.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), m.bytes_sent);
}

test "metrics: reset clears all counters" {
    var m = Metrics{
        .commands_total = 100,
        .commands_failed = 5,
        .bytes_received = 1024,
        .bytes_sent = 2048,
    };
    m.reset();
    try std.testing.expectEqual(@as(u64, 0), m.commands_total);
    try std.testing.expectEqual(@as(u64, 0), m.commands_failed);
    try std.testing.expectEqual(@as(u64, 0), m.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), m.bytes_sent);
}

test "metrics: middleware returns a function" {
    var m = Metrics{};
    const mw = m.middleware();
    m.reset();
    try std.testing.expect(@TypeOf(mw) == Middleware);
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

test "ratelimiter: allow permits up to max" {
    var rl = RateLimiter.init(3, 1000);

    try std.testing.expect(rl.allow(100));
    try std.testing.expect(rl.allow(200));
    try std.testing.expect(rl.allow(300));
    try std.testing.expect(!rl.allow(400)); // 4th should be denied
}

test "ratelimiter: new window resets count" {
    var rl = RateLimiter.init(2, 1000);

    try std.testing.expect(rl.allow(100));
    try std.testing.expect(rl.allow(200));
    try std.testing.expect(!rl.allow(300)); // denied

    // Jump to new time window.
    try std.testing.expect(rl.allow(1200)); // new window, allowed
    try std.testing.expect(rl.allow(1300)); // second in new window
    try std.testing.expect(!rl.allow(1400)); // denied again
}

test "ratelimiter: reset clears state" {
    var rl = RateLimiter.init(1, 1000);

    try std.testing.expect(rl.allow(100));
    try std.testing.expect(!rl.allow(200));

    rl.reset();
    try std.testing.expectEqual(@as(u64, 0), rl.current_count);
    try std.testing.expectEqual(@as(i64, 0), rl.window_start_ms);
}

test "ratelimiter: middleware returns a function" {
    var rl = RateLimiter.init(10, 60000);
    const mw = rl.middleware();
    try std.testing.expect(@TypeOf(mw) == Middleware);
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

test "timeout: init sets timeout_ms" {
    const t = Timeout.init(30000);
    try std.testing.expectEqual(@as(u64, 30000), t.timeout_ms);
}

test "timeout: middleware returns a function" {
    const t = Timeout.init(5000);
    const mw = t.middleware();
    try std.testing.expect(@TypeOf(mw) == Middleware);
}

// ---------------------------------------------------------------------------
// LogSink
// ---------------------------------------------------------------------------

fn dummyLog(msg: []const u8) void {
    _ = msg;
}

test "logsink: middleware returns a function" {
    const sink = LogSink{ .log_fn = dummyLog };
    const mw = sink.middleware();
    try std.testing.expect(@TypeOf(mw) == Middleware);
}
