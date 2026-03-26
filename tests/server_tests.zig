const std = @import("std");
const smtp = @import("smtp");

const SessionState = smtp.server.SessionState;
const ExtensionManager = smtp.server.ExtensionManager;
const ServerExtension = smtp.server.ServerExtension;
const Dispatcher = smtp.server.Dispatcher;
const CommandContext = smtp.server.CommandContext;

// ---------------------------------------------------------------------------
// SessionState tests
// ---------------------------------------------------------------------------

test "session: initial state is connect" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try std.testing.expectEqual(smtp.ConnState.connect, sess.state);
    try std.testing.expect(!sess.authenticated);
    try std.testing.expect(sess.username == null);
    try std.testing.expect(sess.from == null);
    try std.testing.expect(!sess.is_tls);
    try std.testing.expect(sess.client_domain == null);
    try std.testing.expectEqual(@as(usize, 0), sess.recipientCount());
}

test "session: setClientDomain transitions to ready" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("mail.example.com");
    try std.testing.expectEqual(smtp.ConnState.ready, sess.state);
    try std.testing.expectEqualStrings("mail.example.com", sess.client_domain.?);
}

test "session: setFrom transitions to mail state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("example.com");
    try sess.setFrom("sender@example.com");
    try std.testing.expectEqual(smtp.ConnState.mail, sess.state);
    try std.testing.expectEqualStrings("sender@example.com", sess.from.?);
}

test "session: addRecipient transitions to rcpt state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("example.com");
    try sess.setFrom("sender@example.com");
    try sess.addRecipient("rcpt@example.com");

    try std.testing.expectEqual(smtp.ConnState.rcpt, sess.state);
    try std.testing.expectEqual(@as(usize, 1), sess.recipientCount());
    try std.testing.expectEqualStrings("rcpt@example.com", sess.getRecipient(0));
}

test "session: multiple recipients" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("example.com");
    try sess.setFrom("sender@example.com");
    try sess.addRecipient("alice@example.com");
    try sess.addRecipient("bob@example.com");
    try sess.addRecipient("charlie@example.com");

    try std.testing.expectEqual(@as(usize, 3), sess.recipientCount());
    try std.testing.expectEqualStrings("alice@example.com", sess.getRecipient(0));
    try std.testing.expectEqualStrings("bob@example.com", sess.getRecipient(1));
    try std.testing.expectEqualStrings("charlie@example.com", sess.getRecipient(2));
}

test "session: reset clears transaction state but keeps connection" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("example.com");
    try sess.setFrom("sender@example.com");
    try sess.addRecipient("rcpt@example.com");

    sess.reset();
    try std.testing.expectEqual(smtp.ConnState.ready, sess.state);
    try std.testing.expect(sess.from == null);
    try std.testing.expectEqual(@as(usize, 0), sess.recipientCount());
    // Client domain should still be set.
    try std.testing.expectEqualStrings("example.com", sess.client_domain.?);
}

test "session: reset from connect state stays in connect" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    sess.reset();
    // In connect or greeted, reset does not change state.
    try std.testing.expectEqual(smtp.ConnState.connect, sess.state);
}

test "session: logout" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    sess.logout();
    try std.testing.expectEqual(smtp.ConnState.logout, sess.state);
}

test "session: setAuthenticated" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setAuthenticated("alice");
    try std.testing.expect(sess.authenticated);
    try std.testing.expectEqualStrings("alice", sess.username.?);
}

test "session: setAuthenticated replaces previous" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setAuthenticated("alice");
    try sess.setAuthenticated("bob");
    try std.testing.expectEqualStrings("bob", sess.username.?);
}

// ---------------------------------------------------------------------------
// canExecute
// ---------------------------------------------------------------------------

test "session: canExecute EHLO in connect state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try std.testing.expect(sess.canExecute("EHLO"));
    try std.testing.expect(sess.canExecute("HELO"));
    try std.testing.expect(sess.canExecute("QUIT"));
}

test "session: canExecute MAIL FROM only in ready state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try std.testing.expect(!sess.canExecute("MAIL FROM"));

    try sess.setClientDomain("example.com");
    try std.testing.expect(sess.canExecute("MAIL FROM"));
}

test "session: canExecute RCPT TO only in mail/rcpt state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try std.testing.expect(!sess.canExecute("RCPT TO"));

    try sess.setClientDomain("example.com");
    try std.testing.expect(!sess.canExecute("RCPT TO"));

    try sess.setFrom("sender@example.com");
    try std.testing.expect(sess.canExecute("RCPT TO"));
}

test "session: canExecute DATA only in rcpt state" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    try sess.setClientDomain("example.com");
    try sess.setFrom("sender@example.com");
    try std.testing.expect(!sess.canExecute("DATA"));

    try sess.addRecipient("rcpt@example.com");
    try std.testing.expect(sess.canExecute("DATA"));
}

// ---------------------------------------------------------------------------
// Full session flow
// ---------------------------------------------------------------------------

test "session: full SMTP transaction flow" {
    const allocator = std.testing.allocator;
    var sess = SessionState.init(allocator);
    defer sess.deinit();

    // EHLO
    try sess.setClientDomain("client.example.com");
    try std.testing.expectEqual(smtp.ConnState.ready, sess.state);

    // MAIL FROM
    try sess.setFrom("sender@example.com");
    try std.testing.expectEqual(smtp.ConnState.mail, sess.state);

    // RCPT TO
    try sess.addRecipient("rcpt1@example.com");
    try std.testing.expectEqual(smtp.ConnState.rcpt, sess.state);

    try sess.addRecipient("rcpt2@example.com");
    try std.testing.expectEqual(smtp.ConnState.rcpt, sess.state);
    try std.testing.expectEqual(@as(usize, 2), sess.recipientCount());

    // After DATA, reset for next transaction.
    sess.reset();
    try std.testing.expectEqual(smtp.ConnState.ready, sess.state);
    try std.testing.expect(sess.from == null);
    try std.testing.expectEqual(@as(usize, 0), sess.recipientCount());

    // QUIT
    sess.logout();
    try std.testing.expectEqual(smtp.ConnState.logout, sess.state);
}

// ---------------------------------------------------------------------------
// ExtensionManager tests
// ---------------------------------------------------------------------------

test "extension manager: register and get" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try mgr.register(.{
        .name = "TEST",
        .ehlo_keyword = "TEST",
    });

    const ext = mgr.get("TEST");
    try std.testing.expect(ext != null);
    try std.testing.expectEqualStrings("TEST", ext.?.name);
}

test "extension manager: duplicate registration fails" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try mgr.register(.{ .name = "TEST", .ehlo_keyword = "TEST" });

    const result = mgr.register(.{ .name = "TEST", .ehlo_keyword = "TEST" });
    try std.testing.expectError(error.DuplicateExtension, result);
}

test "extension manager: remove extension" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try mgr.register(.{ .name = "TEST", .ehlo_keyword = "TEST" });
    try std.testing.expect(mgr.remove("TEST"));
    try std.testing.expect(mgr.get("TEST") == null);
}

test "extension manager: remove nonexistent returns false" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try std.testing.expect(!mgr.remove("NOPE"));
}

test "extension manager: ehloKeywords collects all keywords" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try mgr.register(.{ .name = "8BITMIME", .ehlo_keyword = "8BITMIME" });
    try mgr.register(.{ .name = "SIZE", .ehlo_keyword = "SIZE 10485760" });
    try mgr.register(.{ .name = "NODISPLAY" }); // no ehlo_keyword

    const keywords = try mgr.ehloKeywords(allocator);
    defer allocator.free(keywords);

    try std.testing.expectEqual(@as(usize, 2), keywords.len);
}

test "extension manager: resolve empty" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    const resolved = try mgr.resolve(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqual(@as(usize, 0), resolved.len);
}

test "extension manager: resolve with dependencies" {
    const allocator = std.testing.allocator;
    var mgr = ExtensionManager.init(allocator);
    defer mgr.deinit();

    try mgr.register(.{
        .name = "REQUIRETLS",
        .ehlo_keyword = "REQUIRETLS",
        .dependencies = &.{"STARTTLS"},
    });
    try mgr.register(.{
        .name = "STARTTLS",
        .ehlo_keyword = "STARTTLS",
    });

    const resolved = try mgr.resolve(allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqual(@as(usize, 2), resolved.len);
    // STARTTLS must come before REQUIRETLS.
    var starttls_idx: ?usize = null;
    var requiretls_idx: ?usize = null;
    for (resolved, 0..) |ext, i| {
        if (std.mem.eql(u8, ext.name, "STARTTLS")) starttls_idx = i;
        if (std.mem.eql(u8, ext.name, "REQUIRETLS")) requiretls_idx = i;
    }
    try std.testing.expect(starttls_idx.? < requiretls_idx.?);
}

// ---------------------------------------------------------------------------
// Dispatcher tests
// ---------------------------------------------------------------------------

test "dispatcher: register and dispatch" {
    const allocator = std.testing.allocator;
    var dispatcher = Dispatcher.init(allocator);
    defer dispatcher.deinit();

    var handler_called = false;
    const HandlerState = struct {
        var called: *bool = undefined;

        fn handle(_: *CommandContext) anyerror!void {
            called.* = true;
        }
    };
    HandlerState.called = &handler_called;

    try dispatcher.register("EHLO", HandlerState.handle);
    try std.testing.expect(dispatcher.handlers.get("EHLO") != null);
}

test "dispatcher: setFallback" {
    const allocator = std.testing.allocator;
    var dispatcher = Dispatcher.init(allocator);
    defer dispatcher.deinit();

    const Fb = struct {
        fn handle(_: *CommandContext) anyerror!void {}
    };

    dispatcher.setFallback(Fb.handle);
    try std.testing.expect(dispatcher.fallback != null);
}

test "dispatcher: setMiddleware" {
    const allocator = std.testing.allocator;
    var dispatcher = Dispatcher.init(allocator);
    defer dispatcher.deinit();

    const Mw = struct {
        fn wrap(handler: *const fn (ctx: *CommandContext) anyerror!void) *const fn (ctx: *CommandContext) anyerror!void {
            return handler;
        }
    };

    dispatcher.setMiddleware(Mw.wrap);
    try std.testing.expect(dispatcher.middleware != null);
}

// ---------------------------------------------------------------------------
// Dispatcher: register multiple handlers
// ---------------------------------------------------------------------------

test "dispatcher: register multiple command handlers" {
    const allocator = std.testing.allocator;
    var dispatcher = Dispatcher.init(allocator);
    defer dispatcher.deinit();

    const H = struct {
        fn handle(_: *CommandContext) anyerror!void {}
    };

    try dispatcher.register("EHLO", H.handle);
    try dispatcher.register("MAIL FROM", H.handle);
    try dispatcher.register("RCPT TO", H.handle);
    try dispatcher.register("DATA", H.handle);
    try dispatcher.register("QUIT", H.handle);

    try std.testing.expect(dispatcher.handlers.get("EHLO") != null);
    try std.testing.expect(dispatcher.handlers.get("MAIL FROM") != null);
    try std.testing.expect(dispatcher.handlers.get("RCPT TO") != null);
    try std.testing.expect(dispatcher.handlers.get("DATA") != null);
    try std.testing.expect(dispatcher.handlers.get("QUIT") != null);
}
