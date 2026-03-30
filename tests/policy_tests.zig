const std = @import("std");
const smtp = @import("smtp");
const builtin = @import("builtin");

const PolicyEngine = smtp.server.PolicyEngine;
const SessionState = smtp.server.SessionState;
const PipeTransport = smtp.smtptest.PipeTransport;

fn dummyStream() std.net.Stream {
    return .{
        .handle = if (builtin.os.tag == .windows)
            std.os.windows.ws2_32.INVALID_SOCKET
        else
            @as(std.posix.fd_t, -1),
    };
}

test "policy: require authentication rejects unauthenticated senders" {
    const allocator = std.testing.allocator;
    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();

    var require_auth = smtp.server.policy.RequireAuthenticationPolicy{};
    try engine.use(require_auth.policy());

    var session = SessionState.init(allocator);
    defer session.deinit();

    const rejection = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .mail_from,
        .command = "MAIL FROM",
        .session = &session,
        .mail_from = "alice@example.com",
    });

    try std.testing.expect(rejection != null);
    try std.testing.expectEqual(@as(u16, 530), rejection.?.code);
}

test "policy: relay policy allows local delivery but blocks unauthenticated relay" {
    const allocator = std.testing.allocator;
    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();

    var relay = smtp.server.policy.RelayPolicy{
        .local_domains = &.{"example.com"},
    };
    try engine.use(relay.policy());

    var session = SessionState.init(allocator);
    defer session.deinit();

    const local_rejection = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .rcpt_to,
        .command = "RCPT TO",
        .session = &session,
        .rcpt_to = "bob@example.com",
    });
    try std.testing.expect(local_rejection == null);

    const relay_rejection = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .rcpt_to,
        .command = "RCPT TO",
        .session = &session,
        .rcpt_to = "bob@remote.test",
    });
    try std.testing.expect(relay_rejection != null);
    try std.testing.expectEqual(@as(u16, 550), relay_rejection.?.code);
}

test "policy: recipient validation policy delegates to callback" {
    const allocator = std.testing.allocator;
    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();

    const Validator = struct {
        fn validate(_: *anyopaque, recipient: []const u8, _: *const smtp.server.PolicyContext) anyerror!?smtp.server.PolicyRejection {
            if (std.mem.eql(u8, recipient, "blocked@example.com")) {
                return .{
                    .code = 550,
                    .message = "5.1.1 Unknown recipient",
                };
            }
            return null;
        }
    };

    var validator = smtp.server.policy.RecipientValidationPolicy{
        .context = undefined,
        .validate_fn = Validator.validate,
    };
    try engine.use(validator.policy());

    var session = SessionState.init(allocator);
    defer session.deinit();

    const rejection = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .rcpt_to,
        .command = "RCPT TO",
        .session = &session,
        .rcpt_to = "blocked@example.com",
    });
    try std.testing.expect(rejection != null);
    try std.testing.expectEqualStrings("5.1.1 Unknown recipient", rejection.?.message);
}

test "policy: rate limit policy tracks clients independently" {
    const allocator = std.testing.allocator;
    var rate_limit = smtp.server.policy.RateLimitPolicy.init(allocator, 2, 60_000);
    defer rate_limit.deinit();

    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();
    try engine.use(rate_limit.policy());

    var session = SessionState.init(allocator);
    defer session.deinit();

    try std.testing.expect((try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .command,
        .command = "NOOP",
        .client_id = "client-a",
        .timestamp_ms = 100,
        .session = &session,
    })) == null);
    try std.testing.expect((try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .command,
        .command = "NOOP",
        .client_id = "client-a",
        .timestamp_ms = 200,
        .session = &session,
    })) == null);

    const limited = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .command,
        .command = "NOOP",
        .client_id = "client-a",
        .timestamp_ms = 300,
        .session = &session,
    });
    try std.testing.expect(limited != null);
    try std.testing.expectEqual(@as(u16, 421), limited.?.code);

    try std.testing.expect((try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .command,
        .command = "NOOP",
        .client_id = "client-b",
        .timestamp_ms = 400,
        .session = &session,
    })) == null);
}

test "policy: mail auth policy can reject SPF and DMARC failures" {
    const allocator = std.testing.allocator;
    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();

    const Assessor = struct {
        fn assess(_: *anyopaque, _: *const smtp.server.PolicyContext) anyerror!smtp.server.policy.MailAuthAssessment {
            return .{
                .spf_result = .fail,
                .spf_domain = "example.com",
                .dkim_pass = false,
                .dkim_domain = null,
                .dmarc_record = .{ .policy = .reject },
            };
        }
    };

    var mail_auth = smtp.server.policy.MailAuthPolicy{
        .context = undefined,
        .assess_fn = Assessor.assess,
        .reject_on_spf_fail = true,
    };
    try engine.use(mail_auth.policy());

    var session = SessionState.init(allocator);
    defer session.deinit();

    const rejection = try engine.evaluate(&.{
        .allocator = allocator,
        .stage = .message,
        .command = "DATA",
        .session = &session,
        .mail_from = "alice@example.com",
        .message = "Subject: test\r\n\r\nhello\r\n",
    });

    try std.testing.expect(rejection != null);
    try std.testing.expectEqualStrings("5.7.1 SPF validation failed", rejection.?.message);
}

test "server: policy engine rejects relay recipients" {
    const allocator = std.testing.allocator;
    var store = smtp.store.MemStore.init(allocator);
    defer store.deinit();

    var relay = smtp.server.policy.RelayPolicy{
        .local_domains = &.{"example.com"},
    };
    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();
    try engine.use(relay.policy());

    var server = smtp.server.Server.initWithOptions(allocator, &store, .{
        .policy_engine = &engine,
    });

    var transport = PipeTransport.init(allocator);
    defer transport.deinit();
    try transport.feedInput(
        "EHLO client.example\r\n" ++
            "MAIL FROM:<alice@example.com>\r\n" ++
            "RCPT TO:<bob@remote.test>\r\n" ++
            "QUIT\r\n",
    );

    server.serveConnectionWithClientId(transport.transport(), dummyStream(), false, "198.51.100.10");

    try std.testing.expect(std.mem.indexOf(u8, transport.output.items, "550 5.7.1 Relay denied\r\n") != null);
}

test "server: policy engine can close a connection on rate limit" {
    const allocator = std.testing.allocator;
    var store = smtp.store.MemStore.init(allocator);
    defer store.deinit();

    var rate_limit = smtp.server.policy.RateLimitPolicy.init(allocator, 2, 60_000);
    defer rate_limit.deinit();

    var engine = PolicyEngine.init(allocator);
    defer engine.deinit();
    try engine.use(rate_limit.policy());

    var server = smtp.server.Server.initWithOptions(allocator, &store, .{
        .policy_engine = &engine,
    });

    var transport = PipeTransport.init(allocator);
    defer transport.deinit();
    try transport.feedInput("NOOP\r\nNOOP\r\nNOOP\r\n");

    server.serveConnectionWithClientId(transport.transport(), dummyStream(), false, "203.0.113.20");

    try std.testing.expect(std.mem.indexOf(u8, transport.output.items, "421 4.7.0 Rate limit exceeded\r\n") != null);
}
