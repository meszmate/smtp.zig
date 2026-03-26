const std = @import("std");
const smtp = @import("smtp");

const CapabilitySet = smtp.CapabilitySet;
const caps = smtp.caps;

// ---------------------------------------------------------------------------
// Capability parsing tests (client-side capability management)
// ---------------------------------------------------------------------------

test "client capability: has returns false for empty set" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();
    try std.testing.expect(!capset.has("8BITMIME"));
}

test "client capability: add and query multiple capabilities" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add(caps.@"8bitmime");
    try capset.add(caps.pipelining);
    try capset.add(caps.starttls);
    try capset.add(caps.smtputf8);

    try std.testing.expect(capset.has(caps.@"8bitmime"));
    try std.testing.expect(capset.has(caps.pipelining));
    try std.testing.expect(capset.has(caps.starttls));
    try std.testing.expect(capset.has(caps.smtputf8));
    try std.testing.expect(!capset.has(caps.chunking));
}

test "client capability: case-insensitive lookup" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("AUTH PLAIN LOGIN");
    try std.testing.expect(capset.has("AUTH PLAIN LOGIN"));
    try std.testing.expect(capset.has("auth plain login"));
    try std.testing.expect(capset.has("Auth Plain Login"));
}

test "client capability: getMaxSize from EHLO response" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("SIZE 52428800");
    const max = capset.getMaxSize().?;
    try std.testing.expectEqual(@as(u64, 52428800), max);
}

test "client capability: getAuthMechanisms from EHLO response" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("AUTH PLAIN LOGIN XOAUTH2");
    const mechs = try capset.getAuthMechanisms(allocator);
    defer {
        for (mechs) |m| allocator.free(m);
        allocator.free(mechs);
    }

    try std.testing.expectEqual(@as(usize, 3), mechs.len);
    try std.testing.expectEqualStrings("PLAIN", mechs[0]);
    try std.testing.expectEqualStrings("LOGIN", mechs[1]);
    try std.testing.expectEqualStrings("XOAUTH2", mechs[2]);
}

test "client capability: slice returns all values" {
    const allocator = std.testing.allocator;
    var capset = CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("A");
    try capset.add("B");
    try capset.add("C");

    const s = capset.slice();
    try std.testing.expectEqual(@as(usize, 3), s.len);
}

// ---------------------------------------------------------------------------
// Capability constants
// ---------------------------------------------------------------------------

test "client capability: cap constants" {
    try std.testing.expectEqualStrings("8BITMIME", caps.@"8bitmime");
    try std.testing.expectEqualStrings("STARTTLS", caps.starttls);
    try std.testing.expectEqualStrings("SIZE", caps.size);
    try std.testing.expectEqualStrings("AUTH", caps.auth);
    try std.testing.expectEqualStrings("AUTH PLAIN", caps.auth_plain);
    try std.testing.expectEqualStrings("AUTH LOGIN", caps.auth_login);
    try std.testing.expectEqualStrings("AUTH CRAM-MD5", caps.auth_cram_md5);
    try std.testing.expectEqualStrings("AUTH XOAUTH2", caps.auth_xoauth2);
    try std.testing.expectEqualStrings("PIPELINING", caps.pipelining);
    try std.testing.expectEqualStrings("CHUNKING", caps.chunking);
    try std.testing.expectEqualStrings("BINARYMIME", caps.binarymime);
    try std.testing.expectEqualStrings("DSN", caps.dsn);
    try std.testing.expectEqualStrings("ENHANCEDSTATUSCODES", caps.enhancedstatuscodes);
    try std.testing.expectEqualStrings("SMTPUTF8", caps.smtputf8);
}

// ---------------------------------------------------------------------------
// Response reading (via response module)
// ---------------------------------------------------------------------------

test "client response: parse success response line" {
    const parsed = try smtp.parseResponseLine("250 2.1.0 Sender OK");
    try std.testing.expectEqual(@as(u16, 250), parsed.code);
    try std.testing.expect(!parsed.more);
    try std.testing.expectEqualStrings("2.1.0 Sender OK", parsed.text);
}

test "client response: parse multiline response line" {
    const parsed = try smtp.parseResponseLine("250-SIZE 10485760");
    try std.testing.expectEqual(@as(u16, 250), parsed.code);
    try std.testing.expect(parsed.more);
    try std.testing.expectEqualStrings("SIZE 10485760", parsed.text);
}

test "client response: parse auth continue" {
    const parsed = try smtp.parseResponseLine("334 VXNlcm5hbWU6");
    try std.testing.expectEqual(@as(u16, 334), parsed.code);
    try std.testing.expectEqualStrings("VXNlcm5hbWU6", parsed.text);
}

test "client response: parse service ready" {
    const parsed = try smtp.parseResponseLine("220 mail.example.com ESMTP Postfix");
    try std.testing.expectEqual(@as(u16, 220), parsed.code);
    try std.testing.expect(!parsed.more);
}

// ---------------------------------------------------------------------------
// Client options / pool options structures
// ---------------------------------------------------------------------------

test "client options: default values" {
    const opts = smtp.client.Options{};
    try std.testing.expect(!opts.debug_log);
    try std.testing.expect(opts.tls_options == null);
}

test "pool options: default values" {
    const opts = smtp.client.PoolOptions{
        .host = "mail.example.com",
    };
    try std.testing.expectEqual(@as(u16, 25), opts.port);
    try std.testing.expectEqual(@as(u16, 4), opts.max_idle);
    try std.testing.expect(opts.username == null);
    try std.testing.expect(opts.password == null);
    try std.testing.expect(opts.dial_fn == null);
}

// ---------------------------------------------------------------------------
// MailOptions and RcptOptions defaults
// ---------------------------------------------------------------------------

test "client: MailOptions defaults" {
    const opts = smtp.MailOptions{};
    try std.testing.expect(opts.size == null);
    try std.testing.expect(opts.body == null);
    try std.testing.expect(!opts.smtputf8);
    try std.testing.expect(opts.ret == null);
    try std.testing.expect(opts.envid == null);
    try std.testing.expect(opts.auth == null);
}

test "client: RcptOptions defaults" {
    const opts = smtp.RcptOptions{};
    try std.testing.expectEqual(@as(usize, 0), opts.notify.len);
    try std.testing.expect(opts.orcpt == null);
}

// ---------------------------------------------------------------------------
// Encoder for building client commands
// ---------------------------------------------------------------------------

test "client: build MAIL FROM command with options" {
    const allocator = std.testing.allocator;
    var enc = smtp.wire.Encoder.init(allocator);
    defer enc.deinit();

    try enc.command("MAIL FROM:");
    try enc.angleBracket("sender@example.com");
    try enc.param("SIZE", "1024");
    try enc.param("BODY", smtp.BodyType.@"8bitmime".label());
    try enc.crlf();

    const result = try enc.finish();
    defer allocator.free(result);

    try std.testing.expectEqualStrings("MAIL FROM:<sender@example.com> SIZE=1024 BODY=8BITMIME\r\n", result);
}

test "client: build RCPT TO command with DSN" {
    const allocator = std.testing.allocator;
    var enc = smtp.wire.Encoder.init(allocator);
    defer enc.deinit();

    try enc.command("RCPT TO:");
    try enc.angleBracket("user@example.com");
    try enc.atom(" NOTIFY=");
    try enc.atom(smtp.DsnNotify.success.label());
    try enc.atom(",");
    try enc.atom(smtp.DsnNotify.failure.label());
    try enc.crlf();

    const result = try enc.finish();
    defer allocator.free(result);

    try std.testing.expectEqualStrings("RCPT TO:<user@example.com> NOTIFY=SUCCESS,FAILURE\r\n", result);
}
