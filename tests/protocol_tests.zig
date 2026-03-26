const std = @import("std");
const smtp = @import("smtp");

const Encoder = smtp.wire.Encoder;

// ---------------------------------------------------------------------------
// Encoder tests
// ---------------------------------------------------------------------------

test "encoder: atom appends raw string" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.atom("HELLO");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("HELLO", result);
}

test "encoder: sp appends space" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.atom("A");
    try enc.sp();
    try enc.atom("B");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("A B", result);
}

test "encoder: crlf appends carriage return and newline" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.atom("OK");
    try enc.crlf();
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("OK\r\n", result);
}

test "encoder: command writes command name" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.command("EHLO");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("EHLO", result);
}

test "encoder: param writes key=value with leading space" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.command("MAIL FROM:<user@example.com>");
    try enc.param("SIZE", "1024");
    try enc.crlf();
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("MAIL FROM:<user@example.com> SIZE=1024\r\n", result);
}

test "encoder: angleBracket wraps in angle brackets" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.angleBracket("user@example.com");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<user@example.com>", result);
}

test "encoder: angleBracket with empty address (bounce)" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.angleBracket("");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("<>", result);
}

test "encoder: dotStuff inserts dot for lines starting with dot" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.dotStuff(".hidden\nnormal\n.also hidden");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("..hidden\nnormal\n..also hidden", result);
}

test "encoder: dotStuff with no dots passes through" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.dotStuff("hello\nworld\n");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello\nworld\n", result);
}

test "encoder: dotStuff with dot not at line start" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.dotStuff("a.b.c");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a.b.c", result);
}

test "encoder: base64 encodes correctly" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.base64("Hello");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("SGVsbG8=", result);
}

test "encoder: base64 empty input" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.base64("");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "encoder: finish returns owned slice and clears" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.atom("first");
    const r1 = try enc.finish();
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("first", r1);

    // After finish, encoder is empty; new content can be built.
    try enc.atom("second");
    const r2 = try enc.finish();
    defer allocator.free(r2);
    try std.testing.expectEqualStrings("second", r2);
}

test "encoder: clear resets buffer" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.atom("discard");
    enc.clear();
    try enc.atom("keep");
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("keep", result);
}

test "encoder: dataTerminator writes dot crlf" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.dataTerminator();
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings(".\r\n", result);
}

test "encoder: full EHLO command construction" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.command("EHLO");
    try enc.sp();
    try enc.atom("mail.example.com");
    try enc.crlf();
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("EHLO mail.example.com\r\n", result);
}

test "encoder: full MAIL FROM with multiple params" {
    const allocator = std.testing.allocator;
    var enc = Encoder.init(allocator);
    defer enc.deinit();
    try enc.command("MAIL FROM:");
    try enc.angleBracket("sender@example.com");
    try enc.param("SIZE", "5000");
    try enc.param("BODY", "8BITMIME");
    try enc.crlf();
    const result = try enc.finish();
    defer allocator.free(result);
    try std.testing.expectEqualStrings("MAIL FROM:<sender@example.com> SIZE=5000 BODY=8BITMIME\r\n", result);
}

// ---------------------------------------------------------------------------
// Response parsing tests
// ---------------------------------------------------------------------------

test "response: parseResponseLine simple 250 ok" {
    const parsed = try smtp.parseResponseLine("250 OK");
    try std.testing.expectEqual(@as(u16, 250), parsed.code);
    try std.testing.expectEqual(false, parsed.more);
    try std.testing.expectEqualStrings("OK", parsed.text);
}

test "response: parseResponseLine multiline continuation" {
    const parsed = try smtp.parseResponseLine("250-mail.example.com");
    try std.testing.expectEqual(@as(u16, 250), parsed.code);
    try std.testing.expectEqual(true, parsed.more);
    try std.testing.expectEqualStrings("mail.example.com", parsed.text);
}

test "response: parseResponseLine code only no text" {
    const parsed = try smtp.parseResponseLine("220");
    try std.testing.expectEqual(@as(u16, 220), parsed.code);
    try std.testing.expectEqual(false, parsed.more);
    try std.testing.expectEqualStrings("", parsed.text);
}

test "response: parseResponseLine 220 service ready with text" {
    const parsed = try smtp.parseResponseLine("220 mail.example.com ESMTP");
    try std.testing.expectEqual(@as(u16, 220), parsed.code);
    try std.testing.expectEqual(false, parsed.more);
    try std.testing.expectEqualStrings("mail.example.com ESMTP", parsed.text);
}

test "response: parseResponseLine 354 start mail input" {
    const parsed = try smtp.parseResponseLine("354 Start mail input");
    try std.testing.expectEqual(@as(u16, 354), parsed.code);
    try std.testing.expectEqualStrings("Start mail input", parsed.text);
}

test "response: parseResponseLine 500 error" {
    const parsed = try smtp.parseResponseLine("500 Syntax error");
    try std.testing.expectEqual(@as(u16, 500), parsed.code);
    try std.testing.expectEqualStrings("Syntax error", parsed.text);
}

test "response: parseResponseLine too short returns error" {
    const result = smtp.parseResponseLine("25");
    try std.testing.expectError(error.InvalidResponseLine, result);
}

test "response: parseResponseLine invalid code returns error" {
    const result = smtp.parseResponseLine("ABC OK");
    try std.testing.expectError(error.InvalidResponseLine, result);
}

test "response: parseResponseLine empty string returns error" {
    const result = smtp.parseResponseLine("");
    try std.testing.expectError(error.InvalidResponseLine, result);
}

test "response: parseResponseLine with space separator and empty text" {
    const parsed = try smtp.parseResponseLine("250 ");
    try std.testing.expectEqual(@as(u16, 250), parsed.code);
    try std.testing.expectEqual(false, parsed.more);
    try std.testing.expectEqualStrings("", parsed.text);
}

// ---------------------------------------------------------------------------
// Enhanced code parsing tests
// ---------------------------------------------------------------------------

test "response: parseEnhancedCode success code" {
    const result = smtp.parseEnhancedCode("2.1.0 Sender OK").?;
    try std.testing.expectEqual(@as(u8, 2), result.code.class);
    try std.testing.expectEqual(@as(u16, 1), result.code.subject);
    try std.testing.expectEqual(@as(u16, 0), result.code.detail);
    try std.testing.expectEqualStrings("Sender OK", result.rest);
}

test "response: parseEnhancedCode permanent failure" {
    const result = smtp.parseEnhancedCode("5.1.1 Bad mailbox").?;
    try std.testing.expectEqual(@as(u8, 5), result.code.class);
    try std.testing.expectEqual(@as(u16, 1), result.code.subject);
    try std.testing.expectEqual(@as(u16, 1), result.code.detail);
    try std.testing.expectEqualStrings("Bad mailbox", result.rest);
}

test "response: parseEnhancedCode transient failure" {
    const result = smtp.parseEnhancedCode("4.2.2 Mailbox full").?;
    try std.testing.expectEqual(@as(u8, 4), result.code.class);
    try std.testing.expectEqual(@as(u16, 2), result.code.subject);
    try std.testing.expectEqual(@as(u16, 2), result.code.detail);
    try std.testing.expectEqualStrings("Mailbox full", result.rest);
}

test "response: parseEnhancedCode no enhanced code returns null" {
    const result = smtp.parseEnhancedCode("OK");
    try std.testing.expect(result == null);
}

test "response: parseEnhancedCode invalid class returns null" {
    const result = smtp.parseEnhancedCode("3.1.0 Invalid");
    try std.testing.expect(result == null);
}

test "response: parseEnhancedCode too short returns null" {
    const result = smtp.parseEnhancedCode("2.1");
    try std.testing.expect(result == null);
}

test "response: parseEnhancedCode multi-digit subject and detail" {
    const result = smtp.parseEnhancedCode("5.12.345 Extended error").?;
    try std.testing.expectEqual(@as(u8, 5), result.code.class);
    try std.testing.expectEqual(@as(u16, 12), result.code.subject);
    try std.testing.expectEqual(@as(u16, 345), result.code.detail);
    try std.testing.expectEqualStrings("Extended error", result.rest);
}

test "response: parseEnhancedCode no text after code" {
    const result = smtp.parseEnhancedCode("2.0.0").?;
    try std.testing.expectEqual(@as(u8, 2), result.code.class);
    try std.testing.expectEqual(@as(u16, 0), result.code.subject);
    try std.testing.expectEqual(@as(u16, 0), result.code.detail);
    try std.testing.expectEqualStrings("", result.rest);
}

// ---------------------------------------------------------------------------
// SmtpResponse classification tests
// ---------------------------------------------------------------------------

test "response: SmtpResponse.isSuccess for 2xx codes" {
    const r = smtp.SmtpResponse{ .code = 250 };
    try std.testing.expect(r.isSuccess());
    try std.testing.expect(!r.isFailure());
    try std.testing.expect(!r.isIntermediate());
}

test "response: SmtpResponse.isIntermediate for 3xx codes" {
    const r = smtp.SmtpResponse{ .code = 354 };
    try std.testing.expect(r.isIntermediate());
    try std.testing.expect(!r.isSuccess());
}

test "response: SmtpResponse.isTransientFailure for 4xx codes" {
    const r = smtp.SmtpResponse{ .code = 450 };
    try std.testing.expect(r.isTransientFailure());
    try std.testing.expect(r.isFailure());
    try std.testing.expect(!r.isPermanentFailure());
}

test "response: SmtpResponse.isPermanentFailure for 5xx codes" {
    const r = smtp.SmtpResponse{ .code = 550 };
    try std.testing.expect(r.isPermanentFailure());
    try std.testing.expect(r.isFailure());
    try std.testing.expect(!r.isTransientFailure());
}

// ---------------------------------------------------------------------------
// Response codes constants
// ---------------------------------------------------------------------------

test "response: code constants have expected values" {
    try std.testing.expectEqual(@as(u16, 220), smtp.response_codes.service_ready);
    try std.testing.expectEqual(@as(u16, 221), smtp.response_codes.service_closing);
    try std.testing.expectEqual(@as(u16, 235), smtp.response_codes.auth_success);
    try std.testing.expectEqual(@as(u16, 250), smtp.response_codes.ok);
    try std.testing.expectEqual(@as(u16, 334), smtp.response_codes.auth_continue);
    try std.testing.expectEqual(@as(u16, 354), smtp.response_codes.start_mail_input);
    try std.testing.expectEqual(@as(u16, 500), smtp.response_codes.syntax_error);
    try std.testing.expectEqual(@as(u16, 535), smtp.response_codes.auth_failed);
    try std.testing.expectEqual(@as(u16, 554), smtp.response_codes.transaction_failed);
}

// ---------------------------------------------------------------------------
// Capability tests
// ---------------------------------------------------------------------------

test "capability: add and has" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("8BITMIME");
    try std.testing.expect(capset.has("8BITMIME"));
    try std.testing.expect(capset.has("8bitmime")); // case-insensitive
    try std.testing.expect(!capset.has("PIPELINING"));
}

test "capability: addMany" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.addMany(&.{ "8BITMIME", "PIPELINING", "SIZE 10485760" });
    try std.testing.expect(capset.has("8BITMIME"));
    try std.testing.expect(capset.has("PIPELINING"));
    try std.testing.expect(capset.has("SIZE 10485760"));
}

test "capability: remove" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("STARTTLS");
    try std.testing.expect(capset.has("STARTTLS"));
    try std.testing.expect(capset.remove("STARTTLS"));
    try std.testing.expect(!capset.has("STARTTLS"));
    try std.testing.expect(!capset.remove("STARTTLS")); // already removed
}

test "capability: clear removes all" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.addMany(&.{ "A", "B", "C" });
    capset.clear();
    try std.testing.expect(!capset.has("A"));
    try std.testing.expect(!capset.has("B"));
    try std.testing.expectEqual(@as(usize, 0), capset.slice().len);
}

test "capability: duplicate add is idempotent" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("8BITMIME");
    try capset.add("8BITMIME");
    try std.testing.expectEqual(@as(usize, 1), capset.slice().len);
}

test "capability: getMaxSize parses SIZE value" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("SIZE 10485760");
    const max = capset.getMaxSize().?;
    try std.testing.expectEqual(@as(u64, 10485760), max);
}

test "capability: getMaxSize with bare SIZE returns 0" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("SIZE");
    const max = capset.getMaxSize().?;
    try std.testing.expectEqual(@as(u64, 0), max);
}

test "capability: getMaxSize returns null when not present" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("8BITMIME");
    try std.testing.expect(capset.getMaxSize() == null);
}

test "capability: getAuthMechanisms" {
    const allocator = std.testing.allocator;
    var capset = smtp.CapabilitySet.init(allocator);
    defer capset.deinit();

    try capset.add("AUTH PLAIN LOGIN CRAM-MD5");
    const mechs = try capset.getAuthMechanisms(allocator);
    defer {
        for (mechs) |m| allocator.free(m);
        allocator.free(mechs);
    }

    try std.testing.expectEqual(@as(usize, 3), mechs.len);
    try std.testing.expectEqualStrings("PLAIN", mechs[0]);
    try std.testing.expectEqualStrings("LOGIN", mechs[1]);
    try std.testing.expectEqualStrings("CRAM-MD5", mechs[2]);
}

// ---------------------------------------------------------------------------
// Command names tests
// ---------------------------------------------------------------------------

test "command: names have expected values" {
    try std.testing.expectEqualStrings("EHLO", smtp.commands.ehlo);
    try std.testing.expectEqualStrings("HELO", smtp.commands.helo);
    try std.testing.expectEqualStrings("MAIL FROM", smtp.commands.mail_from);
    try std.testing.expectEqualStrings("RCPT TO", smtp.commands.rcpt_to);
    try std.testing.expectEqualStrings("DATA", smtp.commands.data);
    try std.testing.expectEqualStrings("QUIT", smtp.commands.quit);
    try std.testing.expectEqualStrings("RSET", smtp.commands.rset);
    try std.testing.expectEqualStrings("NOOP", smtp.commands.noop);
    try std.testing.expectEqualStrings("AUTH", smtp.commands.auth);
    try std.testing.expectEqualStrings("STARTTLS", smtp.commands.starttls);
}

// ---------------------------------------------------------------------------
// Types tests
// ---------------------------------------------------------------------------

test "types: enhanced_codes constants" {
    try std.testing.expectEqual(@as(u8, 2), smtp.enhanced_codes.success.class);
    try std.testing.expectEqual(@as(u16, 0), smtp.enhanced_codes.success.subject);
    try std.testing.expectEqual(@as(u16, 0), smtp.enhanced_codes.success.detail);

    try std.testing.expectEqual(@as(u8, 5), smtp.enhanced_codes.bad_dest_mailbox.class);
    try std.testing.expectEqual(@as(u16, 1), smtp.enhanced_codes.bad_dest_mailbox.subject);
    try std.testing.expectEqual(@as(u16, 1), smtp.enhanced_codes.bad_dest_mailbox.detail);
}

test "types: ConnState labels" {
    try std.testing.expectEqualStrings("connect", smtp.ConnState.connect.label());
    try std.testing.expectEqualStrings("greeted", smtp.ConnState.greeted.label());
    try std.testing.expectEqualStrings("ready", smtp.ConnState.ready.label());
    try std.testing.expectEqualStrings("mail", smtp.ConnState.mail.label());
    try std.testing.expectEqualStrings("rcpt", smtp.ConnState.rcpt.label());
    try std.testing.expectEqualStrings("data", smtp.ConnState.data.label());
    try std.testing.expectEqualStrings("logout", smtp.ConnState.logout.label());
}

test "types: DsnNotify labels" {
    try std.testing.expectEqualStrings("NEVER", smtp.DsnNotify.never.label());
    try std.testing.expectEqualStrings("SUCCESS", smtp.DsnNotify.success.label());
    try std.testing.expectEqualStrings("FAILURE", smtp.DsnNotify.failure.label());
    try std.testing.expectEqualStrings("DELAY", smtp.DsnNotify.delay.label());
}

test "types: BodyType labels" {
    try std.testing.expectEqualStrings("7BIT", smtp.BodyType.@"7bit".label());
    try std.testing.expectEqualStrings("8BITMIME", smtp.BodyType.@"8bitmime".label());
    try std.testing.expectEqualStrings("BINARYMIME", smtp.BodyType.binarymime.label());
}

test "types: DsnReturn labels" {
    try std.testing.expectEqualStrings("FULL", smtp.DsnReturn.full.label());
    try std.testing.expectEqualStrings("HDRS", smtp.DsnReturn.hdrs.label());
}

test "types: TransferEncoding labels" {
    try std.testing.expectEqualStrings("7bit", smtp.TransferEncoding.@"7bit".label());
    try std.testing.expectEqualStrings("quoted-printable", smtp.TransferEncoding.quoted_printable.label());
    try std.testing.expectEqualStrings("base64", smtp.TransferEncoding.base64.label());
}

test "types: ContentDisposition labels" {
    try std.testing.expectEqualStrings("inline", smtp.ContentDisposition.inline_disp.label());
    try std.testing.expectEqualStrings("attachment", smtp.ContentDisposition.attachment.label());
}

test "types: Address formatAlloc with name" {
    const allocator = std.testing.allocator;
    const addr = smtp.Address{ .name = "John", .mailbox = "john", .host = "example.com" };
    const result = try addr.formatAlloc(allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("John <john@example.com>", result);
}

test "types: Address formatAlloc without name" {
    const allocator = std.testing.allocator;
    const addr = smtp.Address{ .mailbox = "john", .host = "example.com" };
    const result = try addr.formatAlloc(allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john@example.com", result);
}

test "types: Address emailAlloc" {
    const allocator = std.testing.allocator;
    const addr = smtp.Address{ .name = "John", .mailbox = "john", .host = "example.com" };
    const result = try addr.emailAlloc(allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john@example.com", result);
}

test "types: SMTPError factory functions" {
    const e500 = smtp.SMTPError.err500("bad");
    try std.testing.expectEqual(@as(u16, 500), e500.code);
    try std.testing.expectEqualStrings("bad", e500.text);

    const e421 = smtp.SMTPError.err421("going away");
    try std.testing.expectEqual(@as(u16, 421), e421.code);

    const e550 = smtp.SMTPError.err550("no such user");
    try std.testing.expectEqual(@as(u16, 550), e550.code);
}
