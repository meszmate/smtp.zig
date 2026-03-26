const std = @import("std");
const smtp = @import("smtp");

const qp = smtp.mime.quoted_printable;
const base64 = smtp.mime.base64;
const headers = smtp.mime.headers;
const MessageBuilder = smtp.mime.MessageBuilder;

// ---------------------------------------------------------------------------
// Quoted-printable encoding
// ---------------------------------------------------------------------------

test "qp: encode basic ASCII passthrough" {
    const allocator = std.testing.allocator;
    const result = try qp.encodeAlloc(allocator, "Hello, World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "qp: encode equals sign" {
    const allocator = std.testing.allocator;
    const result = try qp.encodeAlloc(allocator, "a=b");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a=3Db", result);
}

test "qp: encode non-ASCII bytes" {
    const allocator = std.testing.allocator;
    const result = try qp.encodeAlloc(allocator, "\xC3\xA9");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("=C3=A9", result);
}

test "qp: encode preserves LF line breaks" {
    const allocator = std.testing.allocator;
    const result = try qp.encodeAlloc(allocator, "line1\nline2");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("line1\nline2", result);
}

test "qp: encode empty string" {
    const allocator = std.testing.allocator;
    const result = try qp.encodeAlloc(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Quoted-printable decoding
// ---------------------------------------------------------------------------

test "qp: decode basic hex sequences" {
    const allocator = std.testing.allocator;
    const result = try qp.decodeAlloc(allocator, "a=3Db=20c");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("a=b c", result);
}

test "qp: decode soft line break removal" {
    const allocator = std.testing.allocator;
    const result = try qp.decodeAlloc(allocator, "hello=\r\nworld");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("helloworld", result);
}

test "qp: decode passthrough non-encoded" {
    const allocator = std.testing.allocator;
    const result = try qp.decodeAlloc(allocator, "simple text");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("simple text", result);
}

test "qp: decode empty string" {
    const allocator = std.testing.allocator;
    const result = try qp.decodeAlloc(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Quoted-printable roundtrip
// ---------------------------------------------------------------------------

test "qp: roundtrip with non-ASCII content" {
    const allocator = std.testing.allocator;
    const original = "Subject: =?UTF-8?Q?Hello?= \xC3\xA9\xC3\xA0";
    const encoded = try qp.encodeAlloc(allocator, original);
    defer allocator.free(encoded);
    const decoded = try qp.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}

test "qp: roundtrip with pure ASCII" {
    const allocator = std.testing.allocator;
    const original = "This is plain ASCII text.";
    const encoded = try qp.encodeAlloc(allocator, original);
    defer allocator.free(encoded);
    const decoded = try qp.decodeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}

// ---------------------------------------------------------------------------
// Base64 MIME encoding
// ---------------------------------------------------------------------------

test "base64: encode short string" {
    const allocator = std.testing.allocator;
    const result = try base64.encodeMimeAlloc(allocator, "Hello, World!");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("SGVsbG8sIFdvcmxkIQ==", result);
}

test "base64: encode wraps at 76 characters" {
    const allocator = std.testing.allocator;
    const input = "This is a somewhat longer string that should produce base64 output exceeding seventy-six characters in length.";
    const result = try base64.encodeMimeAlloc(allocator, input);
    defer allocator.free(result);

    var iter = std.mem.splitSequence(u8, result, "\r\n");
    while (iter.next()) |line| {
        try std.testing.expect(line.len <= 76);
    }
}

test "base64: encode empty string" {
    const allocator = std.testing.allocator;
    const result = try base64.encodeMimeAlloc(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Base64 MIME decoding
// ---------------------------------------------------------------------------

test "base64: decode with line breaks" {
    const allocator = std.testing.allocator;
    const result = try base64.decodeMimeAlloc(allocator, "SGVs\r\nbG8s\r\nIFdvcmxkIQ==");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "base64: decode without line breaks" {
    const allocator = std.testing.allocator;
    const result = try base64.decodeMimeAlloc(allocator, "SGVsbG8sIFdvcmxkIQ==");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "base64: decode empty" {
    const allocator = std.testing.allocator;
    const result = try base64.decodeMimeAlloc(allocator, "");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Base64 MIME roundtrip
// ---------------------------------------------------------------------------

test "base64: roundtrip with binary data" {
    const allocator = std.testing.allocator;
    const original = "Binary data: \x00\x01\x02\xFF\xFE\xFD";
    const encoded = try base64.encodeMimeAlloc(allocator, original);
    defer allocator.free(encoded);
    const decoded = try base64.decodeMimeAlloc(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(original, decoded);
}

// ---------------------------------------------------------------------------
// Header encoding (RFC 2047)
// ---------------------------------------------------------------------------

test "headers: encodeWord ASCII passthrough" {
    const allocator = std.testing.allocator;
    const result = try headers.encodeWordAlloc(allocator, "Hello World", "UTF-8");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello World", result);
}

test "headers: encodeWord non-ASCII uses RFC 2047" {
    const allocator = std.testing.allocator;
    const result = try headers.encodeWordAlloc(allocator, "H\xC3\xA9llo", "UTF-8");
    defer allocator.free(result);
    try std.testing.expect(std.mem.startsWith(u8, result, "=?UTF-8?B?"));
    try std.testing.expect(std.mem.endsWith(u8, result, "?="));
}

test "headers: encodeWord empty string" {
    const allocator = std.testing.allocator;
    const result = try headers.encodeWordAlloc(allocator, "", "UTF-8");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Address formatting
// ---------------------------------------------------------------------------

test "headers: formatAddress with name" {
    const allocator = std.testing.allocator;
    const result = try headers.formatAddressAlloc(allocator, "John Doe", "john@example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("John Doe <john@example.com>", result);
}

test "headers: formatAddress without name" {
    const allocator = std.testing.allocator;
    const result = try headers.formatAddressAlloc(allocator, "", "john@example.com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john@example.com", result);
}

test "headers: formatAddress with non-ASCII name" {
    const allocator = std.testing.allocator;
    const result = try headers.formatAddressAlloc(allocator, "Jos\xC3\xA9", "jose@example.com");
    defer allocator.free(result);
    // Should use RFC 2047 encoding for the name.
    try std.testing.expect(std.mem.indexOf(u8, result, "=?UTF-8?B?") != null);
    try std.testing.expect(std.mem.endsWith(u8, result, "<jose@example.com>"));
}

// ---------------------------------------------------------------------------
// Address list formatting
// ---------------------------------------------------------------------------

test "headers: formatAddressList" {
    const allocator = std.testing.allocator;
    const addresses = [_][2][]const u8{
        .{ "Alice", "alice@example.com" },
        .{ "", "bob@example.com" },
    };
    const result = try headers.formatAddressListAlloc(allocator, &addresses);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Alice <alice@example.com>, bob@example.com", result);
}

test "headers: formatAddressList single address" {
    const allocator = std.testing.allocator;
    const addresses = [_][2][]const u8{
        .{ "Alice", "alice@example.com" },
    };
    const result = try headers.formatAddressListAlloc(allocator, &addresses);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Alice <alice@example.com>", result);
}

// ---------------------------------------------------------------------------
// Message-ID formatting
// ---------------------------------------------------------------------------

test "headers: formatMessageId structure" {
    const allocator = std.testing.allocator;
    const result = try headers.formatMessageIdAlloc(allocator, "example.com");
    defer allocator.free(result);
    try std.testing.expect(result[0] == '<');
    try std.testing.expect(result[result.len - 1] == '>');
    try std.testing.expect(std.mem.endsWith(u8, result, "@example.com>"));
    try std.testing.expect(std.mem.indexOf(u8, result, ".") != null);
}

test "headers: formatMessageId uniqueness" {
    const allocator = std.testing.allocator;
    const id1 = try headers.formatMessageIdAlloc(allocator, "test.com");
    defer allocator.free(id1);
    const id2 = try headers.formatMessageIdAlloc(allocator, "test.com");
    defer allocator.free(id2);
    // Two message IDs should be different (they include random bytes).
    try std.testing.expect(!std.mem.eql(u8, id1, id2));
}

// ---------------------------------------------------------------------------
// MessageBuilder
// ---------------------------------------------------------------------------

test "builder: basic message" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addFrom("sender@example.com");
    try builder.addTo("recipient@example.com");
    try builder.addSubject("Test Subject");
    try builder.addMimeVersion();
    try builder.addContentType("text/plain", "charset=UTF-8");
    try builder.addContentTransferEncoding("7bit");
    try builder.addBlankLine();
    try builder.addBody("Hello, World!");

    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "From: sender@example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "To: recipient@example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Subject: Test Subject\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "MIME-Version: 1.0\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: text/plain; charset=UTF-8\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Hello, World!") != null);
}

test "builder: multipart message" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addFrom("sender@example.com");
    try builder.addTo("recipient@example.com");
    try builder.addMimeVersion();
    try builder.startMultipart("mixed", "boundary123");
    try builder.addBlankLine();

    try builder.addPart("boundary123", "text/plain", "7bit", "Hello, plain text!");
    try builder.addPart("boundary123", "text/html", "7bit", "<p>Hello, HTML!</p>");
    try builder.endMultipart("boundary123");

    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "--boundary123\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "--boundary123--\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Hello, plain text!") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "<p>Hello, HTML!</p>") != null);
}

test "builder: addCc header" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addCc("cc@example.com");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "Cc: cc@example.com\r\n") != null);
}

test "builder: addContentDisposition with filename" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addContentDisposition("attachment", "report.pdf");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Disposition: attachment; filename=\"report.pdf\"\r\n") != null);
}

test "builder: addContentDisposition without filename" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addContentDisposition("inline", null);
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Disposition: inline\r\n") != null);
}

test "builder: addEncodedBody quoted-printable" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addEncodedBody("a=b", "quoted-printable");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "a=3Db") != null);
}

test "builder: addEncodedBody base64" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addEncodedBody("Hello", "base64");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "SGVsbG8=") != null);
}

test "builder: addEncodedBody unknown encoding passes through raw" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addEncodedBody("raw content", "unknown-encoding");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "raw content") != null);
}

test "builder: addSubject with non-ASCII uses RFC 2047" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addSubject("Caf\xC3\xA9");
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "Subject: =?UTF-8?B?") != null);
}

test "builder: addBlankLine produces CRLF" {
    const allocator = std.testing.allocator;
    var builder = MessageBuilder.init(allocator);
    defer builder.deinit();

    try builder.addBlankLine();
    const result = try builder.finish();
    defer allocator.free(result);

    try std.testing.expectEqualStrings("\r\n", result);
}
