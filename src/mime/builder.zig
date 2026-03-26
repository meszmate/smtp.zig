const std = @import("std");
const Allocator = std.mem.Allocator;
const headers = @import("headers.zig");
const quoted_printable = @import("quoted_printable.zig");
const base64 = @import("base64.zig");

/// MIME message builder for constructing RFC 5322 compliant email messages.
pub const MessageBuilder = struct {
    allocator: Allocator,
    output: std.array_list.Managed(u8),

    /// Initialize a new MessageBuilder.
    pub fn init(allocator: Allocator) MessageBuilder {
        return .{
            .allocator = allocator,
            .output = std.array_list.Managed(u8).init(allocator),
        };
    }

    /// Free all resources used by the builder.
    pub fn deinit(self: *MessageBuilder) void {
        self.output.deinit();
    }

    /// Add a header with proper line folding at 78 characters.
    /// Writes "Name: value\r\n", folding long lines with \r\n followed by a space.
    pub fn addHeader(self: *MessageBuilder, name: []const u8, value: []const u8) !void {
        // Build the full header line: "Name: value"
        const prefix_len = name.len + 2; // "Name: "
        try self.output.appendSlice(name);
        try self.output.appendSlice(": ");

        const max_line = 78;
        var line_len = prefix_len;

        for (value) |byte| {
            if (line_len >= max_line and byte == ' ') {
                // Fold at space boundary
                try self.output.appendSlice("\r\n ");
                line_len = 1;
                continue;
            }
            try self.output.append(byte);
            line_len += 1;
        }

        try self.output.appendSlice("\r\n");
    }

    /// Add a From header.
    pub fn addFrom(self: *MessageBuilder, email: []const u8) !void {
        try self.addHeader("From", email);
    }

    /// Add a To header.
    pub fn addTo(self: *MessageBuilder, email: []const u8) !void {
        try self.addHeader("To", email);
    }

    /// Add a Cc header.
    pub fn addCc(self: *MessageBuilder, email: []const u8) !void {
        try self.addHeader("Cc", email);
    }

    /// Add a Subject header, encoding with RFC 2047 if necessary.
    pub fn addSubject(self: *MessageBuilder, subject: []const u8) !void {
        const encoded = try headers.encodeWordAlloc(self.allocator, subject, "UTF-8");
        defer self.allocator.free(encoded);
        try self.addHeader("Subject", encoded);
    }

    /// Add a Date header with the current date/time.
    pub fn addDate(self: *MessageBuilder) !void {
        const date = try headers.formatDateAlloc(self.allocator);
        defer self.allocator.free(date);
        try self.addHeader("Date", date);
    }

    /// Add a Message-ID header.
    pub fn addMessageId(self: *MessageBuilder, domain: []const u8) !void {
        const msg_id = try headers.formatMessageIdAlloc(self.allocator, domain);
        defer self.allocator.free(msg_id);
        try self.addHeader("Message-ID", msg_id);
    }

    /// Add the MIME-Version header (always "1.0").
    pub fn addMimeVersion(self: *MessageBuilder) !void {
        try self.output.appendSlice("MIME-Version: 1.0\r\n");
    }

    /// Add a Content-Type header with optional parameters.
    /// Example: addContentType("text/plain", "charset=UTF-8")
    ///   -> "Content-Type: text/plain; charset=UTF-8\r\n"
    pub fn addContentType(self: *MessageBuilder, content_type: []const u8, params_opt: ?[]const u8) !void {
        if (params_opt) |params| {
            var buf = std.array_list.Managed(u8).init(self.allocator);
            defer buf.deinit();
            try buf.appendSlice(content_type);
            try buf.appendSlice("; ");
            try buf.appendSlice(params);
            try self.addHeader("Content-Type", buf.items);
        } else {
            try self.addHeader("Content-Type", content_type);
        }
    }

    /// Add a Content-Transfer-Encoding header.
    pub fn addContentTransferEncoding(self: *MessageBuilder, encoding: []const u8) !void {
        try self.addHeader("Content-Transfer-Encoding", encoding);
    }

    /// Add a Content-Disposition header with optional filename.
    pub fn addContentDisposition(self: *MessageBuilder, disposition: []const u8, filename_opt: ?[]const u8) !void {
        if (filename_opt) |filename| {
            var buf = std.array_list.Managed(u8).init(self.allocator);
            defer buf.deinit();
            try buf.appendSlice(disposition);
            try buf.appendSlice("; filename=\"");
            try buf.appendSlice(filename);
            try buf.append('"');
            try self.addHeader("Content-Disposition", buf.items);
        } else {
            try self.addHeader("Content-Disposition", disposition);
        }
    }

    /// Add a blank line to separate headers from body.
    pub fn addBlankLine(self: *MessageBuilder) !void {
        try self.output.appendSlice("\r\n");
    }

    /// Add raw body text (no encoding applied).
    pub fn addBody(self: *MessageBuilder, text: []const u8) !void {
        try self.output.appendSlice(text);
    }

    /// Add body text encoded with the specified encoding.
    /// Supported encodings: "quoted-printable", "base64".
    pub fn addEncodedBody(self: *MessageBuilder, text: []const u8, encoding: []const u8) !void {
        if (std.mem.eql(u8, encoding, "quoted-printable")) {
            const encoded = try quoted_printable.encodeAlloc(self.allocator, text);
            defer self.allocator.free(encoded);
            try self.output.appendSlice(encoded);
        } else if (std.mem.eql(u8, encoding, "base64")) {
            const encoded = try base64.encodeMimeAlloc(self.allocator, text);
            defer self.allocator.free(encoded);
            try self.output.appendSlice(encoded);
        } else {
            // Unknown encoding - write raw
            try self.output.appendSlice(text);
        }
    }

    /// Start a multipart message with the given subtype and boundary.
    /// Sets Content-Type to multipart/subtype; boundary="boundary".
    pub fn startMultipart(self: *MessageBuilder, subtype: []const u8, boundary: []const u8) !void {
        var buf = std.array_list.Managed(u8).init(self.allocator);
        defer buf.deinit();
        try buf.appendSlice("multipart/");
        try buf.appendSlice(subtype);
        const ct = try self.allocator.dupe(u8, buf.items);
        defer self.allocator.free(ct);

        var params_buf = std.array_list.Managed(u8).init(self.allocator);
        defer params_buf.deinit();
        try params_buf.appendSlice("boundary=\"");
        try params_buf.appendSlice(boundary);
        try params_buf.append('"');
        const params = try self.allocator.dupe(u8, params_buf.items);
        defer self.allocator.free(params);

        try self.addContentType(ct, params);
    }

    /// Add a MIME part within a multipart message.
    /// Writes the boundary, part headers, and encoded body.
    pub fn addPart(
        self: *MessageBuilder,
        boundary: []const u8,
        content_type: []const u8,
        encoding: []const u8,
        body: []const u8,
    ) !void {
        // Write boundary
        try self.output.appendSlice("--");
        try self.output.appendSlice(boundary);
        try self.output.appendSlice("\r\n");

        // Write part headers
        try self.addContentType(content_type, null);
        try self.addContentTransferEncoding(encoding);
        try self.addBlankLine();

        // Write encoded body
        try self.addEncodedBody(body, encoding);
        try self.output.appendSlice("\r\n");
    }

    /// Write the final multipart boundary.
    pub fn endMultipart(self: *MessageBuilder, boundary: []const u8) !void {
        try self.output.appendSlice("--");
        try self.output.appendSlice(boundary);
        try self.output.appendSlice("--\r\n");
    }

    /// Return the built message as an owned slice. The caller owns the memory.
    /// After calling finish(), the builder's internal buffer is consumed.
    pub fn finish(self: *MessageBuilder) ![]u8 {
        return self.output.toOwnedSlice();
    }
};

test "basic message" {
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
    try std.testing.expect(std.mem.indexOf(u8, result, "Hello, World!") != null);
}

test "multipart message" {
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
