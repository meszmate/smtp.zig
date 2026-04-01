const std = @import("std");
const Allocator = std.mem.Allocator;

/// DSN action types per RFC 3464.
pub const Action = enum {
    failed,
    delayed,
    delivered,
    relayed,
    expanded,

    pub fn label(self: Action) []const u8 {
        return switch (self) {
            .failed => "failed",
            .delayed => "delayed",
            .delivered => "delivered",
            .relayed => "relayed",
            .expanded => "expanded",
        };
    }
};

/// DSN status code (class.subject.detail format per RFC 3464).
pub const Status = struct {
    class: u8, // 2=success, 4=transient, 5=permanent
    subject: u16,
    detail: u16,

    pub fn formatAlloc(self: Status, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}", .{ self.class, self.subject, self.detail });
    }
};

/// Common DSN status codes per RFC 3463.
pub const status_codes = struct {
    pub const mailbox_not_found = Status{ .class = 5, .subject = 1, .detail = 1 };
    pub const mailbox_full = Status{ .class = 4, .subject = 2, .detail = 2 };
    pub const message_too_large = Status{ .class = 5, .subject = 3, .detail = 4 };
    pub const network_error = Status{ .class = 4, .subject = 4, .detail = 1 };
    pub const protocol_error = Status{ .class = 5, .subject = 5, .detail = 0 };
    pub const success = Status{ .class = 2, .subject = 0, .detail = 0 };
    pub const undefined_status = Status{ .class = 4, .subject = 0, .detail = 0 };
};

/// Per-recipient delivery status.
pub const RecipientStatus = struct {
    recipient: []const u8,
    action: Action,
    status: Status,
    diagnostic: ?[]const u8 = null,
    remote_mta: ?[]const u8 = null,
};

/// Options for generating a DSN message.
pub const DsnOptions = struct {
    reporting_mta: []const u8,
    original_envelope_id: ?[]const u8 = null,
    arrival_date: ?[]const u8 = null,
    original_from: []const u8,
    original_to: []const u8,
    recipients: []const RecipientStatus,
    /// Include original message headers in the DSN.
    include_headers: ?[]const u8 = null,
    /// Include full original message.
    include_message: ?[]const u8 = null,
    /// Human-readable explanation text.
    explanation: ?[]const u8 = null,
};

/// Append a formatted line to the buffer.
fn appendFmt(buf: *std.ArrayList(u8), allocator: Allocator, comptime fmt: []const u8, args: anytype) !void {
    const line = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(line);
    try buf.appendSlice(allocator, line);
}

/// Generate just the message/delivery-status part per RFC 3464.
/// Caller owns the returned memory.
pub fn generateDeliveryStatusAlloc(
    allocator: Allocator,
    reporting_mta: []const u8,
    envelope_id: ?[]const u8,
    arrival_date: ?[]const u8,
    recipients: []const RecipientStatus,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Per-message DSN fields
    try appendFmt(&buf, allocator, "Reporting-MTA: dns; {s}\r\n", .{reporting_mta});
    if (envelope_id) |eid| {
        try appendFmt(&buf, allocator, "Original-Envelope-Id: {s}\r\n", .{eid});
    }
    if (arrival_date) |date| {
        try appendFmt(&buf, allocator, "Arrival-Date: {s}\r\n", .{date});
    }

    // Per-recipient fields (each group separated by a blank line)
    for (recipients) |r| {
        try buf.appendSlice(allocator, "\r\n");
        try appendFmt(&buf, allocator, "Final-Recipient: rfc822; {s}\r\n", .{r.recipient});
        try appendFmt(&buf, allocator, "Action: {s}\r\n", .{r.action.label()});
        const status_str = try r.status.formatAlloc(allocator);
        defer allocator.free(status_str);
        try appendFmt(&buf, allocator, "Status: {s}\r\n", .{status_str});
        if (r.diagnostic) |diag| {
            try appendFmt(&buf, allocator, "Diagnostic-Code: smtp; {s}\r\n", .{diag});
        }
        if (r.remote_mta) |mta| {
            try appendFmt(&buf, allocator, "Remote-MTA: dns; {s}\r\n", .{mta});
        }
    }

    return buf.toOwnedSlice(allocator);
}

/// Generate a complete DSN bounce message per RFC 3464.
/// Returns the full RFC 2822 message ready for sending.
/// Caller owns the returned memory.
pub fn generateDsnAlloc(allocator: Allocator, options: DsnOptions) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    const boundary = "DSN_BOUNDARY_0000";

    // Determine subject based on first recipient action
    const subject = if (options.recipients.len > 0)
        switch (options.recipients[0].action) {
            .failed => "Delivery Status Notification (Failure)",
            .delayed => "Delivery Status Notification (Delay)",
            .delivered => "Delivery Status Notification (Success)",
            .relayed => "Delivery Status Notification (Relayed)",
            .expanded => "Delivery Status Notification (Expanded)",
        }
    else
        "Delivery Status Notification";

    // RFC 2822 headers
    try appendFmt(&buf, allocator, "From: mailer-daemon@{s}\r\n", .{options.reporting_mta});
    try appendFmt(&buf, allocator, "To: {s}\r\n", .{options.original_from});
    try appendFmt(&buf, allocator, "Subject: {s}\r\n", .{subject});
    try buf.appendSlice(allocator, "MIME-Version: 1.0\r\n");
    try appendFmt(&buf, allocator, "Content-Type: multipart/report; report-type=delivery-status; boundary=\"{s}\"\r\n", .{boundary});
    try buf.appendSlice(allocator, "\r\n");

    // Part 1: Human-readable explanation
    try appendFmt(&buf, allocator, "--{s}\r\n", .{boundary});
    try buf.appendSlice(allocator, "Content-Type: text/plain; charset=utf-8\r\n");
    try buf.appendSlice(allocator, "\r\n");
    if (options.explanation) |expl| {
        try buf.appendSlice(allocator, expl);
        try buf.appendSlice(allocator, "\r\n");
    } else {
        try buf.appendSlice(allocator, "This is an automatically generated Delivery Status Notification.\r\n\r\n");
        for (options.recipients) |r| {
            switch (r.action) {
                .failed => try appendFmt(&buf, allocator, "Delivery to {s} failed.\r\n", .{r.recipient}),
                .delayed => try appendFmt(&buf, allocator, "Delivery to {s} has been delayed.\r\n", .{r.recipient}),
                .delivered => try appendFmt(&buf, allocator, "Message was successfully delivered to {s}.\r\n", .{r.recipient}),
                .relayed => try appendFmt(&buf, allocator, "Message was relayed to {s}.\r\n", .{r.recipient}),
                .expanded => try appendFmt(&buf, allocator, "Message was expanded for {s}.\r\n", .{r.recipient}),
            }
            if (r.diagnostic) |diag| {
                try appendFmt(&buf, allocator, "Diagnostic: {s}\r\n", .{diag});
            }
        }
    }
    try buf.appendSlice(allocator, "\r\n");

    // Part 2: message/delivery-status
    try appendFmt(&buf, allocator, "--{s}\r\n", .{boundary});
    try buf.appendSlice(allocator, "Content-Type: message/delivery-status\r\n");
    try buf.appendSlice(allocator, "\r\n");
    const ds = try generateDeliveryStatusAlloc(
        allocator,
        options.reporting_mta,
        options.original_envelope_id,
        options.arrival_date,
        options.recipients,
    );
    defer allocator.free(ds);
    try buf.appendSlice(allocator, ds);
    try buf.appendSlice(allocator, "\r\n");

    // Part 3 (optional): original message or headers
    if (options.include_message) |msg| {
        try appendFmt(&buf, allocator, "--{s}\r\n", .{boundary});
        try buf.appendSlice(allocator, "Content-Type: message/rfc822\r\n");
        try buf.appendSlice(allocator, "\r\n");
        try buf.appendSlice(allocator, msg);
        try buf.appendSlice(allocator, "\r\n");
    } else if (options.include_headers) |hdrs| {
        try appendFmt(&buf, allocator, "--{s}\r\n", .{boundary});
        try buf.appendSlice(allocator, "Content-Type: message/rfc822-headers\r\n");
        try buf.appendSlice(allocator, "\r\n");
        try buf.appendSlice(allocator, hdrs);
        try buf.appendSlice(allocator, "\r\n");
    }

    // Closing boundary
    try appendFmt(&buf, allocator, "--{s}--\r\n", .{boundary});

    return buf.toOwnedSlice(allocator);
}

// ─── Tests ───

test "generate simple bounce for mailbox not found" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "nobody@example.com",
            .action = .failed,
            .status = status_codes.mailbox_not_found,
            .diagnostic = "550 5.1.1 User unknown",
            .remote_mta = "mail.example.com",
        },
    };

    const result = try generateDsnAlloc(allocator, .{
        .reporting_mta = "mx.sender.com",
        .original_from = "sender@sender.com",
        .original_to = "nobody@example.com",
        .recipients = &recipients,
    });
    defer allocator.free(result);

    // Verify top-level headers
    try std.testing.expect(std.mem.indexOf(u8, result, "From: mailer-daemon@mx.sender.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "To: sender@sender.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Subject: Delivery Status Notification (Failure)\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: multipart/report; report-type=delivery-status;") != null);

    // Verify delivery-status part
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: message/delivery-status\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Reporting-MTA: dns; mx.sender.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Final-Recipient: rfc822; nobody@example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Action: failed\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Status: 5.1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Diagnostic-Code: smtp; 550 5.1.1 User unknown\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Remote-MTA: dns; mail.example.com\r\n") != null);
}

test "generate bounce with multiple recipients" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "alice@example.com",
            .action = .failed,
            .status = status_codes.mailbox_not_found,
            .diagnostic = "550 User unknown",
        },
        .{
            .recipient = "bob@example.com",
            .action = .failed,
            .status = status_codes.mailbox_full,
            .diagnostic = "452 Mailbox full",
        },
    };

    const result = try generateDsnAlloc(allocator, .{
        .reporting_mta = "mx.sender.com",
        .original_from = "sender@sender.com",
        .original_to = "alice@example.com",
        .recipients = &recipients,
        .original_envelope_id = "msg-001",
    });
    defer allocator.free(result);

    // Both recipients present in delivery-status
    try std.testing.expect(std.mem.indexOf(u8, result, "Final-Recipient: rfc822; alice@example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Final-Recipient: rfc822; bob@example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Status: 5.1.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Status: 4.2.2\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Original-Envelope-Id: msg-001\r\n") != null);
}

test "generate delayed delivery notification" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "user@example.com",
            .action = .delayed,
            .status = status_codes.network_error,
            .diagnostic = "Connection timed out",
        },
    };

    const result = try generateDsnAlloc(allocator, .{
        .reporting_mta = "mx.sender.com",
        .original_from = "sender@sender.com",
        .original_to = "user@example.com",
        .recipients = &recipients,
        .arrival_date = "Thu, 01 Apr 2026 12:00:00 +0000",
    });
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "Subject: Delivery Status Notification (Delay)\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Action: delayed\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Status: 4.4.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Arrival-Date: Thu, 01 Apr 2026 12:00:00 +0000\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "has been delayed") != null);
}

test "verify multipart/report structure" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "user@example.com",
            .action = .failed,
            .status = status_codes.mailbox_not_found,
        },
    };

    const original_headers = "From: sender@sender.com\r\nTo: user@example.com\r\nSubject: Hello\r\n";

    const result = try generateDsnAlloc(allocator, .{
        .reporting_mta = "mx.sender.com",
        .original_from = "sender@sender.com",
        .original_to = "user@example.com",
        .recipients = &recipients,
        .include_headers = original_headers,
    });
    defer allocator.free(result);

    // Must have exactly 3 parts: text/plain, delivery-status, rfc822-headers
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: text/plain; charset=utf-8\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: message/delivery-status\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: message/rfc822-headers\r\n") != null);

    // Original headers included
    try std.testing.expect(std.mem.indexOf(u8, result, original_headers) != null);

    // Closing boundary present
    try std.testing.expect(std.mem.indexOf(u8, result, "--DSN_BOUNDARY_0000--\r\n") != null);
}

test "verify delivery-status part formatting" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "user@example.com",
            .action = .delivered,
            .status = status_codes.success,
        },
    };

    const ds = try generateDeliveryStatusAlloc(
        allocator,
        "mx.sender.com",
        "envelope-123",
        "Thu, 01 Apr 2026 12:00:00 +0000",
        &recipients,
    );
    defer allocator.free(ds);

    // Per-message fields come first
    try std.testing.expect(std.mem.startsWith(u8, ds, "Reporting-MTA: dns; mx.sender.com\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, ds, "Original-Envelope-Id: envelope-123\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, ds, "Arrival-Date: Thu, 01 Apr 2026 12:00:00 +0000\r\n") != null);

    // Blank line separates per-message from per-recipient
    try std.testing.expect(std.mem.indexOf(u8, ds, "\r\n\r\nFinal-Recipient:") != null);

    // Per-recipient fields
    try std.testing.expect(std.mem.indexOf(u8, ds, "Action: delivered\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, ds, "Status: 2.0.0\r\n") != null);

    // No Diagnostic-Code or Remote-MTA when not set
    try std.testing.expect(std.mem.indexOf(u8, ds, "Diagnostic-Code:") == null);
    try std.testing.expect(std.mem.indexOf(u8, ds, "Remote-MTA:") == null);
}

test "generate bounce with include_message" {
    const allocator = std.testing.allocator;

    const recipients = [_]RecipientStatus{
        .{
            .recipient = "user@example.com",
            .action = .failed,
            .status = status_codes.protocol_error,
        },
    };

    const original_message = "From: sender@sender.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nHello world\r\n";

    const result = try generateDsnAlloc(allocator, .{
        .reporting_mta = "mx.sender.com",
        .original_from = "sender@sender.com",
        .original_to = "user@example.com",
        .recipients = &recipients,
        .include_message = original_message,
    });
    defer allocator.free(result);

    // Full message uses message/rfc822 (not rfc822-headers)
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: message/rfc822\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Content-Type: message/rfc822-headers\r\n") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, original_message) != null);
}
