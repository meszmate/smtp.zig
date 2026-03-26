const std = @import("std");
const response = @import("response.zig");

/// SMTP connection/session state.
pub const ConnState = enum {
    connect,
    greeted,
    ready,
    mail,
    rcpt,
    data,
    logout,

    pub fn label(self: ConnState) []const u8 {
        return switch (self) {
            .connect => "connect",
            .greeted => "greeted",
            .ready => "ready",
            .mail => "mail",
            .rcpt => "rcpt",
            .data => "data",
            .logout => "logout",
        };
    }
};

/// DSN notification conditions.
pub const DsnNotify = enum {
    never,
    success,
    failure,
    delay,

    pub fn label(self: DsnNotify) []const u8 {
        return switch (self) {
            .never => "NEVER",
            .success => "SUCCESS",
            .failure => "FAILURE",
            .delay => "DELAY",
        };
    }
};

/// DSN return type for MAIL FROM RET parameter.
pub const DsnReturn = enum {
    full,
    hdrs,

    pub fn label(self: DsnReturn) []const u8 {
        return switch (self) {
            .full => "FULL",
            .hdrs => "HDRS",
        };
    }
};

/// Body type for 8BITMIME MAIL FROM parameter.
pub const BodyType = enum {
    @"7bit",
    @"8bitmime",
    binarymime,

    pub fn label(self: BodyType) []const u8 {
        return switch (self) {
            .@"7bit" => "7BIT",
            .@"8bitmime" => "8BITMIME",
            .binarymime => "BINARYMIME",
        };
    }
};

/// Options for MAIL FROM command.
pub const MailOptions = struct {
    size: ?u64 = null,
    body: ?BodyType = null,
    smtputf8: bool = false,
    ret: ?DsnReturn = null,
    envid: ?[]const u8 = null,
    auth: ?[]const u8 = null,
};

/// Options for RCPT TO command.
pub const RcptOptions = struct {
    notify: []const DsnNotify = &.{},
    orcpt: ?[]const u8 = null,
};

/// Parsed SMTP response.
pub const SmtpResponse = struct {
    code: u16,
    enhanced_code: ?EnhancedCode = null,
    lines: []const []const u8 = &.{},
    text: []const u8 = "",
    is_multiline: bool = false,

    pub fn isSuccess(self: SmtpResponse) bool {
        return self.code >= 200 and self.code < 300;
    }

    pub fn isIntermediate(self: SmtpResponse) bool {
        return self.code >= 300 and self.code < 400;
    }

    pub fn isTransientFailure(self: SmtpResponse) bool {
        return self.code >= 400 and self.code < 500;
    }

    pub fn isPermanentFailure(self: SmtpResponse) bool {
        return self.code >= 500;
    }

    pub fn isFailure(self: SmtpResponse) bool {
        return self.code >= 400;
    }
};

/// Enhanced status code (RFC 3463).
pub const EnhancedCode = struct {
    class: u8,
    subject: u16,
    detail: u16,
};

/// Common enhanced status codes.
pub const enhanced_codes = struct {
    pub const success = EnhancedCode{ .class = 2, .subject = 0, .detail = 0 };
    pub const sender_ok = EnhancedCode{ .class = 2, .subject = 1, .detail = 0 };
    pub const recipient_ok = EnhancedCode{ .class = 2, .subject = 1, .detail = 5 };
    pub const message_ok = EnhancedCode{ .class = 2, .subject = 6, .detail = 0 };
    pub const auth_ok = EnhancedCode{ .class = 2, .subject = 7, .detail = 0 };
    pub const bad_dest_mailbox = EnhancedCode{ .class = 5, .subject = 1, .detail = 1 };
    pub const bad_dest_system = EnhancedCode{ .class = 5, .subject = 1, .detail = 2 };
    pub const bad_dest_syntax = EnhancedCode{ .class = 5, .subject = 1, .detail = 3 };
    pub const mailbox_full = EnhancedCode{ .class = 4, .subject = 2, .detail = 2 };
    pub const message_too_big = EnhancedCode{ .class = 5, .subject = 3, .detail = 4 };
    pub const invalid_command = EnhancedCode{ .class = 5, .subject = 5, .detail = 1 };
    pub const syntax_error = EnhancedCode{ .class = 5, .subject = 5, .detail = 2 };
    pub const auth_failed = EnhancedCode{ .class = 5, .subject = 7, .detail = 8 };
    pub const encryption_required = EnhancedCode{ .class = 5, .subject = 7, .detail = 11 };
};

/// Email address components.
pub const Address = struct {
    name: []const u8 = "",
    mailbox: []const u8 = "",
    host: []const u8 = "",

    pub fn formatAlloc(self: Address, allocator: std.mem.Allocator) ![]u8 {
        if (self.name.len > 0) {
            return std.fmt.allocPrint(allocator, "{s} <{s}@{s}>", .{ self.name, self.mailbox, self.host });
        }
        return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.mailbox, self.host });
    }

    pub fn emailAlloc(self: Address, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.mailbox, self.host });
    }
};

/// An email message envelope.
pub const Envelope = struct {
    from: []const u8 = "",
    to: []const []const u8 = &.{},
    cc: []const []const u8 = &.{},
    bcc: []const []const u8 = &.{},
    subject: []const u8 = "",
    date: []const u8 = "",
    message_id: []const u8 = "",
    in_reply_to: []const u8 = "",
    reply_to: []const u8 = "",
};

/// BDAT chunk information.
pub const BdatChunk = struct {
    size: usize,
    last: bool = false,
};

/// SMTP error information.
pub const SMTPError = struct {
    code: u16,
    enhanced: ?EnhancedCode = null,
    text: []const u8 = "",

    pub fn err421(text: []const u8) SMTPError {
        return .{ .code = 421, .text = text };
    }

    pub fn err450(text: []const u8) SMTPError {
        return .{ .code = 450, .text = text };
    }

    pub fn err451(text: []const u8) SMTPError {
        return .{ .code = 451, .text = text };
    }

    pub fn err452(text: []const u8) SMTPError {
        return .{ .code = 452, .text = text };
    }

    pub fn err500(text: []const u8) SMTPError {
        return .{ .code = 500, .text = text };
    }

    pub fn err501(text: []const u8) SMTPError {
        return .{ .code = 501, .text = text };
    }

    pub fn err502(text: []const u8) SMTPError {
        return .{ .code = 502, .text = text };
    }

    pub fn err503(text: []const u8) SMTPError {
        return .{ .code = 503, .text = text };
    }

    pub fn err504(text: []const u8) SMTPError {
        return .{ .code = 504, .text = text };
    }

    pub fn err550(text: []const u8) SMTPError {
        return .{ .code = 550, .text = text };
    }

    pub fn err552(text: []const u8) SMTPError {
        return .{ .code = 552, .text = text };
    }

    pub fn err553(text: []const u8) SMTPError {
        return .{ .code = 553, .text = text };
    }

    pub fn err554(text: []const u8) SMTPError {
        return .{ .code = 554, .text = text };
    }
};

/// Content-Transfer-Encoding values.
pub const TransferEncoding = enum {
    @"7bit",
    @"8bit",
    binary,
    quoted_printable,
    base64,

    pub fn label(self: TransferEncoding) []const u8 {
        return switch (self) {
            .@"7bit" => "7bit",
            .@"8bit" => "8bit",
            .binary => "binary",
            .quoted_printable => "quoted-printable",
            .base64 => "base64",
        };
    }
};

/// Content-Disposition values.
pub const ContentDisposition = enum {
    inline_disp,
    attachment,

    pub fn label(self: ContentDisposition) []const u8 {
        return switch (self) {
            .inline_disp => "inline",
            .attachment => "attachment",
        };
    }
};

/// Represents a MIME part of an email message.
pub const MimePart = struct {
    content_type: []const u8 = "text/plain",
    charset: []const u8 = "UTF-8",
    encoding: TransferEncoding = .@"7bit",
    disposition: ?ContentDisposition = null,
    filename: ?[]const u8 = null,
    content_id: ?[]const u8 = null,
    body: []const u8 = "",
};

/// Parameters for constructing a multipart message.
pub const MultipartOptions = struct {
    boundary: []const u8 = "",
    subtype: []const u8 = "mixed",
    parts: []const MimePart = &.{},
};

/// SMTP timeouts per RFC 5321 Section 4.5.3.2 (in milliseconds).
pub const Timeouts = struct {
    greeting: u64 = 300_000,
    ehlo: u64 = 300_000,
    mail_from: u64 = 300_000,
    rcpt_to: u64 = 300_000,
    data_initiation: u64 = 120_000,
    data_block: u64 = 180_000,
    data_termination: u64 = 600_000,
};

pub fn formatDateRfc5322(buffer: []u8, unix_seconds: u64) ![]const u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = unix_seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const day_of_week = epoch_seconds.getEpochDay().calculateDayOfWeek();
    const dow = switch (day_of_week) {
        .mon => "Mon",
        .tue => "Tue",
        .wed => "Wed",
        .thu => "Thu",
        .fri => "Fri",
        .sat => "Sat",
        .sun => "Sun",
    };
    const month_name = switch (month_day.month) {
        .jan => "Jan",
        .feb => "Feb",
        .mar => "Mar",
        .apr => "Apr",
        .may => "May",
        .jun => "Jun",
        .jul => "Jul",
        .aug => "Aug",
        .sep => "Sep",
        .oct => "Oct",
        .nov => "Nov",
        .dec => "Dec",
    };
    return std.fmt.bufPrint(
        buffer,
        "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} +0000",
        .{
            dow,
            @as(u8, month_day.day_index) + 1,
            month_name,
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}
