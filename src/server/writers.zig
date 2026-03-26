const std = @import("std");
const wire = @import("../wire/transport.zig");
const response = @import("../response.zig");
const types = @import("../types.zig");

const Transport = wire.Transport;
const EnhancedCode = types.EnhancedCode;

/// ResponseWriter writes SMTP responses with proper formatting.
/// Wraps a Transport to provide high-level SMTP response methods.
pub const ResponseWriter = struct {
    allocator: std.mem.Allocator,
    transport: Transport,

    pub fn init(allocator: std.mem.Allocator, transport: Transport) ResponseWriter {
        return .{
            .allocator = allocator,
            .transport = transport,
        };
    }

    /// Write a 220 service ready greeting.
    pub fn writeGreeting(self: *ResponseWriter, hostname: []const u8, greeting_text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s} {s}\r\n", .{ response.codes.service_ready, hostname, greeting_text });
    }

    /// Write a multiline 250 EHLO response with hostname and extension keywords.
    pub fn writeEhloResponse(self: *ResponseWriter, hostname: []const u8, extension_keywords: []const []const u8) Transport.WriteError!void {
        if (extension_keywords.len == 0) {
            try self.transport.print("{d} {s}\r\n", .{ response.codes.ok, hostname });
            return;
        }
        // First line: 250-hostname
        try self.transport.print("{d}-{s}\r\n", .{ response.codes.ok, hostname });
        // Middle lines: 250-EXTENSION
        for (extension_keywords[0 .. extension_keywords.len - 1]) |kw| {
            try self.transport.print("{d}-{s}\r\n", .{ response.codes.ok, kw });
        }
        // Last line: 250 EXTENSION
        try self.transport.print("{d} {s}\r\n", .{ response.codes.ok, extension_keywords[extension_keywords.len - 1] });
    }

    /// Write a 250 OK response.
    pub fn writeOk(self: *ResponseWriter, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s}\r\n", .{ response.codes.ok, text });
    }

    /// Write a 250 OK response with an enhanced status code (e.g., 250 2.1.0 Sender OK).
    pub fn writeOkEnhanced(self: *ResponseWriter, enhanced_code: EnhancedCode, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {d}.{d}.{d} {s}\r\n", .{
            response.codes.ok,
            enhanced_code.class,
            enhanced_code.subject,
            enhanced_code.detail,
            text,
        });
    }

    /// Write a 354 intermediate response (start mail input).
    pub fn writeIntermediate(self: *ResponseWriter, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s}\r\n", .{ response.codes.start_mail_input, text });
    }

    /// Write an error response with the given status code.
    pub fn writeError(self: *ResponseWriter, code: u16, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s}\r\n", .{ code, text });
    }

    /// Write an error response with an enhanced status code.
    pub fn writeErrorEnhanced(self: *ResponseWriter, code: u16, enhanced_code: EnhancedCode, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {d}.{d}.{d} {s}\r\n", .{
            code,
            enhanced_code.class,
            enhanced_code.subject,
            enhanced_code.detail,
            text,
        });
    }

    /// Write a 334 authentication challenge (base64-encoded).
    pub fn writeAuthChallenge(self: *ResponseWriter, challenge_b64: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s}\r\n", .{ response.codes.auth_continue, challenge_b64 });
    }

    /// Write a 235 authentication success response.
    pub fn writeAuthSuccess(self: *ResponseWriter) Transport.WriteError!void {
        try self.transport.print("{d} {d}.{d}.{d} Authentication successful\r\n", .{
            response.codes.auth_success,
            types.enhanced_codes.auth_ok.class,
            types.enhanced_codes.auth_ok.subject,
            types.enhanced_codes.auth_ok.detail,
        });
    }

    /// Write a 221 service closing / bye response.
    pub fn writeBye(self: *ResponseWriter, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {s}\r\n", .{ response.codes.service_closing, text });
    }
};

/// StatusWriter provides DSN-related status responses for recipient handling.
pub const StatusWriter = struct {
    allocator: std.mem.Allocator,
    transport: Transport,

    pub fn init(allocator: std.mem.Allocator, transport: Transport) StatusWriter {
        return .{
            .allocator = allocator,
            .transport = transport,
        };
    }

    /// Write a 250 OK response for an accepted recipient.
    pub fn writeRecipientOk(self: *StatusWriter, recipient: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} {d}.{d}.{d} <{s}> recipient ok\r\n", .{
            response.codes.ok,
            types.enhanced_codes.recipient_ok.class,
            types.enhanced_codes.recipient_ok.subject,
            types.enhanced_codes.recipient_ok.detail,
            recipient,
        });
    }

    /// Write an error response for a rejected recipient.
    pub fn writeRecipientFailed(self: *StatusWriter, recipient: []const u8, code: u16, text: []const u8) Transport.WriteError!void {
        try self.transport.print("{d} <{s}> {s}\r\n", .{ code, recipient, text });
    }
};
