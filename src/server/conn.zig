const std = @import("std");
const transport_mod = @import("../wire/transport.zig");
const line_reader_mod = @import("../wire/line_reader.zig");
const session_mod = @import("session.zig");
const response = @import("../response.zig");

const Transport = transport_mod.Transport;
const LineReader = line_reader_mod.LineReader;
const SessionState = session_mod.SessionState;

/// A parsed SMTP command from the client.
pub const Command = struct {
    /// The command verb (e.g., "EHLO", "MAIL FROM", "RCPT TO").
    verb: []const u8,
    /// The arguments/parameters after the verb.
    args: []const u8,
};

/// An SMTP server connection, wrapping transport, reader, and session state.
pub const Conn = struct {
    allocator: std.mem.Allocator,
    transport: Transport,
    reader: LineReader,
    session: SessionState,
    stream: ?std.net.Stream = null,

    pub fn init(allocator: std.mem.Allocator, transport: Transport) Conn {
        return .{
            .allocator = allocator,
            .transport = transport,
            .reader = LineReader.init(allocator, transport),
            .session = SessionState.init(allocator),
        };
    }

    pub fn deinit(self: *Conn) void {
        self.session.deinit();
    }

    /// Send the initial 220 greeting.
    pub fn writeGreeting(self: *Conn, hostname: []const u8, greeting_text: []const u8) !void {
        try self.transport.print("220 {s} {s}\r\n", .{ hostname, greeting_text });
    }

    /// Write a single-line SMTP response.
    pub fn writeResponse(self: *Conn, code: u16, text: []const u8) !void {
        try self.transport.print("{d} {s}\r\n", .{ code, text });
    }

    /// Write a multiline SMTP response. Each line except the last uses '-' continuation.
    pub fn writeMultiline(self: *Conn, code: u16, lines: []const []const u8) !void {
        for (lines, 0..) |line, i| {
            if (i == lines.len - 1) {
                try self.transport.print("{d} {s}\r\n", .{ code, line });
            } else {
                try self.transport.print("{d}-{s}\r\n", .{ code, line });
            }
        }
    }

    /// Write a 250 OK response.
    pub fn writeOk(self: *Conn, text: []const u8) !void {
        try self.writeResponse(response.codes.ok, text);
    }

    /// Write an error response.
    pub fn writeError(self: *Conn, code: u16, text: []const u8) !void {
        try self.writeResponse(code, text);
    }

    /// Read and parse a command from the client.
    /// Returns a Command struct with verb and args.
    /// Caller owns the underlying line memory.
    pub fn readCommandAlloc(self: *Conn) !struct { command: Command, raw: []u8 } {
        const line = try self.reader.readLineAlloc();
        errdefer self.allocator.free(line);

        const cmd = parseCommand(line);
        return .{ .command = cmd, .raw = line };
    }
};

/// Parse a raw SMTP command line into verb and arguments.
/// Handles special two-word commands: "MAIL FROM" and "RCPT TO".
fn parseCommand(line: []const u8) Command {
    // Check for "MAIL FROM:" or "RCPT TO:" (case-insensitive).
    if (line.len >= 10) {
        var upper_buf: [10]u8 = undefined;
        const check_len = @min(line.len, 10);
        for (line[0..check_len], 0..) |c, i| {
            upper_buf[i] = std.ascii.toUpper(c);
        }
        if (std.mem.eql(u8, &upper_buf, "MAIL FROM:")) {
            return .{
                .verb = "MAIL FROM",
                .args = std.mem.trimLeft(u8, line[10..], " "),
            };
        }
    }

    if (line.len >= 8) {
        var upper_buf2: [8]u8 = undefined;
        const check_len2 = @min(line.len, 8);
        for (line[0..check_len2], 0..) |c, i| {
            upper_buf2[i] = std.ascii.toUpper(c);
        }
        if (std.mem.eql(u8, &upper_buf2, "RCPT TO:")) {
            return .{
                .verb = "RCPT TO",
                .args = std.mem.trimLeft(u8, line[8..], " "),
            };
        }
    }

    // Standard single-word command.
    if (std.mem.indexOfScalar(u8, line, ' ')) |space_idx| {
        return .{
            .verb = line[0..space_idx],
            .args = std.mem.trimLeft(u8, line[space_idx + 1 ..], " "),
        };
    }

    return .{
        .verb = line,
        .args = "",
    };
}
