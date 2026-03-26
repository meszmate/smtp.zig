const std = @import("std");
const types = @import("types.zig");

pub const codes = struct {
    pub const system_status: u16 = 211;
    pub const help_message: u16 = 214;
    pub const service_ready: u16 = 220;
    pub const service_closing: u16 = 221;
    pub const auth_success: u16 = 235;
    pub const ok: u16 = 250;
    pub const user_not_local_will_forward: u16 = 251;
    pub const cannot_vrfy: u16 = 252;
    pub const auth_continue: u16 = 334;
    pub const start_mail_input: u16 = 354;
    pub const service_not_available: u16 = 421;
    pub const auth_temp_failure: u16 = 454;
    pub const mailbox_unavailable_temp: u16 = 450;
    pub const local_error: u16 = 451;
    pub const insufficient_storage: u16 = 452;
    pub const unable_to_accommodate: u16 = 455;
    pub const syntax_error: u16 = 500;
    pub const param_syntax_error: u16 = 501;
    pub const command_not_implemented: u16 = 502;
    pub const bad_sequence: u16 = 503;
    pub const param_not_implemented: u16 = 504;
    pub const auth_failed: u16 = 535;
    pub const mailbox_unavailable: u16 = 550;
    pub const user_not_local: u16 = 551;
    pub const exceeded_storage: u16 = 552;
    pub const mailbox_name_not_allowed: u16 = 553;
    pub const transaction_failed: u16 = 554;
    pub const param_not_recognized: u16 = 555;
};

/// Parse a single SMTP response line into code, continuation flag, and text.
pub fn parseResponseLine(line: []const u8) !struct { code: u16, more: bool, text: []const u8 } {
    if (line.len < 3) return error.InvalidResponseLine;

    const code = std.fmt.parseInt(u16, line[0..3], 10) catch return error.InvalidResponseLine;

    if (line.len == 3) return .{ .code = code, .more = false, .text = "" };

    const separator = line[3];
    const more = separator == '-';
    if (separator != ' ' and separator != '-') return error.InvalidResponseLine;

    return .{ .code = code, .more = more, .text = if (line.len > 4) line[4..] else "" };
}

/// Parse an enhanced status code from the beginning of response text.
pub fn parseEnhancedCode(text: []const u8) ?struct { code: types.EnhancedCode, rest: []const u8 } {
    if (text.len < 5) return null;

    // First digit must be 2, 4, or 5
    const class = text[0];
    if (class != '2' and class != '4' and class != '5') return null;
    if (text[1] != '.') return null;

    // Parse subject (1-3 digits)
    var i: usize = 2;
    const subject_start = i;
    while (i < text.len and text[i] >= '0' and text[i] <= '9') : (i += 1) {}
    if (i == subject_start or i >= text.len or text[i] != '.') return null;
    const subject = std.fmt.parseInt(u16, text[subject_start..i], 10) catch return null;
    i += 1; // skip '.'

    // Parse detail (1-3 digits)
    const detail_start = i;
    while (i < text.len and text[i] >= '0' and text[i] <= '9') : (i += 1) {}
    if (i == detail_start) return null;
    const detail = std.fmt.parseInt(u16, text[detail_start..i], 10) catch return null;

    const rest = if (i < text.len and text[i] == ' ') text[i + 1 ..] else text[i..];

    return .{
        .code = .{
            .class = class - '0',
            .subject = subject,
            .detail = detail,
        },
        .rest = rest,
    };
}

/// Read and parse a complete SMTP response (potentially multiline) from the reader.
pub fn readResponseAlloc(allocator: std.mem.Allocator, reader: anytype) !types.SmtpResponse {
    var all_lines: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (all_lines.items) |line| allocator.free(line);
        all_lines.deinit(allocator);
    }

    var final_code: u16 = 0;
    var final_text: []u8 = &.{};
    var enhanced: ?types.EnhancedCode = null;
    var is_multiline = false;

    while (true) {
        const line = try reader.readLineAlloc();
        errdefer allocator.free(line);

        const parsed = try parseResponseLine(line);
        final_code = parsed.code;

        try all_lines.append(allocator, line);

        if (!parsed.more) {
            // Parse enhanced code from final line
            if (parseEnhancedCode(parsed.text)) |ec| {
                enhanced = ec.code;
                final_text = try allocator.dupe(u8, ec.rest);
            } else {
                final_text = try allocator.dupe(u8, parsed.text);
            }
            break;
        }
        is_multiline = true;
    }

    return types.SmtpResponse{
        .code = final_code,
        .enhanced_code = enhanced,
        .lines = try all_lines.toOwnedSlice(allocator),
        .text = final_text,
        .is_multiline = is_multiline,
    };
}

pub fn freeResponse(allocator: std.mem.Allocator, resp: *types.SmtpResponse) void {
    for (resp.lines) |line| allocator.free(line);
    allocator.free(resp.lines);
    if (resp.text.len > 0) allocator.free(resp.text);
    resp.* = undefined;
}
