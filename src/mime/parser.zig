const std = @import("std");
const types = @import("../types.zig");
const quoted_printable = @import("quoted_printable.zig");
const base64 = @import("base64.zig");

const TransferEncoding = types.TransferEncoding;
const ContentDisposition = types.ContentDisposition;

pub const Header = struct {
    name: []u8,
    value: []u8,
};

pub const Part = struct {
    allocator: std.mem.Allocator,
    headers: []Header,
    content_type: []u8,
    charset: ?[]u8,
    encoding: TransferEncoding,
    disposition: ?ContentDisposition,
    filename: ?[]u8,
    body: []u8,
    children: []Part,

    pub fn deinit(self: *Part) void {
        for (self.headers) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.allocator.free(self.headers);
        self.allocator.free(self.content_type);
        if (self.charset) |charset| self.allocator.free(charset);
        if (self.filename) |filename| self.allocator.free(filename);
        self.allocator.free(self.body);
        for (self.children) |*child| child.deinit();
        self.allocator.free(self.children);
    }

    pub fn headerValue(self: *const Part, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }
};

pub const Message = struct {
    root: Part,

    pub fn deinit(self: *Message) void {
        self.root.deinit();
    }

    pub fn headerValue(self: *const Message, name: []const u8) ?[]const u8 {
        return self.root.headerValue(name);
    }
};

pub fn parseMessageAlloc(allocator: std.mem.Allocator, raw: []const u8) anyerror!Message {
    return .{ .root = try parseEntityAlloc(allocator, raw) };
}

pub fn parsePartAlloc(allocator: std.mem.Allocator, raw: []const u8) anyerror!Part {
    return try parseEntityAlloc(allocator, raw);
}

fn parseEntityAlloc(allocator: std.mem.Allocator, raw: []const u8) anyerror!Part {
    const split = splitHeadersAndBody(raw);
    const headers = try parseHeadersAlloc(allocator, split.headers);
    errdefer freeHeaders(allocator, headers);

    const content_type_value = headerValue(headers, "Content-Type");
    const encoding = parseTransferEncoding(headerValue(headers, "Content-Transfer-Encoding"));
    const disposition_value = headerValue(headers, "Content-Disposition");

    const content_type = try allocator.dupe(u8, parseMainValue(content_type_value orelse "text/plain"));
    errdefer allocator.free(content_type);

    const charset = if (content_type_value) |value|
        try dupOptionalParam(allocator, value, "charset")
    else
        null;
    errdefer if (charset) |value| allocator.free(value);

    const filename = if (disposition_value) |value|
        try dupOptionalParam(allocator, value, "filename")
    else if (content_type_value) |value|
        try dupOptionalParam(allocator, value, "name")
    else
        null;
    errdefer if (filename) |value| allocator.free(value);

    const disposition = parseDisposition(disposition_value);
    const body = try decodeBodyAlloc(allocator, split.body, encoding);
    errdefer allocator.free(body);

    var children: []Part = &.{};
    errdefer {
        for (children) |*child| child.deinit();
        allocator.free(children);
    }

    if (std.ascii.startsWithIgnoreCase(content_type, "multipart/")) {
        if (content_type_value) |value| {
            if (extractParamValue(value, "boundary")) |boundary| {
                children = try parseMultipartAlloc(allocator, split.body, boundary);
            }
        }
    } else {
        children = try allocator.alloc(Part, 0);
    }

    return .{
        .allocator = allocator,
        .headers = headers,
        .content_type = content_type,
        .charset = charset,
        .encoding = encoding,
        .disposition = disposition,
        .filename = filename,
        .body = body,
        .children = children,
    };
}

fn splitHeadersAndBody(raw: []const u8) struct { headers: []const u8, body: []const u8 } {
    if (std.mem.indexOf(u8, raw, "\r\n\r\n")) |idx| {
        return .{
            .headers = raw[0..idx],
            .body = raw[idx + 4 ..],
        };
    }
    if (std.mem.indexOf(u8, raw, "\n\n")) |idx| {
        return .{
            .headers = raw[0..idx],
            .body = raw[idx + 2 ..],
        };
    }
    return .{
        .headers = raw,
        .body = "",
    };
}

fn parseHeadersAlloc(allocator: std.mem.Allocator, text: []const u8) anyerror![]Header {
    var list: std.ArrayList(Header) = .empty;
    errdefer {
        freeHeaders(allocator, list.items);
        list.deinit(allocator);
    }

    var current_name: ?[]u8 = null;
    var current_value: ?std.ArrayList(u8) = null;
    defer {
        if (current_name) |name| allocator.free(name);
        if (current_value) |*value| value.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimRight(u8, raw_line, "\r");
        if (line.len == 0) continue;

        if ((line[0] == ' ' or line[0] == '\t') and current_value != null) {
            try current_value.?.append(allocator, ' ');
            try current_value.?.appendSlice(allocator, std.mem.trim(u8, line, " \t"));
            continue;
        }

        if (current_name != null and current_value != null) {
            try list.append(allocator, .{
                .name = current_name.?,
                .value = try current_value.?.toOwnedSlice(allocator),
            });
            current_name = null;
            current_value.?.deinit(allocator);
            current_value = null;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        current_name = try allocator.dupe(u8, std.mem.trim(u8, line[0..colon], " \t"));
        current_value = std.ArrayList(u8).empty;
        try current_value.?.appendSlice(allocator, std.mem.trim(u8, line[colon + 1 ..], " \t"));
    }

    if (current_name != null and current_value != null) {
        try list.append(allocator, .{
            .name = current_name.?,
            .value = try current_value.?.toOwnedSlice(allocator),
        });
        current_name = null;
        current_value.?.deinit(allocator);
        current_value = null;
    }

    return try list.toOwnedSlice(allocator);
}

fn parseMultipartAlloc(allocator: std.mem.Allocator, body: []const u8, boundary: []const u8) anyerror![]Part {
    var parts: std.ArrayList(Part) = .empty;
    errdefer {
        for (parts.items) |*part| part.deinit();
        parts.deinit(allocator);
    }

    const marker = try std.fmt.allocPrint(allocator, "--{s}", .{boundary});
    defer allocator.free(marker);
    const closing_marker = try std.fmt.allocPrint(allocator, "--{s}--", .{boundary});
    defer allocator.free(closing_marker);

    var current: ?usize = null;
    var lines = std.mem.splitScalar(u8, body, '\n');
    var offset: usize = 0;

    while (lines.next()) |raw_line| {
        const line_with_lf_len = raw_line.len + 1;
        const line = std.mem.trimRight(u8, raw_line, "\r");

        if (std.mem.eql(u8, line, marker)) {
            if (current) |start| {
                const raw_part = std.mem.trim(u8, body[start..offset], "\r\n");
                if (raw_part.len > 0) {
                    try parts.append(allocator, try parseEntityAlloc(allocator, raw_part));
                }
            }
            current = offset + line_with_lf_len;
        } else if (std.mem.eql(u8, line, closing_marker)) {
            if (current) |start| {
                const raw_part = std.mem.trim(u8, body[start..offset], "\r\n");
                if (raw_part.len > 0) {
                    try parts.append(allocator, try parseEntityAlloc(allocator, raw_part));
                }
            }
            break;
        }

        offset += line_with_lf_len;
    }

    return try parts.toOwnedSlice(allocator);
}

fn parseTransferEncoding(value: ?[]const u8) TransferEncoding {
    const encoding = value orelse return .@"7bit";
    if (std.ascii.eqlIgnoreCase(encoding, "7bit")) return .@"7bit";
    if (std.ascii.eqlIgnoreCase(encoding, "8bit")) return .@"8bit";
    if (std.ascii.eqlIgnoreCase(encoding, "binary")) return .binary;
    if (std.ascii.eqlIgnoreCase(encoding, "quoted-printable")) return .quoted_printable;
    if (std.ascii.eqlIgnoreCase(encoding, "base64")) return .base64;
    return .@"7bit";
}

fn parseDisposition(value: ?[]const u8) ?ContentDisposition {
    const disposition = value orelse return null;
    const main = parseMainValue(disposition);
    if (std.ascii.eqlIgnoreCase(main, "inline")) return .inline_disp;
    if (std.ascii.eqlIgnoreCase(main, "attachment")) return .attachment;
    return null;
}

fn decodeBodyAlloc(allocator: std.mem.Allocator, body: []const u8, encoding: TransferEncoding) anyerror![]u8 {
    return switch (encoding) {
        .quoted_printable => try quoted_printable.decodeAlloc(allocator, body),
        .base64 => try base64.decodeMimeAlloc(allocator, body),
        else => try allocator.dupe(u8, body),
    };
}

fn headerValue(headers: []const Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

fn parseMainValue(value: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, value, ';')) |idx| {
        return std.mem.trim(u8, value[0..idx], " \t");
    }
    return std.mem.trim(u8, value, " \t");
}

fn dupOptionalParam(allocator: std.mem.Allocator, value: []const u8, key: []const u8) anyerror!?[]u8 {
    const param = extractParamValue(value, key) orelse return null;
    return try allocator.dupe(u8, param);
}

fn extractParamValue(value: []const u8, key: []const u8) ?[]const u8 {
    var params = std.mem.splitScalar(u8, value, ';');
    _ = params.next();

    while (params.next()) |raw_param| {
        const param = std.mem.trim(u8, raw_param, " \t");
        const eq = std.mem.indexOfScalar(u8, param, '=') orelse continue;
        const name = std.mem.trim(u8, param[0..eq], " \t");
        if (!std.ascii.eqlIgnoreCase(name, key)) continue;

        const raw_value = std.mem.trim(u8, param[eq + 1 ..], " \t");
        return std.mem.trim(u8, raw_value, "\"");
    }

    return null;
}

fn freeHeaders(allocator: std.mem.Allocator, headers: []Header) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}
