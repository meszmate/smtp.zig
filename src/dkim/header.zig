const std = @import("std");
const canonicalize = @import("canonicalize.zig");

/// Parsed DKIM-Signature header fields.
pub const DkimHeader = struct {
    version: []const u8 = "1",
    algorithm: []const u8 = "ed25519-sha256",
    signature: []const u8 = "",
    body_hash: []const u8 = "",
    canonicalization: canonicalize.Canonicalization = .{},
    domain: []const u8 = "",
    signed_headers: []const u8 = "",
    selector: []const u8 = "",
    timestamp: ?u64 = null,
    expiration: ?u64 = null,
    identity: ?[]const u8 = null,
    body_length: ?u64 = null,
    query_method: []const u8 = "dns/txt",
};

/// Build a DKIM-Signature header string.
/// The `b=` field will be empty if signature is empty (for signing input construction).
pub fn buildDkimHeaderAlloc(allocator: std.mem.Allocator, hdr: DkimHeader) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("DKIM-Signature: v=");
    try writer.writeAll(hdr.version);
    try writer.writeAll("; a=");
    try writer.writeAll(hdr.algorithm);
    try writer.writeAll(";\r\n\t");

    var canon_buf: [15]u8 = undefined;
    const canon_label = hdr.canonicalization.label(&canon_buf);
    try writer.writeAll("c=");
    try writer.writeAll(canon_label);
    try writer.writeAll("; d=");
    try writer.writeAll(hdr.domain);
    try writer.writeAll("; s=");
    try writer.writeAll(hdr.selector);
    try writer.writeAll(";\r\n\t");

    if (hdr.timestamp) |t| {
        try writer.print("t={d}; ", .{t});
    }
    if (hdr.expiration) |x| {
        try writer.print("x={d}; ", .{x});
    }

    try writer.writeAll("h=");
    try writer.writeAll(hdr.signed_headers);
    try writer.writeAll(";\r\n\t");

    try writer.writeAll("bh=");
    try writer.writeAll(hdr.body_hash);
    try writer.writeAll(";\r\n\t");

    try writer.writeAll("b=");
    try writer.writeAll(hdr.signature);

    return out.toOwnedSlice(allocator);
}

/// Parse a DKIM-Signature header value into a DkimHeader struct.
/// Input should be the value portion after "DKIM-Signature: ".
pub fn parseDkimHeader(value: []const u8) DkimHeader {
    var hdr = DkimHeader{};

    // Split on semicolons
    var it = std.mem.splitScalar(u8, value, ';');
    while (it.next()) |tag_raw| {
        const tag = std.mem.trim(u8, tag_raw, " \t\r\n");
        if (tag.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, tag, '=') orelse continue;
        const name = std.mem.trim(u8, tag[0..eq], " \t\r\n");
        const val = std.mem.trim(u8, tag[eq + 1 ..], " \t\r\n");

        if (std.mem.eql(u8, name, "v")) {
            hdr.version = val;
        } else if (std.mem.eql(u8, name, "a")) {
            hdr.algorithm = val;
        } else if (std.mem.eql(u8, name, "b")) {
            hdr.signature = val;
        } else if (std.mem.eql(u8, name, "bh")) {
            hdr.body_hash = val;
        } else if (std.mem.eql(u8, name, "c")) {
            hdr.canonicalization = parseCanonicalization(val);
        } else if (std.mem.eql(u8, name, "d")) {
            hdr.domain = val;
        } else if (std.mem.eql(u8, name, "h")) {
            hdr.signed_headers = val;
        } else if (std.mem.eql(u8, name, "s")) {
            hdr.selector = val;
        } else if (std.mem.eql(u8, name, "t")) {
            hdr.timestamp = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, name, "x")) {
            hdr.expiration = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, name, "i")) {
            hdr.identity = val;
        } else if (std.mem.eql(u8, name, "l")) {
            hdr.body_length = std.fmt.parseInt(u64, val, 10) catch null;
        } else if (std.mem.eql(u8, name, "q")) {
            hdr.query_method = val;
        }
    }

    return hdr;
}

fn parseCanonicalization(val: []const u8) canonicalize.Canonicalization {
    const slash = std.mem.indexOfScalar(u8, val, '/');
    if (slash) |s| {
        return .{
            .header = parseAlgo(val[0..s]),
            .body = parseAlgo(val[s + 1 ..]),
        };
    }
    const algo = parseAlgo(val);
    return .{ .header = algo, .body = .simple };
}

fn parseAlgo(val: []const u8) canonicalize.CanonicalizationAlgo {
    if (std.ascii.eqlIgnoreCase(val, "relaxed")) return .relaxed;
    return .simple;
}

test "build dkim header with empty signature" {
    const allocator = std.testing.allocator;
    const hdr = DkimHeader{
        .domain = "example.com",
        .selector = "sel1",
        .signed_headers = "From:To:Subject:Date",
        .body_hash = "abc123==",
        .timestamp = 1679900000,
    };
    const result = try buildDkimHeaderAlloc(allocator, hdr);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "d=example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "s=sel1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "bh=abc123==") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "b=") != null);
}

test "parse dkim header" {
    const hdr = parseDkimHeader("v=1; a=ed25519-sha256; d=example.com; s=sel1; h=From:To; bh=abc==; b=xyz==; t=12345");
    try std.testing.expectEqualStrings("1", hdr.version);
    try std.testing.expectEqualStrings("ed25519-sha256", hdr.algorithm);
    try std.testing.expectEqualStrings("example.com", hdr.domain);
    try std.testing.expectEqualStrings("sel1", hdr.selector);
    try std.testing.expectEqualStrings("From:To", hdr.signed_headers);
    try std.testing.expectEqualStrings("abc==", hdr.body_hash);
    try std.testing.expectEqualStrings("xyz==", hdr.signature);
    try std.testing.expectEqual(@as(u64, 12345), hdr.timestamp.?);
}
