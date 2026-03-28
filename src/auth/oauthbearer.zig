const std = @import("std");

const base64 = std.base64.standard;

pub const DecodedOAuthBearer = struct {
    user: []const u8,
    access_token: []const u8,
    host: ?[]const u8,
    port: ?u16,

    allocator: std.mem.Allocator,
    raw: []const u8,

    pub fn deinit(self: DecodedOAuthBearer) void {
        self.allocator.free(self.raw);
    }
};

/// Builds and base64-encodes the OAUTHBEARER initial response per RFC 7628.
///
/// Format: "n,a=<user>,\x01host=<host>\x01port=<port>\x01auth=Bearer <access_token>\x01\x01"
/// The host and port fields are optional.
/// Caller owns the returned memory.
pub fn initialResponseAlloc(
    allocator: std.mem.Allocator,
    user: []const u8,
    access_token: []const u8,
    host: ?[]const u8,
    port: ?u16,
) std.mem.Allocator.Error![]const u8 {
    const gs_header_prefix = "n,a=";
    const gs_header_suffix = ",\x01";
    const prefix_auth = "auth=Bearer ";
    const sep = "\x01";

    var total_len: usize = gs_header_prefix.len + user.len + gs_header_suffix.len;

    if (host) |h| {
        // "host=<host>\x01"
        total_len += "host=".len + h.len + sep.len;
    }

    var port_buf: [5]u8 = undefined;
    var port_str: ?[]const u8 = null;
    if (port) |p| {
        const s = std.fmt.bufPrint(&port_buf, "{d}", .{p}) catch unreachable;
        port_str = s;
        // "port=<port>\x01"
        total_len += "port=".len + s.len + sep.len;
    }

    total_len += prefix_auth.len + access_token.len + sep.len + sep.len;

    const raw = try allocator.alloc(u8, total_len);
    defer allocator.free(raw);

    var offset: usize = 0;

    @memcpy(raw[offset .. offset + gs_header_prefix.len], gs_header_prefix);
    offset += gs_header_prefix.len;

    @memcpy(raw[offset .. offset + user.len], user);
    offset += user.len;

    @memcpy(raw[offset .. offset + gs_header_suffix.len], gs_header_suffix);
    offset += gs_header_suffix.len;

    if (host) |h| {
        const host_prefix = "host=";
        @memcpy(raw[offset .. offset + host_prefix.len], host_prefix);
        offset += host_prefix.len;
        @memcpy(raw[offset .. offset + h.len], h);
        offset += h.len;
        raw[offset] = '\x01';
        offset += 1;
    }

    if (port_str) |ps| {
        const port_prefix = "port=";
        @memcpy(raw[offset .. offset + port_prefix.len], port_prefix);
        offset += port_prefix.len;
        @memcpy(raw[offset .. offset + ps.len], ps);
        offset += ps.len;
        raw[offset] = '\x01';
        offset += 1;
    }

    @memcpy(raw[offset .. offset + prefix_auth.len], prefix_auth);
    offset += prefix_auth.len;

    @memcpy(raw[offset .. offset + access_token.len], access_token);
    offset += access_token.len;

    raw[offset] = '\x01';
    offset += 1;

    raw[offset] = '\x01';

    return encodeBase64Alloc(allocator, raw);
}

/// Decodes a base64-encoded OAUTHBEARER response and extracts the user,
/// access_token, host, and port fields.
/// Caller must call `.deinit()` on the returned value to free memory.
pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    text: []const u8,
) !DecodedOAuthBearer {
    const raw = try decodeBase64Alloc(allocator, text);
    errdefer allocator.free(raw);

    // Parse GS2 header: "n,a=<user>,"
    if (raw.len < 4 or raw[0] != 'n' or raw[1] != ',') return error.InvalidFormat;
    if (!std.mem.startsWith(u8, raw[2..], "a=")) return error.InvalidFormat;

    const after_a_eq = raw[4..];
    const comma_idx = std.mem.indexOfScalar(u8, after_a_eq, ',') orelse return error.InvalidFormat;
    const user = after_a_eq[0..comma_idx];

    // After the comma there should be a \x01 starting the key-value pairs.
    const kv_start = 4 + comma_idx + 1;
    if (kv_start >= raw.len or raw[kv_start] != '\x01') return error.InvalidFormat;

    const kv_section = raw[kv_start + 1 ..];

    const token = try extractField(kv_section, "auth=Bearer ");
    const host_val = extractField(kv_section, "host=") catch null;

    var port_val: ?u16 = null;
    if (extractField(kv_section, "port=")) |port_s| {
        port_val = std.fmt.parseInt(u16, port_s, 10) catch return error.InvalidPort;
    } else |_| {}

    return DecodedOAuthBearer{
        .user = user,
        .access_token = token,
        .host = host_val,
        .port = port_val,
        .allocator = allocator,
        .raw = raw,
    };
}

/// Extracts the value of a field from the key-value section.
/// The returned slice points into `data` -- no allocation is performed.
fn extractField(data: []const u8, prefix: []const u8) ![]const u8 {
    const start_idx = std.mem.indexOf(u8, data, prefix) orelse return error.FieldNotFound;
    const value_start = start_idx + prefix.len;
    const remaining = data[value_start..];

    // Field value ends at the next \x01 or end of data.
    const end_idx = std.mem.indexOfScalar(u8, remaining, '\x01') orelse remaining.len;
    return remaining[0..end_idx];
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error![]const u8 {
    const encoded_len = base64.Encoder.calcSize(data.len);
    const buf = try allocator.alloc(u8, encoded_len);
    _ = base64.Encoder.encode(buf, data);
    return buf;
}

fn decodeBase64Alloc(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    const decoded_len = base64.Decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    const buf = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(buf);
    base64.Decoder.decode(buf, encoded) catch return error.InvalidBase64;
    return buf;
}

test "oauthbearer: initial response encode and decode round-trip with host and port" {
    const allocator = std.testing.allocator;

    const encoded = try initialResponseAlloc(allocator, "testuser@example.com", "ya29.token123", "smtp.example.com", 587);
    defer allocator.free(encoded);

    const decoded = try decodeAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, "testuser@example.com", decoded.user);
    try std.testing.expectEqualSlices(u8, "ya29.token123", decoded.access_token);
    try std.testing.expectEqualSlices(u8, "smtp.example.com", decoded.host.?);
    try std.testing.expectEqual(@as(u16, 587), decoded.port.?);
}

test "oauthbearer: initial response encode and decode round-trip without host and port" {
    const allocator = std.testing.allocator;

    const encoded = try initialResponseAlloc(allocator, "user@example.com", "token456", null, null);
    defer allocator.free(encoded);

    const decoded = try decodeAlloc(allocator, encoded);
    defer decoded.deinit();

    try std.testing.expectEqualSlices(u8, "user@example.com", decoded.user);
    try std.testing.expectEqualSlices(u8, "token456", decoded.access_token);
    try std.testing.expectEqual(@as(?[]const u8, null), decoded.host);
    try std.testing.expectEqual(@as(?u16, null), decoded.port);
}
