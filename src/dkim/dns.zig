const std = @import("std");

/// DKIM DNS TXT record data.
pub const DnsRecord = struct {
    version: []const u8 = "DKIM1",
    key_type: []const u8 = "ed25519",
    public_key: []const u8 = "",
    hash_algorithms: ?[]const u8 = null,
    service_type: ?[]const u8 = null,
    flags: ?[]const u8 = null,
    notes: ?[]const u8 = null,
};

/// Build a DNS TXT record value for DKIM public key publication.
/// Returns the TXT record content (without quotes or DNS framing).
pub fn buildDnsRecordAlloc(allocator: std.mem.Allocator, record: DnsRecord) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("v=");
    try writer.writeAll(record.version);
    try writer.writeAll("; k=");
    try writer.writeAll(record.key_type);

    if (record.hash_algorithms) |h| {
        try writer.writeAll("; h=");
        try writer.writeAll(h);
    }

    if (record.service_type) |s| {
        try writer.writeAll("; s=");
        try writer.writeAll(s);
    }

    if (record.flags) |f| {
        try writer.writeAll("; t=");
        try writer.writeAll(f);
    }

    if (record.notes) |n| {
        try writer.writeAll("; n=");
        try writer.writeAll(n);
    }

    try writer.writeAll("; p=");
    try writer.writeAll(record.public_key);

    return out.toOwnedSlice(allocator);
}

/// Format the full DNS record name for a DKIM selector.
/// Returns "<selector>._domainkey.<domain>"
pub fn formatRecordNameAlloc(allocator: std.mem.Allocator, selector: []const u8, domain: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}._domainkey.{s}", .{ selector, domain });
}

test "build dns record" {
    const allocator = std.testing.allocator;
    const record = DnsRecord{
        .key_type = "ed25519",
        .public_key = "abc123==",
    };
    const result = try buildDnsRecordAlloc(allocator, record);
    defer allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "v=DKIM1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "k=ed25519") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "p=abc123==") != null);
}

test "format record name" {
    const allocator = std.testing.allocator;
    const name = try formatRecordNameAlloc(allocator, "sel1", "example.com");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("sel1._domainkey.example.com", name);
}
