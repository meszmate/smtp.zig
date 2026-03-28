const std = @import("std");

/// SPF result per RFC 7208 Section 2.6.
pub const SpfResult = enum {
    pass,
    fail,
    softfail,
    neutral,
    none,
    temperror,
    permerror,

    pub fn label(self: SpfResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .softfail => "softfail",
            .neutral => "neutral",
            .none => "none",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }

    pub fn isPass(self: SpfResult) bool {
        return self == .pass;
    }
};

/// SPF mechanism qualifier per RFC 7208 Section 4.6.2.
pub const MechanismQualifier = enum {
    pass,
    fail,
    softfail,
    neutral,

    pub fn label(self: MechanismQualifier) []const u8 {
        return switch (self) {
            .pass => "+",
            .fail => "-",
            .softfail => "~",
            .neutral => "?",
        };
    }

    pub fn toResult(self: MechanismQualifier) SpfResult {
        return switch (self) {
            .pass => .pass,
            .fail => .fail,
            .softfail => .softfail,
            .neutral => .neutral,
        };
    }
};

/// SPF mechanism kind per RFC 7208 Sections 5.1-5.7.
pub const MechanismKind = union(enum) {
    all,
    ip4: []const u8,
    ip6: []const u8,
    a: ?[]const u8,
    mx: ?[]const u8,
    include: []const u8,
    exists: []const u8,
    ptr: ?[]const u8,
};

/// A single SPF mechanism with qualifier.
pub const Mechanism = struct {
    qualifier: MechanismQualifier = .pass,
    kind: MechanismKind,

    /// Format this mechanism back to SPF text representation.
    pub fn formatAlloc(self: Mechanism, allocator: std.mem.Allocator) ![]u8 {
        const prefix: []const u8 = if (self.qualifier == .pass) "" else self.qualifier.label();
        return switch (self.kind) {
            .all => std.fmt.allocPrint(allocator, "{s}all", .{prefix}),
            .ip4 => |v| std.fmt.allocPrint(allocator, "{s}ip4:{s}", .{ prefix, v }),
            .ip6 => |v| std.fmt.allocPrint(allocator, "{s}ip6:{s}", .{ prefix, v }),
            .a => |v| if (v) |d|
                std.fmt.allocPrint(allocator, "{s}a:{s}", .{ prefix, d })
            else
                std.fmt.allocPrint(allocator, "{s}a", .{prefix}),
            .mx => |v| if (v) |d|
                std.fmt.allocPrint(allocator, "{s}mx:{s}", .{ prefix, d })
            else
                std.fmt.allocPrint(allocator, "{s}mx", .{prefix}),
            .include => |v| std.fmt.allocPrint(allocator, "{s}include:{s}", .{ prefix, v }),
            .exists => |v| std.fmt.allocPrint(allocator, "{s}exists:{s}", .{ prefix, v }),
            .ptr => |v| if (v) |d|
                std.fmt.allocPrint(allocator, "{s}ptr:{s}", .{ prefix, d })
            else
                std.fmt.allocPrint(allocator, "{s}ptr", .{prefix}),
        };
    }
};

/// Parsed SPF record per RFC 7208.
pub const SpfRecord = struct {
    version: []const u8 = "spf1",
    mechanisms: []const Mechanism = &.{},
    redirect: ?[]const u8 = null,
    explanation: ?[]const u8 = null,
};

pub const SpfParseError = error{
    InvalidVersion,
    InvalidMechanism,
    OutOfMemory,
};

/// Parse an SPF TXT record string into an SpfRecord.
/// Caller owns the returned mechanisms slice.
pub fn parseSpfRecord(allocator: std.mem.Allocator, txt: []const u8) SpfParseError!SpfRecord {
    const trimmed = std.mem.trim(u8, txt, " \t\r\n");
    if (!std.mem.startsWith(u8, trimmed, "v=spf1")) {
        return SpfParseError.InvalidVersion;
    }

    var mechanisms: std.ArrayList(Mechanism) = .empty;
    defer mechanisms.deinit(allocator);

    var redirect: ?[]const u8 = null;
    var explanation: ?[]const u8 = null;

    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    // Skip "v=spf1"
    _ = parts.next();

    while (parts.next()) |part| {
        const term = std.mem.trim(u8, part, " \t");
        if (term.len == 0) continue;

        // Check for modifiers
        if (std.mem.startsWith(u8, term, "redirect=")) {
            redirect = term["redirect=".len..];
            continue;
        }
        if (std.mem.startsWith(u8, term, "exp=")) {
            explanation = term["exp=".len..];
            continue;
        }

        const mech = parseMechanism(term) catch {
            return SpfParseError.InvalidMechanism;
        };
        try mechanisms.append(allocator, mech);
    }

    return SpfRecord{
        .version = "spf1",
        .mechanisms = try mechanisms.toOwnedSlice(allocator),
        .redirect = redirect,
        .explanation = explanation,
    };
}

/// Parse a single SPF mechanism from text (e.g., "+ip4:192.168.0.0/16").
pub fn parseMechanism(text: []const u8) !Mechanism {
    if (text.len == 0) return error.InvalidMechanism;

    var qualifier: MechanismQualifier = .pass;
    var body = text;

    // Check for qualifier prefix
    switch (text[0]) {
        '+' => {
            qualifier = .pass;
            body = text[1..];
        },
        '-' => {
            qualifier = .fail;
            body = text[1..];
        },
        '~' => {
            qualifier = .softfail;
            body = text[1..];
        },
        '?' => {
            qualifier = .neutral;
            body = text[1..];
        },
        else => {},
    }

    if (body.len == 0) return error.InvalidMechanism;

    // Lowercase comparison for mechanism names
    if (eqlIgnoreCase(body, "all")) {
        return Mechanism{ .qualifier = qualifier, .kind = .all };
    }

    if (eqlIgnoreCase(body, "a") or eqlIgnoreCase(body, "a/")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .a = null } };
    }
    if (startsWithIgnoreCase(body, "a:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .a = body[2..] } };
    }
    if (startsWithIgnoreCase(body, "a/")) {
        // a with CIDR length, no domain
        return Mechanism{ .qualifier = qualifier, .kind = .{ .a = null } };
    }

    if (eqlIgnoreCase(body, "mx")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .mx = null } };
    }
    if (startsWithIgnoreCase(body, "mx:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .mx = body[3..] } };
    }

    if (startsWithIgnoreCase(body, "ip4:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .ip4 = body[4..] } };
    }
    if (startsWithIgnoreCase(body, "ip6:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .ip6 = body[4..] } };
    }

    if (startsWithIgnoreCase(body, "include:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .include = body[8..] } };
    }
    if (startsWithIgnoreCase(body, "exists:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .exists = body[7..] } };
    }

    if (eqlIgnoreCase(body, "ptr")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .ptr = null } };
    }
    if (startsWithIgnoreCase(body, "ptr:")) {
        return Mechanism{ .qualifier = qualifier, .kind = .{ .ptr = body[4..] } };
    }

    return error.InvalidMechanism;
}

/// Check if an IP address matches a CIDR notation string.
/// Supports both IPv4 (e.g. "192.168.1.0/24") and plain IPs.
pub fn matchesCidr(ip: []const u8, cidr: []const u8) bool {
    // Split CIDR into address and prefix length
    const slash_pos = std.mem.indexOfScalar(u8, cidr, '/');
    const cidr_addr = if (slash_pos) |pos| cidr[0..pos] else cidr;
    const prefix_len_str = if (slash_pos) |pos| cidr[pos + 1 ..] else null;

    const ip_bytes = parseIpv4(ip) orelse return false;
    const cidr_bytes = parseIpv4(cidr_addr) orelse return false;

    const prefix_len: u6 = if (prefix_len_str) |s|
        std.fmt.parseInt(u6, s, 10) catch return false
    else
        32;

    if (prefix_len == 0) return true;
    if (prefix_len > 32) return false;

    const ip_val = ipv4ToU32(ip_bytes);
    const cidr_val = ipv4ToU32(cidr_bytes);

    // Create mask: prefix_len most-significant bits set
    const mask: u32 = if (prefix_len == 32)
        0xFFFFFFFF
    else
        ~((@as(u32, 1) << @as(u5, @intCast(32 - prefix_len))) - 1);

    return (ip_val & mask) == (cidr_val & mask);
}

/// Format an SPF result as a Received-SPF header value per RFC 7208 Section 9.1.
pub fn formatResultHeaderAlloc(
    allocator: std.mem.Allocator,
    result: SpfResult,
    domain: []const u8,
    ip: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Received-SPF: {s} (domain of {s} designates {s} as permitted sender)",
        .{ result.label(), domain, ip },
    );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parseIpv4(ip: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, ip, '.');
    var i: usize = 0;
    while (parts.next()) |part| {
        if (i >= 4) return null;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return result;
}

fn ipv4ToU32(bytes: [4]u8) u32 {
    return @as(u32, bytes[0]) << 24 |
        @as(u32, bytes[1]) << 16 |
        @as(u32, bytes[2]) << 8 |
        @as(u32, bytes[3]);
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "SpfResult.label returns correct strings" {
    try std.testing.expectEqualStrings("pass", SpfResult.pass.label());
    try std.testing.expectEqualStrings("fail", SpfResult.fail.label());
    try std.testing.expectEqualStrings("softfail", SpfResult.softfail.label());
    try std.testing.expectEqualStrings("neutral", SpfResult.neutral.label());
    try std.testing.expectEqualStrings("none", SpfResult.none.label());
    try std.testing.expectEqualStrings("temperror", SpfResult.temperror.label());
    try std.testing.expectEqualStrings("permerror", SpfResult.permerror.label());
}

test "SpfResult.isPass" {
    try std.testing.expect(SpfResult.pass.isPass());
    try std.testing.expect(!SpfResult.fail.isPass());
    try std.testing.expect(!SpfResult.softfail.isPass());
    try std.testing.expect(!SpfResult.none.isPass());
}

test "MechanismQualifier.label" {
    try std.testing.expectEqualStrings("+", MechanismQualifier.pass.label());
    try std.testing.expectEqualStrings("-", MechanismQualifier.fail.label());
    try std.testing.expectEqualStrings("~", MechanismQualifier.softfail.label());
    try std.testing.expectEqualStrings("?", MechanismQualifier.neutral.label());
}

test "MechanismQualifier.toResult" {
    try std.testing.expectEqual(SpfResult.pass, MechanismQualifier.pass.toResult());
    try std.testing.expectEqual(SpfResult.fail, MechanismQualifier.fail.toResult());
    try std.testing.expectEqual(SpfResult.softfail, MechanismQualifier.softfail.toResult());
    try std.testing.expectEqual(SpfResult.neutral, MechanismQualifier.neutral.toResult());
}

test "parseMechanism parses all" {
    const m = try parseMechanism("all");
    try std.testing.expectEqual(MechanismQualifier.pass, m.qualifier);
    try std.testing.expectEqual(MechanismKind.all, m.kind);
}

test "parseMechanism parses ~all" {
    const m = try parseMechanism("~all");
    try std.testing.expectEqual(MechanismQualifier.softfail, m.qualifier);
    try std.testing.expectEqual(MechanismKind.all, m.kind);
}

test "parseMechanism parses -all" {
    const m = try parseMechanism("-all");
    try std.testing.expectEqual(MechanismQualifier.fail, m.qualifier);
    try std.testing.expectEqual(MechanismKind.all, m.kind);
}

test "parseMechanism parses ip4" {
    const m = try parseMechanism("ip4:192.168.0.0/16");
    try std.testing.expectEqual(MechanismQualifier.pass, m.qualifier);
    try std.testing.expectEqualStrings("192.168.0.0/16", m.kind.ip4);
}

test "parseMechanism parses ip6" {
    const m = try parseMechanism("+ip6:2001:db8::/32");
    try std.testing.expectEqual(MechanismQualifier.pass, m.qualifier);
    try std.testing.expectEqualStrings("2001:db8::/32", m.kind.ip6);
}

test "parseMechanism parses include" {
    const m = try parseMechanism("include:_spf.google.com");
    try std.testing.expectEqualStrings("_spf.google.com", m.kind.include);
}

test "parseMechanism parses mx with domain" {
    const m = try parseMechanism("mx:example.com");
    try std.testing.expectEqualStrings("example.com", m.kind.mx.?);
}

test "parseMechanism parses mx without domain" {
    const m = try parseMechanism("mx");
    try std.testing.expect(m.kind.mx == null);
}

test "parseMechanism parses a with domain" {
    const m = try parseMechanism("a:mail.example.com");
    try std.testing.expectEqualStrings("mail.example.com", m.kind.a.?);
}

test "parseMechanism parses a without domain" {
    const m = try parseMechanism("a");
    try std.testing.expect(m.kind.a == null);
}

test "parseMechanism parses exists" {
    const m = try parseMechanism("exists:example.com");
    try std.testing.expectEqualStrings("example.com", m.kind.exists);
}

test "parseMechanism parses ptr without domain" {
    const m = try parseMechanism("ptr");
    try std.testing.expect(m.kind.ptr == null);
}

test "parseMechanism parses ptr with domain" {
    const m = try parseMechanism("ptr:example.com");
    try std.testing.expectEqualStrings("example.com", m.kind.ptr.?);
}

test "parseMechanism rejects empty" {
    try std.testing.expectError(error.InvalidMechanism, parseMechanism(""));
}

test "parseMechanism rejects unknown" {
    try std.testing.expectError(error.InvalidMechanism, parseMechanism("unknown:foo"));
}

test "parseSpfRecord parses basic record" {
    const allocator = std.testing.allocator;
    const record = try parseSpfRecord(allocator, "v=spf1 ip4:192.168.0.0/16 include:example.com ~all");
    defer allocator.free(record.mechanisms);

    try std.testing.expectEqual(@as(usize, 3), record.mechanisms.len);
    try std.testing.expectEqualStrings("192.168.0.0/16", record.mechanisms[0].kind.ip4);
    try std.testing.expectEqualStrings("example.com", record.mechanisms[1].kind.include);
    try std.testing.expectEqual(MechanismKind.all, record.mechanisms[2].kind);
    try std.testing.expectEqual(MechanismQualifier.softfail, record.mechanisms[2].qualifier);
}

test "parseSpfRecord parses redirect" {
    const allocator = std.testing.allocator;
    const record = try parseSpfRecord(allocator, "v=spf1 redirect=_spf.example.com");
    defer allocator.free(record.mechanisms);

    try std.testing.expectEqualStrings("_spf.example.com", record.redirect.?);
    try std.testing.expectEqual(@as(usize, 0), record.mechanisms.len);
}

test "parseSpfRecord parses explanation" {
    const allocator = std.testing.allocator;
    const record = try parseSpfRecord(allocator, "v=spf1 -all exp=explain._spf.example.com");
    defer allocator.free(record.mechanisms);

    try std.testing.expectEqualStrings("explain._spf.example.com", record.explanation.?);
    try std.testing.expectEqual(@as(usize, 1), record.mechanisms.len);
}

test "parseSpfRecord rejects invalid version" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(SpfParseError.InvalidVersion, parseSpfRecord(allocator, "v=spf2 all"));
}

test "parseSpfRecord rejects non-SPF text" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(SpfParseError.InvalidVersion, parseSpfRecord(allocator, "some random txt record"));
}

test "matchesCidr matches exact IP" {
    try std.testing.expect(matchesCidr("192.168.1.1", "192.168.1.1"));
}

test "matchesCidr matches /24 network" {
    try std.testing.expect(matchesCidr("192.168.1.100", "192.168.1.0/24"));
    try std.testing.expect(matchesCidr("192.168.1.255", "192.168.1.0/24"));
    try std.testing.expect(!matchesCidr("192.168.2.1", "192.168.1.0/24"));
}

test "matchesCidr matches /16 network" {
    try std.testing.expect(matchesCidr("10.0.50.1", "10.0.0.0/16"));
    try std.testing.expect(!matchesCidr("10.1.0.1", "10.0.0.0/16"));
}

test "matchesCidr matches /8 network" {
    try std.testing.expect(matchesCidr("10.100.200.50", "10.0.0.0/8"));
    try std.testing.expect(!matchesCidr("11.0.0.1", "10.0.0.0/8"));
}

test "matchesCidr returns false for invalid IP" {
    try std.testing.expect(!matchesCidr("not.an.ip", "192.168.1.0/24"));
    try std.testing.expect(!matchesCidr("192.168.1.1", "not.valid/24"));
}

test "formatResultHeaderAlloc formats pass" {
    const allocator = std.testing.allocator;
    const header = try formatResultHeaderAlloc(allocator, .pass, "example.com", "192.168.1.1");
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "Received-SPF: pass (domain of example.com designates 192.168.1.1 as permitted sender)",
        header,
    );
}

test "formatResultHeaderAlloc formats fail" {
    const allocator = std.testing.allocator;
    const header = try formatResultHeaderAlloc(allocator, .fail, "example.com", "10.0.0.1");
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        "Received-SPF: fail (domain of example.com designates 10.0.0.1 as permitted sender)",
        header,
    );
}

test "Mechanism.formatAlloc formats ip4" {
    const allocator = std.testing.allocator;
    const m = Mechanism{ .qualifier = .pass, .kind = .{ .ip4 = "192.168.0.0/16" } };
    const s = try m.formatAlloc(allocator);
    defer allocator.free(s);
    try std.testing.expectEqualStrings("ip4:192.168.0.0/16", s);
}

test "Mechanism.formatAlloc formats ~all" {
    const allocator = std.testing.allocator;
    const m = Mechanism{ .qualifier = .softfail, .kind = .all };
    const s = try m.formatAlloc(allocator);
    defer allocator.free(s);
    try std.testing.expectEqualStrings("~all", s);
}

test "Mechanism.formatAlloc formats -all" {
    const allocator = std.testing.allocator;
    const m = Mechanism{ .qualifier = .fail, .kind = .all };
    const s = try m.formatAlloc(allocator);
    defer allocator.free(s);
    try std.testing.expectEqualStrings("-all", s);
}

test "Mechanism.formatAlloc formats include" {
    const allocator = std.testing.allocator;
    const m = Mechanism{ .qualifier = .pass, .kind = .{ .include = "_spf.google.com" } };
    const s = try m.formatAlloc(allocator);
    defer allocator.free(s);
    try std.testing.expectEqualStrings("include:_spf.google.com", s);
}

test "parseIpv4 parses valid addresses" {
    const result = parseIpv4("192.168.1.1").?;
    try std.testing.expectEqual(@as(u8, 192), result[0]);
    try std.testing.expectEqual(@as(u8, 168), result[1]);
    try std.testing.expectEqual(@as(u8, 1), result[2]);
    try std.testing.expectEqual(@as(u8, 1), result[3]);
}

test "parseIpv4 returns null for invalid" {
    try std.testing.expect(parseIpv4("not.valid") == null);
    try std.testing.expect(parseIpv4("256.1.1.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
}

test "case insensitive mechanism parsing" {
    const m1 = try parseMechanism("IP4:10.0.0.0/8");
    try std.testing.expectEqualStrings("10.0.0.0/8", m1.kind.ip4);

    const m2 = try parseMechanism("ALL");
    try std.testing.expectEqual(MechanismKind.all, m2.kind);

    const m3 = try parseMechanism("Include:example.com");
    try std.testing.expectEqualStrings("example.com", m3.kind.include);
}
