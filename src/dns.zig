const std = @import("std");

/// An MX record with priority and hostname.
pub const MxRecord = struct {
    priority: u16,
    host: []const u8,
};

/// Result of MX lookup.
pub const MxLookupResult = struct {
    records: []MxRecord,

    pub fn deinit(self: *MxLookupResult, allocator: std.mem.Allocator) void {
        for (self.records) |rec| allocator.free(rec.host);
        allocator.free(self.records);
    }
};

/// Look up MX records for a domain by shelling out to `dig` or `host`.
/// Records are sorted by priority (lowest first).
/// If no MX records are found, returns the domain itself as implicit MX (RFC 5321 Section 5.1).
pub fn lookupMxAlloc(allocator: std.mem.Allocator, domain: []const u8) !MxLookupResult {
    // Try dig first
    if (lookupMxViaDig(allocator, domain)) |result| {
        if (result.records.len > 0) return result;
        // No records found via dig, fall through to try host
        var mut_result = result;
        mut_result.deinit(allocator);
    } else |_| {
        // dig failed, try host
    }

    // Fall back to host command
    if (lookupMxViaHost(allocator, domain)) |result| {
        if (result.records.len > 0) return result;
        var mut_result = result;
        mut_result.deinit(allocator);
    } else |_| {
        // host also failed
    }

    // No MX records found -- return the domain itself as implicit MX per RFC 5321 Section 5.1
    const records = try allocator.alloc(MxRecord, 1);
    records[0] = MxRecord{
        .priority = 0,
        .host = try allocator.dupe(u8, domain),
    };
    return MxLookupResult{ .records = records };
}

/// Look up MX records using the `dig` command.
fn lookupMxViaDig(allocator: std.mem.Allocator, domain: []const u8) !MxLookupResult {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "dig", "+short", "MX", domain },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var records = std.ArrayList(MxRecord).empty;
    defer records.deinit(allocator);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const maybe_rec = parseMxLine(allocator, line) catch continue;
        if (maybe_rec) |rec| {
            try records.append(allocator, rec);
        }
    }

    const owned = try records.toOwnedSlice(allocator);
    sortByPriority(owned);
    return MxLookupResult{ .records = owned };
}

/// Look up MX records using the `host` command (fallback).
fn lookupMxViaHost(allocator: std.mem.Allocator, domain: []const u8) !MxLookupResult {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "host", "-t", "MX", domain },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var records: std.ArrayList(MxRecord) = .empty;
    defer records.deinit(allocator);

    // host output format: "domain mail is handled by priority hostname."
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        const maybe_rec = parseHostMxLine(allocator, line) catch continue;
        if (maybe_rec) |rec| {
            try records.append(allocator, rec);
        }
    }

    const owned = try records.toOwnedSlice(allocator);
    sortByPriority(owned);
    return MxLookupResult{ .records = owned };
}

/// Parse a dig +short MX output line.
/// Format: "priority hostname."
fn parseMxLine(allocator: std.mem.Allocator, line: []const u8) !?MxRecord {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;

    // Split into priority and hostname
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const priority_str = parts.next() orelse return null;
    const host_raw = parts.next() orelse return null;

    const priority = std.fmt.parseInt(u16, priority_str, 10) catch return null;

    // Strip trailing dot from hostname
    const host = std.mem.trimRight(u8, host_raw, ".");
    if (host.len == 0) return null;

    return MxRecord{
        .priority = priority,
        .host = try allocator.dupe(u8, host),
    };
}

/// Parse a `host -t MX` output line.
/// Format: "domain mail is handled by priority hostname."
fn parseHostMxLine(allocator: std.mem.Allocator, line: []const u8) !?MxRecord {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;

    // Look for "mail is handled by"
    const marker = "mail is handled by ";
    const idx = std.mem.indexOf(u8, trimmed, marker) orelse return null;
    const after = trimmed[idx + marker.len ..];

    // after should be "priority hostname."
    var parts = std.mem.splitScalar(u8, after, ' ');
    const priority_str = parts.next() orelse return null;
    const host_raw = parts.next() orelse return null;

    const priority = std.fmt.parseInt(u16, priority_str, 10) catch return null;
    const host = std.mem.trimRight(u8, host_raw, ".");
    if (host.len == 0) return null;

    return MxRecord{
        .priority = priority,
        .host = try allocator.dupe(u8, host),
    };
}

/// Sort MX records by priority (lowest first).
fn sortByPriority(records: []MxRecord) void {
    std.mem.sort(MxRecord, records, {}, struct {
        fn lessThan(_: void, a: MxRecord, b: MxRecord) bool {
            return a.priority < b.priority;
        }
    }.lessThan);
}

/// Get the best MX host for a domain (lowest priority).
/// Caller owns the returned memory.
pub fn bestMxHostAlloc(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    var result = try lookupMxAlloc(allocator, domain);
    defer result.deinit(allocator);

    if (result.records.len == 0) {
        return try allocator.dupe(u8, domain);
    }

    // Records are already sorted by priority; take the first one.
    return try allocator.dupe(u8, result.records[0].host);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseMxLine parses valid dig output" {
    const allocator = std.testing.allocator;

    const rec = (try parseMxLine(allocator, "10 mail.example.com.")).?;
    defer allocator.free(rec.host);

    try std.testing.expectEqual(@as(u16, 10), rec.priority);
    try std.testing.expectEqualStrings("mail.example.com", rec.host);
}

test "parseMxLine returns null for empty line" {
    const allocator = std.testing.allocator;
    const rec = try parseMxLine(allocator, "");
    try std.testing.expect(rec == null);
}

test "parseMxLine returns null for malformed line" {
    const allocator = std.testing.allocator;
    const rec = try parseMxLine(allocator, "not a valid mx line");
    try std.testing.expect(rec == null);
}

test "parseHostMxLine parses valid host output" {
    const allocator = std.testing.allocator;

    const rec = (try parseHostMxLine(allocator, "example.com mail is handled by 5 alt1.aspmx.l.google.com.")).?;
    defer allocator.free(rec.host);

    try std.testing.expectEqual(@as(u16, 5), rec.priority);
    try std.testing.expectEqualStrings("alt1.aspmx.l.google.com", rec.host);
}

test "parseHostMxLine returns null for irrelevant line" {
    const allocator = std.testing.allocator;
    const rec = try parseHostMxLine(allocator, "example.com has address 93.184.216.34");
    try std.testing.expect(rec == null);
}

test "sortByPriority sorts ascending" {
    var records = [_]MxRecord{
        .{ .priority = 30, .host = "c" },
        .{ .priority = 10, .host = "a" },
        .{ .priority = 20, .host = "b" },
    };
    sortByPriority(&records);

    try std.testing.expectEqual(@as(u16, 10), records[0].priority);
    try std.testing.expectEqual(@as(u16, 20), records[1].priority);
    try std.testing.expectEqual(@as(u16, 30), records[2].priority);
}

test "MxLookupResult deinit frees memory" {
    const allocator = std.testing.allocator;
    const records = try allocator.alloc(MxRecord, 2);
    records[0] = .{ .priority = 10, .host = try allocator.dupe(u8, "mx1.example.com") };
    records[1] = .{ .priority = 20, .host = try allocator.dupe(u8, "mx2.example.com") };

    var result = MxLookupResult{ .records = records };
    result.deinit(allocator);
}
