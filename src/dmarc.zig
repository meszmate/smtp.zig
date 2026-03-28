const std = @import("std");

/// DMARC policy per RFC 7489 Section 6.3.
pub const DmarcPolicy = enum {
    none,
    quarantine,
    reject,

    pub fn label(self: DmarcPolicy) []const u8 {
        return switch (self) {
            .none => "none",
            .quarantine => "quarantine",
            .reject => "reject",
        };
    }
};

/// DMARC identifier alignment per RFC 7489 Section 3.1.
pub const DmarcAlignment = enum {
    relaxed,
    strict,

    pub fn label(self: DmarcAlignment) []const u8 {
        return switch (self) {
            .relaxed => "r",
            .strict => "s",
        };
    }
};

/// Parsed DMARC record per RFC 7489 Section 6.3.
pub const DmarcRecord = struct {
    version: []const u8 = "DMARC1",
    policy: DmarcPolicy = .none,
    subdomain_policy: ?DmarcPolicy = null,
    dkim_alignment: DmarcAlignment = .relaxed,
    spf_alignment: DmarcAlignment = .relaxed,
    percentage: u8 = 100,
    rua: ?[]const u8 = null,
    ruf: ?[]const u8 = null,
    report_interval: u64 = 86400,
    failure_options: []const u8 = "0",
};

/// DMARC evaluation result per RFC 7489 Section 4.2.
pub const DmarcResult = enum {
    pass,
    fail,
    none,
    temperror,
    permerror,

    pub fn label(self: DmarcResult) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .none => "none",
            .temperror => "temperror",
            .permerror => "permerror",
        };
    }
};

/// Full DMARC evaluation result with details.
pub const DmarcEvaluation = struct {
    result: DmarcResult,
    policy: DmarcPolicy = .none,
    dkim_aligned: bool = false,
    spf_aligned: bool = false,
    from_domain: []const u8 = "",
};

/// Parse a DMARC TXT record string per RFC 7489 Section 6.3.
pub fn parseDmarcRecord(txt: []const u8) DmarcRecord {
    var record = DmarcRecord{};
    const trimmed = std.mem.trim(u8, txt, " \t\r\n");

    var parts = std.mem.splitScalar(u8, trimmed, ';');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t");
        if (part.len == 0) continue;

        const eq_pos = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const key = std.mem.trim(u8, part[0..eq_pos], " \t");
        const value = std.mem.trim(u8, part[eq_pos + 1 ..], " \t");

        if (eqlIgnoreCase(key, "v")) {
            record.version = value;
        } else if (eqlIgnoreCase(key, "p")) {
            record.policy = parsePolicy(value);
        } else if (eqlIgnoreCase(key, "sp")) {
            record.subdomain_policy = parsePolicy(value);
        } else if (eqlIgnoreCase(key, "adkim")) {
            record.dkim_alignment = parseAlignment(value);
        } else if (eqlIgnoreCase(key, "aspf")) {
            record.spf_alignment = parseAlignment(value);
        } else if (eqlIgnoreCase(key, "pct")) {
            record.percentage = std.fmt.parseInt(u8, value, 10) catch 100;
        } else if (eqlIgnoreCase(key, "rua")) {
            record.rua = value;
        } else if (eqlIgnoreCase(key, "ruf")) {
            record.ruf = value;
        } else if (eqlIgnoreCase(key, "ri")) {
            record.report_interval = std.fmt.parseInt(u64, value, 10) catch 86400;
        } else if (eqlIgnoreCase(key, "fo")) {
            record.failure_options = value;
        }
    }

    return record;
}

/// Build a DMARC TXT record string from a DmarcRecord.
/// Caller owns the returned memory.
pub fn buildDmarcRecordAlloc(allocator: std.mem.Allocator, record: DmarcRecord) ![]u8 {
    var parts: std.ArrayList(u8) = .empty;
    defer parts.deinit(allocator);

    try parts.appendSlice(allocator, "v=");
    try parts.appendSlice(allocator, record.version);
    try parts.appendSlice(allocator, "; p=");
    try parts.appendSlice(allocator, record.policy.label());

    if (record.subdomain_policy) |sp| {
        try parts.appendSlice(allocator, "; sp=");
        try parts.appendSlice(allocator, sp.label());
    }

    if (record.dkim_alignment != .relaxed) {
        try parts.appendSlice(allocator, "; adkim=");
        try parts.appendSlice(allocator, record.dkim_alignment.label());
    }

    if (record.spf_alignment != .relaxed) {
        try parts.appendSlice(allocator, "; aspf=");
        try parts.appendSlice(allocator, record.spf_alignment.label());
    }

    if (record.percentage != 100) {
        const pct_str = try std.fmt.allocPrint(allocator, "; pct={d}", .{record.percentage});
        defer allocator.free(pct_str);
        try parts.appendSlice(allocator, pct_str);
    }

    if (record.rua) |rua| {
        try parts.appendSlice(allocator, "; rua=");
        try parts.appendSlice(allocator, rua);
    }

    if (record.ruf) |ruf| {
        try parts.appendSlice(allocator, "; ruf=");
        try parts.appendSlice(allocator, ruf);
    }

    if (record.report_interval != 86400) {
        const ri_str = try std.fmt.allocPrint(allocator, "; ri={d}", .{record.report_interval});
        defer allocator.free(ri_str);
        try parts.appendSlice(allocator, ri_str);
    }

    if (!std.mem.eql(u8, record.failure_options, "0")) {
        try parts.appendSlice(allocator, "; fo=");
        try parts.appendSlice(allocator, record.failure_options);
    }

    return parts.toOwnedSlice(allocator);
}

/// Evaluate DMARC policy given SPF and DKIM results per RFC 7489 Section 4.2.
pub fn evaluate(
    record: DmarcRecord,
    from_domain: []const u8,
    spf_domain: ?[]const u8,
    spf_pass: bool,
    dkim_domain: ?[]const u8,
    dkim_pass: bool,
) DmarcEvaluation {
    var eval = DmarcEvaluation{
        .result = .fail,
        .policy = record.policy,
        .from_domain = from_domain,
    };

    // Check DKIM alignment
    if (dkim_pass) {
        if (dkim_domain) |dd| {
            eval.dkim_aligned = isAligned(from_domain, dd, record.dkim_alignment);
        }
    }

    // Check SPF alignment
    if (spf_pass) {
        if (spf_domain) |sd| {
            eval.spf_aligned = isAligned(from_domain, sd, record.spf_alignment);
        }
    }

    // DMARC passes if either DKIM or SPF is aligned and passes
    if (eval.dkim_aligned or eval.spf_aligned) {
        eval.result = .pass;
    }

    return eval;
}

/// Check domain alignment per RFC 7489 Section 3.1.
/// Relaxed: organizational domain must match.
/// Strict: exact domain must match.
pub fn isAligned(from_domain: []const u8, auth_domain: []const u8, alignment: DmarcAlignment) bool {
    return switch (alignment) {
        .strict => eqlIgnoreCase(from_domain, auth_domain),
        .relaxed => {
            const from_org = organizationalDomain(from_domain);
            const auth_org = organizationalDomain(auth_domain);
            return eqlIgnoreCase(from_org, auth_org);
        },
    };
}

/// Get the organizational domain (registered domain) from a full domain.
/// Simple heuristic: take last two labels, or three for known ccTLD patterns
/// like .co.uk, .com.au, etc.
pub fn organizationalDomain(domain: []const u8) []const u8 {
    const trimmed = std.mem.trimRight(u8, domain, ".");

    // Count dots and find positions
    var dot_positions: [64]usize = undefined;
    var dot_count: usize = 0;

    for (trimmed, 0..) |c, i| {
        if (c == '.') {
            if (dot_count < 64) {
                dot_positions[dot_count] = i;
                dot_count += 1;
            }
        }
    }

    // Single label or no dots -- return as-is
    if (dot_count == 0) return trimmed;

    // Two labels -- already an organizational domain
    if (dot_count == 1) return trimmed;

    // Check for known two-level TLDs (ccTLD patterns)
    const last_dot = dot_positions[dot_count - 1];
    const tld = trimmed[last_dot + 1 ..];
    const second_last_dot = dot_positions[dot_count - 2];
    const sld = trimmed[second_last_dot + 1 .. last_dot];

    const known_two_level = [_]struct { sld: []const u8, tld: []const u8 }{
        .{ .sld = "co", .tld = "uk" },
        .{ .sld = "org", .tld = "uk" },
        .{ .sld = "ac", .tld = "uk" },
        .{ .sld = "com", .tld = "au" },
        .{ .sld = "net", .tld = "au" },
        .{ .sld = "org", .tld = "au" },
        .{ .sld = "co", .tld = "nz" },
        .{ .sld = "co", .tld = "jp" },
        .{ .sld = "or", .tld = "jp" },
        .{ .sld = "com", .tld = "br" },
        .{ .sld = "co", .tld = "in" },
        .{ .sld = "co", .tld = "za" },
    };

    for (known_two_level) |entry| {
        if (eqlIgnoreCase(sld, entry.sld) and eqlIgnoreCase(tld, entry.tld)) {
            // Need three labels for two-level TLD
            if (dot_count >= 3) {
                return trimmed[dot_positions[dot_count - 3] + 1 ..];
            }
            return trimmed;
        }
    }

    // Default: take the last two labels
    return trimmed[second_last_dot + 1 ..];
}

/// Format the DNS record name for DMARC lookup per RFC 7489 Section 6.1.
/// Returns "_dmarc.<domain>".
pub fn formatDmarcDnsNameAlloc(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "_dmarc.{s}", .{domain});
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parsePolicy(value: []const u8) DmarcPolicy {
    if (eqlIgnoreCase(value, "none")) return .none;
    if (eqlIgnoreCase(value, "quarantine")) return .quarantine;
    if (eqlIgnoreCase(value, "reject")) return .reject;
    return .none;
}

fn parseAlignment(value: []const u8) DmarcAlignment {
    if (eqlIgnoreCase(value, "s")) return .strict;
    return .relaxed;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "DmarcPolicy.label" {
    try std.testing.expectEqualStrings("none", DmarcPolicy.none.label());
    try std.testing.expectEqualStrings("quarantine", DmarcPolicy.quarantine.label());
    try std.testing.expectEqualStrings("reject", DmarcPolicy.reject.label());
}

test "DmarcAlignment.label" {
    try std.testing.expectEqualStrings("r", DmarcAlignment.relaxed.label());
    try std.testing.expectEqualStrings("s", DmarcAlignment.strict.label());
}

test "DmarcResult.label" {
    try std.testing.expectEqualStrings("pass", DmarcResult.pass.label());
    try std.testing.expectEqualStrings("fail", DmarcResult.fail.label());
    try std.testing.expectEqualStrings("none", DmarcResult.none.label());
    try std.testing.expectEqualStrings("temperror", DmarcResult.temperror.label());
    try std.testing.expectEqualStrings("permerror", DmarcResult.permerror.label());
}

test "parseDmarcRecord parses basic record" {
    const record = parseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s");
    try std.testing.expectEqualStrings("DMARC1", record.version);
    try std.testing.expectEqual(DmarcPolicy.reject, record.policy);
    try std.testing.expectEqual(DmarcAlignment.strict, record.dkim_alignment);
    try std.testing.expectEqual(DmarcAlignment.strict, record.spf_alignment);
}

test "parseDmarcRecord parses full record" {
    const record = parseDmarcRecord(
        "v=DMARC1; p=quarantine; sp=reject; adkim=r; aspf=s; pct=50; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; ri=3600; fo=1",
    );
    try std.testing.expectEqual(DmarcPolicy.quarantine, record.policy);
    try std.testing.expectEqual(DmarcPolicy.reject, record.subdomain_policy.?);
    try std.testing.expectEqual(DmarcAlignment.relaxed, record.dkim_alignment);
    try std.testing.expectEqual(DmarcAlignment.strict, record.spf_alignment);
    try std.testing.expectEqual(@as(u8, 50), record.percentage);
    try std.testing.expectEqualStrings("mailto:dmarc@example.com", record.rua.?);
    try std.testing.expectEqualStrings("mailto:forensic@example.com", record.ruf.?);
    try std.testing.expectEqual(@as(u64, 3600), record.report_interval);
    try std.testing.expectEqualStrings("1", record.failure_options);
}

test "parseDmarcRecord handles minimal record" {
    const record = parseDmarcRecord("v=DMARC1; p=none");
    try std.testing.expectEqual(DmarcPolicy.none, record.policy);
    try std.testing.expect(record.subdomain_policy == null);
    try std.testing.expect(record.rua == null);
    try std.testing.expect(record.ruf == null);
    try std.testing.expectEqual(@as(u8, 100), record.percentage);
}

test "parseDmarcRecord defaults on empty" {
    const record = parseDmarcRecord("");
    try std.testing.expectEqual(DmarcPolicy.none, record.policy);
}

test "buildDmarcRecordAlloc roundtrip basic" {
    const allocator = std.testing.allocator;
    const record = DmarcRecord{
        .policy = .reject,
    };
    const txt = try buildDmarcRecordAlloc(allocator, record);
    defer allocator.free(txt);
    try std.testing.expectEqualStrings("v=DMARC1; p=reject", txt);
}

test "buildDmarcRecordAlloc with subdomain policy" {
    const allocator = std.testing.allocator;
    const record = DmarcRecord{
        .policy = .quarantine,
        .subdomain_policy = .reject,
        .percentage = 50,
    };
    const txt = try buildDmarcRecordAlloc(allocator, record);
    defer allocator.free(txt);
    try std.testing.expectEqualStrings("v=DMARC1; p=quarantine; sp=reject; pct=50", txt);
}

test "buildDmarcRecordAlloc with strict alignment" {
    const allocator = std.testing.allocator;
    const record = DmarcRecord{
        .policy = .none,
        .dkim_alignment = .strict,
        .spf_alignment = .strict,
    };
    const txt = try buildDmarcRecordAlloc(allocator, record);
    defer allocator.free(txt);
    try std.testing.expectEqualStrings("v=DMARC1; p=none; adkim=s; aspf=s", txt);
}

test "buildDmarcRecordAlloc with report URIs" {
    const allocator = std.testing.allocator;
    const record = DmarcRecord{
        .policy = .none,
        .rua = "mailto:dmarc@example.com",
        .ruf = "mailto:forensic@example.com",
    };
    const txt = try buildDmarcRecordAlloc(allocator, record);
    defer allocator.free(txt);
    try std.testing.expectEqualStrings("v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com", txt);
}

test "evaluate DMARC pass with DKIM aligned" {
    const record = DmarcRecord{ .policy = .reject };
    const eval = evaluate(record, "example.com", null, false, "example.com", true);
    try std.testing.expectEqual(DmarcResult.pass, eval.result);
    try std.testing.expect(eval.dkim_aligned);
    try std.testing.expect(!eval.spf_aligned);
}

test "evaluate DMARC pass with SPF aligned" {
    const record = DmarcRecord{ .policy = .reject };
    const eval = evaluate(record, "example.com", "example.com", true, null, false);
    try std.testing.expectEqual(DmarcResult.pass, eval.result);
    try std.testing.expect(!eval.dkim_aligned);
    try std.testing.expect(eval.spf_aligned);
}

test "evaluate DMARC pass with both aligned" {
    const record = DmarcRecord{ .policy = .reject };
    const eval = evaluate(record, "example.com", "example.com", true, "example.com", true);
    try std.testing.expectEqual(DmarcResult.pass, eval.result);
    try std.testing.expect(eval.dkim_aligned);
    try std.testing.expect(eval.spf_aligned);
}

test "evaluate DMARC fail when nothing aligned" {
    const record = DmarcRecord{ .policy = .reject };
    const eval = evaluate(record, "example.com", "other.com", true, "other.com", true);
    try std.testing.expectEqual(DmarcResult.fail, eval.result);
    try std.testing.expect(!eval.dkim_aligned);
    try std.testing.expect(!eval.spf_aligned);
}

test "evaluate DMARC fail when auth fails" {
    const record = DmarcRecord{ .policy = .reject };
    const eval = evaluate(record, "example.com", "example.com", false, "example.com", false);
    try std.testing.expectEqual(DmarcResult.fail, eval.result);
}

test "evaluate relaxed alignment with subdomain" {
    const record = DmarcRecord{ .policy = .reject, .dkim_alignment = .relaxed };
    const eval = evaluate(record, "mail.example.com", null, false, "example.com", true);
    try std.testing.expectEqual(DmarcResult.pass, eval.result);
    try std.testing.expect(eval.dkim_aligned);
}

test "evaluate strict alignment rejects subdomain" {
    const record = DmarcRecord{ .policy = .reject, .dkim_alignment = .strict };
    const eval = evaluate(record, "mail.example.com", null, false, "example.com", true);
    try std.testing.expectEqual(DmarcResult.fail, eval.result);
    try std.testing.expect(!eval.dkim_aligned);
}

test "isAligned strict exact match" {
    try std.testing.expect(isAligned("example.com", "example.com", .strict));
}

test "isAligned strict case insensitive" {
    try std.testing.expect(isAligned("Example.COM", "example.com", .strict));
}

test "isAligned strict rejects subdomain" {
    try std.testing.expect(!isAligned("mail.example.com", "example.com", .strict));
}

test "isAligned relaxed matches subdomain" {
    try std.testing.expect(isAligned("mail.example.com", "example.com", .relaxed));
}

test "isAligned relaxed matches both subdomains" {
    try std.testing.expect(isAligned("a.example.com", "b.example.com", .relaxed));
}

test "isAligned relaxed rejects different domains" {
    try std.testing.expect(!isAligned("example.com", "other.com", .relaxed));
}

test "organizationalDomain simple" {
    try std.testing.expectEqualStrings("example.com", organizationalDomain("example.com"));
}

test "organizationalDomain with subdomain" {
    try std.testing.expectEqualStrings("example.com", organizationalDomain("mail.example.com"));
}

test "organizationalDomain with deep subdomain" {
    try std.testing.expectEqualStrings("example.com", organizationalDomain("a.b.c.example.com"));
}

test "organizationalDomain ccTLD co.uk" {
    try std.testing.expectEqualStrings("example.co.uk", organizationalDomain("mail.example.co.uk"));
}

test "organizationalDomain ccTLD com.au" {
    try std.testing.expectEqualStrings("example.com.au", organizationalDomain("www.example.com.au"));
}

test "organizationalDomain single label" {
    try std.testing.expectEqualStrings("localhost", organizationalDomain("localhost"));
}

test "organizationalDomain trailing dot" {
    try std.testing.expectEqualStrings("example.com", organizationalDomain("mail.example.com."));
}

test "formatDmarcDnsNameAlloc" {
    const allocator = std.testing.allocator;
    const name = try formatDmarcDnsNameAlloc(allocator, "example.com");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("_dmarc.example.com", name);
}
