const std = @import("std");

/// MTA-STS policy mode (RFC 8461 Section 5).
pub const Mode = enum {
    enforce,
    testing,
    none,

    pub fn label(self: Mode) []const u8 {
        return switch (self) {
            .enforce => "enforce",
            .testing => "testing",
            .none => "none",
        };
    }

    pub fn fromString(s: []const u8) ?Mode {
        if (std.ascii.eqlIgnoreCase(s, "enforce")) return .enforce;
        if (std.ascii.eqlIgnoreCase(s, "testing")) return .testing;
        if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
        return null;
    }
};

/// A parsed MTA-STS policy (RFC 8461 Section 3.2).
pub const Policy = struct {
    version: []const u8 = "STSv1",
    mode: Mode = .none,
    max_age: u64 = 0,
    mx_patterns: []const []const u8 = &.{},

    /// Check if a given MX hostname matches this policy's MX patterns.
    pub fn matchesMx(self: *const Policy, mx_host: []const u8) bool {
        for (self.mx_patterns) |pattern| {
            if (matchPattern(pattern, mx_host)) return true;
        }
        return false;
    }

    /// Check if TLS should be required based on this policy.
    pub fn requiresTls(self: *const Policy) bool {
        return self.mode == .enforce;
    }
};

/// Parse an MTA-STS policy text file (RFC 8461 Section 3.2).
///
/// Format:
///   version: STSv1
///   mode: enforce
///   mx: *.example.com
///   mx: mail.example.com
///   max_age: 604800
pub fn parsePolicyAlloc(allocator: std.mem.Allocator, text: []const u8) !Policy {
    var policy = Policy{};
    var mx_list = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (mx_list.items) |p| allocator.free(p);
        mx_list.deinit(allocator);
    }

    var version_set = false;
    var mode_set = false;
    var max_age_set = false;

    var lines = std.mem.splitSequence(u8, text, "\n");
    while (lines.next()) |raw_line| {
        // Strip trailing \r for CRLF line endings
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;

        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) continue;

        const colon_pos = std.mem.indexOf(u8, trimmed, ":") orelse continue;
        const key = std.mem.trim(u8, trimmed[0..colon_pos], " \t");
        const value = std.mem.trim(u8, trimmed[colon_pos + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(key, "version")) {
            if (version_set) return error.DuplicateField;
            if (!std.mem.eql(u8, value, "STSv1")) return error.UnsupportedVersion;
            policy.version = "STSv1";
            version_set = true;
        } else if (std.ascii.eqlIgnoreCase(key, "mode")) {
            if (mode_set) return error.DuplicateField;
            policy.mode = Mode.fromString(value) orelse return error.InvalidMode;
            mode_set = true;
        } else if (std.ascii.eqlIgnoreCase(key, "max_age")) {
            if (max_age_set) return error.DuplicateField;
            policy.max_age = std.fmt.parseInt(u64, value, 10) catch return error.InvalidMaxAge;
            max_age_set = true;
        } else if (std.ascii.eqlIgnoreCase(key, "mx")) {
            const mx_dup = try allocator.dupe(u8, value);
            try mx_list.append(allocator, mx_dup);
        }
        // Unknown keys are ignored per the RFC.
    }

    if (!version_set) return error.MissingVersion;
    if (!mode_set) return error.MissingMode;
    if (!max_age_set) return error.MissingMaxAge;

    policy.mx_patterns = try mx_list.toOwnedSlice(allocator);
    return policy;
}

/// Free a policy's allocated mx_patterns.
pub fn freePolicy(allocator: std.mem.Allocator, policy: *Policy) void {
    for (policy.mx_patterns) |p| allocator.free(@constCast(p));
    if (policy.mx_patterns.len > 0) allocator.free(@constCast(policy.mx_patterns));
    policy.* = .{};
}

/// Parsed MTA-STS DNS TXT record (RFC 8461 Section 3.1).
/// Format: "v=STSv1; id=20190429T010101"
pub const DnsRecord = struct {
    version: []const u8 = "",
    id: []const u8 = "",

    pub fn isValid(self: *const DnsRecord) bool {
        return std.mem.eql(u8, self.version, "STSv1") and self.id.len > 0;
    }
};

/// Parse an MTA-STS DNS TXT record value.
pub fn parseDnsRecord(value: []const u8) DnsRecord {
    var record = DnsRecord{};
    var parts = std.mem.splitSequence(u8, value, ";");
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t");
        if (std.mem.indexOf(u8, part, "=")) |eq_pos| {
            const key = std.mem.trim(u8, part[0..eq_pos], " \t");
            const val = std.mem.trim(u8, part[eq_pos + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, "v")) {
                record.version = val;
            } else if (std.ascii.eqlIgnoreCase(key, "id")) {
                record.id = val;
            }
        }
    }
    return record;
}

/// Match an MX pattern against a hostname (RFC 8461 Section 4.1).
/// Supports wildcard prefix: "*.example.com" matches "mail.example.com"
/// but not "sub.mail.example.com" or "example.com".
pub fn matchPattern(pattern: []const u8, hostname: []const u8) bool {
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..]; // ".example.com"
        if (hostname.len <= suffix.len) return false;
        const host_suffix = hostname[hostname.len - suffix.len ..];
        if (!std.ascii.eqlIgnoreCase(suffix, host_suffix)) return false;
        // The part before the suffix must not contain a dot (single-level wildcard).
        const prefix = hostname[0 .. hostname.len - suffix.len];
        return std.mem.indexOf(u8, prefix, ".") == null;
    }
    return std.ascii.eqlIgnoreCase(pattern, hostname);
}

/// Simple in-memory MTA-STS policy cache with TTL-based expiry.
pub const PolicyCache = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(CacheEntry),

    const CacheEntry = struct {
        policy: Policy,
        fetched_at: i64, // timestamp in seconds
    };

    pub fn init(allocator: std.mem.Allocator) PolicyCache {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(CacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *PolicyCache) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            var policy = entry.value_ptr.policy;
            freePolicy(self.allocator, &policy);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    /// Retrieve a cached policy for the given domain. Returns null if
    /// not cached or if the cache entry has expired (based on max_age).
    pub fn get(self: *PolicyCache, domain: []const u8) ?*const Policy {
        const entry = self.entries.getPtr(domain) orelse return null;
        const now = std.time.timestamp();
        const age: u64 = @intCast(@max(0, now - entry.fetched_at));
        if (age > entry.policy.max_age) {
            // Expired — remove the entry.
            self.removeEntry(domain);
            return null;
        }
        return &entry.policy;
    }

    /// Store a policy in the cache for the given domain.
    pub fn put(self: *PolicyCache, domain: []const u8, policy: Policy) !void {
        // Remove existing entry if present.
        if (self.entries.fetchRemove(domain)) |removed| {
            var old_policy = removed.value.policy;
            freePolicy(self.allocator, &old_policy);
            self.allocator.free(removed.key);
        }

        const key = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(key);

        try self.entries.put(key, .{
            .policy = policy,
            .fetched_at = std.time.timestamp(),
        });
    }

    /// Store a policy with an explicit timestamp (useful for testing).
    pub fn putWithTimestamp(self: *PolicyCache, domain: []const u8, policy: Policy, timestamp: i64) !void {
        if (self.entries.fetchRemove(domain)) |removed| {
            var old_policy = removed.value.policy;
            freePolicy(self.allocator, &old_policy);
            self.allocator.free(removed.key);
        }

        const key = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(key);

        try self.entries.put(key, .{
            .policy = policy,
            .fetched_at = timestamp,
        });
    }

    /// Remove a cached policy for the given domain.
    pub fn invalidate(self: *PolicyCache, domain: []const u8) void {
        self.removeEntry(domain);
    }

    fn removeEntry(self: *PolicyCache, domain: []const u8) void {
        if (self.entries.fetchRemove(domain)) |removed| {
            var policy = removed.value.policy;
            freePolicy(self.allocator, &policy);
            self.allocator.free(removed.key);
        }
    }
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test "parse valid policy" {
    const allocator = std.testing.allocator;
    const text =
        \\version: STSv1
        \\mode: enforce
        \\mx: *.example.com
        \\mx: mail.example.com
        \\max_age: 604800
    ;

    var policy = try parsePolicyAlloc(allocator, text);
    defer freePolicy(allocator, &policy);

    try std.testing.expectEqual(Mode.enforce, policy.mode);
    try std.testing.expectEqual(@as(u64, 604800), policy.max_age);
    try std.testing.expectEqualStrings("STSv1", policy.version);
    try std.testing.expectEqual(@as(usize, 2), policy.mx_patterns.len);
    try std.testing.expectEqualStrings("*.example.com", policy.mx_patterns[0]);
    try std.testing.expectEqualStrings("mail.example.com", policy.mx_patterns[1]);
}

test "parse policy with CRLF line endings" {
    const allocator = std.testing.allocator;
    const text = "version: STSv1\r\nmode: testing\r\nmx: mail.example.com\r\nmax_age: 86400\r\n";

    var policy = try parsePolicyAlloc(allocator, text);
    defer freePolicy(allocator, &policy);

    try std.testing.expectEqual(Mode.testing, policy.mode);
    try std.testing.expectEqual(@as(u64, 86400), policy.max_age);
    try std.testing.expectEqual(@as(usize, 1), policy.mx_patterns.len);
}

test "parse policy missing version" {
    const allocator = std.testing.allocator;
    const text =
        \\mode: enforce
        \\mx: *.example.com
        \\max_age: 604800
    ;
    try std.testing.expectError(error.MissingVersion, parsePolicyAlloc(allocator, text));
}

test "parse policy invalid mode" {
    const allocator = std.testing.allocator;
    const text =
        \\version: STSv1
        \\mode: invalid
        \\mx: *.example.com
        \\max_age: 604800
    ;
    try std.testing.expectError(error.InvalidMode, parsePolicyAlloc(allocator, text));
}

test "parse DNS record" {
    const record = parseDnsRecord("v=STSv1; id=20190429T010101");
    try std.testing.expectEqualStrings("STSv1", record.version);
    try std.testing.expectEqualStrings("20190429T010101", record.id);
    try std.testing.expect(record.isValid());
}

test "parse DNS record with extra spaces" {
    const record = parseDnsRecord("  v=STSv1 ;  id=abc123  ");
    try std.testing.expectEqualStrings("STSv1", record.version);
    try std.testing.expectEqualStrings("abc123", record.id);
}

test "parse DNS record invalid" {
    const record = parseDnsRecord("garbage");
    try std.testing.expectEqualStrings("", record.version);
    try std.testing.expectEqualStrings("", record.id);
    try std.testing.expect(!record.isValid());
}

test "pattern matching - exact" {
    try std.testing.expect(matchPattern("mail.example.com", "mail.example.com"));
    try std.testing.expect(matchPattern("mail.example.com", "MAIL.EXAMPLE.COM"));
    try std.testing.expect(!matchPattern("mail.example.com", "other.example.com"));
}

test "pattern matching - wildcard" {
    try std.testing.expect(matchPattern("*.example.com", "mail.example.com"));
    try std.testing.expect(matchPattern("*.example.com", "mx1.example.com"));
    // Must not match bare domain
    try std.testing.expect(!matchPattern("*.example.com", "example.com"));
    // Must not match multi-level subdomain (single-level wildcard)
    try std.testing.expect(!matchPattern("*.example.com", "sub.mail.example.com"));
}

test "policy requiresTls" {
    var enforce = Policy{ .mode = .enforce };
    var testing_mode = Policy{ .mode = .testing };
    var none_mode = Policy{ .mode = .none };

    try std.testing.expect(enforce.requiresTls());
    try std.testing.expect(!testing_mode.requiresTls());
    try std.testing.expect(!none_mode.requiresTls());
}

test "policy matchesMx" {
    const allocator = std.testing.allocator;
    const text =
        \\version: STSv1
        \\mode: enforce
        \\mx: *.example.com
        \\mx: relay.example.org
        \\max_age: 604800
    ;

    var policy = try parsePolicyAlloc(allocator, text);
    defer freePolicy(allocator, &policy);

    try std.testing.expect(policy.matchesMx("mail.example.com"));
    try std.testing.expect(policy.matchesMx("relay.example.org"));
    try std.testing.expect(!policy.matchesMx("evil.attacker.com"));
    try std.testing.expect(!policy.matchesMx("example.com"));
}

test "mode label" {
    try std.testing.expectEqualStrings("enforce", Mode.enforce.label());
    try std.testing.expectEqualStrings("testing", Mode.testing.label());
    try std.testing.expectEqualStrings("none", Mode.none.label());
}

test "cache put and get" {
    const allocator = std.testing.allocator;
    var cache = PolicyCache.init(allocator);
    defer cache.deinit();

    const text =
        \\version: STSv1
        \\mode: enforce
        \\mx: *.example.com
        \\max_age: 604800
    ;

    const policy = try parsePolicyAlloc(allocator, text);
    // policy ownership transfers to cache via put
    try cache.put("example.com", policy);

    const cached = cache.get("example.com");
    try std.testing.expect(cached != null);
    try std.testing.expectEqual(Mode.enforce, cached.?.mode);
    try std.testing.expect(cached.?.matchesMx("mail.example.com"));

    // Non-existent domain
    try std.testing.expect(cache.get("other.com") == null);
}

test "cache invalidate" {
    const allocator = std.testing.allocator;
    var cache = PolicyCache.init(allocator);
    defer cache.deinit();

    const text =
        \\version: STSv1
        \\mode: none
        \\mx: *.example.com
        \\max_age: 604800
    ;

    const policy = try parsePolicyAlloc(allocator, text);
    try cache.put("example.com", policy);

    try std.testing.expect(cache.get("example.com") != null);
    cache.invalidate("example.com");
    try std.testing.expect(cache.get("example.com") == null);

    // Invalidating non-existent key should not panic.
    cache.invalidate("nonexistent.com");
}

test "cache expiry" {
    const allocator = std.testing.allocator;
    var cache = PolicyCache.init(allocator);
    defer cache.deinit();

    const text =
        \\version: STSv1
        \\mode: enforce
        \\mx: *.example.com
        \\max_age: 100
    ;

    const policy = try parsePolicyAlloc(allocator, text);
    // Insert with a timestamp far in the past so it's already expired.
    try cache.putWithTimestamp("example.com", policy, 0);

    // Should be expired since max_age=100 and fetched_at=0.
    try std.testing.expect(cache.get("example.com") == null);
}
