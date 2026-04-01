const std = @import("std");

/// Actions that can be taken on a message.
pub const Action = enum {
    accept, // Accept for local delivery
    relay, // Forward to another server
    reject, // Reject with error
    defer_msg, // Temporarily reject (try later)
};

/// A relay rule matching criteria and action.
pub const Rule = struct {
    /// Match criteria (all must match for the rule to apply)
    from_domain: ?[]const u8 = null, // sender domain pattern
    to_domain: ?[]const u8 = null, // recipient domain pattern
    from_address: ?[]const u8 = null, // exact sender address
    to_address: ?[]const u8 = null, // exact recipient address
    authenticated: ?bool = null, // require authentication
    tls_required: ?bool = null, // require TLS

    /// Action to take when this rule matches.
    action: Action = .reject,

    /// For relay action: destination server host:port.
    relay_host: ?[]const u8 = null,
    relay_port: u16 = 25,

    /// Error message for reject/defer actions.
    error_message: []const u8 = "5.7.1 Relay denied",
    error_code: u16 = 550,
};

/// Virtual domain configuration.
pub const VirtualDomain = struct {
    domain: []const u8,
    /// Local delivery (accept mail for this domain).
    local_delivery: bool = true,
    /// Aliases: map addresses to other addresses.
    aliases: []const Alias = &.{},
    /// Catch-all address for this domain (if set).
    catchall: ?[]const u8 = null,
};

pub const Alias = struct {
    from: []const u8, // local part or full address
    to: []const u8, // destination address
};

/// Relay policy engine that evaluates rules in order.
pub const RelayEngine = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayList(Rule),
    domains: std.ArrayList(VirtualDomain),
    default_action: Action = .reject,
    default_error: []const u8 = "5.7.1 Relay access denied",
    default_error_code: u16 = 550,

    pub fn init(allocator: std.mem.Allocator) RelayEngine {
        return .{
            .allocator = allocator,
            .rules = .empty,
            .domains = .empty,
        };
    }

    pub fn deinit(self: *RelayEngine) void {
        self.rules.deinit(self.allocator);
        self.domains.deinit(self.allocator);
    }

    /// Add a relay rule.
    pub fn addRule(self: *RelayEngine, rule: Rule) !void {
        try self.rules.append(self.allocator, rule);
    }

    /// Add a virtual domain.
    pub fn addDomain(self: *RelayEngine, domain: VirtualDomain) !void {
        try self.domains.append(self.allocator, domain);
    }

    /// Evaluate rules for a given message context.
    /// Returns the action and any associated parameters.
    /// Rules are evaluated in order; first match wins.
    pub fn evaluate(self: *const RelayEngine, ctx: RelayContext) Decision {
        const from_domain = extractDomain(ctx.from);
        const to_domain = extractDomain(ctx.to);

        // Try alias resolution for local domains
        const resolved_to = self.resolveAlias(ctx.to);

        for (self.rules.items) |rule| {
            if (!ruleMatches(rule, ctx, from_domain, to_domain)) continue;

            return .{
                .action = rule.action,
                .relay_host = rule.relay_host,
                .relay_port = rule.relay_port,
                .error_message = rule.error_message,
                .error_code = rule.error_code,
                .resolved_to = resolved_to,
            };
        }

        // Check if the recipient domain is a local domain with local delivery
        if (to_domain) |td| {
            if (self.isLocalDomain(td)) {
                return .{
                    .action = .accept,
                    .resolved_to = resolved_to,
                };
            }
        }

        return .{
            .action = self.default_action,
            .error_message = self.default_error,
            .error_code = self.default_error_code,
        };
    }

    /// Check if a domain is configured as local.
    pub fn isLocalDomain(self: *const RelayEngine, domain: []const u8) bool {
        for (self.domains.items) |vd| {
            if (vd.local_delivery and std.ascii.eqlIgnoreCase(vd.domain, domain)) {
                return true;
            }
        }
        return false;
    }

    /// Resolve aliases for an address (non-allocating, returns slice into existing data).
    fn resolveAlias(self: *const RelayEngine, address: []const u8) ?[]const u8 {
        const addr_domain = extractDomain(address) orelse return null;
        const local_part = extractLocalPart(address) orelse return null;

        for (self.domains.items) |vd| {
            if (!std.ascii.eqlIgnoreCase(vd.domain, addr_domain)) continue;

            // Check aliases
            for (vd.aliases) |alias| {
                // Match against full address or just local part
                if (std.ascii.eqlIgnoreCase(alias.from, address) or
                    std.ascii.eqlIgnoreCase(alias.from, local_part))
                {
                    return alias.to;
                }
            }

            // Check catch-all
            if (vd.catchall) |catchall| {
                return catchall;
            }
        }
        return null;
    }

    /// Resolve aliases for an address (allocating version for public API).
    pub fn resolveAliasAlloc(self: *const RelayEngine, allocator: std.mem.Allocator, address: []const u8) !?[]u8 {
        const result = self.resolveAlias(address) orelse return null;
        return try allocator.dupe(u8, result);
    }

    fn ruleMatches(rule: Rule, ctx: RelayContext, from_domain: ?[]const u8, to_domain: ?[]const u8) bool {
        if (rule.from_domain) |pattern| {
            const fd = from_domain orelse return false;
            if (!matchDomain(pattern, fd)) return false;
        }
        if (rule.to_domain) |pattern| {
            const td = to_domain orelse return false;
            if (!matchDomain(pattern, td)) return false;
        }
        if (rule.from_address) |addr| {
            if (!std.ascii.eqlIgnoreCase(addr, ctx.from)) return false;
        }
        if (rule.to_address) |addr| {
            if (!std.ascii.eqlIgnoreCase(addr, ctx.to)) return false;
        }
        if (rule.authenticated) |required| {
            if (ctx.authenticated != required) return false;
        }
        if (rule.tls_required) |required| {
            if (required and !ctx.is_tls) return false;
        }
        return true;
    }
};

pub const RelayContext = struct {
    from: []const u8,
    to: []const u8,
    authenticated: bool = false,
    is_tls: bool = false,
    client_ip: ?[]const u8 = null,
};

pub const Decision = struct {
    action: Action,
    relay_host: ?[]const u8 = null,
    relay_port: u16 = 25,
    error_message: []const u8 = "",
    error_code: u16 = 0,
    resolved_to: ?[]const u8 = null, // for alias resolution
};

/// Helper: extract domain from email address.
pub fn extractDomain(address: []const u8) ?[]const u8 {
    const at = std.mem.lastIndexOfScalar(u8, address, '@') orelse return null;
    const domain = address[at + 1 ..];
    if (domain.len == 0) return null;
    return domain;
}

/// Helper: extract local part from email address.
pub fn extractLocalPart(address: []const u8) ?[]const u8 {
    const at = std.mem.lastIndexOfScalar(u8, address, '@') orelse return null;
    if (at == 0) return null;
    return address[0..at];
}

/// Helper: match a domain pattern (supports prefix wildcard).
pub fn matchDomain(pattern: []const u8, domain: []const u8) bool {
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..]; // e.g. ".example.com"
        // Match exact subdomain parent or any subdomain
        return std.ascii.eqlIgnoreCase(domain, pattern[2..]) or
            (domain.len > suffix.len and std.ascii.eqlIgnoreCase(domain[domain.len - suffix.len ..], suffix));
    }
    return std.ascii.eqlIgnoreCase(pattern, domain);
}

test "extractDomain" {
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com").?);
    try std.testing.expectEqualStrings("example.com", extractDomain("complex+tag@example.com").?);
    try std.testing.expect(extractDomain("no-at-sign") == null);
    try std.testing.expect(extractDomain("trailing@") == null);
}

test "extractLocalPart" {
    try std.testing.expectEqualStrings("user", extractLocalPart("user@example.com").?);
    try std.testing.expect(extractLocalPart("no-at-sign") == null);
    try std.testing.expect(extractLocalPart("@example.com") == null);
}

test "matchDomain exact" {
    try std.testing.expect(matchDomain("example.com", "example.com"));
    try std.testing.expect(matchDomain("Example.COM", "example.com"));
    try std.testing.expect(!matchDomain("other.com", "example.com"));
}

test "matchDomain wildcard" {
    try std.testing.expect(matchDomain("*.example.com", "sub.example.com"));
    try std.testing.expect(matchDomain("*.example.com", "example.com"));
    try std.testing.expect(matchDomain("*.example.com", "deep.sub.example.com"));
    try std.testing.expect(!matchDomain("*.example.com", "notexample.com"));
    try std.testing.expect(!matchDomain("*.example.com", "other.org"));
}

test "default reject when no rules match" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    const decision = engine.evaluate(.{
        .from = "sender@external.com",
        .to = "user@unknown.com",
    });
    try std.testing.expectEqual(Action.reject, decision.action);
    try std.testing.expectEqual(@as(u16, 550), decision.error_code);
}

test "rule matching by domain pattern" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .to_domain = "local.com",
        .action = .accept,
    });

    const accept = engine.evaluate(.{
        .from = "anyone@external.com",
        .to = "user@local.com",
    });
    try std.testing.expectEqual(Action.accept, accept.action);

    const reject = engine.evaluate(.{
        .from = "anyone@external.com",
        .to = "user@other.com",
    });
    try std.testing.expectEqual(Action.reject, reject.action);
}

test "rule matching by exact address" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .to_address = "admin@example.com",
        .action = .accept,
    });

    const accept = engine.evaluate(.{
        .from = "anyone@external.com",
        .to = "admin@example.com",
    });
    try std.testing.expectEqual(Action.accept, accept.action);

    const reject = engine.evaluate(.{
        .from = "anyone@external.com",
        .to = "other@example.com",
    });
    try std.testing.expectEqual(Action.reject, reject.action);
}

test "rule requiring authentication" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .authenticated = true,
        .action = .relay,
        .relay_host = "smtp.relay.com",
        .relay_port = 587,
    });

    const authed = engine.evaluate(.{
        .from = "user@local.com",
        .to = "someone@remote.com",
        .authenticated = true,
    });
    try std.testing.expectEqual(Action.relay, authed.action);
    try std.testing.expectEqualStrings("smtp.relay.com", authed.relay_host.?);
    try std.testing.expectEqual(@as(u16, 587), authed.relay_port);

    const unauthed = engine.evaluate(.{
        .from = "user@local.com",
        .to = "someone@remote.com",
        .authenticated = false,
    });
    try std.testing.expectEqual(Action.reject, unauthed.action);
}

test "rule requiring TLS" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .tls_required = true,
        .action = .accept,
    });

    const tls_on = engine.evaluate(.{
        .from = "a@b.com",
        .to = "c@d.com",
        .is_tls = true,
    });
    try std.testing.expectEqual(Action.accept, tls_on.action);

    const tls_off = engine.evaluate(.{
        .from = "a@b.com",
        .to = "c@d.com",
        .is_tls = false,
    });
    try std.testing.expectEqual(Action.reject, tls_off.action);
}

test "first-match-wins ordering" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    // First rule: reject from spammer domain
    try engine.addRule(.{
        .from_domain = "spammer.com",
        .action = .reject,
        .error_message = "5.7.1 Spam rejected",
        .error_code = 550,
    });
    // Second rule: accept everything to local.com
    try engine.addRule(.{
        .to_domain = "local.com",
        .action = .accept,
    });

    // Spammer sending to local.com should be rejected (first rule wins)
    const decision = engine.evaluate(.{
        .from = "bad@spammer.com",
        .to = "user@local.com",
    });
    try std.testing.expectEqual(Action.reject, decision.action);
    try std.testing.expectEqualStrings("5.7.1 Spam rejected", decision.error_message);
}

test "virtual domain lookup" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addDomain(.{
        .domain = "example.com",
        .local_delivery = true,
    });
    try engine.addDomain(.{
        .domain = "relay-only.com",
        .local_delivery = false,
    });

    try std.testing.expect(engine.isLocalDomain("example.com"));
    try std.testing.expect(engine.isLocalDomain("Example.COM"));
    try std.testing.expect(!engine.isLocalDomain("relay-only.com"));
    try std.testing.expect(!engine.isLocalDomain("unknown.com"));
}

test "local domain auto-accept" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addDomain(.{
        .domain = "myserver.com",
        .local_delivery = true,
    });

    // No explicit rules, but domain is local -> accept
    const decision = engine.evaluate(.{
        .from = "anyone@external.com",
        .to = "user@myserver.com",
    });
    try std.testing.expectEqual(Action.accept, decision.action);
}

test "alias resolution" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addDomain(.{
        .domain = "example.com",
        .local_delivery = true,
        .aliases = &.{
            .{ .from = "postmaster", .to = "admin@example.com" },
            .{ .from = "abuse@example.com", .to = "admin@example.com" },
        },
    });

    // Local part match
    const r1 = try engine.resolveAliasAlloc(std.testing.allocator, "postmaster@example.com");
    defer if (r1) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("admin@example.com", r1.?);

    // Full address match
    const r2 = try engine.resolveAliasAlloc(std.testing.allocator, "abuse@example.com");
    defer if (r2) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("admin@example.com", r2.?);

    // No match
    const r3 = try engine.resolveAliasAlloc(std.testing.allocator, "other@example.com");
    try std.testing.expect(r3 == null);
}

test "catch-all resolution" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addDomain(.{
        .domain = "catchall.com",
        .local_delivery = true,
        .catchall = "inbox@catchall.com",
    });

    const r = try engine.resolveAliasAlloc(std.testing.allocator, "anything@catchall.com");
    defer if (r) |v| std.testing.allocator.free(v);
    try std.testing.expectEqualStrings("inbox@catchall.com", r.?);
}

test "wildcard domain rule" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .to_domain = "*.corp.com",
        .action = .accept,
    });

    const sub = engine.evaluate(.{
        .from = "ext@other.com",
        .to = "user@mail.corp.com",
    });
    try std.testing.expectEqual(Action.accept, sub.action);

    const parent = engine.evaluate(.{
        .from = "ext@other.com",
        .to = "user@corp.com",
    });
    try std.testing.expectEqual(Action.accept, parent.action);

    const other = engine.evaluate(.{
        .from = "ext@other.com",
        .to = "user@notcorp.com",
    });
    try std.testing.expectEqual(Action.reject, other.action);
}

test "relay action with host" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .from_domain = "partner.com",
        .action = .relay,
        .relay_host = "relay.internal.com",
        .relay_port = 2525,
    });

    const decision = engine.evaluate(.{
        .from = "user@partner.com",
        .to = "dest@anywhere.com",
    });
    try std.testing.expectEqual(Action.relay, decision.action);
    try std.testing.expectEqualStrings("relay.internal.com", decision.relay_host.?);
    try std.testing.expectEqual(@as(u16, 2525), decision.relay_port);
}

test "defer action" {
    var engine = RelayEngine.init(std.testing.allocator);
    defer engine.deinit();

    try engine.addRule(.{
        .to_domain = "overloaded.com",
        .action = .defer_msg,
        .error_message = "4.7.1 Try again later",
        .error_code = 451,
    });

    const decision = engine.evaluate(.{
        .from = "sender@any.com",
        .to = "user@overloaded.com",
    });
    try std.testing.expectEqual(Action.defer_msg, decision.action);
    try std.testing.expectEqual(@as(u16, 451), decision.error_code);
    try std.testing.expectEqualStrings("4.7.1 Try again later", decision.error_message);
}
