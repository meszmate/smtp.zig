const std = @import("std");

/// A parsed and validated email address.
pub const EmailAddress = struct {
    local: []const u8,
    domain: []const u8,

    pub fn formatAlloc(self: EmailAddress, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}@{s}", .{ self.local, self.domain });
    }

    pub fn formatAngleBracketAlloc(self: EmailAddress, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "<{s}@{s}>", .{ self.local, self.domain });
    }
};

pub const ParseError = error{
    InvalidAddress,
    LocalPartTooLong,
    DomainTooLong,
    LabelTooLong,
    EmptyLocalPart,
    EmptyDomain,
    InvalidLocalPart,
    InvalidDomain,
    InvalidQuotedString,
    InvalidIPLiteral,
};

/// Validate and parse an email address per RFC 5321.
/// Returns error if invalid.
pub fn parse(input: []const u8) ParseError!EmailAddress {
    if (input.len == 0) return error.InvalidAddress;

    var addr = input;

    // Strip angle brackets if present
    if (addr.len >= 2 and addr[0] == '<' and addr[addr.len - 1] == '>') {
        addr = addr[1 .. addr.len - 1];
    }

    if (addr.len == 0) return error.InvalidAddress;

    // Find the last @ separator (to handle quoted strings with @ in them)
    var at_pos: ?usize = null;

    // If it starts with a quote, find the end of the quoted string first
    if (addr[0] == '"') {
        var i: usize = 1;
        var found_end = false;
        while (i < addr.len) : (i += 1) {
            if (addr[i] == '\\') {
                i += 1; // skip escaped char
                continue;
            }
            if (addr[i] == '"') {
                found_end = true;
                i += 1;
                break;
            }
        }
        if (!found_end) return error.InvalidQuotedString;
        if (i >= addr.len or addr[i] != '@') return error.InvalidAddress;
        at_pos = i;
    } else {
        // Find last @ for unquoted local parts
        var i: usize = addr.len;
        while (i > 0) {
            i -= 1;
            if (addr[i] == '@') {
                at_pos = i;
                break;
            }
        }
    }

    if (at_pos == null) return error.InvalidAddress;

    const local = addr[0..at_pos.?];
    const domain = addr[at_pos.? + 1 ..];

    if (local.len == 0) return error.EmptyLocalPart;
    if (domain.len == 0) return error.EmptyDomain;
    if (local.len > 64) return error.LocalPartTooLong;
    if (domain.len > 255) return error.DomainTooLong;

    if (!validateLocal(local)) return error.InvalidLocalPart;
    if (!validateDomain(domain)) return error.InvalidDomain;

    return EmailAddress{
        .local = local,
        .domain = domain,
    };
}

/// Check if a string is a valid email address.
pub fn isValid(input: []const u8) bool {
    _ = parse(input) catch return false;
    return true;
}

/// Validate just the local part of an email address.
pub fn validateLocal(local: []const u8) bool {
    if (local.len == 0 or local.len > 64) return false;

    // Quoted string
    if (local[0] == '"') {
        return validateQuotedLocal(local);
    }

    // Dot-atom: no leading, trailing, or consecutive dots
    if (local[0] == '.' or local[local.len - 1] == '.') return false;

    var prev_dot = false;
    for (local) |c| {
        if (c == '.') {
            if (prev_dot) return false; // consecutive dots
            prev_dot = true;
            continue;
        }
        prev_dot = false;
        if (!isLocalChar(c)) return false;
    }

    return true;
}

fn validateQuotedLocal(local: []const u8) bool {
    if (local.len < 2) return false;
    if (local[0] != '"' or local[local.len - 1] != '"') return false;

    var i: usize = 1;
    while (i < local.len - 1) : (i += 1) {
        const c = local[i];
        if (c == '\\') {
            i += 1;
            if (i >= local.len - 1) return false;
            // Escaped character: must be printable ASCII (32-126)
            if (local[i] < 32 or local[i] > 126) return false;
            continue;
        }
        // Unescaped characters: printable ASCII except backslash and quote
        if (c < 32 or c > 126) return false;
        if (c == '\\') return false;
        // Quote only valid at the end (which we skip via the loop bound)
    }

    return true;
}

/// Validate just the domain part of an email address.
pub fn validateDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 255) return false;

    // IP address literal
    if (domain[0] == '[' and domain[domain.len - 1] == ']') {
        return validateIPLiteral(domain);
    }

    // Domain name: labels separated by dots
    if (domain[0] == '.' or domain[domain.len - 1] == '.') return false;

    var label_start: usize = 0;
    for (domain, 0..) |c, i| {
        if (c == '.') {
            const label = domain[label_start..i];
            if (!validateLabel(label)) return false;
            label_start = i + 1;
        }
    }
    // Validate last label
    const last_label = domain[label_start..];
    return validateLabel(last_label);
}

fn validateIPLiteral(domain: []const u8) bool {
    if (domain.len < 3) return false;
    if (domain[0] != '[' or domain[domain.len - 1] != ']') return false;

    const inner = domain[1 .. domain.len - 1];

    // IPv6
    if (inner.len > 5 and std.ascii.eqlIgnoreCase(inner[0..5], "IPv6:")) {
        const ipv6_str = inner[5..];
        return validateIPv6(ipv6_str);
    }

    // IPv4
    return validateIPv4(inner);
}

fn validateIPv4(s: []const u8) bool {
    var octets: usize = 0;
    var current: u16 = 0;
    var digits: usize = 0;

    for (s) |c| {
        if (c == '.') {
            if (digits == 0) return false;
            if (current > 255) return false;
            octets += 1;
            current = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            digits += 1;
            if (digits > 3) return false;
        } else {
            return false;
        }
    }

    // Last octet
    if (digits == 0) return false;
    if (current > 255) return false;
    octets += 1;

    return octets == 4;
}

fn validateIPv6(s: []const u8) bool {
    // Basic IPv6 validation: 1-8 groups of hex digits separated by colons
    // Allow :: for zero compression
    if (s.len == 0) return false;

    var groups: usize = 0;
    var has_double_colon = false;
    var i: usize = 0;

    // Check for leading ::
    if (s.len >= 2 and s[0] == ':' and s[1] == ':') {
        has_double_colon = true;
        i = 2;
        if (i == s.len) return true; // :: alone is valid
    } else if (s[0] == ':') {
        return false; // single leading colon invalid
    }

    while (i < s.len) {
        var hex_digits: usize = 0;
        while (i < s.len and s[i] != ':') : (i += 1) {
            if (!std.ascii.isHex(s[i])) return false;
            hex_digits += 1;
            if (hex_digits > 4) return false;
        }
        if (hex_digits > 0) groups += 1;
        if (hex_digits == 0 and i < s.len) return false;

        if (i < s.len and s[i] == ':') {
            i += 1;
            if (i < s.len and s[i] == ':') {
                if (has_double_colon) return false; // only one :: allowed
                has_double_colon = true;
                i += 1;
                if (i == s.len) break; // trailing :: is ok
            } else if (i == s.len) {
                return false; // trailing single colon
            }
        }
    }

    if (has_double_colon) {
        return groups <= 7;
    } else {
        return groups == 8;
    }
}

/// Validate a domain label (single segment between dots).
pub fn validateLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > 63) return false;

    // Cannot start or end with hyphen
    if (label[0] == '-' or label[label.len - 1] == '-') return false;

    for (label) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }

    return true;
}

/// Check if a character is valid in the local part (unquoted dot-atom).
fn isLocalChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9' => true,
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=' => true,
        '?', '^', '_', '`', '{', '|', '}', '~' => true,
        else => false,
    };
}

/// Normalize an email address (lowercase domain, preserve local case).
pub fn normalizeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const parsed = parse(input) catch return error.InvalidAddress;

    const domain_lower = try allocator.alloc(u8, parsed.domain.len);
    defer allocator.free(domain_lower);
    for (parsed.domain, 0..) |c, i| {
        domain_lower[i] = std.ascii.toLower(c);
    }

    return std.fmt.allocPrint(allocator, "{s}@{s}", .{ parsed.local, domain_lower });
}

/// Extract the domain from an email address without full validation.
pub fn extractDomain(input: []const u8) ?[]const u8 {
    var addr = input;
    if (addr.len >= 2 and addr[0] == '<' and addr[addr.len - 1] == '>') {
        addr = addr[1 .. addr.len - 1];
    }

    // Handle quoted local part
    if (addr.len > 0 and addr[0] == '"') {
        var i: usize = 1;
        while (i < addr.len) : (i += 1) {
            if (addr[i] == '\\') {
                i += 1;
                continue;
            }
            if (addr[i] == '"') {
                i += 1;
                break;
            }
        }
        if (i < addr.len and addr[i] == '@') {
            return addr[i + 1 ..];
        }
        return null;
    }

    // Find last @
    var at_pos: ?usize = null;
    var i: usize = addr.len;
    while (i > 0) {
        i -= 1;
        if (addr[i] == '@') {
            at_pos = i;
            break;
        }
    }

    if (at_pos) |pos| {
        const domain = addr[pos + 1 ..];
        if (domain.len > 0) return domain;
    }
    return null;
}

/// Extract the local part from an email address without full validation.
pub fn extractLocal(input: []const u8) ?[]const u8 {
    var addr = input;
    if (addr.len >= 2 and addr[0] == '<' and addr[addr.len - 1] == '>') {
        addr = addr[1 .. addr.len - 1];
    }

    // Handle quoted local part
    if (addr.len > 0 and addr[0] == '"') {
        var i: usize = 1;
        while (i < addr.len) : (i += 1) {
            if (addr[i] == '\\') {
                i += 1;
                continue;
            }
            if (addr[i] == '"') {
                i += 1;
                break;
            }
        }
        if (i < addr.len and addr[i] == '@') {
            return addr[0..i];
        }
        return null;
    }

    // Find last @
    var at_pos: ?usize = null;
    var i: usize = addr.len;
    while (i > 0) {
        i -= 1;
        if (addr[i] == '@') {
            at_pos = i;
            break;
        }
    }

    if (at_pos) |pos| {
        const local = addr[0..pos];
        if (local.len > 0) return local;
    }
    return null;
}

// =============================================================================
// Tests
// =============================================================================

test "parse valid simple address" {
    const result = try parse("user@example.com");
    try std.testing.expectEqualStrings("user", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parse valid address with dots in local" {
    const result = try parse("first.last@example.com");
    try std.testing.expectEqualStrings("first.last", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parse valid address with plus addressing" {
    const result = try parse("user+tag@example.com");
    try std.testing.expectEqualStrings("user+tag", result.local);
}

test "parse valid address with angle brackets" {
    const result = try parse("<user@example.com>");
    try std.testing.expectEqualStrings("user", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parse valid address with IPv4 literal" {
    const result = try parse("user@[192.168.1.1]");
    try std.testing.expectEqualStrings("user", result.local);
    try std.testing.expectEqualStrings("[192.168.1.1]", result.domain);
}

test "parse valid address with IPv6 literal" {
    const result = try parse("user@[IPv6:2001:db8::1]");
    try std.testing.expectEqualStrings("[IPv6:2001:db8::1]", result.domain);
}

test "parse valid quoted string local" {
    const result = try parse("\"user name\"@example.com");
    try std.testing.expectEqualStrings("\"user name\"", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parse valid quoted string with special chars" {
    const result = try parse("\"user@host\"@example.com");
    try std.testing.expectEqualStrings("\"user@host\"", result.local);
    try std.testing.expectEqualStrings("example.com", result.domain);
}

test "parse valid address with various special local chars" {
    _ = try parse("!#$%&'*+-/=?^_`{|}~@example.com");
}

test "parse valid single char local" {
    _ = try parse("a@example.com");
}

test "parse valid subdomain" {
    const result = try parse("user@mail.sub.example.com");
    try std.testing.expectEqualStrings("mail.sub.example.com", result.domain);
}

test "invalid: empty string" {
    try std.testing.expectError(error.InvalidAddress, parse(""));
}

test "invalid: no @ sign" {
    try std.testing.expectError(error.InvalidAddress, parse("userexample.com"));
}

test "invalid: empty local part" {
    try std.testing.expectError(error.EmptyLocalPart, parse("@example.com"));
}

test "invalid: empty domain" {
    try std.testing.expectError(error.EmptyDomain, parse("user@"));
}

test "invalid: double dots in local" {
    try std.testing.expectError(error.InvalidLocalPart, parse("user..name@example.com"));
}

test "invalid: leading dot in local" {
    try std.testing.expectError(error.InvalidLocalPart, parse(".user@example.com"));
}

test "invalid: trailing dot in local" {
    try std.testing.expectError(error.InvalidLocalPart, parse("user.@example.com"));
}

test "invalid: local part too long" {
    const long_local = "a" ** 65;
    try std.testing.expectError(error.LocalPartTooLong, parse(long_local ++ "@example.com"));
}

test "invalid: domain too long" {
    const long_domain = "a" ** 256;
    try std.testing.expectError(error.DomainTooLong, parse("user@" ++ long_domain));
}

test "invalid: space in unquoted local" {
    try std.testing.expectError(error.InvalidLocalPart, parse("user name@example.com"));
}

test "invalid: domain label starts with hyphen" {
    try std.testing.expectError(error.InvalidDomain, parse("user@-example.com"));
}

test "invalid: domain label ends with hyphen" {
    try std.testing.expectError(error.InvalidDomain, parse("user@example-.com"));
}

test "invalid: empty angle brackets" {
    try std.testing.expectError(error.InvalidAddress, parse("<>"));
}

test "invalid: domain leading dot" {
    try std.testing.expectError(error.InvalidDomain, parse("user@.example.com"));
}

test "invalid: domain trailing dot" {
    try std.testing.expectError(error.InvalidDomain, parse("user@example.com."));
}

test "isValid returns true for valid" {
    try std.testing.expect(isValid("user@example.com"));
}

test "isValid returns false for invalid" {
    try std.testing.expect(!isValid("not-an-email"));
}

test "validateLocal valid" {
    try std.testing.expect(validateLocal("user"));
    try std.testing.expect(validateLocal("first.last"));
    try std.testing.expect(validateLocal("user+tag"));
    try std.testing.expect(validateLocal("\"quoted\""));
}

test "validateLocal invalid" {
    try std.testing.expect(!validateLocal(""));
    try std.testing.expect(!validateLocal(".leading"));
    try std.testing.expect(!validateLocal("trailing."));
    try std.testing.expect(!validateLocal("dou..ble"));
}

test "validateDomain valid" {
    try std.testing.expect(validateDomain("example.com"));
    try std.testing.expect(validateDomain("sub.example.com"));
    try std.testing.expect(validateDomain("[192.168.1.1]"));
    try std.testing.expect(validateDomain("[IPv6:2001:db8::1]"));
}

test "validateDomain invalid" {
    try std.testing.expect(!validateDomain(""));
    try std.testing.expect(!validateDomain("-example.com"));
    try std.testing.expect(!validateDomain(".example.com"));
    try std.testing.expect(!validateDomain("example.com."));
}

test "validateLabel" {
    try std.testing.expect(validateLabel("example"));
    try std.testing.expect(validateLabel("ex-ample"));
    try std.testing.expect(validateLabel("a"));
    try std.testing.expect(!validateLabel(""));
    try std.testing.expect(!validateLabel("-start"));
    try std.testing.expect(!validateLabel("end-"));
}

test "normalizeAlloc lowercases domain" {
    const allocator = std.testing.allocator;
    const result = try normalizeAlloc(allocator, "User@EXAMPLE.COM");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("User@example.com", result);
}

test "normalizeAlloc preserves local case" {
    const allocator = std.testing.allocator;
    const result = try normalizeAlloc(allocator, "UsEr@Example.Com");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("UsEr@example.com", result);
}

test "normalizeAlloc rejects invalid" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidAddress, normalizeAlloc(allocator, "not-valid"));
}

test "extractDomain" {
    try std.testing.expectEqualStrings("example.com", extractDomain("user@example.com").?);
    try std.testing.expectEqualStrings("example.com", extractDomain("<user@example.com>").?);
    try std.testing.expectEqualStrings("example.com", extractDomain("\"quoted\"@example.com").?);
    try std.testing.expect(extractDomain("noemail") == null);
}

test "extractLocal" {
    try std.testing.expectEqualStrings("user", extractLocal("user@example.com").?);
    try std.testing.expectEqualStrings("user", extractLocal("<user@example.com>").?);
    try std.testing.expectEqualStrings("\"quoted\"", extractLocal("\"quoted\"@example.com").?);
    try std.testing.expect(extractLocal("noemail") == null);
}

test "formatAlloc" {
    const allocator = std.testing.allocator;
    const addr = try parse("user@example.com");
    const formatted = try addr.formatAlloc(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("user@example.com", formatted);
}

test "formatAngleBracketAlloc" {
    const allocator = std.testing.allocator;
    const addr = try parse("user@example.com");
    const formatted = try addr.formatAngleBracketAlloc(allocator);
    defer allocator.free(formatted);
    try std.testing.expectEqualStrings("<user@example.com>", formatted);
}

test "IPv4 literal validation" {
    try std.testing.expect(validateDomain("[127.0.0.1]"));
    try std.testing.expect(validateDomain("[255.255.255.255]"));
    try std.testing.expect(!validateDomain("[256.1.1.1]"));
    try std.testing.expect(!validateDomain("[1.2.3]"));
    try std.testing.expect(!validateDomain("[1.2.3.4.5]"));
}

test "IPv6 literal validation" {
    try std.testing.expect(validateDomain("[IPv6:2001:db8:85a3::8a2e:370:7334]"));
    try std.testing.expect(validateDomain("[IPv6:::]"));
    try std.testing.expect(validateDomain("[IPv6:::1]"));
    try std.testing.expect(validateDomain("[IPv6:2001:db8:85a3:0:0:8a2e:370:7334]"));
}
