const std = @import("std");

pub const Cap = []const u8;

pub const caps = struct {
    pub const @"8bitmime" = "8BITMIME";
    pub const starttls = "STARTTLS";
    pub const size = "SIZE";
    pub const auth = "AUTH";
    pub const auth_plain = "AUTH PLAIN";
    pub const auth_login = "AUTH LOGIN";
    pub const auth_cram_md5 = "AUTH CRAM-MD5";
    pub const auth_xoauth2 = "AUTH XOAUTH2";
    pub const pipelining = "PIPELINING";
    pub const chunking = "CHUNKING";
    pub const binarymime = "BINARYMIME";
    pub const dsn = "DSN";
    pub const enhancedstatuscodes = "ENHANCEDSTATUSCODES";
    pub const smtputf8 = "SMTPUTF8";
    pub const vrfy = "VRFY";
    pub const help = "HELP";
    pub const requiretls = "REQUIRETLS";
    pub const deliverby = "DELIVERBY";
    pub const etrn = "ETRN";
};

pub const CapabilitySet = struct {
    allocator: std.mem.Allocator,
    values: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) CapabilitySet {
        return .{
            .allocator = allocator,
            .values = .empty,
        };
    }

    pub fn deinit(self: *CapabilitySet) void {
        for (self.values.items) |value| {
            self.allocator.free(value);
        }
        self.values.deinit(self.allocator);
    }

    pub fn add(self: *CapabilitySet, value: []const u8) !void {
        if (self.has(value)) return;
        try self.values.append(self.allocator, try self.allocator.dupe(u8, value));
    }

    pub fn addMany(self: *CapabilitySet, values: []const []const u8) !void {
        for (values) |value| {
            try self.add(value);
        }
    }

    pub fn has(self: *const CapabilitySet, value: []const u8) bool {
        for (self.values.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing, value)) return true;
        }
        return false;
    }

    pub fn remove(self: *CapabilitySet, value: []const u8) bool {
        for (self.values.items, 0..) |existing, index| {
            if (std.ascii.eqlIgnoreCase(existing, value)) {
                self.allocator.free(existing);
                _ = self.values.orderedRemove(index);
                return true;
            }
        }
        return false;
    }

    pub fn clear(self: *CapabilitySet) void {
        for (self.values.items) |value| {
            self.allocator.free(value);
        }
        self.values.clearRetainingCapacity();
    }

    pub fn slice(self: *const CapabilitySet) []const []const u8 {
        return self.values.items;
    }

    /// Get the maximum message size advertised by SIZE extension.
    pub fn getMaxSize(self: *const CapabilitySet) ?u64 {
        for (self.values.items) |value| {
            if (std.mem.startsWith(u8, value, "SIZE ") or std.mem.startsWith(u8, value, "SIZE\t")) {
                const size_str = std.mem.trimLeft(u8, value[4..], " \t");
                return std.fmt.parseInt(u64, size_str, 10) catch null;
            }
            if (std.ascii.eqlIgnoreCase(value, "SIZE")) return 0;
        }
        return null;
    }

    /// Get supported AUTH mechanisms from capability list.
    pub fn getAuthMechanisms(self: *const CapabilitySet, allocator: std.mem.Allocator) ![][]u8 {
        var mechs: std.ArrayList([]u8) = .empty;
        errdefer {
            for (mechs.items) |m| allocator.free(m);
            mechs.deinit(allocator);
        }
        for (self.values.items) |value| {
            if (std.ascii.startsWithIgnoreCase(value, "AUTH ")) {
                var it = std.mem.tokenizeAny(u8, value[5..], " ");
                while (it.next()) |mech| {
                    try mechs.append(allocator, try allocator.dupe(u8, mech));
                }
            }
        }
        return mechs.toOwnedSlice(allocator);
    }
};

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    for (haystack[0..prefix.len], prefix) |h, p| {
        if (std.ascii.toLower(h) != std.ascii.toLower(p)) return false;
    }
    return true;
}
