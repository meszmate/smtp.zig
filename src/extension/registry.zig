const std = @import("std");
const extension_mod = @import("extension.zig");

const Extension = extension_mod.Extension;

/// Registry for managing SMTP extensions.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    extensions: std.StringHashMap(Extension),

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{
            .allocator = allocator,
            .extensions = std.StringHashMap(Extension).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        self.extensions.deinit();
    }

    /// Register an extension. Replaces any existing extension with the same name.
    pub fn register(self: *Registry, ext: Extension) !void {
        try self.extensions.put(ext.name, ext);
    }

    /// Get an extension by name.
    pub fn get(self: *const Registry, name: []const u8) ?Extension {
        return self.extensions.get(name);
    }

    /// Remove an extension by name. Returns true if it was present.
    pub fn remove(self: *Registry, name: []const u8) bool {
        return self.extensions.remove(name);
    }

    /// Check if an extension is registered.
    pub fn contains(self: *const Registry, name: []const u8) bool {
        return self.extensions.contains(name);
    }

    /// Get the number of registered extensions.
    pub fn count(self: *const Registry) u32 {
        return @intCast(self.extensions.count());
    }

    /// Resolve extension dependencies using topological sort.
    /// Returns extensions in dependency order.
    /// Caller owns the returned slice.
    pub fn resolve(self: *const Registry, allocator: std.mem.Allocator) ![]Extension {
        // Collect all extensions.
        var all: std.ArrayList(Extension) = .empty;
        defer all.deinit(allocator);

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            try all.append(allocator, entry.value_ptr.*);
        }

        const n = all.items.len;
        if (n == 0) return try allocator.alloc(Extension, 0);

        var resolved: std.ArrayList(Extension) = .empty;
        errdefer resolved.deinit(allocator);

        const visited = try allocator.alloc(bool, n);
        defer allocator.free(visited);
        @memset(visited, false);

        const in_progress = try allocator.alloc(bool, n);
        defer allocator.free(in_progress);
        @memset(in_progress, false);

        for (0..n) |i| {
            if (!visited[i]) {
                try visit(allocator, all.items, i, visited, in_progress, &resolved);
            }
        }

        return resolved.toOwnedSlice(allocator);
    }

    /// Collect EHLO keywords from all registered extensions.
    /// Caller owns the returned slice.
    pub fn ehloKeywords(self: *const Registry, allocator: std.mem.Allocator) ![][]const u8 {
        var keywords: std.ArrayList([]const u8) = .empty;
        errdefer keywords.deinit(allocator);

        var it = self.extensions.iterator();
        while (it.next()) |entry| {
            try keywords.append(allocator, entry.value_ptr.ehlo_keyword);
        }

        return keywords.toOwnedSlice(allocator);
    }
};

fn visit(
    allocator: std.mem.Allocator,
    extensions: []const Extension,
    idx: usize,
    visited: []bool,
    in_progress: []bool,
    resolved: *std.ArrayList(Extension),
) !void {
    if (in_progress[idx]) return error.CyclicDependency;
    if (visited[idx]) return;

    in_progress[idx] = true;

    const ext = extensions[idx];
    for (ext.dependencies) |dep_name| {
        if (findIndex(extensions, dep_name)) |dep_idx| {
            try visit(allocator, extensions, dep_idx, visited, in_progress, resolved);
        }
    }

    in_progress[idx] = false;
    visited[idx] = true;
    try resolved.append(allocator, ext);
}

fn findIndex(extensions: []const Extension, name: []const u8) ?usize {
    for (extensions, 0..) |ext, i| {
        if (std.ascii.eqlIgnoreCase(ext.name, name)) return i;
    }
    return null;
}
