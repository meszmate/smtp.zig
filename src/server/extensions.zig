const std = @import("std");
const dispatch_mod = @import("dispatch.zig");

const CommandHandlerFn = dispatch_mod.CommandHandlerFn;
const CommandContext = dispatch_mod.CommandContext;
const Dispatcher = dispatch_mod.Dispatcher;

/// A server extension that can register command handlers and advertise capabilities.
pub const ServerExtension = struct {
    /// Unique name for this extension (e.g., "8BITMIME", "DSN").
    name: []const u8,

    /// EHLO keyword(s) to advertise. May include parameters (e.g., "SIZE 10485760").
    ehlo_keyword: ?[]const u8 = null,

    /// Optional initialization function called when the extension is loaded.
    init_fn: ?*const fn (ctx: *anyopaque) anyerror!void = null,

    /// Optional function to register command handlers with the dispatcher.
    register_fn: ?*const fn (dispatcher: *Dispatcher, ctx: *anyopaque) anyerror!void = null,

    /// Optional cleanup function.
    deinit_fn: ?*const fn (ctx: *anyopaque) void = null,

    /// Opaque context for the extension.
    context: ?*anyopaque = null,

    /// Extension dependencies (names of extensions that must be loaded first).
    dependencies: []const []const u8 = &.{},
};

/// Manages a set of server extensions, handling registration and EHLO capability listing.
pub const ExtensionManager = struct {
    allocator: std.mem.Allocator,
    extensions: std.ArrayList(ServerExtension),

    pub fn init(allocator: std.mem.Allocator) ExtensionManager {
        return .{
            .allocator = allocator,
            .extensions = .empty,
        };
    }

    pub fn deinit(self: *ExtensionManager) void {
        for (self.extensions.items) |*ext| {
            if (ext.deinit_fn) |deinit_fn| {
                if (ext.context) |ctx| {
                    deinit_fn(ctx);
                }
            }
        }
        self.extensions.deinit(self.allocator);
    }

    /// Register a new extension.
    pub fn register(self: *ExtensionManager, ext: ServerExtension) !void {
        // Check for duplicate.
        for (self.extensions.items) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, ext.name)) {
                return error.DuplicateExtension;
            }
        }
        try self.extensions.append(self.allocator, ext);
    }

    /// Remove an extension by name.
    pub fn remove(self: *ExtensionManager, name: []const u8) bool {
        for (self.extensions.items, 0..) |ext, i| {
            if (std.ascii.eqlIgnoreCase(ext.name, name)) {
                if (ext.deinit_fn) |deinit_fn| {
                    if (ext.context) |ctx| {
                        deinit_fn(ctx);
                    }
                }
                _ = self.extensions.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Get an extension by name.
    pub fn get(self: *const ExtensionManager, name: []const u8) ?*const ServerExtension {
        for (self.extensions.items) |*ext| {
            if (std.ascii.eqlIgnoreCase(ext.name, name)) {
                return ext;
            }
        }
        return null;
    }

    /// Initialize all registered extensions.
    pub fn initAll(self: *ExtensionManager) !void {
        for (self.extensions.items) |*ext| {
            if (ext.init_fn) |init_fn| {
                if (ext.context) |ctx| {
                    try init_fn(ctx);
                }
            }
        }
    }

    /// Register all extension command handlers with the dispatcher.
    pub fn registerHandlers(self: *ExtensionManager, dispatcher: *Dispatcher) !void {
        for (self.extensions.items) |*ext| {
            if (ext.register_fn) |reg_fn| {
                if (ext.context) |ctx| {
                    try reg_fn(dispatcher, ctx);
                }
            }
        }
    }

    /// Collect EHLO keywords from all registered extensions.
    /// Caller owns the returned slice.
    pub fn ehloKeywords(self: *const ExtensionManager, allocator: std.mem.Allocator) ![][]const u8 {
        var keywords: std.ArrayList([]const u8) = .empty;
        errdefer keywords.deinit(allocator);

        for (self.extensions.items) |ext| {
            if (ext.ehlo_keyword) |kw| {
                try keywords.append(allocator, kw);
            }
        }

        return keywords.toOwnedSlice(allocator);
    }

    /// Resolve extension dependencies using topological sort.
    /// Returns extensions in dependency order.
    /// Caller owns the returned slice.
    pub fn resolve(self: *const ExtensionManager, allocator: std.mem.Allocator) ![]ServerExtension {
        const n = self.extensions.items.len;
        if (n == 0) return try allocator.alloc(ServerExtension, 0);

        var resolved: std.ArrayList(ServerExtension) = .empty;
        errdefer resolved.deinit(allocator);

        const visited = try allocator.alloc(bool, n);
        defer allocator.free(visited);
        @memset(visited, false);

        const in_progress = try allocator.alloc(bool, n);
        defer allocator.free(in_progress);
        @memset(in_progress, false);

        for (0..n) |i| {
            if (!visited[i]) {
                try self.visit(allocator, i, visited, in_progress, &resolved);
            }
        }

        return resolved.toOwnedSlice(allocator);
    }

    fn visit(
        self: *const ExtensionManager,
        allocator: std.mem.Allocator,
        idx: usize,
        visited: []bool,
        in_progress: []bool,
        resolved: *std.ArrayList(ServerExtension),
    ) !void {
        if (in_progress[idx]) return error.CyclicDependency;
        if (visited[idx]) return;

        in_progress[idx] = true;

        const ext = self.extensions.items[idx];
        for (ext.dependencies) |dep_name| {
            if (self.findIndex(dep_name)) |dep_idx| {
                try self.visit(allocator, dep_idx, visited, in_progress, resolved);
            }
        }

        in_progress[idx] = false;
        visited[idx] = true;
        try resolved.append(allocator, ext);
    }

    fn findIndex(self: *const ExtensionManager, name: []const u8) ?usize {
        for (self.extensions.items, 0..) |ext, i| {
            if (std.ascii.eqlIgnoreCase(ext.name, name)) return i;
        }
        return null;
    }
};
