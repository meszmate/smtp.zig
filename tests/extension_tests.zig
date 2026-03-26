const std = @import("std");
const smtp = @import("smtp");

const Registry = smtp.extension.Registry;
const Extension = smtp.extension.Extension;
const Builtins = smtp.extension.Builtins;

// ---------------------------------------------------------------------------
// Registry: register, get, remove
// ---------------------------------------------------------------------------

test "registry: register and get extension" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{
        .name = "TEST",
        .ehlo_keyword = "TEST",
        .description = "Test extension",
    });

    const ext = reg.get("TEST");
    try std.testing.expect(ext != null);
    try std.testing.expectEqualStrings("TEST", ext.?.name);
    try std.testing.expectEqualStrings("Test extension", ext.?.description);
}

test "registry: get nonexistent returns null" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try std.testing.expect(reg.get("NOPE") == null);
}

test "registry: remove existing extension" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{
        .name = "TEST",
        .ehlo_keyword = "TEST",
    });

    try std.testing.expect(reg.contains("TEST"));
    try std.testing.expect(reg.remove("TEST"));
    try std.testing.expect(!reg.contains("TEST"));
    try std.testing.expectEqual(@as(u32, 0), reg.count());
}

test "registry: remove nonexistent returns false" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try std.testing.expect(!reg.remove("NOPE"));
}

test "registry: contains" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{ .name = "A", .ehlo_keyword = "A" });
    try std.testing.expect(reg.contains("A"));
    try std.testing.expect(!reg.contains("B"));
}

test "registry: count" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try std.testing.expectEqual(@as(u32, 0), reg.count());
    try reg.register(.{ .name = "A", .ehlo_keyword = "A" });
    try std.testing.expectEqual(@as(u32, 1), reg.count());
    try reg.register(.{ .name = "B", .ehlo_keyword = "B" });
    try std.testing.expectEqual(@as(u32, 2), reg.count());
}

test "registry: register replaces existing" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{
        .name = "TEST",
        .ehlo_keyword = "TEST",
        .description = "first",
    });
    try reg.register(.{
        .name = "TEST",
        .ehlo_keyword = "TEST",
        .description = "second",
    });

    const ext = reg.get("TEST").?;
    try std.testing.expectEqualStrings("second", ext.description);
    try std.testing.expectEqual(@as(u32, 1), reg.count());
}

// ---------------------------------------------------------------------------
// EHLO keywords
// ---------------------------------------------------------------------------

test "registry: ehloKeywords collects all keywords" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{ .name = "8BITMIME", .ehlo_keyword = "8BITMIME" });
    try reg.register(.{ .name = "PIPELINING", .ehlo_keyword = "PIPELINING" });

    const keywords = try reg.ehloKeywords(allocator);
    defer allocator.free(keywords);

    try std.testing.expectEqual(@as(usize, 2), keywords.len);
}

// ---------------------------------------------------------------------------
// Dependency resolution
// ---------------------------------------------------------------------------

test "registry: resolve with no dependencies" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    try reg.register(.{ .name = "A", .ehlo_keyword = "A" });
    try reg.register(.{ .name = "B", .ehlo_keyword = "B" });

    const resolved = try reg.resolve(allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqual(@as(usize, 2), resolved.len);
}

test "registry: resolve with dependencies orders correctly" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    // REQUIRETLS depends on STARTTLS
    try reg.register(.{
        .name = "REQUIRETLS",
        .ehlo_keyword = "REQUIRETLS",
        .dependencies = &.{"STARTTLS"},
    });
    try reg.register(.{
        .name = "STARTTLS",
        .ehlo_keyword = "STARTTLS",
    });

    const resolved = try reg.resolve(allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqual(@as(usize, 2), resolved.len);
    // STARTTLS must come before REQUIRETLS.
    var starttls_idx: ?usize = null;
    var requiretls_idx: ?usize = null;
    for (resolved, 0..) |ext, i| {
        if (std.mem.eql(u8, ext.name, "STARTTLS")) starttls_idx = i;
        if (std.mem.eql(u8, ext.name, "REQUIRETLS")) requiretls_idx = i;
    }
    try std.testing.expect(starttls_idx.? < requiretls_idx.?);
}

test "registry: resolve empty registry" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    const resolved = try reg.resolve(allocator);
    defer allocator.free(resolved);

    try std.testing.expectEqual(@as(usize, 0), resolved.len);
}

// ---------------------------------------------------------------------------
// Builtins
// ---------------------------------------------------------------------------

test "builtins: all returns non-empty list" {
    const all = Builtins.all();
    try std.testing.expect(all.len > 0);
}

test "builtins: defaults returns subset of all" {
    const all = Builtins.all();
    const defaults = Builtins.defaults();
    try std.testing.expect(defaults.len > 0);
    try std.testing.expect(defaults.len <= all.len);
}

test "builtins: 8BITMIME extension properties" {
    const ext = Builtins.@"8bitmime";
    try std.testing.expectEqualStrings("8BITMIME", ext.name);
    try std.testing.expectEqualStrings("8BITMIME", ext.ehlo_keyword);
    try std.testing.expectEqualStrings("RFC 6152", ext.rfc);
    try std.testing.expect(ext.default_enabled);
}

test "builtins: PIPELINING extension properties" {
    const ext = Builtins.pipelining;
    try std.testing.expectEqualStrings("PIPELINING", ext.name);
    try std.testing.expect(ext.default_enabled);
}

test "builtins: STARTTLS extension properties" {
    const ext = Builtins.starttls;
    try std.testing.expectEqualStrings("STARTTLS", ext.name);
    try std.testing.expectEqualStrings("RFC 3207", ext.rfc);
}

test "builtins: REQUIRETLS has STARTTLS dependency" {
    const ext = Builtins.requiretls;
    try std.testing.expectEqual(@as(usize, 1), ext.dependencies.len);
    try std.testing.expectEqualStrings("STARTTLS", ext.dependencies[0]);
    try std.testing.expect(!ext.default_enabled);
}

test "builtins: VRFY is not default-enabled" {
    const ext = Builtins.vrfy;
    try std.testing.expect(!ext.default_enabled);
}

test "builtins: HELP is not default-enabled" {
    const ext = Builtins.help;
    try std.testing.expect(!ext.default_enabled);
}

test "builtins: DSN extension" {
    const ext = Builtins.dsn;
    try std.testing.expectEqualStrings("DSN", ext.name);
    try std.testing.expectEqualStrings("RFC 3461", ext.rfc);
}

test "builtins: CHUNKING extension" {
    const ext = Builtins.chunking;
    try std.testing.expectEqualStrings("CHUNKING", ext.name);
    try std.testing.expect(ext.default_enabled);
}

test "builtins: register all builtins in registry" {
    const allocator = std.testing.allocator;
    var reg = Registry.init(allocator);
    defer reg.deinit();

    for (Builtins.all()) |ext| {
        try reg.register(ext);
    }

    try std.testing.expect(reg.count() > 0);
    try std.testing.expect(reg.contains("8BITMIME"));
    try std.testing.expect(reg.contains("PIPELINING"));
    try std.testing.expect(reg.contains("STARTTLS"));
    try std.testing.expect(reg.contains("AUTH"));
}
