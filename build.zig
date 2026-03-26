const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const smtp_mod = b.addModule("smtp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const examples = [_][]const u8{
        "simple_client",
        "simple_server",
    };

    for (examples) |example_name| {
        const exe = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("examples/{s}.zig", .{example_name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "smtp", .module = smtp_mod },
                },
            }),
        });
        b.installArtifact(exe);
    }

    const test_files = [_][]const u8{
        "tests/protocol_tests.zig",
        "tests/client_tests.zig",
        "tests/server_tests.zig",
        "tests/state_tests.zig",
        "tests/extension_tests.zig",
        "tests/auth_tests.zig",
        "tests/store_tests.zig",
        "tests/store_interface_tests.zig",
        "tests/middleware_tests.zig",
        "tests/mime_tests.zig",
    };

    const test_step = b.step("test", "Run unit tests");

    for (test_files) |test_file| {
        const unit_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "smtp", .module = smtp_mod },
                },
            }),
        });
        const run_unit_tests = b.addRunArtifact(unit_tests);
        test_step.dependOn(&run_unit_tests.step);
    }

    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    test_step.dependOn(&run_lib_tests.step);
}
