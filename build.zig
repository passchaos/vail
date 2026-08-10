const std = @import("std");
const builtin = @import("builtin");

const required_zig_version = "0.16.0";

pub fn build(b: *std.Build) void {
    comptime {
        if (!std.mem.eql(
            u8,
            builtin.zig_version_string,
            required_zig_version,
        )) {
            @compileError(
                "vail requires Zig " ++ required_zig_version ++ "; found " ++
                    builtin.zig_version_string,
            );
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const aws_lc_path = b.option(
        []const u8,
        "aws-lc-path",
        "Path to an AWS-LC checkout or install prefix for optional backend metadata/linking",
    );
    const aws_lc_link = b.option(
        bool,
        "aws-lc-link",
        "Link libcrypto from -Daws-lc-path; requires built AWS-LC libraries",
    ) orelse false;
    const aws_lc_sm_available = if (aws_lc_path) |path|
        awsLcHasShangMi(path)
    else
        false;

    const build_options = b.addOptions();
    build_options.addOption(?[]const u8, "aws_lc_path", aws_lc_path);
    build_options.addOption(bool, "aws_lc_link", aws_lc_link);
    build_options.addOption(bool, "aws_lc_sm_available", aws_lc_sm_available);

    const vail = b.addModule("vail", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{
            .name = "vail_build_options",
            .module = build_options.createModule(),
        }},
    });
    if (aws_lc_path) |path| {
        vail.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ path, "include" }) });
        if (aws_lc_link) {
            const lib_dir = b.pathJoin(&.{ path, "build", "crypto" });
            if (!pathExists(b.pathJoin(&.{ lib_dir, "libcrypto.a" }))) {
                @panic("-Daws-lc-link requires " ++
                    "<aws-lc-path>/build/crypto/libcrypto.a; build AWS-LC first");
            }
            vail.addLibraryPath(.{ .cwd_relative = lib_dir });
            vail.linkSystemLibrary("crypto", .{ .needed = true });
        }
    }
    const library = b.addLibrary(.{
        .name = "vail",
        .root_module = vail,
        .linkage = .static,
    });
    b.installArtifact(library);

    const tests = b.addTest(.{ .root_module = vail });
    const run_tests = b.addRunArtifact(tests);
    const package_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/package_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_package_tests = b.addRunArtifact(package_tests);
    const test_step = b.step("test", "Run all Vail tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_package_tests.step);

    const traffic_bench = b.addExecutable(.{
        .name = "vail-bench-quic-traffic-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/quic_traffic_crypto.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_traffic_bench = b.addRunArtifact(traffic_bench);
    const bench_step = b.step(
        "bench-quic-traffic-crypto",
        "Benchmark QUIC AES-GCM and ChaCha20 traffic protection",
    );
    bench_step.dependOn(&run_traffic_bench.step);
}

fn awsLcHasShangMi(path: []const u8) bool {
    var buffer: [4096]u8 = undefined;
    const conf_path = std.fmt.bufPrint(
        &buffer,
        "{s}/include/openssl/opensslconf.h",
        .{path},
    ) catch return false;
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        std.Options.debug_io,
        conf_path,
        std.heap.page_allocator,
        .limited(64 * 1024),
    ) catch return false;
    defer std.heap.page_allocator.free(bytes);
    return std.mem.indexOf(u8, bytes, "OPENSSL_NO_SM2") == null and
        std.mem.indexOf(u8, bytes, "OPENSSL_NO_SM3") == null and
        std.mem.indexOf(u8, bytes, "OPENSSL_NO_SM4") == null;
}

fn pathExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch return false;
    return true;
}
