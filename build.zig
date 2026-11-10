const std = @import("std");
const builtin = @import("builtin");
const mldsa_benchmarks = @import("build_support/mldsa_benchmarks.zig");
const mlkem_benchmarks = @import("build_support/mlkem_benchmarks.zig");
const benches = @import("build_support/benches.zig");
const interop = @import("build_support/interop.zig");

const required_zig_version = "0.16";

pub fn build(b: *std.Build) void {
    comptime {
        if (!std.mem.startsWith(
            u8,
            builtin.zig_version_string,
            required_zig_version ++ ".",
        )) {
            @compileError(
                "vail requires Zig " ++ required_zig_version ++ ".x; found " ++
                    builtin.zig_version_string,
            );
        }
    }

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_bench = b.option(
        bool,
        "bench",
        "Register benchmark steps",
    ) orelse true;
    const enable_interop = b.option(
        bool,
        "interop",
        "Register interoperability steps",
    ) orelse true;
    const enable_archive = b.option(
        bool,
        "archive",
        "Include archive_crypto tests in test-all",
    ) orelse true;
    const enable_examples = b.option(
        bool,
        "examples",
        "Build example programs",
    ) orelse true;
    const vort_dep = b.dependency("vort", .{
        .target = target,
        .optimize = optimize,
    });
    const vort = vort_dep.module("vort");

    const vail = b.addModule("vail", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "vort", .module = vort }},
    });
    _ = b.addModule("vail_sm", .{
        .root_source_file = b.path("src/crypto/sm.zig"),
        .target = target,
        .optimize = optimize,
    });
    const signature_primitives = b.addModule("vail_signature_primitives", .{
        .root_source_file = b.path("src/signature_primitives.zig"),
        .target = target,
        .optimize = optimize,
    });
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
    const test_compile_step = b.step(
        "test-compile",
        "Compile all Vail tests without running them",
    );
    test_compile_step.dependOn(&tests.step);
    test_compile_step.dependOn(&package_tests.step);
    const signature_primitives_tests = b.addTest(.{
        .root_module = signature_primitives,
    });
    const run_signature_primitives_tests = b.addRunArtifact(
        signature_primitives_tests,
    );
    const signature_primitives_test_step = b.step(
        "test-signature-primitives",
        "Run dependency-light P-521/SM2/SM3 signature primitive tests",
    );
    signature_primitives_test_step.dependOn(
        &run_signature_primitives_tests.step,
    );

    const test_all_step = b.step(
        "test-all",
        "Run Vail, signature-primitive, package, and archive test suites",
    );
    test_all_step.dependOn(&run_tests.step);
    test_all_step.dependOn(&run_package_tests.step);
    test_all_step.dependOn(&run_signature_primitives_tests.step);
    if (enable_archive) {
        const archive_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("archive_crypto/src/root.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        const run_archive_tests = b.addRunArtifact(archive_tests);
        test_all_step.dependOn(&run_archive_tests.step);
    }

    if (enable_bench) benches.add(b, vail, target, optimize);
    if (enable_interop) interop.add(b, vail, target, optimize);

    var bench_deps: std.ArrayList(*std.Build.Step) = .empty;
    var interop_deps: std.ArrayList(*std.Build.Step) = .empty;
    var top_level_it = b.top_level_steps.iterator();
    while (top_level_it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (std.mem.startsWith(u8, name, "bench-")) {
            bench_deps.append(b.allocator, &entry.value_ptr.*.step) catch
                @panic("OOM");
        } else if (std.mem.startsWith(u8, name, "interop-")) {
            interop_deps.append(b.allocator, &entry.value_ptr.*.step) catch
                @panic("OOM");
        }
    }
    const bench_all_step = b.step("bench", "Run all Vail benchmarks");
    for (bench_deps.items) |dep| bench_all_step.dependOn(dep);
    const interop_all_step = b.step(
        "interop",
        "Run all Vail interoperability checks",
    );
    for (interop_deps.items) |dep| interop_all_step.dependOn(dep);

    const fmt_paths = &.{
        "build.zig",
        "src",
        "bench",
        "build_support",
        "test",
        "tools",
        "archive_crypto",
        "examples",
    };
    const fmt_excludes = &.{
        "bench/rustls_client_hello/target",
        "bench/rustls_min_client/target",
        "bench/rustls_min_server/target",
        "archive_crypto/.zig-cache",
        "src/crypto/ec/p256_tables.zig",
        "src/crypto/ec/p384_tables.zig",
        "src/crypto/sign/ed25519_base_table.zig",
        "src/crypto/sign/ed25519_verify_table.zig",
        "src/crypto/sign/ed25519_tables.zig",
        "src/crypto/kex/x25519_public_tables.zig",
        "src/x509/stringprep_data.zig",
    };
    const fmt = b.addFmt(.{
        .paths = fmt_paths,
        .exclude_paths = fmt_excludes,
    });
    const fmt_step = b.step("fmt", "Format Zig sources");
    fmt_step.dependOn(&fmt.step);
    const fmt_check = b.addFmt(.{
        .paths = fmt_paths,
        .exclude_paths = fmt_excludes,
        .check = true,
    });
    const check_step = b.step(
        "check",
        "Check formatting and run all test suites",
    );
    check_step.dependOn(&fmt_check.step);
    check_step.dependOn(test_all_step);

    const check_generated = b.addExecutable(.{
        .name = "vail-check-generated",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/check_generated_tables.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_check_generated = b.addRunArtifact(check_generated);
    run_check_generated.setCwd(b.path("."));
    const check_generated_step = b.step(
        "check-generated",
        "Verify checked-in generated files against their manifest",
    );
    check_generated_step.dependOn(&run_check_generated.step);
    check_step.dependOn(check_generated_step);

    const check_docs = b.addExecutable(.{
        .name = "vail-check-docs",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/check_docs_links.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_check_docs = b.addRunArtifact(check_docs);
    run_check_docs.setCwd(b.path("."));
    const check_docs_step = b.step(
        "check-docs",
        "Verify relative links in Markdown documentation",
    );
    check_docs_step.dependOn(&run_check_docs.step);
    check_step.dependOn(check_docs_step);

    const example_names = [_][]const u8{ "sha256", "aes_gcm", "mac" };
    const examples_step = b.step("examples", "Build example programs");
    if (enable_examples) {
        for (example_names) |name| {
            const example = b.addExecutable(.{
                .name = b.fmt("vail-example-{s}", .{name}),
                .root_module = b.createModule(.{
                    .root_source_file = b.path(
                        b.fmt("examples/{s}.zig", .{name}),
                    ),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{.{ .name = "vail", .module = vail }},
                }),
            });
            examples_step.dependOn(&example.step);
        }
    }
    check_step.dependOn(examples_step);
}
