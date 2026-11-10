//! ML-KEM benchmark build graph.

const std = @import("std");

pub fn add(
    b: *std.Build,
    vail: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const common = b.createModule(.{
        .root_source_file = b.path("bench/mlkem/common.zig"),
        .target = target,
        .optimize = optimize,
    });

    inline for (.{
        .{
            .name = "mlkem512",
            .source = "bench/mlkem/mlkem512.zig",
            .description = "Benchmark pure-Zig ML-KEM-512",
        },
        .{
            .name = "mlkem768-random",
            .source = "bench/mlkem/mlkem768.zig",
            .description = "Benchmark pure-Zig ML-KEM-768 with matched randomness",
        },
        .{
            .name = "mlkem1024",
            .source = "bench/mlkem/mlkem1024.zig",
            .description = "Benchmark pure-Zig ML-KEM-1024",
        },
    }) |config| {
        const executable = b.addExecutable(.{
            .name = "vail-bench-" ++ config.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(config.source),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "vail", .module = vail },
                    .{ .name = "benchmark", .module = common },
                },
            }),
        });
        const run = b.addRunArtifact(executable);
        const step = b.step("bench-" ++ config.name, config.description);
        step.dependOn(&run.step);
    }

    inline for (.{
        .{
            .name = "mlkem512",
            .binary = "vail-aws-lc-mlkem512-bench",
            .description = "Benchmark test-only AWS-LC ML-KEM-512",
        },
        .{
            .name = "mlkem768",
            .binary = "vail-aws-lc-mlkem768-random-bench",
            .description = "Benchmark test-only AWS-LC ML-KEM-768 with matched randomness",
        },
        .{
            .name = "mlkem1024",
            .binary = "vail-aws-lc-mlkem1024-bench",
            .description = "Benchmark test-only AWS-LC ML-KEM-1024",
        },
    }) |config| {
        const command = b.addSystemCommand(&.{
            "cargo",
            "run",
            "--release",
            "--locked",
            "--manifest-path",
            "bench/rustls_min_client/Cargo.toml",
            "--bin",
            config.binary,
        });
        const step = b.step(
            "bench-aws-lc-" ++ config.name ++ "-random",
            config.description,
        );
        step.dependOn(&command.step);
    }

    const mlkem768_bench = b.addExecutable(.{
        .name = "vail-bench-mlkem768",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mlkem/full_768.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mlkem768_bench = b.addRunArtifact(mlkem768_bench);
    const mlkem768_bench_step = b.step(
        "bench-mlkem768",
        "Benchmark pure-Zig ML-KEM-768 and hybrid client setup",
    );
    mlkem768_bench_step.dependOn(&run_mlkem768_bench.step);

    const mlkem768_keygen_bench = b.addExecutable(.{
        .name = "vail-bench-mlkem768-keygen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mlkem/keygen_768_deterministic.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mlkem768_keygen_bench = b.addRunArtifact(mlkem768_keygen_bench);
    const mlkem768_keygen_bench_step = b.step(
        "bench-mlkem768-keygen",
        "Benchmark pure-Zig ML-KEM-768 decapsulation-key generation",
    );
    mlkem768_keygen_bench_step.dependOn(&run_mlkem768_keygen_bench.step);

    const aws_lc_mlkem768_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mlkem768-bench",
    });
    const aws_lc_mlkem768_bench_step = b.step(
        "bench-aws-lc-mlkem768",
        "Benchmark test-only AWS-LC ML-KEM-768",
    );
    aws_lc_mlkem768_bench_step.dependOn(&aws_lc_mlkem768_bench.step);
}
