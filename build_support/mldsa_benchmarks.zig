//! ML-DSA benchmark build graph.

const std = @import("std");

pub fn add(
    b: *std.Build,
    vail: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const mldsa_wide_verify_benchmark = b.createModule(.{
        .root_source_file = b.path("bench/mldsa/common/verify.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "vail", .module = vail }},
    });
    const mldsa_wide_sign_std_benchmark = b.createModule(.{
        .root_source_file = b.path("bench/mldsa/common/sign_std.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mldsa_wide_sign_prepared_benchmark = b.createModule(.{
        .root_source_file = b.path("bench/mldsa/common/sign_prepared.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "vail", .module = vail }},
    });
    const mldsa_wide_keygen_std_benchmark = b.createModule(.{
        .root_source_file = b.path("bench/mldsa/common/keygen_std.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mldsa44_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa44.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_bench = b.addRunArtifact(mldsa44_bench);
    const mldsa44_bench_step = b.step(
        "bench-mldsa44",
        "Benchmark pure-Zig ML-DSA-44 primitives",
    );
    mldsa44_bench_step.dependOn(&run_mldsa44_bench.step);

    const mldsa65_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa65",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_65/verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vail", .module = vail },
                .{ .name = "benchmark", .module = mldsa_wide_verify_benchmark },
            },
        }),
    });
    const run_mldsa65_bench = b.addRunArtifact(mldsa65_bench);
    const mldsa65_bench_step = b.step(
        "bench-mldsa65",
        "Benchmark pure-Zig ML-DSA-65 verification",
    );
    mldsa65_bench_step.dependOn(&run_mldsa65_bench.step);

    const mldsa87_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa87",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_87/verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vail", .module = vail },
                .{ .name = "benchmark", .module = mldsa_wide_verify_benchmark },
            },
        }),
    });
    const run_mldsa87_bench = b.addRunArtifact(mldsa87_bench);
    const mldsa87_bench_step = b.step(
        "bench-mldsa87",
        "Benchmark pure-Zig ML-DSA-87 verification",
    );
    mldsa87_bench_step.dependOn(&run_mldsa87_bench.step);

    const aws_lc_mldsa65_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa65-bench",
    });
    const aws_lc_mldsa65_bench_step = b.step(
        "bench-aws-lc-mldsa65",
        "Benchmark test-only AWS-LC ML-DSA-65 verification",
    );
    aws_lc_mldsa65_bench_step.dependOn(&aws_lc_mldsa65_bench.step);

    const aws_lc_mldsa87_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa87-bench",
    });
    const aws_lc_mldsa87_bench_step = b.step(
        "bench-aws-lc-mldsa87",
        "Benchmark test-only AWS-LC ML-DSA-87 verification",
    );
    aws_lc_mldsa87_bench_step.dependOn(&aws_lc_mldsa87_bench.step);

    const mldsa65_sign_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa65-sign-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_65/sign_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "benchmark",
                .module = mldsa_wide_sign_std_benchmark,
            }},
        }),
    });
    const run_mldsa65_sign_std_bench = b.addRunArtifact(
        mldsa65_sign_std_bench,
    );
    const mldsa65_sign_std_bench_step = b.step(
        "bench-mldsa65-sign-std",
        "Benchmark Zig std ML-DSA-65 randomized signing",
    );
    mldsa65_sign_std_bench_step.dependOn(&run_mldsa65_sign_std_bench.step);

    const mldsa87_sign_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa87-sign-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_87/sign_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "benchmark",
                .module = mldsa_wide_sign_std_benchmark,
            }},
        }),
    });
    const run_mldsa87_sign_std_bench = b.addRunArtifact(
        mldsa87_sign_std_bench,
    );
    const mldsa87_sign_std_bench_step = b.step(
        "bench-mldsa87-sign-std",
        "Benchmark Zig std ML-DSA-87 randomized signing",
    );
    mldsa87_sign_std_bench_step.dependOn(&run_mldsa87_sign_std_bench.step);

    const mldsa65_sign_prepared_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa65-sign-prepared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_65/sign_prepared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vail", .module = vail },
                .{ .name = "benchmark", .module = mldsa_wide_sign_prepared_benchmark },
            },
        }),
    });
    const run_mldsa65_sign_prepared_bench = b.addRunArtifact(
        mldsa65_sign_prepared_bench,
    );
    const mldsa65_sign_prepared_bench_step = b.step(
        "bench-mldsa65-sign-prepared",
        "Benchmark prepared pure-Zig ML-DSA-65 randomized signing",
    );
    mldsa65_sign_prepared_bench_step.dependOn(
        &run_mldsa65_sign_prepared_bench.step,
    );

    const mldsa87_sign_prepared_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa87-sign-prepared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_87/sign_prepared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "vail", .module = vail },
                .{ .name = "benchmark", .module = mldsa_wide_sign_prepared_benchmark },
            },
        }),
    });
    const run_mldsa87_sign_prepared_bench = b.addRunArtifact(
        mldsa87_sign_prepared_bench,
    );
    const mldsa87_sign_prepared_bench_step = b.step(
        "bench-mldsa87-sign-prepared",
        "Benchmark prepared pure-Zig ML-DSA-87 randomized signing",
    );
    mldsa87_sign_prepared_bench_step.dependOn(
        &run_mldsa87_sign_prepared_bench.step,
    );

    const mldsa65_keygen_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa65-keygen-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_65/keygen_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "benchmark",
                .module = mldsa_wide_keygen_std_benchmark,
            }},
        }),
    });
    const run_mldsa65_keygen_std_bench = b.addRunArtifact(
        mldsa65_keygen_std_bench,
    );
    const mldsa65_keygen_std_bench_step = b.step(
        "bench-mldsa65-keygen-std",
        "Benchmark Zig std ML-DSA-65 deterministic key generation",
    );
    mldsa65_keygen_std_bench_step.dependOn(&run_mldsa65_keygen_std_bench.step);

    const mldsa65_keygen_accelerated_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa65-keygen-accelerated",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_65/keygen_accelerated.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa65_keygen_accelerated_bench = b.addRunArtifact(
        mldsa65_keygen_accelerated_bench,
    );
    const mldsa65_keygen_accelerated_bench_step = b.step(
        "bench-mldsa65-keygen-accelerated",
        "Benchmark accelerated pure-Zig ML-DSA-65 key generation",
    );
    mldsa65_keygen_accelerated_bench_step.dependOn(
        &run_mldsa65_keygen_accelerated_bench.step,
    );

    const mldsa87_keygen_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa87-keygen-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_87/keygen_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{
                .name = "benchmark",
                .module = mldsa_wide_keygen_std_benchmark,
            }},
        }),
    });
    const run_mldsa87_keygen_std_bench = b.addRunArtifact(
        mldsa87_keygen_std_bench,
    );
    const mldsa87_keygen_std_bench_step = b.step(
        "bench-mldsa87-keygen-std",
        "Benchmark Zig std ML-DSA-87 deterministic key generation",
    );
    mldsa87_keygen_std_bench_step.dependOn(&run_mldsa87_keygen_std_bench.step);

    const mldsa87_keygen_accelerated_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa87-keygen-accelerated",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_87/keygen_accelerated.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa87_keygen_accelerated_bench = b.addRunArtifact(
        mldsa87_keygen_accelerated_bench,
    );
    const mldsa87_keygen_accelerated_bench_step = b.step(
        "bench-mldsa87-keygen-accelerated",
        "Benchmark accelerated pure-Zig ML-DSA-87 key generation",
    );
    mldsa87_keygen_accelerated_bench_step.dependOn(
        &run_mldsa87_keygen_accelerated_bench.step,
    );

    const aws_lc_mldsa65_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa65-sign-bench",
    });
    const aws_lc_mldsa65_sign_bench_step = b.step(
        "bench-aws-lc-mldsa65-sign",
        "Benchmark test-only AWS-LC ML-DSA-65 randomized signing",
    );
    aws_lc_mldsa65_sign_bench_step.dependOn(
        &aws_lc_mldsa65_sign_bench.step,
    );

    const aws_lc_mldsa87_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa87-sign-bench",
    });
    const aws_lc_mldsa87_sign_bench_step = b.step(
        "bench-aws-lc-mldsa87-sign",
        "Benchmark test-only AWS-LC ML-DSA-87 randomized signing",
    );
    aws_lc_mldsa87_sign_bench_step.dependOn(
        &aws_lc_mldsa87_sign_bench.step,
    );

    const aws_lc_mldsa65_keygen_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa65-keygen-bench",
    });
    const aws_lc_mldsa65_keygen_bench_step = b.step(
        "bench-aws-lc-mldsa65-keygen",
        "Benchmark test-only AWS-LC ML-DSA-65 deterministic key generation",
    );
    aws_lc_mldsa65_keygen_bench_step.dependOn(
        &aws_lc_mldsa65_keygen_bench.step,
    );

    const aws_lc_mldsa87_keygen_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa87-keygen-bench",
    });
    const aws_lc_mldsa87_keygen_bench_step = b.step(
        "bench-aws-lc-mldsa87-keygen",
        "Benchmark test-only AWS-LC ML-DSA-87 deterministic key generation",
    );
    aws_lc_mldsa87_keygen_bench_step.dependOn(
        &aws_lc_mldsa87_keygen_bench.step,
    );

    const mldsa44_prepared_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-prepared-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/prepared_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_prepared_std_bench = b.addRunArtifact(
        mldsa44_prepared_std_bench,
    );
    const mldsa44_prepared_std_bench_step = b.step(
        "bench-mldsa44-prepared-std",
        "Benchmark Zig std ML-DSA-44 prepared-key verification",
    );
    mldsa44_prepared_std_bench_step.dependOn(
        &run_mldsa44_prepared_std_bench.step,
    );

    const mldsa44_prepared_cached_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-prepared-cached",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/prepared_cached.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_prepared_cached_bench = b.addRunArtifact(
        mldsa44_prepared_cached_bench,
    );
    const mldsa44_prepared_cached_bench_step = b.step(
        "bench-mldsa44-prepared-cached",
        "Benchmark cached-t1-NTT ML-DSA-44 prepared-key verification",
    );
    mldsa44_prepared_cached_bench_step.dependOn(
        &run_mldsa44_prepared_cached_bench.step,
    );

    const mldsa44_raw_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-raw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/raw.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_raw_bench = b.addRunArtifact(mldsa44_raw_bench);
    const mldsa44_raw_bench_step = b.step(
        "bench-mldsa44-raw",
        "Benchmark pure-Zig ML-DSA-44 raw-key verification",
    );
    mldsa44_raw_bench_step.dependOn(&run_mldsa44_raw_bench.step);

    const mldsa44_sign_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-sign-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/sign_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_sign_std_bench = b.addRunArtifact(
        mldsa44_sign_std_bench,
    );
    const mldsa44_sign_std_bench_step = b.step(
        "bench-mldsa44-sign-std",
        "Benchmark Zig std ML-DSA-44 randomized signing",
    );
    mldsa44_sign_std_bench_step.dependOn(
        &run_mldsa44_sign_std_bench.step,
    );

    const mldsa44_sign_prepared_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-sign-prepared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/sign_prepared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_sign_prepared_bench = b.addRunArtifact(
        mldsa44_sign_prepared_bench,
    );
    const mldsa44_sign_prepared_bench_step = b.step(
        "bench-mldsa44-sign-prepared",
        "Benchmark prepared pure-Zig ML-DSA-44 randomized signing",
    );
    mldsa44_sign_prepared_bench_step.dependOn(
        &run_mldsa44_sign_prepared_bench.step,
    );

    const mldsa44_keygen_std_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-keygen-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/keygen_std.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_keygen_std_bench = b.addRunArtifact(
        mldsa44_keygen_std_bench,
    );
    const mldsa44_keygen_std_bench_step = b.step(
        "bench-mldsa44-keygen-std",
        "Benchmark Zig std ML-DSA-44 deterministic key generation",
    );
    mldsa44_keygen_std_bench_step.dependOn(
        &run_mldsa44_keygen_std_bench.step,
    );

    const mldsa44_keygen_accelerated_bench = b.addExecutable(.{
        .name = "vail-bench-mldsa44-keygen-accelerated",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/mldsa/ml_dsa_44/keygen_accelerated.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_mldsa44_keygen_accelerated_bench = b.addRunArtifact(
        mldsa44_keygen_accelerated_bench,
    );
    const mldsa44_keygen_accelerated_bench_step = b.step(
        "bench-mldsa44-keygen-accelerated",
        "Benchmark accelerated pure-Zig ML-DSA-44 key generation",
    );
    mldsa44_keygen_accelerated_bench_step.dependOn(
        &run_mldsa44_keygen_accelerated_bench.step,
    );

    const aws_lc_mldsa44_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa44-bench",
    });
    const aws_lc_mldsa44_bench_step = b.step(
        "bench-aws-lc-mldsa44",
        "Benchmark test-only AWS-LC ML-DSA-44 primitives",
    );
    aws_lc_mldsa44_bench_step.dependOn(&aws_lc_mldsa44_bench.step);

    const aws_lc_mldsa44_prepared_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa44-prepared-bench",
    });
    const aws_lc_mldsa44_prepared_bench_step = b.step(
        "bench-aws-lc-mldsa44-prepared",
        "Benchmark test-only AWS-LC ML-DSA-44 prepared verification",
    );
    aws_lc_mldsa44_prepared_bench_step.dependOn(
        &aws_lc_mldsa44_prepared_bench.step,
    );

    const aws_lc_mldsa44_raw_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa44-raw-bench",
    });
    const aws_lc_mldsa44_raw_bench_step = b.step(
        "bench-aws-lc-mldsa44-raw",
        "Benchmark test-only AWS-LC ML-DSA-44 raw-key verification",
    );
    aws_lc_mldsa44_raw_bench_step.dependOn(
        &aws_lc_mldsa44_raw_bench.step,
    );

    const aws_lc_mldsa44_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa44-sign-bench",
    });
    const aws_lc_mldsa44_sign_bench_step = b.step(
        "bench-aws-lc-mldsa44-sign",
        "Benchmark test-only AWS-LC ML-DSA-44 randomized signing",
    );
    aws_lc_mldsa44_sign_bench_step.dependOn(
        &aws_lc_mldsa44_sign_bench.step,
    );

    const aws_lc_mldsa44_keygen_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-mldsa44-keygen-bench",
    });
    const aws_lc_mldsa44_keygen_bench_step = b.step(
        "bench-aws-lc-mldsa44-keygen",
        "Benchmark test-only AWS-LC ML-DSA-44 deterministic key generation",
    );
    aws_lc_mldsa44_keygen_bench_step.dependOn(
        &aws_lc_mldsa44_keygen_bench.step,
    );
}
