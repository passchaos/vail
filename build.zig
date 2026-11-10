const std = @import("std");
const builtin = @import("builtin");
const mldsa_benchmarks = @import("build/mldsa_benchmarks.zig");
const mlkem_benchmarks = @import("build/mlkem_benchmarks.zig");

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

    const archive_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("archive_crypto/src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_archive_tests = b.addRunArtifact(archive_tests);
    const test_all_step = b.step(
        "test-all",
        "Run Vail, signature-primitive, package, and archive test suites",
    );
    test_all_step.dependOn(&run_tests.step);
    test_all_step.dependOn(&run_package_tests.step);
    test_all_step.dependOn(&run_signature_primitives_tests.step);
    test_all_step.dependOn(&run_archive_tests.step);

    const traffic_bench = b.addExecutable(.{
        .name = "vail-bench-quic-traffic-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/quic/quic_traffic_crypto.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_traffic_bench = b.addRunArtifact(traffic_bench);
    const bench_step = b.step(
        "bench-quic-traffic-crypto",
        "Benchmark QUIC AEAD traffic protection",
    );
    bench_step.dependOn(&run_traffic_bench.step);

    const tls_record_bench = b.addExecutable(.{
        .name = "vail-bench-tls-record-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_record_crypto.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_record_bench = b.addRunArtifact(tls_record_bench);
    const tls_record_bench_step = b.step(
        "bench-tls-record-crypto",
        "Benchmark stateful TLS 1.3 record protection",
    );
    tls_record_bench_step.dependOn(&run_tls_record_bench.step);

    const tls12_record_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-record-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls12_record_crypto.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls12_record_bench = b.addRunArtifact(tls12_record_bench);
    const tls12_record_bench_step = b.step(
        "bench-tls12-record-crypto",
        "Benchmark stateful TLS 1.2 AEAD record protection",
    );
    tls12_record_bench_step.dependOn(&run_tls12_record_bench.step);

    const chacha_components_bench = b.addExecutable(.{
        .name = "vail-bench-chacha-components",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/chacha_components.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_chacha_components_bench = b.addRunArtifact(
        chacha_components_bench,
    );
    const chacha_components_bench_step = b.step(
        "bench-chacha-components",
        "Profile Zig std ChaCha20-Poly1305 components",
    );
    chacha_components_bench_step.dependOn(
        &run_chacha_components_bench.step,
    );

    const chacha20_poly1305_bench = b.addExecutable(.{
        .name = "vail-bench-chacha20-poly1305",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/chacha20_poly1305.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_chacha20_poly1305_bench = b.addRunArtifact(
        chacha20_poly1305_bench,
    );
    const chacha20_poly1305_bench_step = b.step(
        "bench-chacha20-poly1305",
        "Benchmark prepared pure-Zig ChaCha20-Poly1305 seal/open",
    );
    chacha20_poly1305_bench_step.dependOn(
        &run_chacha20_poly1305_bench.step,
    );

    const aws_lc_aead_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-aead-bench",
    });
    const aws_lc_aead_bench_step = b.step(
        "bench-aws-lc-aead",
        "Benchmark test-only AWS-LC AEAD implementations",
    );
    aws_lc_aead_bench_step.dependOn(&aws_lc_aead_bench.step);

    const aws_lc_rsa_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-rsa-bench",
        "--",
        "src/crypto/testdata/rsa_signing_key.pem",
    });
    const aws_lc_rsa_bench_step = b.step(
        "bench-aws-lc-rsa",
        "Benchmark test-only AWS-LC RSA-2048 signing",
    );
    aws_lc_rsa_bench_step.dependOn(&aws_lc_rsa_bench.step);

    const p521_verify_bench = b.addExecutable(.{
        .name = "vail-bench-p521-verify",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_verify_bench = b.addRunArtifact(p521_verify_bench);
    const p521_verify_bench_step = b.step(
        "bench-p521-verify",
        "Benchmark pure-Zig P-521 ECDSA verification",
    );
    p521_verify_bench_step.dependOn(&run_p521_verify_bench.step);

    const p521_one_shot_bench = b.addExecutable(.{
        .name = "vail-bench-p521-one-shot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_one_shot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_one_shot_bench = b.addRunArtifact(p521_one_shot_bench);
    const p521_one_shot_bench_step = b.step(
        "bench-p521-one-shot",
        "Benchmark pure-Zig one-shot P-521 ECDSA verification",
    );
    p521_one_shot_bench_step.dependOn(&run_p521_one_shot_bench.step);

    const p521_public_key_bench = b.addExecutable(.{
        .name = "vail-bench-p521-public-key",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_public_key.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_public_key_bench = b.addRunArtifact(p521_public_key_bench);
    const p521_public_key_bench_step = b.step(
        "bench-p521-public-key",
        "Benchmark P-521 public-key SEC1 serialization",
    );
    p521_public_key_bench_step.dependOn(&run_p521_public_key_bench.step);

    const p521_prepared_bench = b.addExecutable(.{
        .name = "vail-bench-p521-prepared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_prepared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_prepared_bench = b.addRunArtifact(p521_prepared_bench);
    const p521_prepared_bench_step = b.step(
        "bench-p521-prepared",
        "Benchmark pure-Zig prepared P-521 ECDSA verification",
    );
    p521_prepared_bench_step.dependOn(&run_p521_prepared_bench.step);

    const p521_sign_bench = b.addExecutable(.{
        .name = "vail-bench-p521-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_sign_bench = b.addRunArtifact(p521_sign_bench);
    const p521_sign_bench_step = b.step(
        "bench-p521-sign",
        "Benchmark pure-Zig P-521 ECDSA signing",
    );
    p521_sign_bench_step.dependOn(&run_p521_sign_bench.step);

    const p521_sign_one_shot_bench = b.addExecutable(.{
        .name = "vail-bench-p521-sign-one-shot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_sign_one_shot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_sign_one_shot_bench = b.addRunArtifact(
        p521_sign_one_shot_bench,
    );
    const p521_sign_one_shot_bench_step = b.step(
        "bench-p521-sign-one-shot",
        "Benchmark pure-Zig random-nonce P-521 ECDSA signing",
    );
    p521_sign_one_shot_bench_step.dependOn(
        &run_p521_sign_one_shot_bench.step,
    );

    const p521_ecdh_bench = b.addExecutable(.{
        .name = "vail-bench-p521-ecdh",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p521_ecdh.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p521_ecdh_bench = b.addRunArtifact(p521_ecdh_bench);
    const p521_ecdh_bench_step = b.step(
        "bench-p521-ecdh",
        "Benchmark pure-Zig P-521 public-key recovery and ECDH",
    );
    p521_ecdh_bench_step.dependOn(&run_p521_ecdh_bench.step);

    const aws_lc_p521_ecdh_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p521-ecdh-bench",
    });
    const aws_lc_p521_ecdh_bench_step = b.step(
        "bench-aws-lc-p521-ecdh",
        "Benchmark test-only AWS-LC P-521 public-key recovery and ECDH",
    );
    aws_lc_p521_ecdh_bench_step.dependOn(&aws_lc_p521_ecdh_bench.step);

    const p384_ecdh_bench = b.addExecutable(.{
        .name = "vail-bench-p384-ecdh",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p384_ecdh.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p384_ecdh_bench = b.addRunArtifact(p384_ecdh_bench);
    const p384_ecdh_bench_step = b.step(
        "bench-p384-ecdh",
        "Benchmark pure-Zig P-384 public-key recovery and ECDH",
    );
    p384_ecdh_bench_step.dependOn(&run_p384_ecdh_bench.step);

    const aws_lc_p384_ecdh_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p384-ecdh-bench",
    });
    const aws_lc_p384_ecdh_bench_step = b.step(
        "bench-aws-lc-p384-ecdh",
        "Benchmark test-only AWS-LC P-384 public-key recovery and ECDH",
    );
    aws_lc_p384_ecdh_bench_step.dependOn(&aws_lc_p384_ecdh_bench.step);

    const p256_ecdh_bench = b.addExecutable(.{
        .name = "vail-bench-p256-ecdh",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p256_ecdh.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p256_ecdh_bench = b.addRunArtifact(p256_ecdh_bench);
    const p256_ecdh_bench_step = b.step(
        "bench-p256-ecdh",
        "Benchmark pure-Zig P-256 public-key recovery and ECDH",
    );
    p256_ecdh_bench_step.dependOn(&run_p256_ecdh_bench.step);

    const aws_lc_p256_ecdh_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p256-ecdh-bench",
    });
    const aws_lc_p256_ecdh_bench_step = b.step(
        "bench-aws-lc-p256-ecdh",
        "Benchmark test-only AWS-LC P-256 public-key recovery and ECDH",
    );
    aws_lc_p256_ecdh_bench_step.dependOn(&aws_lc_p256_ecdh_bench.step);

    const aws_lc_p521_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p521-bench",
    });
    const aws_lc_p521_bench_step = b.step(
        "bench-aws-lc-p521",
        "Benchmark test-only AWS-LC P-521 ECDSA verification",
    );
    aws_lc_p521_bench_step.dependOn(&aws_lc_p521_bench.step);

    const aws_lc_p521_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p521-sign-bench",
    });
    const aws_lc_p521_sign_bench_step = b.step(
        "bench-aws-lc-p521-sign",
        "Benchmark test-only AWS-LC P-521 ECDSA signing",
    );
    aws_lc_p521_sign_bench_step.dependOn(&aws_lc_p521_sign_bench.step);

    const p384_verify_bench = b.addExecutable(.{
        .name = "vail-bench-p384-verify",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p384_verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p384_verify_bench = b.addRunArtifact(p384_verify_bench);
    const p384_verify_bench_step = b.step(
        "bench-p384-verify",
        "Benchmark pure-Zig P-384 ECDSA verification and signing",
    );
    p384_verify_bench_step.dependOn(&run_p384_verify_bench.step);

    const p384_one_shot_bench = b.addExecutable(.{
        .name = "vail-bench-p384-one-shot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p384_one_shot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p384_one_shot_bench = b.addRunArtifact(p384_one_shot_bench);
    const p384_one_shot_bench_step = b.step(
        "bench-p384-one-shot",
        "Benchmark pure-Zig one-shot P-384 ECDSA verification",
    );
    p384_one_shot_bench_step.dependOn(&run_p384_one_shot_bench.step);

    const p384_sign_bench = b.addExecutable(.{
        .name = "vail-bench-p384-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p384_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p384_sign_bench = b.addRunArtifact(p384_sign_bench);
    const p384_sign_bench_step = b.step(
        "bench-p384-sign",
        "Benchmark pure-Zig P-384 ECDSA signing",
    );
    p384_sign_bench_step.dependOn(&run_p384_sign_bench.step);

    const aws_lc_p384_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p384-bench",
    });
    const aws_lc_p384_bench_step = b.step(
        "bench-aws-lc-p384",
        "Benchmark test-only AWS-LC P-384 ECDSA verification and signing",
    );
    aws_lc_p384_bench_step.dependOn(&aws_lc_p384_bench.step);

    const aws_lc_p384_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p384-sign-bench",
    });
    const aws_lc_p384_sign_bench_step = b.step(
        "bench-aws-lc-p384-sign",
        "Benchmark test-only AWS-LC P-384 ECDSA signing",
    );
    aws_lc_p384_sign_bench_step.dependOn(&aws_lc_p384_sign_bench.step);

    const x25519_bench = b.addExecutable(.{
        .name = "vail-bench-x25519",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/x25519.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_x25519_bench = b.addRunArtifact(x25519_bench);
    const x25519_bench_step = b.step(
        "bench-x25519",
        "Benchmark Vail and Zig standard-library X25519 primitives",
    );
    x25519_bench_step.dependOn(&run_x25519_bench.step);

    const p256_verify_bench = b.addExecutable(.{
        .name = "vail-bench-p256-verify",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p256_verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p256_verify_bench = b.addRunArtifact(p256_verify_bench);
    const p256_verify_bench_step = b.step(
        "bench-p256-verify",
        "Benchmark Zig P-256 ECDSA verification components",
    );
    p256_verify_bench_step.dependOn(&run_p256_verify_bench.step);

    const p256_one_shot_bench = b.addExecutable(.{
        .name = "vail-bench-p256-one-shot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p256_one_shot.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p256_one_shot_bench = b.addRunArtifact(p256_one_shot_bench);
    const p256_one_shot_bench_step = b.step(
        "bench-p256-one-shot",
        "Benchmark pure-Zig one-shot P-256 ECDSA verification",
    );
    p256_one_shot_bench_step.dependOn(&run_p256_one_shot_bench.step);

    const p256_prepared_bench = b.addExecutable(.{
        .name = "vail-bench-p256-prepared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p256_prepared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p256_prepared_bench = b.addRunArtifact(p256_prepared_bench);
    const p256_prepared_bench_step = b.step(
        "bench-p256-prepared",
        "Benchmark prepared pure-Zig P-256 ECDSA verification",
    );
    p256_prepared_bench_step.dependOn(&run_p256_prepared_bench.step);

    const p256_sign_bench = b.addExecutable(.{
        .name = "vail-bench-p256-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/p256_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_p256_sign_bench = b.addRunArtifact(p256_sign_bench);
    const p256_sign_bench_step = b.step(
        "bench-p256-sign",
        "Benchmark pure-Zig P-256 ECDSA signing",
    );
    p256_sign_bench_step.dependOn(&run_p256_sign_bench.step);

    const aws_lc_p256_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p256-sign-bench",
    });
    const aws_lc_p256_sign_bench_step = b.step(
        "bench-aws-lc-p256-sign",
        "Benchmark test-only AWS-LC P-256 ECDSA signing",
    );
    aws_lc_p256_sign_bench_step.dependOn(&aws_lc_p256_sign_bench.step);

    const aws_lc_p256_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-p256-bench",
    });
    const aws_lc_p256_bench_step = b.step(
        "bench-aws-lc-p256",
        "Benchmark test-only AWS-LC P-256 ECDSA verification",
    );
    aws_lc_p256_bench_step.dependOn(&aws_lc_p256_bench.step);

    const ed25519_bench = b.addExecutable(.{
        .name = "vail-bench-ed25519",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/ed25519.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_ed25519_bench = b.addRunArtifact(ed25519_bench);
    const ed25519_bench_step = b.step(
        "bench-ed25519",
        "Benchmark Zig std and Vail Ed25519 primitives",
    );
    ed25519_bench_step.dependOn(&run_ed25519_bench.step);

    const ed25519_keygen_bench = b.addExecutable(.{
        .name = "vail-bench-ed25519-keygen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/ed25519_keygen.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_ed25519_keygen_bench = b.addRunArtifact(ed25519_keygen_bench);
    const ed25519_keygen_bench_step = b.step(
        "bench-ed25519-keygen",
        "Benchmark Vail Ed25519 deterministic key generation",
    );
    ed25519_keygen_bench_step.dependOn(&run_ed25519_keygen_bench.step);

    const aws_lc_ed25519_keygen_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-ed25519-keygen-bench",
    });
    const aws_lc_ed25519_keygen_bench_step = b.step(
        "bench-aws-lc-ed25519-keygen",
        "Benchmark test-only AWS-LC Ed25519 key generation",
    );
    aws_lc_ed25519_keygen_bench_step.dependOn(
        &aws_lc_ed25519_keygen_bench.step,
    );

    const ed25519_verify_bench = b.addExecutable(.{
        .name = "vail-bench-ed25519-verify",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/ed25519_verify.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_ed25519_verify_bench = b.addRunArtifact(ed25519_verify_bench);
    const ed25519_verify_bench_step = b.step(
        "bench-ed25519-verify",
        "Benchmark pure-Zig one-shot Ed25519 verification",
    );
    ed25519_verify_bench_step.dependOn(&run_ed25519_verify_bench.step);

    const aws_lc_ed25519_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-ed25519-bench",
    });
    const aws_lc_ed25519_bench_step = b.step(
        "bench-aws-lc-ed25519",
        "Benchmark test-only AWS-LC Ed25519 primitives",
    );
    aws_lc_ed25519_bench_step.dependOn(&aws_lc_ed25519_bench.step);

    const aws_lc_ed25519_verify_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-ed25519-verify-bench",
    });
    const aws_lc_ed25519_verify_bench_step = b.step(
        "bench-aws-lc-ed25519-verify",
        "Benchmark test-only AWS-LC one-shot Ed25519 verification",
    );
    aws_lc_ed25519_verify_bench_step.dependOn(
        &aws_lc_ed25519_verify_bench.step,
    );

    const ed25519_sign_bench = b.addExecutable(.{
        .name = "vail-bench-ed25519-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/ed25519_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_ed25519_sign_bench = b.addRunArtifact(ed25519_sign_bench);
    const ed25519_sign_bench_step = b.step(
        "bench-ed25519-sign",
        "Benchmark pure-Zig Ed25519 signing",
    );
    ed25519_sign_bench_step.dependOn(&run_ed25519_sign_bench.step);

    const aws_lc_ed25519_sign_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-ed25519-sign-bench",
    });
    const aws_lc_ed25519_sign_bench_step = b.step(
        "bench-aws-lc-ed25519-sign",
        "Benchmark test-only AWS-LC Ed25519 signing",
    );
    aws_lc_ed25519_sign_bench_step.dependOn(
        &aws_lc_ed25519_sign_bench.step,
    );

    const aws_lc_x25519_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-x25519-bench",
    });
    const aws_lc_x25519_bench_step = b.step(
        "bench-aws-lc-x25519",
        "Benchmark test-only AWS-LC X25519 primitives",
    );
    aws_lc_x25519_bench_step.dependOn(&aws_lc_x25519_bench.step);

    const x25519_shared_bench = b.addExecutable(.{
        .name = "vail-bench-x25519-shared",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/x25519_shared.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_x25519_shared_bench = b.addRunArtifact(x25519_shared_bench);
    const x25519_shared_bench_step = b.step(
        "bench-x25519-shared",
        "Benchmark pure-Zig X25519 arbitrary-point multiplication",
    );
    x25519_shared_bench_step.dependOn(&run_x25519_shared_bench.step);

    const aws_lc_x25519_shared_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-x25519-shared-bench",
    });
    const aws_lc_x25519_shared_bench_step = b.step(
        "bench-aws-lc-x25519-shared",
        "Benchmark test-only AWS-LC X25519 arbitrary-point multiplication",
    );
    aws_lc_x25519_shared_bench_step.dependOn(
        &aws_lc_x25519_shared_bench.step,
    );

    const hkdf_sha256_bench = b.addExecutable(.{
        .name = "vail-bench-hkdf-sha256",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/hkdf_sha256.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_hkdf_sha256_bench = b.addRunArtifact(hkdf_sha256_bench);
    const hkdf_sha256_bench_step = b.step(
        "bench-hkdf-sha256",
        "Benchmark prepared pure-Zig three-label HKDF-SHA-256",
    );
    hkdf_sha256_bench_step.dependOn(&run_hkdf_sha256_bench.step);

    const hkdf_sha256_std_bench = b.addExecutable(.{
        .name = "vail-bench-hkdf-sha256-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/hkdf_sha256_std.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_hkdf_sha256_std_bench = b.addRunArtifact(
        hkdf_sha256_std_bench,
    );
    const hkdf_sha256_std_bench_step = b.step(
        "bench-hkdf-sha256-std",
        "Benchmark Zig std three-label HKDF-SHA-256",
    );
    hkdf_sha256_std_bench_step.dependOn(
        &run_hkdf_sha256_std_bench.step,
    );

    const aws_lc_hkdf_sha256_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-hkdf-sha256-bench",
    });
    const aws_lc_hkdf_sha256_bench_step = b.step(
        "bench-aws-lc-hkdf-sha256",
        "Benchmark test-only AWS-LC three-label HKDF-SHA-256",
    );
    aws_lc_hkdf_sha256_bench_step.dependOn(
        &aws_lc_hkdf_sha256_bench.step,
    );

    const hkdf_sha384_bench = b.addExecutable(.{
        .name = "vail-bench-hkdf-sha384",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/hkdf_sha384.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_hkdf_sha384_bench = b.addRunArtifact(hkdf_sha384_bench);
    const hkdf_sha384_bench_step = b.step(
        "bench-hkdf-sha384",
        "Benchmark prepared pure-Zig three-label HKDF-SHA-384",
    );
    hkdf_sha384_bench_step.dependOn(&run_hkdf_sha384_bench.step);

    const hkdf_sha384_std_bench = b.addExecutable(.{
        .name = "vail-bench-hkdf-sha384-std",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/hkdf_sha384_std.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_hkdf_sha384_std_bench = b.addRunArtifact(
        hkdf_sha384_std_bench,
    );
    const hkdf_sha384_std_bench_step = b.step(
        "bench-hkdf-sha384-std",
        "Benchmark Zig std three-label HKDF-SHA-384",
    );
    hkdf_sha384_std_bench_step.dependOn(
        &run_hkdf_sha384_std_bench.step,
    );

    const aws_lc_hkdf_sha384_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-hkdf-sha384-bench",
    });
    const aws_lc_hkdf_sha384_bench_step = b.step(
        "bench-aws-lc-hkdf-sha384",
        "Benchmark test-only AWS-LC three-label HKDF-SHA-384",
    );
    aws_lc_hkdf_sha384_bench_step.dependOn(
        &aws_lc_hkdf_sha384_bench.step,
    );

    const sha512_primitives_bench = b.addExecutable(.{
        .name = "vail-bench-sha512-primitives",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/sha512_primitives.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_sha512_primitives_bench = b.addRunArtifact(
        sha512_primitives_bench,
    );
    const sha512_primitives_bench_step = b.step(
        "bench-sha512-primitives",
        "Benchmark pure-Zig SHA-384/SHA-512 digest and HMAC primitives",
    );
    sha512_primitives_bench_step.dependOn(
        &run_sha512_primitives_bench.step,
    );

    const aws_lc_sha512_primitives_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-sha512-primitives-bench",
    });
    const aws_lc_sha512_primitives_bench_step = b.step(
        "bench-aws-lc-sha512-primitives",
        "Benchmark test-only AWS-LC SHA-384/SHA-512 digest and HMAC primitives",
    );
    aws_lc_sha512_primitives_bench_step.dependOn(
        &aws_lc_sha512_primitives_bench.step,
    );

    const sha256_primitives_bench = b.addExecutable(.{
        .name = "vail-bench-sha256-primitives",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/sha256_primitives.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_sha256_primitives_bench = b.addRunArtifact(
        sha256_primitives_bench,
    );
    const sha256_primitives_bench_step = b.step(
        "bench-sha256-primitives",
        "Benchmark pure-Zig SHA-256 digest and HMAC primitives",
    );
    sha256_primitives_bench_step.dependOn(
        &run_sha256_primitives_bench.step,
    );

    const aws_lc_sha256_primitives_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-sha256-primitives-bench",
    });
    const aws_lc_sha256_primitives_bench_step = b.step(
        "bench-aws-lc-sha256-primitives",
        "Benchmark test-only AWS-LC SHA-256 digest and HMAC primitives",
    );
    aws_lc_sha256_primitives_bench_step.dependOn(
        &aws_lc_sha256_primitives_bench.step,
    );

    mldsa_benchmarks.add(b, vail, target, optimize);

    const x25519_public_bench = b.addExecutable(.{
        .name = "vail-bench-x25519-public",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/x25519_public.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_x25519_public_bench = b.addRunArtifact(x25519_public_bench);
    const x25519_public_bench_step = b.step(
        "bench-x25519-public",
        "Benchmark pure-Zig X25519 public-key recovery",
    );
    x25519_public_bench_step.dependOn(&run_x25519_public_bench.step);

    const aws_lc_x25519_public_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-aws-lc-x25519-public-bench",
    });
    const aws_lc_x25519_public_bench_step = b.step(
        "bench-aws-lc-x25519-public",
        "Benchmark test-only AWS-LC X25519 public-key recovery",
    );
    aws_lc_x25519_public_bench_step.dependOn(
        &aws_lc_x25519_public_bench.step,
    );

    mlkem_benchmarks.add(b, vail, target, optimize);

    const rsa_sha3_sign = b.addExecutable(.{
        .name = "vail-rsa-sha3-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/rsa_sha3_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rsa_sha3_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_rsa_sha3_sign.addArg(
        "work=$(mktemp -d /tmp/vail-rsa-sha3.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -in src/crypto/testdata/rsa_signing_cert.pem -pubkey -noout >\"$work/public.pem\"; " ++
            "$1 \"$work\"; " ++
            "for digest in sha3-224 sha3-256 sha3-384 sha3-512; do " ++
            "printf 'Vail pure Zig RSA SHA3 signing oracle' | openssl dgst -\"$digest\" -verify \"$work/public.pem\" -signature \"$work/pss-$digest.sig\" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest >/dev/null || exit 1; " ++
            "printf 'Vail pure Zig RSA SHA3 signing oracle' | openssl dgst -\"$digest\" -verify \"$work/public.pem\" -signature \"$work/pkcs1-$digest.sig\" >/dev/null || exit 1; " ++
            "done",
    );
    check_rsa_sha3_sign.addArg("bash");
    check_rsa_sha3_sign.addArtifactArg(rsa_sha3_sign);
    const interop_rsa_sha3_sign_step = b.step(
        "interop-openssl-rsa-sha3-sign",
        "Verify pure-Zig RSA SHA3 signatures with OpenSSL",
    );
    interop_rsa_sha3_sign_step.dependOn(&check_rsa_sha3_sign.step);

    const rsa_sha512_truncated_sign = b.addExecutable(.{
        .name = "vail-rsa-sha512-truncated-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/rsa_sha512_truncated_sign.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rsa_sha512_truncated_sign = b.addSystemCommand(&.{
        "bash",
        "-c",
    });
    check_rsa_sha512_truncated_sign.addArg(
        "work=$(mktemp -d /tmp/vail-rsa-sha512-truncated.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -in src/crypto/testdata/rsa_signing_cert.pem -pubkey -noout >\"$work/public.pem\"; " ++
            "$1 \"$work\"; " ++
            "for digest in sha512-224 sha512-256; do " ++
            "printf 'Vail pure Zig RSA SHA-512 truncated signing oracle' | openssl dgst -\"$digest\" -verify \"$work/public.pem\" -signature \"$work/pss-$digest.sig\" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:\"$digest\" >/dev/null || exit 1; " ++
            "printf 'Vail pure Zig RSA SHA-512 truncated signing oracle' | openssl dgst -\"$digest\" -verify \"$work/public.pem\" -signature \"$work/pkcs1-$digest.sig\" >/dev/null || exit 1; " ++
            "done",
    );
    check_rsa_sha512_truncated_sign.addArg("bash");
    check_rsa_sha512_truncated_sign.addArtifactArg(
        rsa_sha512_truncated_sign,
    );
    const interop_rsa_sha512_truncated_sign_step = b.step(
        "interop-openssl-rsa-sha512-truncated-sign",
        "Verify pure-Zig RSA SHA-512/224 and SHA-512/256 signatures with OpenSSL",
    );
    interop_rsa_sha512_truncated_sign_step.dependOn(
        &check_rsa_sha512_truncated_sign.step,
    );

    const rsa_shake_sign = b.addExecutable(.{
        .name = "vail-rsa-shake-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/rsa_shake_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rsa_shake_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_rsa_shake_sign.addArg(
        "work=$(mktemp -d /tmp/vail-rsa-shake.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -in src/crypto/testdata/rsa_signing_cert.pem -pubkey -noout >\"$work/public.pem\"; " ++
            "$1 \"$work\"; " ++
            "for digest in shake128 shake256; do " ++
            "openssl pkeyutl -encrypt -pubin -inkey \"$work/public.pem\" -pkeyopt rsa_padding_mode:none -in \"$work/pss-$digest.sig\" -out \"$work/$digest.em\" || exit 1; " ++
            "xxd -r -p \"tools/interop/testdata/rsa-pss-$digest.em.hex\" >\"$work/$digest.expected\"; " ++
            "cmp \"$work/$digest.expected\" \"$work/$digest.em\" || exit 1; " ++
            "done",
    );
    check_rsa_shake_sign.addArg("bash");
    check_rsa_shake_sign.addArtifactArg(rsa_shake_sign);
    const interop_rsa_shake_sign_step = b.step(
        "interop-openssl-rsa-shake-sign",
        "Check pure-Zig RFC 8692 RSA-PSS-SHAKE signatures with OpenSSL raw RSA",
    );
    interop_rsa_shake_sign_step.dependOn(&check_rsa_shake_sign.step);

    const p521_sign = b.addExecutable(.{
        .name = "vail-p521-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/p521_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_p521_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_p521_sign.addArg(
        "work=$(mktemp -d /tmp/vail-p521-sign.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp521r1 -out \"$work/key.pem\"; " ++
            "openssl pkcs8 -topk8 -nocrypt -in \"$work/key.pem\" -outform DER -out \"$work/key.der\"; " ++
            "key_hex=$(xxd -p -c 100000 \"$work/key.der\"); " ++
            "$1 \"$work\" \"$key_hex\"; " ++
            "openssl dgst -sha512 -verify \"$work/public.der\" -keyform DER " ++
            "-signature \"$work/signature.der\" \"$work/message.bin\" >/dev/null",
    );
    check_p521_sign.addArg("bash");
    check_p521_sign.addArtifactArg(p521_sign);
    const interop_p521_sign_step = b.step(
        "interop-openssl-p521-sign",
        "Verify a pure-Zig P-521 signature with OpenSSL",
    );
    interop_p521_sign_step.dependOn(&check_p521_sign.step);

    const p256_sign = b.addExecutable(.{
        .name = "vail-p256-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/p256_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_p256_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_p256_sign.addArg(
        "work=$(mktemp -d /tmp/vail-p256-sign.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "$1 \"$work\"; " ++
            "openssl dgst -sha256 -verify \"$work/public.der\" -keyform DER " ++
            "-signature \"$work/signature.der\" \"$work/message.bin\" >/dev/null",
    );
    check_p256_sign.addArg("bash");
    check_p256_sign.addArtifactArg(p256_sign);
    const interop_p256_sign_step = b.step(
        "interop-openssl-p256-sign",
        "Verify a pure-Zig P-256 signature with OpenSSL",
    );
    interop_p256_sign_step.dependOn(&check_p256_sign.step);

    const p384_sign = b.addExecutable(.{
        .name = "vail-p384-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/p384_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_p384_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_p384_sign.addArg(
        "work=$(mktemp -d /tmp/vail-p384-sign.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "$1 \"$work\"; " ++
            "openssl dgst -sha384 -verify \"$work/public.der\" -keyform DER " ++
            "-signature \"$work/signature.der\" \"$work/message.bin\" >/dev/null",
    );
    check_p384_sign.addArg("bash");
    check_p384_sign.addArtifactArg(p384_sign);
    const interop_p384_sign_step = b.step(
        "interop-openssl-p384-sign",
        "Verify a pure-Zig P-384 signature with OpenSSL",
    );
    interop_p384_sign_step.dependOn(&check_p384_sign.step);

    const ed25519_sign = b.addExecutable(.{
        .name = "vail-ed25519-sign",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/ed25519_sign.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_ed25519_sign = b.addSystemCommand(&.{ "bash", "-c" });
    check_ed25519_sign.addArg(
        "work=$(mktemp -d /tmp/vail-ed25519-sign.XXXXXX); " ++
            "trap 'rm -rf \"$work\"' EXIT; " ++
            "$1 \"$work\"; " ++
            "openssl pkeyutl -verify -pubin -keyform DER " ++
            "-inkey \"$work/public.der\" -rawin " ++
            "-in \"$work/message.bin\" " ++
            "-sigfile \"$work/signature.bin\" >/dev/null",
    );
    check_ed25519_sign.addArg("bash");
    check_ed25519_sign.addArtifactArg(ed25519_sign);
    const interop_ed25519_sign_step = b.step(
        "interop-openssl-ed25519-sign",
        "Verify a pure-Zig Ed25519 signature with OpenSSL",
    );
    interop_ed25519_sign_step.dependOn(&check_ed25519_sign.step);

    const tls_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls-server-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_server_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_handshake_bench = b.addRunArtifact(tls_handshake_bench);
    const tls_handshake_bench_step = b.step(
        "bench-tls-server-handshake",
        "Benchmark managed TLS 1.3 server handshake flights",
    );
    tls_handshake_bench_step.dependOn(&run_tls_handshake_bench.step);

    const tls_server_connection_bench = b.addExecutable(.{
        .name = "vail-bench-tls-server-connection",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_server_connection.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_server_connection_bench = b.addRunArtifact(
        tls_server_connection_bench,
    );
    const tls_server_connection_bench_step = b.step(
        "bench-tls-server-connection",
        "Benchmark the managed TLS 1.3 server connection first flight",
    );
    tls_server_connection_bench_step.dependOn(
        &run_tls_server_connection_bench.step,
    );

    const rustls_tls_server_connection_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_server/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-server-bench",
    });
    const rustls_tls_server_connection_bench_step = b.step(
        "bench-rustls-tls-server-connection",
        "Benchmark the test-only rustls/AWS-LC TLS 1.3 server first flight",
    );
    rustls_tls_server_connection_bench_step.dependOn(
        &rustls_tls_server_connection_bench.step,
    );

    const rustls_tls_server_x509_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_server/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-server-bench",
        "--",
        "x509",
    });
    const rustls_tls_server_x509_bench_step = b.step(
        "bench-rustls-tls-server-x509",
        "Benchmark rustls/AWS-LC TLS 1.3 server with an X.509 identity",
    );
    rustls_tls_server_x509_bench_step.dependOn(
        &rustls_tls_server_x509_bench.step,
    );

    const tls_client_connection_bench = b.addExecutable(.{
        .name = "vail-bench-tls-client-connection",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_client_connection.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_client_connection_bench = b.addRunArtifact(
        tls_client_connection_bench,
    );
    const tls_client_connection_bench_step = b.step(
        "bench-tls-client-connection",
        "Benchmark the TLS 1.3 client through its encrypted Finished",
    );
    tls_client_connection_bench_step.dependOn(
        &run_tls_client_connection_bench.step,
    );

    const rustls_tls_client_connection_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-client-bench",
    });
    const rustls_tls_client_connection_bench_step = b.step(
        "bench-rustls-tls-client-connection",
        "Benchmark the test-only rustls/AWS-LC TLS 1.3 client handshake",
    );
    rustls_tls_client_connection_bench_step.dependOn(
        &rustls_tls_client_connection_bench.step,
    );

    const rustls_tls_client_x509_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-client-bench",
        "--",
        "x509",
    });
    const rustls_tls_client_x509_bench_step = b.step(
        "bench-rustls-tls-client-x509",
        "Benchmark rustls/AWS-LC TLS 1.3 client X.509 validation",
    );
    rustls_tls_client_x509_bench_step.dependOn(
        &rustls_tls_client_x509_bench.step,
    );

    const tls_client_x509_bench = b.addExecutable(.{
        .name = "vail-bench-tls-client-x509",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_client_x509.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_client_x509_bench = b.addRunArtifact(
        tls_client_x509_bench,
    );
    const tls_client_x509_bench_step = b.step(
        "bench-tls-client-x509",
        "Benchmark TLS 1.3 client handshake with X.509 path validation",
    );
    tls_client_x509_bench_step.dependOn(
        &run_tls_client_x509_bench.step,
    );

    const tls_server_x509_bench = b.addExecutable(.{
        .name = "vail-bench-tls-server-x509",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_server_x509.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_server_x509_bench = b.addRunArtifact(
        tls_server_x509_bench,
    );
    const tls_server_x509_bench_step = b.step(
        "bench-tls-server-x509",
        "Benchmark TLS 1.3 server first flight with an X.509 identity",
    );
    tls_server_x509_bench_step.dependOn(
        &run_tls_server_x509_bench.step,
    );

    const tls_x509_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls-x509-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_handshake_x509.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_x509_handshake_bench = b.addRunArtifact(
        tls_x509_handshake_bench,
    );
    const tls_x509_handshake_bench_step = b.step(
        "bench-tls-x509-handshake",
        "Benchmark a complete in-process TLS 1.3 X.509 handshake",
    );
    tls_x509_handshake_bench_step.dependOn(
        &run_tls_x509_handshake_bench.step,
    );

    const rustls_tls_x509_handshake_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-client-bench",
        "--",
        "pair-x509",
    });
    const rustls_tls_x509_handshake_bench_step = b.step(
        "bench-rustls-tls-x509-handshake",
        "Benchmark a complete rustls/AWS-LC TLS 1.3 X.509 handshake",
    );
    rustls_tls_x509_handshake_bench_step.dependOn(
        &rustls_tls_x509_handshake_bench.step,
    );

    const versioned_tls_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-versioned-tls-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/versioned_tls_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_versioned_tls_handshake_bench = b.addRunArtifact(
        versioned_tls_handshake_bench,
    );
    const versioned_tls_handshake_bench_step = b.step(
        "bench-versioned-tls-handshake",
        "Benchmark a complete dual-version in-process TLS 1.3 handshake",
    );
    versioned_tls_handshake_bench_step.dependOn(
        &run_versioned_tls_handshake_bench.step,
    );

    const rustls_versioned_tls_handshake_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-client-bench",
        "--",
        "pair-x509-auto",
    });
    const rustls_versioned_tls_handshake_bench_step = b.step(
        "bench-rustls-versioned-tls-handshake",
        "Benchmark a complete rustls/AWS-LC dual-version TLS 1.3 handshake",
    );
    rustls_versioned_tls_handshake_bench_step.dependOn(
        &rustls_versioned_tls_handshake_bench.step,
    );

    const quic_tls_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-quic-tls-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/quic/quic_tls_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_quic_tls_handshake_bench = b.addRunArtifact(
        quic_tls_handshake_bench,
    );
    const quic_tls_handshake_bench_step = b.step(
        "bench-quic-tls-handshake",
        "Benchmark a complete in-process QUIC TLS 1.3 X.509 handshake",
    );
    quic_tls_handshake_bench_step.dependOn(
        &run_quic_tls_handshake_bench.step,
    );

    const rustls_quic_tls_handshake_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-quic-handshake-bench",
    });
    const rustls_quic_tls_handshake_bench_step = b.step(
        "bench-rustls-quic-tls-handshake",
        "Benchmark a complete rustls/AWS-LC QUIC TLS 1.3 X.509 handshake",
    );
    rustls_quic_tls_handshake_bench_step.dependOn(
        &rustls_quic_tls_handshake_bench.step,
    );

    const quic_tls_resumption_bench = b.addExecutable(.{
        .name = "vail-bench-quic-tls-resumption",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/quic/quic_tls_resumption.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_quic_tls_resumption_bench = b.addRunArtifact(
        quic_tls_resumption_bench,
    );
    const quic_tls_resumption_bench_step = b.step(
        "bench-quic-tls-resumption",
        "Benchmark QUIC TLS 1.3 PSK-DHE resumption with ticket rollover",
    );
    quic_tls_resumption_bench_step.dependOn(
        &run_quic_tls_resumption_bench.step,
    );

    const rustls_quic_tls_resumption_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-quic-handshake-bench",
        "--",
        "resume",
    });
    const rustls_quic_tls_resumption_bench_step = b.step(
        "bench-rustls-quic-tls-resumption",
        "Benchmark rustls/AWS-LC QUIC TLS 1.3 resumption with ticket rollover",
    );
    rustls_quic_tls_resumption_bench_step.dependOn(
        &rustls_quic_tls_resumption_bench.step,
    );

    const run_quic_tls_0rtt_bench = b.addRunArtifact(
        quic_tls_resumption_bench,
    );
    run_quic_tls_0rtt_bench.addArg("early");
    const quic_tls_0rtt_bench_step = b.step(
        "bench-quic-tls-0rtt",
        "Benchmark accepted QUIC TLS 1.3 0-RTT with ticket rollover",
    );
    quic_tls_0rtt_bench_step.dependOn(&run_quic_tls_0rtt_bench.step);

    const rustls_quic_tls_0rtt_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-quic-handshake-bench",
        "--",
        "early",
    });
    const rustls_quic_tls_0rtt_bench_step = b.step(
        "bench-rustls-quic-tls-0rtt",
        "Benchmark rustls/AWS-LC accepted QUIC TLS 1.3 0-RTT",
    );
    rustls_quic_tls_0rtt_bench_step.dependOn(
        &rustls_quic_tls_0rtt_bench.step,
    );

    const tls_resumption_bench = b.addExecutable(.{
        .name = "vail-bench-tls-resumption",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls_resumption.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls_resumption_bench = b.addRunArtifact(tls_resumption_bench);
    const tls_resumption_bench_step = b.step(
        "bench-tls-resumption",
        "Benchmark TLS 1.3 PSK-DHE resumption with ticket rollover",
    );
    tls_resumption_bench_step.dependOn(&run_tls_resumption_bench.step);

    const rustls_tls_resumption_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls13-client-bench",
        "--",
        "resume",
    });
    const rustls_tls_resumption_bench_step = b.step(
        "bench-rustls-tls-resumption",
        "Benchmark rustls/AWS-LC TLS 1.3 resumption with ticket rollover",
    );
    rustls_tls_resumption_bench_step.dependOn(
        &rustls_tls_resumption_bench.step,
    );

    const x509_path_bench = b.addExecutable(.{
        .name = "vail-bench-x509-path",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/x509/x509_path.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_x509_path_bench = b.addRunArtifact(x509_path_bench);
    const x509_path_bench_step = b.step(
        "bench-x509-path",
        "Benchmark X.509 path construction, backtracking, and OCSP",
    );
    x509_path_bench_step.dependOn(&run_x509_path_bench.step);

    const certificate_compression_bench = b.addExecutable(.{
        .name = "vail-bench-certificate-compression",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/certificate_compression.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_certificate_compression_bench = b.addRunArtifact(
        certificate_compression_bench,
    );
    const certificate_compression_bench_step = b.step(
        "bench-certificate-compression",
        "Benchmark RFC 8879 zlib, Brotli, and Zstandard certificate compression",
    );
    certificate_compression_bench_step.dependOn(
        &run_certificate_compression_bench.step,
    );

    const rsa_pss_bench = b.addExecutable(.{
        .name = "vail-bench-rsa-pss",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/rsa_pss.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_rsa_pss_bench = b.addRunArtifact(rsa_pss_bench);
    const rsa_pss_bench_step = b.step(
        "bench-rsa-pss",
        "Benchmark pure-Zig RSA-2048-PSS signing",
    );
    rsa_pss_bench_step.dependOn(&run_rsa_pss_bench.step);

    const hpke_bench = b.addExecutable(.{
        .name = "vail-bench-hpke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/primitives/hpke.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_hpke_bench = b.addRunArtifact(hpke_bench);
    const hpke_bench_step = b.step(
        "bench-hpke",
        "Benchmark RFC 9180 base-mode setup and traffic",
    );
    hpke_bench_step.dependOn(&run_hpke_bench.step);

    const ech_bench = b.addExecutable(.{
        .name = "vail-bench-ech",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/ech.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_ech_bench = b.addRunArtifact(ech_bench);
    const ech_bench_step = b.step(
        "bench-ech",
        "Benchmark RFC 9849 ClientHello protection",
    );
    ech_bench_step.dependOn(&run_ech_bench.step);

    const tls12_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-server-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls12_server_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls12_handshake_bench = b.addRunArtifact(
        tls12_handshake_bench,
    );
    const tls12_handshake_bench_step = b.step(
        "bench-tls12-server-handshake",
        "Benchmark TLS 1.2 P-256/RSA-PSS server flights",
    );
    tls12_handshake_bench_step.dependOn(
        &run_tls12_handshake_bench.step,
    );

    const tls12_client_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-client-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls12_client_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls12_client_handshake_bench = b.addRunArtifact(
        tls12_client_handshake_bench,
    );
    const tls12_client_handshake_bench_step = b.step(
        "bench-tls12-client-handshake",
        "Benchmark authenticated TLS 1.2 client flights",
    );
    tls12_client_handshake_bench_step.dependOn(
        &run_tls12_client_handshake_bench.step,
    );

    const tls12_full_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls12_handshake.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls12_full_handshake_bench = b.addRunArtifact(
        tls12_full_handshake_bench,
    );
    const tls12_full_handshake_bench_step = b.step(
        "bench-tls12-handshake",
        "Benchmark a complete in-process TLS 1.2 handshake",
    );
    tls12_full_handshake_bench_step.dependOn(
        &run_tls12_full_handshake_bench.step,
    );
    const run_tls12_full_handshake_pss_bench = b.addRunArtifact(
        tls12_full_handshake_bench,
    );
    run_tls12_full_handshake_pss_bench.addArg("pss");
    const tls12_full_handshake_pss_bench_step = b.step(
        "bench-tls12-handshake-pss",
        "Benchmark a complete in-process RSA-PSS TLS 1.2 handshake",
    );
    tls12_full_handshake_pss_bench_step.dependOn(
        &run_tls12_full_handshake_pss_bench.step,
    );
    const run_tls12_full_handshake_aes256_bench = b.addRunArtifact(
        tls12_full_handshake_bench,
    );
    run_tls12_full_handshake_aes256_bench.addArg("aes256");
    const tls12_full_handshake_aes256_bench_step = b.step(
        "bench-tls12-handshake-aes256",
        "Benchmark a complete AES-256/SHA-384 TLS 1.2 handshake",
    );
    tls12_full_handshake_aes256_bench_step.dependOn(
        &run_tls12_full_handshake_aes256_bench.step,
    );

    const rustls_tls12_full_handshake_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls12-handshake-bench",
    });
    const rustls_tls12_full_handshake_bench_step = b.step(
        "bench-rustls-tls12-handshake",
        "Benchmark a complete rustls/AWS-LC TLS 1.2 handshake",
    );
    rustls_tls12_full_handshake_bench_step.dependOn(
        &rustls_tls12_full_handshake_bench.step,
    );
    const rustls_tls12_full_handshake_pss_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls12-handshake-bench",
        "--",
        "pss",
    });
    const rustls_tls12_full_handshake_pss_bench_step = b.step(
        "bench-rustls-tls12-handshake-pss",
        "Benchmark a complete rustls/AWS-LC RSA-PSS TLS 1.2 handshake",
    );
    rustls_tls12_full_handshake_pss_bench_step.dependOn(
        &rustls_tls12_full_handshake_pss_bench.step,
    );
    const rustls_tls12_full_handshake_aes256_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls12-handshake-bench",
        "--",
        "aes256",
    });
    const rustls_tls12_full_handshake_aes256_bench_step = b.step(
        "bench-rustls-tls12-handshake-aes256",
        "Benchmark a complete rustls/AWS-LC AES-256/SHA-384 TLS 1.2 handshake",
    );
    rustls_tls12_full_handshake_aes256_bench_step.dependOn(
        &rustls_tls12_full_handshake_aes256_bench.step,
    );

    const tls12_resumption_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-resumption",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls/tls12_resumption.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const run_tls12_resumption_bench = b.addRunArtifact(
        tls12_resumption_bench,
    );
    const tls12_resumption_bench_step = b.step(
        "bench-tls12-resumption",
        "Benchmark TLS 1.2 ticket resumption with ticket rollover",
    );
    tls12_resumption_bench_step.dependOn(
        &run_tls12_resumption_bench.step,
    );
    const run_tls12_session_resumption_bench = b.addRunArtifact(
        tls12_resumption_bench,
    );
    run_tls12_session_resumption_bench.addArg("session");
    const tls12_session_resumption_bench_step = b.step(
        "bench-tls12-session-resumption",
        "Benchmark TLS 1.2 session-ID resumption",
    );
    tls12_session_resumption_bench_step.dependOn(
        &run_tls12_session_resumption_bench.step,
    );

    const rustls_tls12_resumption_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls12-handshake-bench",
        "--",
        "resume",
    });
    const rustls_tls12_resumption_bench_step = b.step(
        "bench-rustls-tls12-resumption",
        "Benchmark rustls/AWS-LC TLS 1.2 ticket resumption with rollover",
    );
    rustls_tls12_resumption_bench_step.dependOn(
        &rustls_tls12_resumption_bench.step,
    );
    const rustls_tls12_session_resumption_bench = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
        "--bin",
        "vail-rustls-tls12-handshake-bench",
        "--",
        "resume-session",
    });
    const rustls_tls12_session_resumption_bench_step = b.step(
        "bench-rustls-tls12-session-resumption",
        "Benchmark rustls/AWS-LC TLS 1.2 session-ID resumption",
    );
    rustls_tls12_session_resumption_bench_step.dependOn(
        &rustls_tls12_session_resumption_bench.step,
    );

    const client_hello_check = b.addExecutable(.{
        .name = "vail-clienthello-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/client_hello_check.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });

    const openssl_ch = b.addSystemCommand(&.{"tools/interop/openssl_client_hello.sh"});
    openssl_ch.addArg("--status");
    const openssl_ch_hex = openssl_ch.addOutputFileArg("openssl-clienthello.hex");
    const check_openssl_ch = b.addRunArtifact(client_hello_check);
    check_openssl_ch.addFileArg(openssl_ch_hex);
    check_openssl_ch.addArg("example.com");
    check_openssl_ch.addArg("1301");
    check_openssl_ch.addArg("ocsp");
    const interop_openssl_step = b.step(
        "interop-openssl-clienthello",
        "Parse a real OpenSSL TLS 1.3 ClientHello",
    );
    interop_openssl_step.dependOn(&check_openssl_ch.step);

    const rustls_ch = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_client_hello/Cargo.toml",
    });
    const rustls_ch_hex = rustls_ch.captureStdOut(.{});
    const check_rustls_ch = b.addRunArtifact(client_hello_check);
    check_rustls_ch.addFileArg(rustls_ch_hex);
    check_rustls_ch.addArg("example.com");
    check_rustls_ch.addArg("1301");
    check_rustls_ch.addArg("ocsp");
    check_rustls_ch.addArg("zlib");
    const interop_rustls_step = b.step(
        "interop-rustls-clienthello",
        "Parse a real rustls TLS 1.3 ClientHello",
    );
    interop_rustls_step.dependOn(&check_rustls_ch.step);

    const min_tls13_server = b.addExecutable(.{
        .name = "vail-min-tls13-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls13_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const interop_min_server_compile = b.step(
        "interop-min-server-compile",
        "Compile Vail's experimental minimal TLS 1.3 server harness",
    );
    interop_min_server_compile.dependOn(&min_tls13_server.step);

    const check_min_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_min_server.addArg(
        "$1 > /tmp/vail-min-tls13-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 3s openssl s_client -connect 127.0.0.1:24444 -tls1_3 -servername localhost -alpn h2 -msg -ign_eof < /dev/null > /tmp/vail-min-tls13-client.log 2>&1 || true; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256' /tmp/vail-min-tls13-client.log && " ++
            "grep -q 'Peer signature type: rsa_pss_rsae_sha256' /tmp/vail-min-tls13-client.log && " ++
            "grep -q '>>> TLS 1.3, Handshake .* Finished' /tmp/vail-min-tls13-client.log && " ++
            "grep -q 'client finished verified' /tmp/vail-min-tls13-server.log && grep -q 'warning close_notify' /tmp/vail-min-tls13-client.log",
    );
    check_min_server.addArg("sh");
    check_min_server.addArtifactArg(min_tls13_server);
    const interop_min_server_step = b.step(
        "interop-openssl-min-server",
        "Exercise Vail's minimal TLS 1.3 server flight with openssl s_client",
    );
    interop_min_server_step.dependOn(&check_min_server.step);

    const check_p521_server = b.addSystemCommand(&.{ "bash", "-c" });
    check_p521_server.addArg(
        "work=$(mktemp -d /tmp/vail-p521-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl pkcs8 -topk8 -nocrypt -in \"$work/key.pem\" -outform DER -out \"$work/key.der\"; " ++
            "openssl x509 -in \"$work/cert.pem\" -outform DER -out \"$work/cert.der\"; " ++
            "key_hex=$(xxd -p -c 100000 \"$work/key.der\"); " ++
            "cert_hex=$(xxd -p -c 100000 \"$work/cert.der\"); " ++
            "$1 p521-all 24460 \"$key_hex\" \"$cert_hex\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 6s openssl s_client -connect 127.0.0.1:24460 -tls1_3 -groups P-521 -sigalgs ecdsa_secp521r1_sha512 -servername localhost -verify_hostname localhost -verify_return_error -CAfile \"$work/cert.pem\" -alpn h2 -ign_eof < /dev/null >\"$work/client.log\" 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256' \"$work/client.log\" && " ++
            "grep -q 'Peer signature type: ecdsa_secp521r1_sha512' \"$work/client.log\" && " ++
            "grep -q 'Verify return code: 0 (ok)' \"$work/client.log\" && " ++
            "grep -q 'client finished verified' \"$work/server.log\" && " ++
            "grep -q 'P-521 ECDH negotiated' \"$work/server.log\"",
    );
    check_p521_server.addArg("bash");
    check_p521_server.addArtifactArg(min_tls13_server);
    const interop_p521_server_step = b.step(
        "interop-openssl-p521-server",
        "Exercise Vail's native P-521 TLS 1.3 signer with OpenSSL",
    );
    interop_p521_server_step.dependOn(&check_p521_server.step);

    const check_p521_kx_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_p521_kx_server.addArg(
        "$1 p521-kx 24461 > /tmp/vail-p521-kx-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 8s openssl s_client -connect 127.0.0.1:24461 -tls1_3 -groups P-521 -servername localhost -alpn h2 -brief -ign_eof < /dev/null > /tmp/vail-p521-kx-client.log 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'Peer Temp Key: ECDH, secp521r1, 521 bits' /tmp/vail-p521-kx-client.log && " ++
            "grep -q 'client finished verified' /tmp/vail-p521-kx-server.log && " ++
            "grep -q 'P-521 ECDH negotiated' /tmp/vail-p521-kx-server.log",
    );
    check_p521_kx_server.addArg("sh");
    check_p521_kx_server.addArtifactArg(min_tls13_server);
    const interop_p521_kx_server_step = b.step(
        "interop-openssl-p521-kx-server",
        "Exercise Vail's pure-Zig P-521 TLS 1.3 key exchange with OpenSSL",
    );
    interop_p521_kx_server_step.dependOn(&check_p521_kx_server.step);

    const check_ccm_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_ccm_server.addArg(
        "$1 ccm > /tmp/vail-ccm-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 3s openssl s_client -connect 127.0.0.1:24444 -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -servername localhost -alpn h2 -ign_eof < /dev/null > /tmp/vail-ccm-client.log 2>&1 || true; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'New, TLSv1.3, Cipher is TLS_AES_128_CCM_SHA256' /tmp/vail-ccm-client.log && " ++
            "grep -q 'client finished verified' /tmp/vail-ccm-server.log",
    );
    check_ccm_server.addArg("sh");
    check_ccm_server.addArtifactArg(min_tls13_server);
    const interop_ccm_server_step = b.step(
        "interop-openssl-ccm-server",
        "Exercise Vail's TLS_AES_128_CCM_SHA256 server with OpenSSL",
    );
    interop_ccm_server_step.dependOn(&check_ccm_server.step);

    const check_ccm8_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_ccm8_server.addArg(
        "$1 ccm8 > /tmp/vail-ccm8-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 3s openssl s_client -connect 127.0.0.1:24444 -tls1_3 -cipher 'DEFAULT:@SECLEVEL=0' -ciphersuites TLS_AES_128_CCM_8_SHA256 -servername localhost -alpn h2 -ign_eof < /dev/null > /tmp/vail-ccm8-client.log 2>&1 || true; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'New, TLSv1.3, Cipher is TLS_AES_128_CCM_8_SHA256' /tmp/vail-ccm8-client.log && " ++
            "grep -q 'client finished verified' /tmp/vail-ccm8-server.log",
    );
    check_ccm8_server.addArg("sh");
    check_ccm8_server.addArtifactArg(min_tls13_server);
    const interop_ccm8_server_step = b.step(
        "interop-openssl-ccm8-server",
        "Exercise Vail's TLS_AES_128_CCM_8_SHA256 server with OpenSSL",
    );
    interop_ccm8_server_step.dependOn(&check_ccm8_server.step);

    const check_certificate_signatures_mtls = b.addSystemCommand(&.{ "sh", "-c" });
    check_certificate_signatures_mtls.addArg(
        "$1 certificate-signatures-mtls > /tmp/vail-cert-signatures-mtls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 5s openssl s_client -connect 127.0.0.1:24444 -tls1_3 -servername localhost -alpn h2 -cert src/crypto/testdata/rsa_signing_client_cert.pem -key src/crypto/testdata/rsa_signing_key.pem -ign_eof < /dev/null > /tmp/vail-cert-signatures-mtls-client.log 2>&1 || true; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256' /tmp/vail-cert-signatures-mtls-client.log && " ++
            "grep -q 'client certificate signature algorithms enforced' /tmp/vail-cert-signatures-mtls-server.log",
    );
    check_certificate_signatures_mtls.addArg("sh");
    check_certificate_signatures_mtls.addArtifactArg(min_tls13_server);
    const interop_certificate_signatures_mtls_step = b.step(
        "interop-openssl-cert-signatures-mtls-server",
        "Constrain an OpenSSL TLS 1.3 client certificate chain separately",
    );
    interop_certificate_signatures_mtls_step.dependOn(
        &check_certificate_signatures_mtls.step,
    );

    const check_constrained_pss_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_constrained_pss_server.addArg(
        "work=$(mktemp -d /tmp/vail-constrained-pss-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -inform DER -in src/x509/testdata/rsa-pss-crl-ca.der -out \"$work/root.pem\"; " ++
            "$1 constrained-pss >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s openssl s_client -connect 127.0.0.1:24444 -tls1_3 -servername localhost -alpn h2 -sigalgs rsa_pss_pss_sha384 -CAfile \"$work/root.pem\" -ign_eof < /dev/null >\"$work/client.log\" 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'Verification: OK' \"$work/client.log\" && " ++
            "grep -q 'Peer signature type: rsa_pss_pss_sha384' \"$work/client.log\" && " ++
            "grep -q 'constrained RSA-PSS server verified' \"$work/server.log\"",
    );
    check_constrained_pss_server.addArg("sh");
    check_constrained_pss_server.addArtifactArg(min_tls13_server);
    const interop_constrained_pss_server_step = b.step(
        "interop-openssl-constrained-pss-server",
        "Exercise Vail's constrained RSA-PSS server with OpenSSL",
    );
    interop_constrained_pss_server_step.dependOn(
        &check_constrained_pss_server.step,
    );

    const build_rustls_min = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
    });
    const check_rustls_min = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_min.step.dependOn(&build_rustls_min.step);
    check_rustls_min.addArg(
        "$1 > /tmp/vail-min-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client > /tmp/vail-min-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-min-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-min-rustls-server.log && " ++
            "grep -q 'certificate compression=zlib' /tmp/vail-min-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-min-rustls-client.log",
    );
    check_rustls_min.addArg("sh");
    check_rustls_min.addArtifactArg(min_tls13_server);
    const interop_rustls_min_step = b.step(
        "interop-rustls-min-server",
        "Exercise Vail's minimal TLS 1.3 server flight with rustls client",
    );
    interop_rustls_min_step.dependOn(&check_rustls_min.step);

    const check_rustls_p521_server = b.addSystemCommand(&.{ "bash", "-c" });
    check_rustls_p521_server.step.dependOn(&build_rustls_min.step);
    check_rustls_p521_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-p521-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes -subj /CN=localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl pkcs8 -topk8 -nocrypt -in \"$work/key.pem\" -outform DER -out \"$work/key.der\"; " ++
            "openssl x509 -in \"$work/cert.pem\" -outform DER -out \"$work/cert.der\"; " ++
            "key_hex=$(xxd -p -c 100000 \"$work/key.der\"); " ++
            "cert_hex=$(xxd -p -c 100000 \"$work/cert.der\"); " ++
            "$1 p521 24460 \"$key_hex\" \"$cert_hex\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 6s bench/rustls_min_client/target/release/vail-rustls-min-client p521 24460 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'client finished verified' \"$work/server.log\" && " ++
            "grep -q 'rustls connected' \"$work/client.log\" && " ++
            "grep -q 'rustls P-521 TLS 1.3 signature verified' \"$work/client.log\"",
    );
    check_rustls_p521_server.addArg("bash");
    check_rustls_p521_server.addArtifactArg(min_tls13_server);
    const interop_rustls_p521_server_step = b.step(
        "interop-rustls-p521-server",
        "Exercise Vail's native P-521 TLS 1.3 signer with rustls/AWS-LC",
    );
    interop_rustls_p521_server_step.dependOn(
        &check_rustls_p521_server.step,
    );

    const check_rustls_ca_hints = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_ca_hints.step.dependOn(&build_rustls_min.step);
    check_rustls_ca_hints.addArg(
        "$1 ca-hints > /tmp/vail-ca-hints-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client ca-hints > /tmp/vail-ca-hints-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-ca-hints-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-ca-hints-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-ca-hints-rustls-client.log",
    );
    check_rustls_ca_hints.addArg("sh");
    check_rustls_ca_hints.addArtifactArg(min_tls13_server);
    const interop_rustls_ca_hints_step = b.step(
        "interop-rustls-ca-hints-server",
        "Select a Vail server identity from rustls certificate authority hints",
    );
    interop_rustls_ca_hints_step.dependOn(&check_rustls_ca_hints.step);

    const check_rustls_ticket_request = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_ticket_request.step.dependOn(&build_rustls_min.step);
    check_rustls_ticket_request.addArg(
        "$1 ticket-request > /tmp/vail-ticket-request-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client ticket-request > /tmp/vail-ticket-request-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-ticket-request-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'ticket request count=2' /tmp/vail-ticket-request-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-ticket-request-rustls-client.log",
    );
    check_rustls_ticket_request.addArg("sh");
    check_rustls_ticket_request.addArtifactArg(min_tls13_server);
    const interop_rustls_ticket_request_step = b.step(
        "interop-rustls-ticket-request-server",
        "Honor a rustls RFC 9149 ticket request in the Vail server",
    );
    interop_rustls_ticket_request_step.dependOn(
        &check_rustls_ticket_request.step,
    );

    const check_aws_lc_alps = b.addSystemCommand(&.{ "sh", "-c" });
    check_aws_lc_alps.step.dependOn(&build_rustls_min.step);
    check_aws_lc_alps.addArg(
        "$1 alps > /tmp/vail-alps-aws-lc-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 5s bench/rustls_min_client/target/release/vail-aws-lc-alps-client > /tmp/vail-alps-aws-lc-client.log 2>&1; client_status=$?; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'AWS-LC ALPS settings verified' /tmp/vail-alps-aws-lc-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "test $client_status -eq 0 && " ++
            "grep -q 'AWS-LC ALPS settings verified' /tmp/vail-alps-aws-lc-server.log && " ++
            "grep -q 'AWS-LC ALPS connected and settings matched' /tmp/vail-alps-aws-lc-client.log",
    );
    check_aws_lc_alps.addArg("sh");
    check_aws_lc_alps.addArtifactArg(min_tls13_server);
    const interop_aws_lc_alps_step = b.step(
        "interop-aws-lc-alps-client",
        "Exchange ALPS settings between AWS-LC and the Vail server",
    );
    interop_aws_lc_alps_step.dependOn(&check_aws_lc_alps.step);

    const check_aws_lc_alps_new = b.addSystemCommand(&.{ "sh", "-c" });
    check_aws_lc_alps_new.step.dependOn(&build_rustls_min.step);
    check_aws_lc_alps_new.addArg(
        "$1 alps-new > /tmp/vail-alps-new-aws-lc-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 5s bench/rustls_min_client/target/release/vail-aws-lc-alps-client new > /tmp/vail-alps-new-aws-lc-client.log 2>&1; client_status=$?; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'AWS-LC ALPS settings verified' /tmp/vail-alps-new-aws-lc-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "test $client_status -eq 0 && " ++
            "grep -q 'AWS-LC ALPS settings verified' /tmp/vail-alps-new-aws-lc-server.log && " ++
            "grep -q 'AWS-LC ALPS connected and settings matched' /tmp/vail-alps-new-aws-lc-client.log",
    );
    check_aws_lc_alps_new.addArg("sh");
    check_aws_lc_alps_new.addArtifactArg(min_tls13_server);
    const interop_aws_lc_alps_new_step = b.step(
        "interop-aws-lc-alps-new-client",
        "Exchange ALPS settings with AWS-LC's newer codepoint",
    );
    interop_aws_lc_alps_new_step.dependOn(&check_aws_lc_alps_new.step);

    const check_rustls_chacha = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_chacha.step.dependOn(&build_rustls_min.step);
    check_rustls_chacha.addArg(
        "$1 chacha > /tmp/vail-chacha-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client > /tmp/vail-chacha-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-chacha-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-chacha-rustls-server.log && " ++
            "grep -q 'TLS13_CHACHA20_POLY1305_SHA256' /tmp/vail-chacha-rustls-client.log",
    );
    check_rustls_chacha.addArg("sh");
    check_rustls_chacha.addArtifactArg(min_tls13_server);
    const interop_rustls_chacha_step = b.step(
        "interop-rustls-chacha-server",
        "Exercise Vail's accelerated ChaCha20-Poly1305 server with rustls",
    );
    interop_rustls_chacha_step.dependOn(&check_rustls_chacha.step);

    const check_rustls_key_log = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_key_log.step.dependOn(&build_rustls_min.step);
    check_rustls_key_log.addArg(
        "$1 keylog > /tmp/vail-keylog-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client keylog > /tmp/vail-keylog-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-keylog-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "sed -n 's/^VAIL_KEY_LOG //p' /tmp/vail-keylog-rustls-server.log | sort > /tmp/vail-keylog-vail.keys; " ++
            "sed -n 's/^RUSTLS_KEY_LOG //p' /tmp/vail-keylog-rustls-client.log | sort > /tmp/vail-keylog-rustls.keys; " ++
            "test \"$(wc -l < /tmp/vail-keylog-vail.keys)\" -eq 5 && " ++
            "cmp /tmp/vail-keylog-vail.keys /tmp/vail-keylog-rustls.keys && " ++
            "grep -q 'rustls connected' /tmp/vail-keylog-rustls-client.log",
    );
    check_rustls_key_log.addArg("sh");
    check_rustls_key_log.addArtifactArg(min_tls13_server);
    const interop_rustls_key_log_step = b.step(
        "interop-rustls-keylog-server",
        "Compare Vail and rustls/AWS-LC NSS key logs for one TLS 1.3 session",
    );
    interop_rustls_key_log_step.dependOn(&check_rustls_key_log.step);

    const check_rustls_traffic_secrets = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_traffic_secrets.step.dependOn(&build_rustls_min.step);
    check_rustls_traffic_secrets.addArg(
        "$1 extract-secrets > /tmp/vail-traffic-secrets-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client extract-secrets > /tmp/vail-traffic-secrets-client.log 2>&1; " ++
            "wait $pid; " ++
            "sed -n 's/^VAIL_TRAFFIC //p' /tmp/vail-traffic-secrets-server.log | sort > /tmp/vail-traffic-secrets-vail.keys; " ++
            "sed -n 's/^RUSTLS_TRAFFIC //p' /tmp/vail-traffic-secrets-client.log | sort > /tmp/vail-traffic-secrets-rustls.keys; " ++
            "test \"$(wc -l < /tmp/vail-traffic-secrets-vail.keys)\" -eq 2 && " ++
            "cmp /tmp/vail-traffic-secrets-vail.keys /tmp/vail-traffic-secrets-rustls.keys",
    );
    check_rustls_traffic_secrets.addArg("sh");
    check_rustls_traffic_secrets.addArtifactArg(min_tls13_server);
    const interop_rustls_traffic_secrets_step = b.step(
        "interop-rustls-traffic-secrets-server",
        "Compare Vail and rustls/AWS-LC TLS 1.3 record keys and sequences",
    );
    interop_rustls_traffic_secrets_step.dependOn(
        &check_rustls_traffic_secrets.step,
    );

    const check_rustls_brotli = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_brotli.step.dependOn(&build_rustls_min.step);
    check_rustls_brotli.addArg(
        "$1 brotli > /tmp/vail-brotli-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client > /tmp/vail-brotli-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-brotli-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-brotli-rustls-server.log && " ++
            "grep -q 'certificate compression=brotli' /tmp/vail-brotli-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-brotli-rustls-client.log",
    );
    check_rustls_brotli.addArg("sh");
    check_rustls_brotli.addArtifactArg(min_tls13_server);
    const interop_rustls_brotli_step = b.step(
        "interop-rustls-brotli-server",
        "Exercise Vort Brotli certificates with a rustls client",
    );
    interop_rustls_brotli_step.dependOn(&check_rustls_brotli.step);

    const check_rustls_zstd = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_zstd.step.dependOn(&build_rustls_min.step);
    check_rustls_zstd.addArg(
        "$1 zstd > /tmp/vail-zstd-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client zstd > /tmp/vail-zstd-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'client finished verified' /tmp/vail-zstd-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-zstd-rustls-server.log && " ++
            "grep -q 'certificate compression=zstd' /tmp/vail-zstd-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-zstd-rustls-client.log",
    );
    check_rustls_zstd.addArg("sh");
    check_rustls_zstd.addArtifactArg(min_tls13_server);
    const interop_rustls_zstd_step = b.step(
        "interop-rustls-zstd-server",
        "Exercise Vort Zstandard certificates with a rustls client",
    );
    interop_rustls_zstd_step.dependOn(&check_rustls_zstd.step);

    const check_rustls_ech = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_ech.step.dependOn(&build_rustls_min.step);
    check_rustls_ech.addArg(
        "$1 ech > /tmp/vail-ech-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client ech > /tmp/vail-ech-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'ech accepted' /tmp/vail-ech-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-ech-rustls-server.log && " ++
            "grep -q 'ech accepted' /tmp/vail-ech-rustls-server.log && " ++
            "grep -q 'ech=Accepted' /tmp/vail-ech-rustls-client.log",
    );
    check_rustls_ech.addArg("sh");
    check_rustls_ech.addArtifactArg(min_tls13_server);
    const interop_rustls_ech_step = b.step(
        "interop-rustls-ech-server",
        "Exercise Vail's RFC 9849 ECH server with a rustls/AWS-LC client",
    );
    interop_rustls_ech_step.dependOn(&check_rustls_ech.step);

    const check_rustls_ech_hrr = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_ech_hrr.step.dependOn(&build_rustls_min.step);
    check_rustls_ech_hrr.addArg(
        "$1 ech-hrr > /tmp/vail-ech-hrr-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client ech > /tmp/vail-ech-hrr-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'ech accepted' /tmp/vail-ech-hrr-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'hello retry request' /tmp/vail-ech-hrr-rustls-server.log && " ++
            "grep -q 'client finished verified' /tmp/vail-ech-hrr-rustls-server.log && " ++
            "grep -q 'ech accepted' /tmp/vail-ech-hrr-rustls-server.log && " ++
            "grep -q 'ech=Accepted' /tmp/vail-ech-hrr-rustls-client.log",
    );
    check_rustls_ech_hrr.addArg("sh");
    check_rustls_ech_hrr.addArtifactArg(min_tls13_server);
    const interop_rustls_ech_hrr_step = b.step(
        "interop-rustls-ech-hrr-server",
        "Exercise Vail ECH HRR with a rustls/AWS-LC client",
    );
    interop_rustls_ech_hrr_step.dependOn(&check_rustls_ech_hrr.step);

    const min_quic_tls_server = b.addExecutable(.{
        .name = "vail-min-quic-tls-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_quic_tls_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_quic_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_client.step.dependOn(&build_rustls_min.step);
    check_rustls_quic_client.addArg(
        "timeout 15s $1 > /tmp/vail-quic-tls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s bench/rustls_min_client/target/release/vail-rustls-quic-client src/crypto/testdata/rsa_signing_cert.pem > /tmp/rustls-quic-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail QUIC server verified rustls/AWS-LC client' /tmp/vail-quic-tls-server.log && " ++
            "grep -q 'rustls/AWS-LC QUIC client completed' /tmp/rustls-quic-client.log",
    );
    check_rustls_quic_client.addArg("sh");
    check_rustls_quic_client.addArtifactArg(min_quic_tls_server);
    const interop_rustls_quic_client_step = b.step(
        "interop-rustls-quic-client",
        "Exercise Vail's QUIC TLS server with a rustls/AWS-LC client",
    );
    interop_rustls_quic_client_step.dependOn(
        &check_rustls_quic_client.step,
    );
    const check_rustls_quic_hybrid_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_hybrid_client.step.dependOn(&build_rustls_min.step);
    check_rustls_quic_hybrid_client.addArg(
        "timeout 20s $1 hybrid > /tmp/vail-quic-hybrid-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s bench/rustls_min_client/target/release/vail-rustls-quic-client src/crypto/testdata/rsa_signing_cert.pem hybrid > /tmp/rustls-quic-hybrid-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=X25519MLKEM768' /tmp/vail-quic-hybrid-server.log && " ++
            "grep -q 'group=X25519MLKEM768' /tmp/rustls-quic-hybrid-client.log",
    );
    check_rustls_quic_hybrid_client.addArg("sh");
    check_rustls_quic_hybrid_client.addArtifactArg(min_quic_tls_server);
    const interop_rustls_quic_hybrid_client_step = b.step(
        "interop-rustls-quic-hybrid-client",
        "Exercise Vail's X25519MLKEM768 QUIC server with rustls/AWS-LC",
    );
    interop_rustls_quic_hybrid_client_step.dependOn(
        &check_rustls_quic_hybrid_client.step,
    );
    const check_rustls_quic_mlkem_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_mlkem_client.step.dependOn(&build_rustls_min.step);
    check_rustls_quic_mlkem_client.addArg(
        "timeout 20s $1 mlkem > /tmp/vail-quic-mlkem-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s bench/rustls_min_client/target/release/vail-rustls-quic-client src/crypto/testdata/rsa_signing_cert.pem mlkem > /tmp/rustls-quic-mlkem-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=MLKEM768' /tmp/vail-quic-mlkem-server.log && " ++
            "grep -q 'group=MLKEM768' /tmp/rustls-quic-mlkem-client.log",
    );
    check_rustls_quic_mlkem_client.addArg("sh");
    check_rustls_quic_mlkem_client.addArtifactArg(min_quic_tls_server);
    const interop_rustls_quic_mlkem_client_step = b.step(
        "interop-rustls-quic-mlkem-client",
        "Exercise Vail's ML-KEM-768 QUIC server with rustls/AWS-LC",
    );
    interop_rustls_quic_mlkem_client_step.dependOn(
        &check_rustls_quic_mlkem_client.step,
    );
    const check_rustls_quic_mlkem1024_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_mlkem1024_client.step.dependOn(&build_rustls_min.step);
    check_rustls_quic_mlkem1024_client.addArg(
        "timeout 20s $1 mlkem1024 > /tmp/vail-quic-mlkem1024-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s bench/rustls_min_client/target/release/vail-rustls-quic-client src/crypto/testdata/rsa_signing_cert.pem mlkem1024 > /tmp/rustls-quic-mlkem1024-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=MLKEM1024' /tmp/vail-quic-mlkem1024-server.log && " ++
            "grep -q 'group=MLKEM1024' /tmp/rustls-quic-mlkem1024-client.log",
    );
    check_rustls_quic_mlkem1024_client.addArg("sh");
    check_rustls_quic_mlkem1024_client.addArtifactArg(min_quic_tls_server);
    const interop_rustls_quic_mlkem1024_client_step = b.step(
        "interop-rustls-quic-mlkem1024-client",
        "Exercise Vail's ML-KEM-1024 QUIC server with rustls/AWS-LC",
    );
    interop_rustls_quic_mlkem1024_client_step.dependOn(
        &check_rustls_quic_mlkem1024_client.step,
    );

    const min_tls13_resume_server = b.addExecutable(.{
        .name = "vail-min-tls13-resume-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/min_tls13_resume_server.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_tls13_resumption = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls13_resumption.step.dependOn(&build_rustls_min.step);
    check_rustls_tls13_resumption.addArg(
        "timeout 25s $1 > /tmp/vail-rustls-tls13-resume-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 20s bench/rustls_min_client/target/release/vail-rustls-tls13-resume-client src/crypto/testdata/rsa_signing_cert.pem > /tmp/rustls-vail-tls13-resume-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail TLS 1.3 resumption and 0-RTT verified' /tmp/vail-rustls-tls13-resume-server.log && " ++
            "grep -q 'rustls/AWS-LC TLS 1.3 resumption and 0-RTT verified' /tmp/rustls-vail-tls13-resume-client.log",
    );
    check_rustls_tls13_resumption.addArg("sh");
    check_rustls_tls13_resumption.addArtifactArg(min_tls13_resume_server);
    const interop_rustls_tls13_resumption_step = b.step(
        "interop-rustls-tls13-resumption-server",
        "Exercise Vail TLS 1.3 ticket resumption and 0-RTT with rustls/AWS-LC",
    );
    interop_rustls_tls13_resumption_step.dependOn(
        &check_rustls_tls13_resumption.step,
    );

    const min_tls13_client = b.addExecutable(.{
        .name = "vail-min-tls13-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls13_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_vail_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24445 -tls1_3 -groups P-256 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_client.addArg("sh");
    check_vail_client.addArtifactArg(min_tls13_client);
    const interop_vail_client_step = b.step(
        "interop-openssl-min-client",
        "Exercise Vail's TLS 1.3 client state against OpenSSL",
    );
    interop_vail_client_step.dependOn(&check_vail_client.step);

    const check_vail_p521_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_p521_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-p521.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-521 -nodes -subj /CN=localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24458 -tls1_3 -groups P-521 -sigalgs ecdsa_secp521r1_sha512 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 6s $1 p521-all 24458 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'P-521 ECDH negotiated' \"$work/client.log\" && " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_p521_client.addArg("sh");
    check_vail_p521_client.addArtifactArg(min_tls13_client);
    const interop_vail_p521_client_step = b.step(
        "interop-openssl-p521-client",
        "Verify an OpenSSL P-521 TLS 1.3 server with Vail",
    );
    interop_vail_p521_client_step.dependOn(&check_vail_p521_client.step);

    const check_vail_p521_kx_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_p521_kx_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-p521-kx.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24459 -tls1_3 -groups P-521 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 p521-kx 24459 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'P-521 ECDH negotiated' \"$work/client.log\" && " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_p521_kx_client.addArg("sh");
    check_vail_p521_kx_client.addArtifactArg(min_tls13_client);
    const interop_vail_p521_kx_client_step = b.step(
        "interop-openssl-p521-kx-client",
        "Exercise Vail's pure-Zig P-521 TLS 1.3 client key exchange",
    );
    interop_vail_p521_kx_client_step.dependOn(
        &check_vail_p521_kx_client.step,
    );

    const check_vail_ccm_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_ccm_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-ccm.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24445 -tls1_3 -groups P-256 -ciphersuites TLS_AES_128_CCM_SHA256 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 ccm >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'cipher suite=aes_128_ccm_sha256' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_ccm_client.addArg("sh");
    check_vail_ccm_client.addArtifactArg(min_tls13_client);
    const interop_vail_ccm_client_step = b.step(
        "interop-openssl-ccm-client",
        "Exercise Vail's TLS_AES_128_CCM_SHA256 client with OpenSSL",
    );
    interop_vail_ccm_client_step.dependOn(&check_vail_ccm_client.step);

    const check_vail_ccm8_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_ccm8_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-ccm8.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24445 -tls1_3 -groups P-256 -cipher 'DEFAULT:@SECLEVEL=0' -ciphersuites TLS_AES_128_CCM_8_SHA256 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 ccm8 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'cipher suite=aes_128_ccm_8_sha256' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_ccm8_client.addArg("sh");
    check_vail_ccm8_client.addArtifactArg(min_tls13_client);
    const interop_vail_ccm8_client_step = b.step(
        "interop-openssl-ccm8-client",
        "Exercise Vail's TLS_AES_128_CCM_8_SHA256 client with OpenSSL",
    );
    interop_vail_ccm8_client_step.dependOn(&check_vail_ccm8_client.step);

    const check_vail_sm4_ccm = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_sm4_ccm.addArg(
        "work=$(mktemp -d /tmp/vail-sm4-ccm.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "$1 sm4-ccm 24446 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 6s $2 sm4-ccm 24446 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'client finished verified' \"$work/server.log\" && " ++
            "grep -q 'client application data verified' \"$work/server.log\" && " ++
            "grep -q 'cipher suite=sm4_ccm_sm3' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_sm4_ccm.addArg("sh");
    check_vail_sm4_ccm.addArtifactArg(min_tls13_server);
    check_vail_sm4_ccm.addArtifactArg(min_tls13_client);
    const interop_vail_sm4_ccm_step = b.step(
        "interop-vail-sm4-ccm",
        "Exercise a complete Vail TLS_SM4_CCM_SM3 connection",
    );
    interop_vail_sm4_ccm_step.dependOn(&check_vail_sm4_ccm.step);

    const check_vail_pss_certificate_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_pss_certificate_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-pss-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -inform DER -in src/x509/testdata/rsa-pss-leaf.der -out \"$work/cert.pem\"; " ++
            "openssl s_server -accept 127.0.0.1:24445 -tls1_3 -groups P-256 -cert \"$work/cert.pem\" -key src/crypto/testdata/rsa_signing_key.pem -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 pss-certificate >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'RSA-PSS certificate path verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_pss_certificate_client.addArg("sh");
    check_vail_pss_certificate_client.addArtifactArg(min_tls13_client);
    const interop_vail_pss_certificate_client_step = b.step(
        "interop-openssl-pss-certificate-client",
        "Verify an OpenSSL RSA-PSS-signed certificate with Vail",
    );
    interop_vail_pss_certificate_client_step.dependOn(
        &check_vail_pss_certificate_client.step,
    );

    const check_vail_constrained_pss_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_constrained_pss_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-constrained-pss.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -inform DER -in src/x509/testdata/rsa-pss-crl-ca.der -out \"$work/root.pem\"; " ++
            "openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:32 -out \"$work/key.pem\" >/dev/null 2>&1; " ++
            "openssl req -new -key \"$work/key.pem\" -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:false -addext keyUsage=critical,digitalSignature -addext extendedKeyUsage=serverAuth -out \"$work/request.pem\"; " ++
            "openssl x509 -req -in \"$work/request.pem\" -CA \"$work/root.pem\" -CAkey src/crypto/testdata/rsa_signing_key.pem -set_serial 20481 -not_before 20260101000000Z -not_after 20360101000000Z -copy_extensions copy -sha256 -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24445 -tls1_3 -groups P-256 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 constrained-pss >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'constrained RSA-PSS key verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_constrained_pss_client.addArg("sh");
    check_vail_constrained_pss_client.addArtifactArg(min_tls13_client);
    const interop_vail_constrained_pss_client_step = b.step(
        "interop-openssl-constrained-pss-client",
        "Verify an RFC 4055 constrained OpenSSL RSA-PSS key with Vail",
    );
    interop_vail_constrained_pss_client_step.dependOn(
        &check_vail_constrained_pss_client.step,
    );

    const build_rustls_server = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        "bench/rustls_min_server/Cargo.toml",
    });
    const check_vail_rustls_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_server.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'certificate compression=brotli' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_server.addArg("sh");
    check_vail_rustls_server.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_server_step = b.step(
        "interop-rustls-min-client",
        "Exercise Vail's TLS 1.3 client against a Brotli-enabled rustls server",
    );
    interop_vail_rustls_server_step.dependOn(
        &check_vail_rustls_server.step,
    );

    const check_vail_rustls_certificate_signatures = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_certificate_signatures.step.dependOn(
        &build_rustls_server.step,
    );
    check_vail_rustls_certificate_signatures.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-cert-signatures.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 certificate-signatures >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'certificate signature algorithms enforced' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_certificate_signatures.addArg("sh");
    check_vail_rustls_certificate_signatures.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_certificate_signatures_step = b.step(
        "interop-rustls-cert-signatures-client",
        "Exercise TLS 1.3 certificate signature constraints with rustls",
    );
    interop_vail_rustls_certificate_signatures_step.dependOn(
        &check_vail_rustls_certificate_signatures.step,
    );

    const check_vail_rustls_pss_certificate = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_pss_certificate.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_pss_certificate.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-pss-certificate.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl x509 -inform DER -in src/x509/testdata/rsa-pss-leaf.der -out \"$work/cert.pem\"; " ++
            "bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" src/crypto/testdata/rsa_signing_key.pem >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 pss-certificate >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'RSA-PSS certificate path verified' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_pss_certificate.addArg("sh");
    check_vail_rustls_pss_certificate.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_pss_certificate_step = b.step(
        "interop-rustls-pss-certificate-client",
        "Verify a rustls/AWS-LC RSA-PSS-signed certificate with Vail",
    );
    interop_vail_rustls_pss_certificate_step.dependOn(
        &check_vail_rustls_pss_certificate.step,
    );

    const check_vail_rustls_ticket_request = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_ticket_request.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_ticket_request.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-ticket-request.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" \"$work/key.pem\" ticket-request >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 ticket-request >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'ticket request count=2' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_ticket_request.addArg("sh");
    check_vail_rustls_ticket_request.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_ticket_request_step = b.step(
        "interop-rustls-ticket-request-client",
        "Verify a rustls RFC 9149 ticket response in the Vail client",
    );
    interop_vail_rustls_ticket_request_step.dependOn(
        &check_vail_rustls_ticket_request.step,
    );

    const check_vail_rustls_chacha_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_chacha_server.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_chacha_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-chacha-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "timeout 10s bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "client_status=1; i=0; while [ $i -lt 20 ]; do " ++
            "if timeout 4s $1 chacha >\"$work/client.log\" 2>&1; then client_status=0; break; fi; " ++
            "sleep 0.05; i=$((i + 1)); done; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 && test $server_status -eq 0 && " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'cipher suite=chacha20_poly1305_sha256' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_chacha_server.addArg("sh");
    check_vail_rustls_chacha_server.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_chacha_server_step = b.step(
        "interop-rustls-chacha-client",
        "Exercise Vail's accelerated ChaCha20-Poly1305 client against rustls",
    );
    interop_vail_rustls_chacha_server_step.dependOn(
        &check_vail_rustls_chacha_server.step,
    );

    const check_vail_rustls_zstd_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_zstd_server.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_zstd_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-zstd-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "bench/rustls_min_server/target/release/vail-rustls-min-server \"$work/cert.pem\" \"$work/key.pem\" zstd >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 4s $1 zstd >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls server completed' \"$work/server.log\" && " ++
            "grep -q 'server authenticated and finished verified' \"$work/client.log\" && " ++
            "grep -q 'certificate compression=zstd' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_zstd_server.addArg("sh");
    check_vail_rustls_zstd_server.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_zstd_server_step = b.step(
        "interop-rustls-zstd-client",
        "Exercise Vail's Zstandard certificate client against rustls",
    );
    interop_vail_rustls_zstd_server_step.dependOn(
        &check_vail_rustls_zstd_server.step,
    );

    const min_quic_tls_client = b.addExecutable(.{
        .name = "vail-min-quic-tls-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_quic_tls_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_quic_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_server.step.dependOn(&build_rustls_server.step);
    check_rustls_quic_server.addArg(
        "timeout 15s bench/rustls_min_server/target/release/vail-rustls-quic-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem > /tmp/rustls-quic-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s $1 > /tmp/vail-quic-tls-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'rustls/AWS-LC QUIC server verified Vail client' /tmp/rustls-quic-server.log && " ++
            "grep -q 'Vail QUIC client verified rustls/AWS-LC server' /tmp/vail-quic-tls-client.log",
    );
    check_rustls_quic_server.addArg("sh");
    check_rustls_quic_server.addArtifactArg(min_quic_tls_client);
    const interop_rustls_quic_server_step = b.step(
        "interop-rustls-quic-server",
        "Exercise Vail's QUIC TLS client with a rustls/AWS-LC server",
    );
    interop_rustls_quic_server_step.dependOn(
        &check_rustls_quic_server.step,
    );
    const check_rustls_quic_hybrid_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_hybrid_server.step.dependOn(&build_rustls_server.step);
    check_rustls_quic_hybrid_server.addArg(
        "timeout 20s bench/rustls_min_server/target/release/vail-rustls-quic-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem hybrid > /tmp/rustls-quic-hybrid-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s $1 hybrid > /tmp/vail-quic-hybrid-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=X25519MLKEM768' /tmp/rustls-quic-hybrid-server.log && " ++
            "grep -q 'group=X25519MLKEM768' /tmp/vail-quic-hybrid-client.log",
    );
    check_rustls_quic_hybrid_server.addArg("sh");
    check_rustls_quic_hybrid_server.addArtifactArg(min_quic_tls_client);
    const interop_rustls_quic_hybrid_server_step = b.step(
        "interop-rustls-quic-hybrid-server",
        "Exercise Vail's X25519MLKEM768 QUIC client with rustls/AWS-LC",
    );
    interop_rustls_quic_hybrid_server_step.dependOn(
        &check_rustls_quic_hybrid_server.step,
    );
    const check_rustls_quic_mlkem_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_mlkem_server.step.dependOn(&build_rustls_server.step);
    check_rustls_quic_mlkem_server.addArg(
        "timeout 20s bench/rustls_min_server/target/release/vail-rustls-quic-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem mlkem > /tmp/rustls-quic-mlkem-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s $1 mlkem > /tmp/vail-quic-mlkem-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=MLKEM768' /tmp/rustls-quic-mlkem-server.log && " ++
            "grep -q 'group=MLKEM768' /tmp/vail-quic-mlkem-client.log",
    );
    check_rustls_quic_mlkem_server.addArg("sh");
    check_rustls_quic_mlkem_server.addArtifactArg(min_quic_tls_client);
    const interop_rustls_quic_mlkem_server_step = b.step(
        "interop-rustls-quic-mlkem-server",
        "Exercise Vail's ML-KEM-768 QUIC client with rustls/AWS-LC",
    );
    interop_rustls_quic_mlkem_server_step.dependOn(
        &check_rustls_quic_mlkem_server.step,
    );
    const check_rustls_quic_mlkem1024_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_quic_mlkem1024_server.step.dependOn(&build_rustls_server.step);
    check_rustls_quic_mlkem1024_server.addArg(
        "timeout 20s bench/rustls_min_server/target/release/vail-rustls-quic-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem mlkem1024 > /tmp/rustls-quic-mlkem1024-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 18s $1 mlkem1024 > /tmp/vail-quic-mlkem1024-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'group=MLKEM1024' /tmp/rustls-quic-mlkem1024-server.log && " ++
            "grep -q 'group=MLKEM1024' /tmp/vail-quic-mlkem1024-client.log",
    );
    check_rustls_quic_mlkem1024_server.addArg("sh");
    check_rustls_quic_mlkem1024_server.addArtifactArg(min_quic_tls_client);
    const interop_rustls_quic_mlkem1024_server_step = b.step(
        "interop-rustls-quic-mlkem1024-server",
        "Exercise Vail's ML-KEM-1024 QUIC client with rustls/AWS-LC",
    );
    interop_rustls_quic_mlkem1024_server_step.dependOn(
        &check_rustls_quic_mlkem1024_server.step,
    );

    const min_tls13_resume_client = b.addExecutable(.{
        .name = "vail-min-tls13-resume-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "tools/interop/min_tls13_resume_client.zig",
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_tls13_resumption_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls13_resumption_client.step.dependOn(&build_rustls_server.step);
    check_rustls_tls13_resumption_client.addArg(
        "timeout 25s bench/rustls_min_server/target/release/vail-rustls-tls13-resume-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem > /tmp/rustls-vail-tls13-resume-server.log 2>&1 & pid=$!; " ++
            "sleep 0.5; timeout 20s $1 > /tmp/vail-rustls-tls13-resume-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'rustls/AWS-LC TLS 1.3 server ticket resumption verified' /tmp/rustls-vail-tls13-resume-server.log && " ++
            "grep -q 'Vail TLS 1.3 client ticket resumption verified' /tmp/vail-rustls-tls13-resume-client.log",
    );
    check_rustls_tls13_resumption_client.addArg("sh");
    check_rustls_tls13_resumption_client.addArtifactArg(
        min_tls13_resume_client,
    );
    const interop_rustls_tls13_resumption_client_step = b.step(
        "interop-rustls-tls13-resumption-client",
        "Exercise Vail's TLS 1.3 ticket client with rustls/AWS-LC",
    );
    interop_rustls_tls13_resumption_client_step.dependOn(
        &check_rustls_tls13_resumption_client.step,
    );

    const min_tls12_server = b.addExecutable(.{
        .name = "vail-min-tls12-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_tls12_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_tls12_server.addArg(
        "$1 > /tmp/vail-min-tls12-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -brief -ign_eof > /tmp/vail-min-tls12-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 client Finished verified' /tmp/vail-min-tls12-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-server.log && " ++
            "grep -q 'Protocol version: TLSv1.2' /tmp/vail-min-tls12-client.log && " ++
            "grep -q 'Ciphersuite: ECDHE-RSA-AES128-GCM-SHA256' /tmp/vail-min-tls12-client.log && " ++
            "grep -q 'vail tls12 ok' /tmp/vail-min-tls12-client.log",
    );
    check_tls12_server.addArg("sh");
    check_tls12_server.addArtifactArg(min_tls12_server);
    const interop_tls12_server_step = b.step(
        "interop-openssl-tls12-server",
        "Exercise Vail's TLS 1.2 server against OpenSSL",
    );
    interop_tls12_server_step.dependOn(&check_tls12_server.step);

    const check_tls12_x25519_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_tls12_x25519_server.addArg(
        "$1 x25519 > /tmp/vail-min-tls12-x25519-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups X25519 -no_ticket -brief -ign_eof > /tmp/vail-min-tls12-x25519-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-x25519-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 X25519 ECDH negotiated' /tmp/vail-min-tls12-x25519-server.log && " ++
            "grep -q 'TLS 1.2 client Finished verified' /tmp/vail-min-tls12-x25519-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-x25519-server.log && " ++
            "grep -q 'Protocol version: TLSv1.2' /tmp/vail-min-tls12-x25519-client.log && " ++
            "grep -q 'Ciphersuite: ECDHE-RSA-AES128-GCM-SHA256' /tmp/vail-min-tls12-x25519-client.log && " ++
            "grep -q 'vail tls12 ok' /tmp/vail-min-tls12-x25519-client.log",
    );
    check_tls12_x25519_server.addArg("sh");
    check_tls12_x25519_server.addArtifactArg(min_tls12_server);
    const interop_tls12_x25519_server_step = b.step(
        "interop-openssl-tls12-x25519-server",
        "Exercise Vail's TLS 1.2 X25519 server against OpenSSL",
    );
    interop_tls12_x25519_server_step.dependOn(
        &check_tls12_x25519_server.step,
    );

    const check_tls12_aes256_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_tls12_aes256_server.addArg(
        "$1 aes256 > /tmp/vail-min-tls12-aes256-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384 -groups P-256 -no_ticket -brief -ign_eof > /tmp/vail-min-tls12-aes256-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-aes256-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 client Finished verified' /tmp/vail-min-tls12-aes256-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-aes256-server.log && " ++
            "grep -q 'Protocol version: TLSv1.2' /tmp/vail-min-tls12-aes256-client.log && " ++
            "grep -q 'Ciphersuite: ECDHE-RSA-AES256-GCM-SHA384' /tmp/vail-min-tls12-aes256-client.log && " ++
            "grep -q 'vail tls12 ok' /tmp/vail-min-tls12-aes256-client.log",
    );
    check_tls12_aes256_server.addArg("sh");
    check_tls12_aes256_server.addArtifactArg(min_tls12_server);
    const interop_tls12_aes256_server_step = b.step(
        "interop-openssl-tls12-aes256-server",
        "Exercise Vail's AES-256/SHA-384 TLS 1.2 server against OpenSSL",
    );
    interop_tls12_aes256_server_step.dependOn(
        &check_tls12_aes256_server.step,
    );

    const check_tls12_p521_server = b.addSystemCommand(&.{ "bash", "-c" });
    check_tls12_p521_server.addArg(
        "work=$(mktemp -d /tmp/vail-tls12-p521-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl pkcs8 -topk8 -nocrypt -in \"$work/key.pem\" -outform DER -out \"$work/key.der\"; " ++
            "openssl x509 -in \"$work/cert.pem\" -outform DER -out \"$work/cert.der\"; " ++
            "key_hex=$(xxd -p -c 100000 \"$work/key.der\"); " ++
            "cert_hex=$(xxd -p -c 100000 \"$work/cert.der\"); " ++
            "$1 p521-all \"$key_hex\" \"$cert_hex\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -groups P-521 -sigalgs ecdsa_secp521r1_sha512 -servername localhost -verify_hostname localhost -verify_return_error -CAfile \"$work/cert.pem\" -brief -ign_eof >\"$work/client.log\" 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' \"$work/server.log\"; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 client Finished verified' \"$work/server.log\" && " ++
            "grep -q 'TLS 1.2 application data verified' \"$work/server.log\" && " ++
            "grep -q 'Protocol version: TLSv1.2' \"$work/client.log\" && " ++
            "grep -q 'Ciphersuite: ECDHE-ECDSA-AES128-GCM-SHA256' \"$work/client.log\" && " ++
            "grep -q 'Signature type: ecdsa_secp521r1_sha512' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 P-521 ECDH negotiated' \"$work/server.log\" && " ++
            "grep -q 'vail tls12 ok' \"$work/client.log\"",
    );
    check_tls12_p521_server.addArg("bash");
    check_tls12_p521_server.addArtifactArg(min_tls12_server);
    const interop_tls12_p521_server_step = b.step(
        "interop-openssl-tls12-p521-server",
        "Exercise Vail's native P-521 TLS 1.2 signer with OpenSSL",
    );
    interop_tls12_p521_server_step.dependOn(
        &check_tls12_p521_server.step,
    );

    const check_tls12_p521_kx_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_tls12_p521_kx_server.addArg(
        "$1 p521-kx > /tmp/vail-tls12-p521-kx-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-521 -no_ticket -brief -ign_eof > /tmp/vail-tls12-p521-kx-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-tls12-p521-kx-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 P-521 ECDH negotiated' /tmp/vail-tls12-p521-kx-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-tls12-p521-kx-server.log && " ++
            "grep -q 'Peer Temp Key: ECDH, secp521r1, 521 bits' /tmp/vail-tls12-p521-kx-client.log && " ++
            "grep -q 'vail tls12 ok' /tmp/vail-tls12-p521-kx-client.log",
    );
    check_tls12_p521_kx_server.addArg("sh");
    check_tls12_p521_kx_server.addArtifactArg(min_tls12_server);
    const interop_tls12_p521_kx_server_step = b.step(
        "interop-openssl-tls12-p521-kx-server",
        "Exercise Vail's pure-Zig P-521 TLS 1.2 server key exchange",
    );
    interop_tls12_p521_kx_server_step.dependOn(
        &check_tls12_p521_kx_server.step,
    );

    const check_rustls_tls12_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_server.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_server.addArg(
        "$1 > /tmp/vail-min-tls12-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 8s bench/rustls_min_client/target/release/vail-rustls-tls12-client > /tmp/vail-min-tls12-rustls-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-rustls-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'TLS 1.2 client Finished verified' /tmp/vail-min-tls12-rustls-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-rustls-server.log && " ++
            "grep -q 'rustls TLS 1.2 connected' /tmp/vail-min-tls12-rustls-client.log && " ++
            "grep -q 'rustls TLS 1.2 application data verified' /tmp/vail-min-tls12-rustls-client.log",
    );
    check_rustls_tls12_server.addArg("sh");
    check_rustls_tls12_server.addArtifactArg(min_tls12_server);
    const interop_rustls_tls12_server_step = b.step(
        "interop-rustls-tls12-server",
        "Exercise Vail's TLS 1.2 server against rustls",
    );
    interop_rustls_tls12_server_step.dependOn(
        &check_rustls_tls12_server.step,
    );

    const check_rustls_tls12_p521_server = b.addSystemCommand(&.{
        "bash",
        "-c",
    });
    check_rustls_tls12_p521_server.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_p521_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-tls12-p521-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp521r1 -nodes -subj /CN=localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl pkcs8 -topk8 -nocrypt -in \"$work/key.pem\" -outform DER -out \"$work/key.der\"; " ++
            "openssl x509 -in \"$work/cert.pem\" -outform DER -out \"$work/cert.der\"; " ++
            "key_hex=$(xxd -p -c 100000 \"$work/key.der\"); " ++
            "cert_hex=$(xxd -p -c 100000 \"$work/cert.der\"); " ++
            "$1 p521 \"$key_hex\" \"$cert_hex\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s bench/rustls_min_client/target/release/vail-rustls-tls12-client p521 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 client Finished verified' \"$work/server.log\" && " ++
            "grep -q 'TLS 1.2 application data verified' \"$work/server.log\" && " ++
            "grep -q 'rustls TLS 1.2 connected' \"$work/client.log\" && " ++
            "grep -q 'rustls P-521 TLS 1.2 signature verified' \"$work/client.log\" && " ++
            "grep -q 'rustls TLS 1.2 application data verified' \"$work/client.log\"",
    );
    check_rustls_tls12_p521_server.addArg("bash");
    check_rustls_tls12_p521_server.addArtifactArg(min_tls12_server);
    const interop_rustls_tls12_p521_server_step = b.step(
        "interop-rustls-tls12-p521-server",
        "Exercise Vail's native P-521 TLS 1.2 signer with rustls/AWS-LC",
    );
    interop_rustls_tls12_p521_server_step.dependOn(
        &check_rustls_tls12_p521_server.step,
    );

    const check_rustls_tls12_key_log = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_key_log.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_key_log.addArg(
        "$1 keylog > /tmp/vail-tls12-keylog-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 8s bench/rustls_min_client/target/release/vail-rustls-tls12-client keylog > /tmp/vail-tls12-keylog-client.log 2>&1 || true; " ++
            "i=0; while [ $i -lt 20 ] && ! grep -q 'TLS 1.2 application data verified' /tmp/vail-tls12-keylog-server.log; do sleep 0.05; i=$((i + 1)); done; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "sed -n 's/^VAIL_KEY_LOG //p' /tmp/vail-tls12-keylog-server.log > /tmp/vail-tls12-keylog-vail.keys; " ++
            "sed -n 's/^RUSTLS_KEY_LOG //p' /tmp/vail-tls12-keylog-client.log > /tmp/vail-tls12-keylog-rustls.keys; " ++
            "test \"$(wc -l < /tmp/vail-tls12-keylog-vail.keys)\" -eq 1 && " ++
            "cmp /tmp/vail-tls12-keylog-vail.keys /tmp/vail-tls12-keylog-rustls.keys && " ++
            "grep -q 'rustls TLS 1.2 application data verified' /tmp/vail-tls12-keylog-client.log",
    );
    check_rustls_tls12_key_log.addArg("sh");
    check_rustls_tls12_key_log.addArtifactArg(min_tls12_server);
    const interop_rustls_tls12_key_log_step = b.step(
        "interop-rustls-tls12-keylog-server",
        "Compare Vail and rustls/AWS-LC NSS key logs for one TLS 1.2 session",
    );
    interop_rustls_tls12_key_log_step.dependOn(
        &check_rustls_tls12_key_log.step,
    );

    const min_tls12_client = b.addExecutable(.{
        .name = "vail-min-tls12-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_vail_tls12_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn http/1.1 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 server authenticated and Finished verified' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 suite=0xc02f alpn=http/1.1' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server application data verified' \"$work/client.log\"",
    );
    check_vail_tls12_client.addArg("sh");
    check_vail_tls12_client.addArtifactArg(min_tls12_client);
    const interop_vail_tls12_client_step = b.step(
        "interop-openssl-tls12-client",
        "Exercise Vail's TLS 1.2 client against OpenSSL",
    );
    interop_vail_tls12_client_step.dependOn(
        &check_vail_tls12_client.step,
    );

    const check_vail_tls12_p521_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_p521_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-p521.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-521 -nodes -subj /CN=localhost -days 1 -sha512 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -groups P-521 -sigalgs ecdsa_secp521r1_sha512 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn http/1.1 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 p521-all >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 P-521 ECDH negotiated' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server authenticated and Finished verified' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server application data verified' \"$work/client.log\"",
    );
    check_vail_tls12_p521_client.addArg("sh");
    check_vail_tls12_p521_client.addArtifactArg(min_tls12_client);
    const interop_vail_tls12_p521_client_step = b.step(
        "interop-openssl-tls12-p521-client",
        "Verify an OpenSSL P-521 TLS 1.2 server with Vail",
    );
    interop_vail_tls12_p521_client_step.dependOn(
        &check_vail_tls12_p521_client.step,
    );

    const check_vail_tls12_p521_kx_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_p521_kx_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-p521-kx.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-521 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn http/1.1 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 p521-kx >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 P-521 ECDH negotiated' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server authenticated and Finished verified' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server application data verified' \"$work/client.log\"",
    );
    check_vail_tls12_p521_kx_client.addArg("sh");
    check_vail_tls12_p521_kx_client.addArtifactArg(min_tls12_client);
    const interop_vail_tls12_p521_kx_client_step = b.step(
        "interop-openssl-tls12-p521-kx-client",
        "Exercise Vail's pure-Zig P-521 TLS 1.2 client key exchange",
    );
    interop_vail_tls12_p521_kx_client_step.dependOn(
        &check_vail_tls12_p521_kx_client.step,
    );

    const check_vail_tls12_client_matrix = b.addSystemCommand(&.{ "bash", "-c" });
    check_vail_tls12_client_matrix.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-matrix.XXXXXX); " ++
            "trap 'kill ${pid:-} 2>/dev/null || true; wait ${pid:-} 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/rsa-key.pem\" -out \"$work/rsa-cert.pem\" >/dev/null 2>&1; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/p256-key.pem\" -out \"$work/p256-cert.pem\" >/dev/null 2>&1; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -subj /CN=localhost -days 1 -keyout \"$work/p384-key.pem\" -out \"$work/p384-cert.pem\" >/dev/null 2>&1; " ++
            "for spec in 'x25519:ECDHE-RSA-AES128-GCM-SHA256:X25519:rsa:c02f' 'aes128:ECDHE-RSA-AES128-GCM-SHA256:P-256:rsa:c02f' 'aes256:ECDHE-RSA-AES256-GCM-SHA384:P-256:rsa:c030' 'chacha:ECDHE-RSA-CHACHA20-POLY1305:P-256:rsa:cca8' 'ecdsa-aes128:ECDHE-ECDSA-AES128-GCM-SHA256:P-256:p256:c02b' 'ecdsa-aes256:ECDHE-ECDSA-AES256-GCM-SHA384:P-384:p384:c02c' 'ecdsa-chacha:ECDHE-ECDSA-CHACHA20-POLY1305:P-256:p256:cca9'; do " ++
            "IFS=: read -r name cipher group identity wire <<<\"$spec\"; " ++
            "openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher \"$cipher\" -groups \"$group\" -no_ticket -cert \"$work/$identity-cert.pem\" -key \"$work/$identity-key.pem\" -alpn http/1.1 -www -naccept 1 >\"$work/server-$name.log\" 2>&1 & pid=$!; " ++
            "sleep 0.15; timeout 8s $1 \"$name\" >\"$work/client-$name.log\" 2>&1; wait $pid; " ++
            "grep -q \"TLS 1.2 suite=0x$wire alpn=http/1.1\" \"$work/client-$name.log\" && grep -q 'TLS 1.2 server application data verified' \"$work/client-$name.log\" || exit 1; " ++
            "done",
    );
    check_vail_tls12_client_matrix.addArg("bash");
    check_vail_tls12_client_matrix.addArtifactArg(min_tls12_client);
    const interop_vail_tls12_client_matrix_step = b.step(
        "interop-openssl-tls12-client-matrix",
        "Exercise every Vail TLS 1.2 AEAD suite against OpenSSL",
    );
    interop_vail_tls12_client_matrix_step.dependOn(
        &check_vail_tls12_client_matrix.step,
    );

    const check_vail_tls12_mtls_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_mtls_client.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-mtls-client.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/server.key\" -out \"$work/server.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert \"$work/server.pem\" -key \"$work/server.key\" -alpn http/1.1 -Verify 1 -verify_return_error -CAfile src/crypto/testdata/rsa_signing_client_cert.pem -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 mtls >\"$work/client.log\" 2>&1; wait $pid; " ++
            "grep -q 'verify return:1' \"$work/server.log\" && " ++
            "grep -q 'TLS 1.2 server authenticated and Finished verified' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server application data verified' \"$work/client.log\"",
    );
    check_vail_tls12_mtls_client.addArg("sh");
    check_vail_tls12_mtls_client.addArtifactArg(min_tls12_client);
    const interop_vail_tls12_mtls_client_step = b.step(
        "interop-openssl-tls12-mtls-client",
        "Exercise Vail's TLS 1.2 client certificate against OpenSSL",
    );
    interop_vail_tls12_mtls_client_step.dependOn(
        &check_vail_tls12_mtls_client.step,
    );

    const check_vail_tls12_mtls_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_mtls_server.addArg(
        "$1 mtls > /tmp/vail-min-tls12-mtls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert src/crypto/testdata/rsa_signing_client_cert.pem -key src/crypto/testdata/rsa_signing_key.pem -brief -ign_eof > /tmp/vail-min-tls12-mtls-client.log 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 client certificate verified' /tmp/vail-min-tls12-mtls-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-min-tls12-mtls-server.log && " ++
            "grep -q 'Protocol version: TLSv1.2' /tmp/vail-min-tls12-mtls-client.log && " ++
            "grep -q 'vail tls12 ok' /tmp/vail-min-tls12-mtls-client.log",
    );
    check_vail_tls12_mtls_server.addArg("sh");
    check_vail_tls12_mtls_server.addArtifactArg(min_tls12_server);
    const interop_vail_tls12_mtls_server_step = b.step(
        "interop-openssl-tls12-mtls-server",
        "Exercise Vail's TLS 1.2 client authentication with OpenSSL",
    );
    interop_vail_tls12_mtls_server_step.dependOn(
        &check_vail_tls12_mtls_server.step,
    );

    const check_vail_rustls_tls12_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_rustls_tls12_server.step.dependOn(&build_rustls_server.step);
    check_vail_rustls_tls12_server.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-tls12-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "bench/rustls_min_server/target/release/vail-rustls-tls12-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 >\"$work/client.log\" 2>&1; " ++
            "wait $pid; " ++
            "grep -q 'rustls TLS 1.2 server completed' \"$work/server.log\" && " ++
            "grep -q 'TLS 1.2 server authenticated and Finished verified' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 suite=0xc02f alpn=http/1.1' \"$work/client.log\" && " ++
            "grep -q 'TLS 1.2 server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_tls12_server.addArg("sh");
    check_vail_rustls_tls12_server.addArtifactArg(min_tls12_client);
    const interop_vail_rustls_tls12_server_step = b.step(
        "interop-rustls-tls12-client",
        "Exercise Vail's TLS 1.2 client against rustls",
    );
    interop_vail_rustls_tls12_server_step.dependOn(
        &check_vail_rustls_tls12_server.step,
    );

    const check_openssl_tls12_pkcs1_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_openssl_tls12_pkcs1_server.addArg(
        "timeout 15s $1 mtls-pkcs1 > /tmp/vail-openssl-tls12-pkcs1-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "printf ping | timeout 10s openssl s_client -connect 127.0.0.1:24446 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -sigalgs rsa_pkcs1_sha256 -no_ticket -cert src/crypto/testdata/rsa_signing_client_cert.pem -key src/crypto/testdata/rsa_signing_key.pem -ign_eof > /tmp/vail-openssl-tls12-pkcs1-client.log 2>&1 || true; " ++
            "wait $pid; server_status=$?; " ++
            "test $server_status -eq 0 && " ++
            "grep -q 'TLS 1.2 client certificate verified' /tmp/vail-openssl-tls12-pkcs1-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-openssl-tls12-pkcs1-server.log && " ++
            "grep -q 'Peer signature type: rsa_pkcs1_sha256' /tmp/vail-openssl-tls12-pkcs1-client.log",
    );
    check_openssl_tls12_pkcs1_server.addArg("sh");
    check_openssl_tls12_pkcs1_server.addArtifactArg(min_tls12_server);
    const interop_openssl_tls12_pkcs1_server_step = b.step(
        "interop-openssl-tls12-rsa-pkcs1-server",
        "Exercise Vail's TLS 1.2 RSA PKCS#1 server against OpenSSL",
    );
    interop_openssl_tls12_pkcs1_server_step.dependOn(
        &check_openssl_tls12_pkcs1_server.step,
    );

    const check_rustls_tls12_pkcs1_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_pkcs1_server.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_pkcs1_server.addArg(
        "timeout 15s $1 mtls-pkcs1 > /tmp/vail-rustls-tls12-pkcs1-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 10s bench/rustls_min_client/target/release/vail-rustls-tls12-client mtls-pkcs1 src/crypto/testdata/rsa_signing_client_cert.pem src/crypto/testdata/rsa_signing_key.pem > /tmp/vail-rustls-tls12-pkcs1-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'TLS 1.2 client certificate verified' /tmp/vail-rustls-tls12-pkcs1-server.log && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-rustls-tls12-pkcs1-server.log && " ++
            "grep -q 'rustls TLS 1.2 application data verified' /tmp/vail-rustls-tls12-pkcs1-client.log",
    );
    check_rustls_tls12_pkcs1_server.addArg("sh");
    check_rustls_tls12_pkcs1_server.addArtifactArg(min_tls12_server);
    const interop_rustls_tls12_pkcs1_server_step = b.step(
        "interop-rustls-tls12-rsa-pkcs1-server",
        "Exercise Vail's TLS 1.2 RSA PKCS#1 server against rustls/AWS-LC",
    );
    interop_rustls_tls12_pkcs1_server_step.dependOn(
        &check_rustls_tls12_pkcs1_server.step,
    );

    const check_openssl_tls12_pkcs1_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_openssl_tls12_pkcs1_client.addArg(
        "timeout 15s openssl s_server -accept 127.0.0.1:24447 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -sigalgs rsa_pkcs1_sha256 -no_ticket -cert src/crypto/testdata/rsa_signing_cert.pem -key src/crypto/testdata/rsa_signing_key.pem -alpn http/1.1 -Verify 1 -verify_return_error -CAfile src/crypto/testdata/rsa_signing_client_cert.pem -www -naccept 1 > /tmp/vail-openssl-tls12-pkcs1-client-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 10s $1 mtls-pkcs1 > /tmp/vail-openssl-tls12-pkcs1-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'verify return:1' /tmp/vail-openssl-tls12-pkcs1-client-server.log && " ++
            "grep -q 'TLS 1.2 server application data verified' /tmp/vail-openssl-tls12-pkcs1-client.log",
    );
    check_openssl_tls12_pkcs1_client.addArg("sh");
    check_openssl_tls12_pkcs1_client.addArtifactArg(min_tls12_client);
    const interop_openssl_tls12_pkcs1_client_step = b.step(
        "interop-openssl-tls12-rsa-pkcs1-client",
        "Exercise Vail's TLS 1.2 RSA PKCS#1 client against OpenSSL",
    );
    interop_openssl_tls12_pkcs1_client_step.dependOn(
        &check_openssl_tls12_pkcs1_client.step,
    );

    const check_rustls_tls12_pkcs1_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_pkcs1_client.step.dependOn(&build_rustls_server.step);
    check_rustls_tls12_pkcs1_client.addArg(
        "timeout 15s bench/rustls_min_server/target/release/vail-rustls-tls12-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem src/crypto/testdata/rsa_signing_client_cert.pem > /tmp/vail-rustls-tls12-pkcs1-client-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 10s $1 mtls-pkcs1 > /tmp/vail-rustls-tls12-pkcs1-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'rustls TLS 1.2 client certificate verified' /tmp/vail-rustls-tls12-pkcs1-client-server.log && " ++
            "grep -q 'rustls TLS 1.2 server completed' /tmp/vail-rustls-tls12-pkcs1-client-server.log && " ++
            "grep -q 'TLS 1.2 server application data verified' /tmp/vail-rustls-tls12-pkcs1-client.log",
    );
    check_rustls_tls12_pkcs1_client.addArg("sh");
    check_rustls_tls12_pkcs1_client.addArtifactArg(min_tls12_client);
    const interop_rustls_tls12_pkcs1_client_step = b.step(
        "interop-rustls-tls12-rsa-pkcs1-client",
        "Exercise Vail's TLS 1.2 RSA PKCS#1 client against rustls/AWS-LC",
    );
    interop_rustls_tls12_pkcs1_client_step.dependOn(
        &check_rustls_tls12_pkcs1_client.step,
    );

    const check_rustls_tls12_ocsp_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_ocsp_server.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_ocsp_server.addArg(
        "timeout 15s $1 ocsp > /tmp/vail-rustls-tls12-ocsp-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 10s bench/rustls_min_client/target/release/vail-rustls-tls12-client ocsp > /tmp/vail-rustls-tls12-ocsp-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'TLS 1.2 application data verified' /tmp/vail-rustls-tls12-ocsp-server.log && " ++
            "grep -q 'rustls TLS 1.2 application data verified' /tmp/vail-rustls-tls12-ocsp-client.log",
    );
    check_rustls_tls12_ocsp_server.addArg("sh");
    check_rustls_tls12_ocsp_server.addArtifactArg(min_tls12_server);
    const interop_rustls_tls12_ocsp_server_step = b.step(
        "interop-rustls-tls12-ocsp-server",
        "Exercise Vail's TLS 1.2 OCSP stapling with rustls/AWS-LC",
    );
    interop_rustls_tls12_ocsp_server_step.dependOn(
        &check_rustls_tls12_ocsp_server.step,
    );

    const check_rustls_tls12_ocsp_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_ocsp_client.step.dependOn(&build_rustls_server.step);
    check_rustls_tls12_ocsp_client.addArg(
        "timeout 15s bench/rustls_min_server/target/release/vail-rustls-tls12-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem ocsp > /tmp/vail-rustls-tls12-ocsp-client-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 10s $1 ocsp > /tmp/vail-rustls-tls12-ocsp-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'rustls TLS 1.2 server completed' /tmp/vail-rustls-tls12-ocsp-client-server.log && " ++
            "grep -q 'TLS 1.2 server application data verified' /tmp/vail-rustls-tls12-ocsp-client.log",
    );
    check_rustls_tls12_ocsp_client.addArg("sh");
    check_rustls_tls12_ocsp_client.addArtifactArg(min_tls12_client);
    const interop_rustls_tls12_ocsp_client_step = b.step(
        "interop-rustls-tls12-ocsp-client",
        "Exercise Vail's TLS 1.2 OCSP client against rustls/AWS-LC",
    );
    interop_rustls_tls12_ocsp_client_step.dependOn(
        &check_rustls_tls12_ocsp_client.step,
    );

    const min_tls12_resume_client = b.addExecutable(.{
        .name = "vail-min-tls12-resume-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_resume_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_vail_tls12_resumption = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_resumption.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-resume.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "timeout 20s openssl s_server -accept 127.0.0.1:24448 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn http/1.1 -www -naccept 2 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.5; timeout 12s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
            "grep -q 'TLS 1.2 session resumption verified' \"$work/client.log\" && " ++
            "grep -q '2 server accepts that finished' \"$work/server.log\" && " ++
            "grep -q '1 session cache hits' \"$work/server.log\"",
    );
    check_vail_tls12_resumption.addArg("sh");
    check_vail_tls12_resumption.addArtifactArg(min_tls12_resume_client);
    const interop_vail_tls12_resumption_step = b.step(
        "interop-openssl-tls12-resumption-client",
        "Exercise Vail's TLS 1.2 session-ID resumption against OpenSSL",
    );
    interop_vail_tls12_resumption_step.dependOn(
        &check_vail_tls12_resumption.step,
    );

    const min_tls12_resume_server = b.addExecutable(.{
        .name = "vail-min-tls12-resume-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_resume_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_vail_tls12_server_resumption = b.addSystemCommand(&.{ "sh", "-c" });
    check_vail_tls12_server_resumption.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-resume-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "timeout 20s $1 >\"$work/server.log\" 2>&1 & pid=$!; sleep 0.5; " ++
            "printf one | timeout 8s openssl s_client -connect 127.0.0.1:24449 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -sess_out \"$work/session.pem\" -ign_eof >\"$work/client1.log\" 2>&1 || true; " ++
            "printf two | timeout 8s openssl s_client -connect 127.0.0.1:24449 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -sess_in \"$work/session.pem\" -ign_eof >\"$work/client2.log\" 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'TLS 1.2 server session resumption verified' \"$work/server.log\" && " ++
            "grep -q 'vail resumed tls12 ok' \"$work/client1.log\" && " ++
            "grep -q 'vail resumed tls12 ok' \"$work/client2.log\" && " ++
            "grep -q 'Reused, TLSv1.2' \"$work/client2.log\"",
    );
    check_vail_tls12_server_resumption.addArg("sh");
    check_vail_tls12_server_resumption.addArtifactArg(min_tls12_resume_server);
    const interop_vail_tls12_server_resumption_step = b.step(
        "interop-openssl-tls12-resumption-server",
        "Exercise Vail's TLS 1.2 session-ID resumption server against OpenSSL",
    );
    interop_vail_tls12_server_resumption_step.dependOn(
        &check_vail_tls12_server_resumption.step,
    );

    const check_rustls_tls12_server_resumption = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_server_resumption.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_server_resumption.addArg(
        "timeout 20s $1 > /tmp/vail-rustls-tls12-resume-server.log 2>&1 & pid=$!; " ++
            "sleep 0.5; timeout 12s bench/rustls_min_client/target/release/vail-rustls-tls12-resume-client > /tmp/vail-rustls-tls12-resume-client.log 2>&1; wait $pid; " ++
            "grep -q 'TLS 1.2 server session resumption verified' /tmp/vail-rustls-tls12-resume-server.log && " ++
            "grep -q 'rustls TLS 1.2 session resumption verified' /tmp/vail-rustls-tls12-resume-client.log",
    );
    check_rustls_tls12_server_resumption.addArg("sh");
    check_rustls_tls12_server_resumption.addArtifactArg(
        min_tls12_resume_server,
    );
    const interop_rustls_tls12_server_resumption_step = b.step(
        "interop-rustls-tls12-resumption-server",
        "Exercise Vail's TLS 1.2 session-ID server against rustls/AWS-LC",
    );
    interop_rustls_tls12_server_resumption_step.dependOn(
        &check_rustls_tls12_server_resumption.step,
    );

    const check_rustls_tls12_client_resumption = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_client_resumption.step.dependOn(&build_rustls_server.step);
    check_rustls_tls12_client_resumption.addArg(
        "work=$(mktemp -d /tmp/vail-rustls-tls12-resume-client.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "timeout 20s bench/rustls_min_server/target/release/vail-rustls-tls12-resume-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.5; timeout 12s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
            "grep -q 'rustls TLS 1.2 session resumption verified' \"$work/server.log\" && " ++
            "grep -q 'TLS 1.2 session resumption verified' \"$work/client.log\"",
    );
    check_rustls_tls12_client_resumption.addArg("sh");
    check_rustls_tls12_client_resumption.addArtifactArg(
        min_tls12_resume_client,
    );
    const interop_rustls_tls12_client_resumption_step = b.step(
        "interop-rustls-tls12-resumption-client",
        "Exercise Vail's TLS 1.2 session-ID client against rustls/AWS-LC",
    );
    interop_rustls_tls12_client_resumption_step.dependOn(
        &check_rustls_tls12_client_resumption.step,
    );

    const min_tls12_ticket_server = b.addExecutable(.{
        .name = "vail-min-tls12-ticket-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_ticket_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_openssl_tls12_ticket_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_openssl_tls12_ticket_server.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-ticket-server.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "timeout 20s $1 >\"$work/server.log\" 2>&1 & pid=$!; sleep 0.5; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24454 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -alpn http/1.1 -sess_out \"$work/session.pem\" -ign_eof >\"$work/client1.log\" 2>&1 || true; " ++
            "test -s \"$work/session.pem\"; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24454 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -alpn http/1.1 -sess_in \"$work/session.pem\" -ign_eof >\"$work/client2.log\" 2>&1 || true; " ++
            "wait $pid; " ++
            "grep -q 'Vail TLS 1.2 stateless ticket resumption verified' \"$work/server.log\" && " ++
            "grep -q 'Reused, TLSv1.2' \"$work/client2.log\"",
    );
    check_openssl_tls12_ticket_server.addArg("sh");
    check_openssl_tls12_ticket_server.addArtifactArg(min_tls12_ticket_server);
    const interop_openssl_tls12_ticket_server_step = b.step(
        "interop-openssl-tls12-ticket-server",
        "Exercise Vail's TLS 1.2 stateless-ticket server against OpenSSL",
    );
    interop_openssl_tls12_ticket_server_step.dependOn(
        &check_openssl_tls12_ticket_server.step,
    );

    const check_rustls_tls12_ticket_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_ticket_server.step.dependOn(&build_rustls_min.step);
    check_rustls_tls12_ticket_server.addArg(
        "timeout 20s $1 > /tmp/vail-rustls-tls12-ticket-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 18s bench/rustls_min_client/target/release/vail-rustls-tls12-ticket-client > /tmp/vail-rustls-tls12-ticket-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail TLS 1.2 stateless ticket resumption verified' /tmp/vail-rustls-tls12-ticket-server.log && " ++
            "grep -q 'rustls/AWS-LC TLS 1.2 ticket resumption verified' /tmp/vail-rustls-tls12-ticket-client.log",
    );
    check_rustls_tls12_ticket_server.addArg("sh");
    check_rustls_tls12_ticket_server.addArtifactArg(min_tls12_ticket_server);
    const interop_rustls_tls12_ticket_server_step = b.step(
        "interop-rustls-tls12-ticket-server",
        "Exercise Vail's TLS 1.2 stateless-ticket server against rustls/AWS-LC",
    );
    interop_rustls_tls12_ticket_server_step.dependOn(
        &check_rustls_tls12_ticket_server.step,
    );

    const min_tls12_ticket_client = b.addExecutable(.{
        .name = "vail-min-tls12-ticket-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_tls12_ticket_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_openssl_tls12_ticket_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_openssl_tls12_ticket_client.addArg(
        "timeout 20s openssl s_server -accept 127.0.0.1:24455 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -cert src/crypto/testdata/rsa_signing_cert.pem -key src/crypto/testdata/rsa_signing_key.pem -alpn http/1.1 -www -naccept 2 -no_cache > /tmp/vail-openssl-tls12-ticket-client-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 18s $1 > /tmp/vail-openssl-tls12-ticket-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail TLS 1.2 ticket resumption verified' /tmp/vail-openssl-tls12-ticket-client.log && " ++
            "grep -q '1 session cache hits' /tmp/vail-openssl-tls12-ticket-client-server.log",
    );
    check_openssl_tls12_ticket_client.addArg("sh");
    check_openssl_tls12_ticket_client.addArtifactArg(min_tls12_ticket_client);
    const interop_openssl_tls12_ticket_client_step = b.step(
        "interop-openssl-tls12-ticket-client",
        "Exercise Vail's TLS 1.2 ticket client against OpenSSL",
    );
    interop_openssl_tls12_ticket_client_step.dependOn(
        &check_openssl_tls12_ticket_client.step,
    );

    const check_rustls_tls12_ticket_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_tls12_ticket_client.step.dependOn(&build_rustls_server.step);
    check_rustls_tls12_ticket_client.addArg(
        "timeout 20s bench/rustls_min_server/target/release/vail-rustls-tls12-ticket-server src/crypto/testdata/rsa_signing_cert.pem src/crypto/testdata/rsa_signing_key.pem > /tmp/vail-rustls-tls12-ticket-client-server.log 2>&1 & pid=$!; sleep 0.5; " ++
            "timeout 18s $1 > /tmp/vail-rustls-tls12-ticket-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail TLS 1.2 ticket resumption verified' /tmp/vail-rustls-tls12-ticket-client.log && " ++
            "grep -q 'rustls/AWS-LC TLS 1.2 ticket resumption verified' /tmp/vail-rustls-tls12-ticket-client-server.log",
    );
    check_rustls_tls12_ticket_client.addArg("sh");
    check_rustls_tls12_ticket_client.addArtifactArg(min_tls12_ticket_client);
    const interop_rustls_tls12_ticket_client_step = b.step(
        "interop-rustls-tls12-ticket-client",
        "Exercise Vail's TLS 1.2 ticket client against rustls/AWS-LC",
    );
    interop_rustls_tls12_ticket_client_step.dependOn(
        &check_rustls_tls12_ticket_client.step,
    );

    const min_versioned_server = b.addExecutable(.{
        .name = "vail-min-versioned-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_versioned_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_versioned_tls13 = b.addSystemCommand(&.{ "sh", "-c" });
    check_versioned_tls13.addArg(
        "$1 > /tmp/vail-versioned-tls13-server.log 2>&1 & pid=$!; sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24450 -tls1_3 -groups X25519 -alpn h2 -ign_eof > /tmp/vail-versioned-tls13-client.log 2>&1 || true; wait $pid; " ++
            "grep -q 'versioned server selected TLS 1.3' /tmp/vail-versioned-tls13-server.log && " ++
            "grep -q 'vail auto tls13 ok' /tmp/vail-versioned-tls13-client.log",
    );
    check_versioned_tls13.addArg("sh");
    check_versioned_tls13.addArtifactArg(min_versioned_server);
    const interop_versioned_tls13_step = b.step(
        "interop-openssl-versioned-server-tls13",
        "Exercise automatic TLS 1.3 server negotiation with OpenSSL",
    );
    interop_versioned_tls13_step.dependOn(&check_versioned_tls13.step);

    const check_versioned_tls12 = b.addSystemCommand(&.{ "sh", "-c" });
    check_versioned_tls12.addArg(
        "$1 > /tmp/vail-versioned-tls12-server.log 2>&1 & pid=$!; sleep 0.2; " ++
            "printf ping | timeout 8s openssl s_client -connect 127.0.0.1:24450 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -alpn http/1.1 -ign_eof > /tmp/vail-versioned-tls12-client.log 2>&1 || true; wait $pid; " ++
            "grep -q 'versioned server selected TLS 1.2' /tmp/vail-versioned-tls12-server.log && " ++
            "grep -q 'vail auto tls12 ok' /tmp/vail-versioned-tls12-client.log",
    );
    check_versioned_tls12.addArg("sh");
    check_versioned_tls12.addArtifactArg(min_versioned_server);
    const interop_versioned_tls12_step = b.step(
        "interop-openssl-versioned-server-tls12",
        "Exercise automatic TLS 1.2 server negotiation with OpenSSL",
    );
    interop_versioned_tls12_step.dependOn(&check_versioned_tls12.step);

    const min_versioned_client = b.addExecutable(.{
        .name = "vail-min-versioned-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_versioned_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_versioned_client_tls13 = b.addSystemCommand(&.{ "sh", "-c" });
    check_versioned_client_tls13.addArg(
        "work=$(mktemp -d /tmp/vail-versioned-client-tls13.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24451 -tls1_3 -groups X25519 -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
            "grep -q 'versioned client selected TLS 1.3' \"$work/client.log\" && grep -q 'versioned client application data verified' \"$work/client.log\"",
    );
    check_versioned_client_tls13.addArg("sh");
    check_versioned_client_tls13.addArtifactArg(min_versioned_client);
    const interop_versioned_client_tls13_step = b.step(
        "interop-openssl-versioned-client-tls13",
        "Exercise automatic TLS 1.3 client negotiation with OpenSSL",
    );
    interop_versioned_client_tls13_step.dependOn(
        &check_versioned_client_tls13.step,
    );

    const check_versioned_client_tls12 = b.addSystemCommand(&.{ "sh", "-c" });
    check_versioned_client_tls12.addArg(
        "work=$(mktemp -d /tmp/vail-versioned-client-tls12.XXXXXX); " ++
            "trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/key.pem\" -out \"$work/cert.pem\" >/dev/null 2>&1; " ++
            "openssl s_server -accept 127.0.0.1:24451 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn h2 -www -naccept 1 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 8s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
            "grep -q 'versioned client selected TLS 1.2' \"$work/client.log\" && grep -q 'versioned client application data verified' \"$work/client.log\"",
    );
    check_versioned_client_tls12.addArg("sh");
    check_versioned_client_tls12.addArtifactArg(min_versioned_client);
    const interop_versioned_client_tls12_step = b.step(
        "interop-openssl-versioned-client-tls12",
        "Exercise automatic TLS 1.2 client negotiation with OpenSSL",
    );
    interop_versioned_client_tls12_step.dependOn(
        &check_versioned_client_tls12.step,
    );

    const min_rpk_server = b.addExecutable(.{
        .name = "vail-min-rpk-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_rpk_server.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_rpk_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_rpk_client.step.dependOn(&build_rustls_min.step);
    check_rustls_rpk_client.addArg(
        "timeout 15s $1 > /tmp/vail-rpk-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s bench/rustls_min_client/target/release/vail-rustls-rpk-client src/crypto/testdata/rsa_signing_key.pem > /tmp/rustls-rpk-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'Vail server verified mutual RFC 7250 RPK' /tmp/vail-rpk-server.log && " ++
            "grep -q 'rustls/AWS-LC client verified mutual RFC 7250 RPK' /tmp/rustls-rpk-client.log",
    );
    check_rustls_rpk_client.addArg("sh");
    check_rustls_rpk_client.addArtifactArg(min_rpk_server);
    const interop_rustls_rpk_server_step = b.step(
        "interop-rustls-rpk-server",
        "Exercise Vail's mutual-RPK server against rustls/AWS-LC",
    );
    interop_rustls_rpk_server_step.dependOn(
        &check_rustls_rpk_client.step,
    );
    const check_rustls_mldsa_rpk_client = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_mldsa_rpk_client.step.dependOn(&build_rustls_min.step);
    check_rustls_mldsa_rpk_client.addArg(
        "for mode in mldsa44 mldsa65 mldsa87; do " ++
            "case $mode in mldsa44) scheme=ML_DSA_44;; mldsa65) scheme=ML_DSA_65;; mldsa87) scheme=ML_DSA_87;; esac; " ++
            "timeout 30s $1 $mode > /tmp/vail-mldsa-rpk-server-$mode.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 25s bench/rustls_min_client/target/release/vail-rustls-rpk-client src/crypto/testdata/rsa_signing_key.pem $mode > /tmp/rustls-mldsa-rpk-client-$mode.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q \"scheme=$scheme\" /tmp/vail-mldsa-rpk-server-$mode.log && " ++
            "grep -q \"scheme=$scheme\" /tmp/rustls-mldsa-rpk-client-$mode.log || exit 1; " ++
            "done",
    );
    check_rustls_mldsa_rpk_client.addArg("sh");
    check_rustls_mldsa_rpk_client.addArtifactArg(min_rpk_server);
    const interop_rustls_mldsa_rpk_server_step = b.step(
        "interop-rustls-mldsa-rpk-server",
        "Exercise Vail's ML-DSA-44/65/87 RPK server with rustls/AWS-LC",
    );
    interop_rustls_mldsa_rpk_server_step.dependOn(
        &check_rustls_mldsa_rpk_client.step,
    );

    const min_rpk_client = b.addExecutable(.{
        .name = "vail-min-rpk-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/interop/min_rpk_client.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "vail", .module = vail }},
        }),
    });
    const check_rustls_rpk_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_rpk_server.step.dependOn(&build_rustls_server.step);
    check_rustls_rpk_server.addArg(
        "timeout 15s bench/rustls_min_server/target/release/vail-rustls-rpk-server src/crypto/testdata/rsa_signing_key.pem > /tmp/rustls-rpk-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s $1 > /tmp/vail-rpk-client.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q 'rustls/AWS-LC server verified mutual RFC 7250 RPK' /tmp/rustls-rpk-server.log && " ++
            "grep -q 'Vail client verified mutual RFC 7250 RPK' /tmp/vail-rpk-client.log",
    );
    check_rustls_rpk_server.addArg("sh");
    check_rustls_rpk_server.addArtifactArg(min_rpk_client);
    const interop_rustls_rpk_client_step = b.step(
        "interop-rustls-rpk-client",
        "Exercise Vail's mutual-RPK client against rustls/AWS-LC",
    );
    interop_rustls_rpk_client_step.dependOn(
        &check_rustls_rpk_server.step,
    );
    const check_rustls_mldsa_rpk_server = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_mldsa_rpk_server.step.dependOn(&build_rustls_server.step);
    check_rustls_mldsa_rpk_server.addArg(
        "for mode in mldsa44 mldsa65 mldsa87; do " ++
            "case $mode in mldsa44) scheme=ML_DSA_44;; mldsa65) scheme=ML_DSA_65;; mldsa87) scheme=ML_DSA_87;; esac; " ++
            "timeout 30s bench/rustls_min_server/target/release/vail-rustls-rpk-server src/crypto/testdata/rsa_signing_key.pem $mode > /tmp/rustls-mldsa-rpk-server-$mode.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 25s $1 $mode > /tmp/vail-mldsa-rpk-client-$mode.log 2>&1; client_status=$?; " ++
            "wait $pid; server_status=$?; " ++
            "test $client_status -eq 0 -a $server_status -eq 0 && " ++
            "grep -q \"scheme=$scheme\" /tmp/rustls-mldsa-rpk-server-$mode.log && " ++
            "grep -q \"scheme=$scheme\" /tmp/vail-mldsa-rpk-client-$mode.log || exit 1; " ++
            "done",
    );
    check_rustls_mldsa_rpk_server.addArg("sh");
    check_rustls_mldsa_rpk_server.addArtifactArg(min_rpk_client);
    const interop_rustls_mldsa_rpk_client_step = b.step(
        "interop-rustls-mldsa-rpk-client",
        "Exercise Vail's ML-DSA-44/65/87 RPK client with rustls/AWS-LC",
    );
    interop_rustls_mldsa_rpk_client_step.dependOn(
        &check_rustls_mldsa_rpk_server.step,
    );

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
        "build",
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

    const example_names = [_][]const u8{ "sha256", "aes_gcm", "mac" };
    const examples_step = b.step("examples", "Build example programs");
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
    check_step.dependOn(examples_step);
}
