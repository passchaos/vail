//! Benchmark build graph.

const std = @import("std");
const mldsa_benchmarks = @import("mldsa_benchmarks.zig");
const mlkem_benchmarks = @import("mlkem_benchmarks.zig");

pub fn add(
    b: *std.Build,
    vail: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
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
}
