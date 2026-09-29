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

    const vail = b.addModule("vail", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    _ = b.addModule("vail_sm", .{
        .root_source_file = b.path("src/crypto/sm.zig"),
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

    const tls_record_bench = b.addExecutable(.{
        .name = "vail-bench-tls-record-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls_record_crypto.zig"),
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
            .root_source_file = b.path("bench/tls12_record_crypto.zig"),
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

    const tls_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls-server-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls_server_handshake.zig"),
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

    const x509_path_bench = b.addExecutable(.{
        .name = "vail-bench-x509-path",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/x509_path.zig"),
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
            .root_source_file = b.path("bench/certificate_compression.zig"),
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
        "Benchmark RFC 8879 zlib certificate compression",
    );
    certificate_compression_bench_step.dependOn(
        &run_certificate_compression_bench.step,
    );

    const rsa_pss_bench = b.addExecutable(.{
        .name = "vail-bench-rsa-pss",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/rsa_pss.zig"),
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

    const tls12_handshake_bench = b.addExecutable(.{
        .name = "vail-bench-tls12-server-handshake",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls12_server_handshake.zig"),
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
            .root_source_file = b.path("bench/tls12_client_handshake.zig"),
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
            "grep -q 'certificate compression=zlib' \"$work/client.log\" && " ++
            "grep -q 'server application data verified' \"$work/client.log\"",
    );
    check_vail_rustls_server.addArg("sh");
    check_vail_rustls_server.addArtifactArg(min_tls13_client);
    const interop_vail_rustls_server_step = b.step(
        "interop-rustls-min-client",
        "Exercise Vail's TLS 1.3 client against a zlib-enabled rustls server",
    );
    interop_vail_rustls_server_step.dependOn(
        &check_vail_rustls_server.step,
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

    const check_vail_tls12_client_matrix = b.addSystemCommand(&.{ "bash", "-c" });
    check_vail_tls12_client_matrix.addArg(
        "work=$(mktemp -d /tmp/vail-openssl-tls12-matrix.XXXXXX); " ++
            "trap 'kill ${pid:-} 2>/dev/null || true; wait ${pid:-} 2>/dev/null || true; rm -rf \"$work\"' EXIT; " ++
            "openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 -keyout \"$work/rsa-key.pem\" -out \"$work/rsa-cert.pem\" >/dev/null 2>&1; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -days 1 -keyout \"$work/p256-key.pem\" -out \"$work/p256-cert.pem\" >/dev/null 2>&1; " ++
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -subj /CN=localhost -days 1 -keyout \"$work/p384-key.pem\" -out \"$work/p384-cert.pem\" >/dev/null 2>&1; " ++
            "for spec in 'aes128:ECDHE-RSA-AES128-GCM-SHA256:P-256:rsa:c02f' 'aes256:ECDHE-RSA-AES256-GCM-SHA384:P-256:rsa:c030' 'chacha:ECDHE-RSA-CHACHA20-POLY1305:P-256:rsa:cca8' 'ecdsa-aes128:ECDHE-ECDSA-AES128-GCM-SHA256:P-256:p256:c02b' 'ecdsa-aes256:ECDHE-ECDSA-AES256-GCM-SHA384:P-384:p384:c02c' 'ecdsa-chacha:ECDHE-ECDSA-CHACHA20-POLY1305:P-256:p256:cca9'; do " ++
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
            "openssl s_server -accept 127.0.0.1:24448 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups P-256 -no_ticket -cert \"$work/cert.pem\" -key \"$work/key.pem\" -alpn http/1.1 -www -naccept 2 >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
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
            "$1 >\"$work/server.log\" 2>&1 & pid=$!; sleep 0.2; " ++
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
        "$1 > /tmp/vail-rustls-tls12-resume-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s bench/rustls_min_client/target/release/vail-rustls-tls12-resume-client > /tmp/vail-rustls-tls12-resume-client.log 2>&1; wait $pid; " ++
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
            "bench/rustls_min_server/target/release/vail-rustls-tls12-resume-server \"$work/cert.pem\" \"$work/key.pem\" >\"$work/server.log\" 2>&1 & pid=$!; " ++
            "sleep 0.2; timeout 12s $1 >\"$work/client.log\" 2>&1; wait $pid; " ++
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
}
