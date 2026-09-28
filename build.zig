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
    const openssl_ch_hex = openssl_ch.addOutputFileArg("openssl-clienthello.hex");
    const check_openssl_ch = b.addRunArtifact(client_hello_check);
    check_openssl_ch.addFileArg(openssl_ch_hex);
    check_openssl_ch.addArg("example.com");
    check_openssl_ch.addArg("1301");
    const interop_openssl_step = b.step(
        "interop-openssl-clienthello",
        "Parse a real OpenSSL TLS 1.3 ClientHello",
    );
    interop_openssl_step.dependOn(&check_openssl_ch.step);

    const rustls_ch = b.addSystemCommand(&.{
        "cargo",
        "run",
        "--release",
        "--manifest-path",
        "bench/rustls_client_hello/Cargo.toml",
    });
    const rustls_ch_hex = rustls_ch.captureStdOut(.{});
    const check_rustls_ch = b.addRunArtifact(client_hello_check);
    check_rustls_ch.addFileArg(rustls_ch_hex);
    check_rustls_ch.addArg("example.com");
    check_rustls_ch.addArg("1301");
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
        "--manifest-path",
        "bench/rustls_min_client/Cargo.toml",
    });
    const check_rustls_min = b.addSystemCommand(&.{ "sh", "-c" });
    check_rustls_min.step.dependOn(&build_rustls_min.step);
    check_rustls_min.addArg(
        "$1 > /tmp/vail-min-rustls-server.log 2>&1 & pid=$!; " ++
            "sleep 0.2; " ++
            "timeout 4s bench/rustls_min_client/target/release/vail-rustls-min-client > /tmp/vail-min-rustls-client.log 2>&1 || true; " ++
            "kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true; " ++
            "grep -q 'client finished verified' /tmp/vail-min-rustls-server.log && " ++
            "grep -q 'rustls connected' /tmp/vail-min-rustls-client.log",
    );
    check_rustls_min.addArg("sh");
    check_rustls_min.addArtifactArg(min_tls13_server);
    const interop_rustls_min_step = b.step(
        "interop-rustls-min-server",
        "Exercise Vail's minimal TLS 1.3 server flight with rustls client",
    );
    interop_rustls_min_step.dependOn(&check_rustls_min.step);
}
