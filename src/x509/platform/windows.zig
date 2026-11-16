//! Windows platform certificate verification through CryptoAPI/WinTrust.
//!
//! `CertGetCertificateChain` uses the Windows certificate stores and AIA
//! retrieval; `CertVerifyCertificateChainPolicy` applies the system SSL policy,
//! including enterprise-installed roots and platform revocation behavior.

const std = @import("std");
const x509_verifier = @import("../verifier.zig");

const c = @cImport({
    @cDefine("WIN32_LEAN_AND_MEAN", "1");
    @cDefine("NOMINMAX", "1");
    @cInclude("windows.h");
    @cInclude("wincrypt.h");
    @cInclude("wintrust.h");
});

const CERT_STORE_PROV_MEMORY: c.LPCSTR = @ptrFromInt(1);
const CERT_CHAIN_POLICY_SSL: c.LPCSTR = @ptrFromInt(4);
const AUTHTYPE_SERVER: c.DWORD = 0x00000002;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: c.DWORD = 0x00001000;

pub const Options = struct {
    verify_host: bool = true,
};

pub const Verifier = struct {
    allocator: std.mem.Allocator,
    verify_host: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) !Verifier {
        return .{
            .allocator = allocator,
            .verify_host = options.verify_host,
        };
    }

    pub fn deinit(self: *Verifier) void {
        _ = self;
    }

    pub fn clientVerifier(self: *const Verifier) x509_verifier.TrustVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust: x509_verifier.TrustContext,
    ) anyerror!void {
        const self: *const Verifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verify(trust);
    }

    fn verify(self: *const Verifier, trust: x509_verifier.TrustContext) !void {
        if (trust.chain.len == 0) return error.EmptyCertificateChain;

        const leaf_der = trust.chain[0];
        const leaf = c.CertCreateCertificateContext(
            c.X509_ASN_ENCODING | c.PKCS_7_ASN_ENCODING,
            leaf_der.ptr,
            @intCast(leaf_der.len),
        ) orelse return error.InvalidCertificate;
        defer _ = c.CertFreeCertificateContext(leaf);

        const store = c.CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            0,
            0,
            c.CERT_STORE_CREATE_NEW_FLAG,
            null,
        ) orelse return error.OutOfMemory;
        defer _ = c.CertCloseStore(store, 0);

        for (trust.chain[1..]) |der| {
            const certificate = c.CertCreateCertificateContext(
                c.X509_ASN_ENCODING | c.PKCS_7_ASN_ENCODING,
                der.ptr,
                @intCast(der.len),
            ) orelse return error.InvalidCertificate;
            defer _ = c.CertFreeCertificateContext(certificate);
            if (c.CertAddCertificateContextToStore(
                store,
                certificate,
                c.CERT_STORE_ADD_ALWAYS,
                null,
            ) == 0) {
                return error.CertificateUntrusted;
            }
        }

        var chain_para: c.CERT_CHAIN_PARA = std.mem.zeroes(c.CERT_CHAIN_PARA);
        chain_para.cbSize = @sizeOf(c.CERT_CHAIN_PARA);
        var chain: c.PCCERT_CHAIN_CONTEXT = null;
        if (c.CertGetCertificateChain(
            null,
            leaf,
            null,
            store,
            &chain_para,
            0,
            null,
            &chain,
        ) == 0) {
            return error.CertificateUntrusted;
        }
        defer c.CertFreeCertificateChain(chain);

        var server_name: ?[:0]u16 = null;
        defer if (server_name) |name| self.allocator.free(name);
        if (self.verify_host) {
            const name = trust.server_name orelse
                return error.MissingServerName;
            server_name = try std.unicode.utf8ToUtf16LeAllocZ(
                self.allocator,
                name,
            );
        }

        var ssl_para: c.SSL_EXTRA_CERT_CHAIN_POLICY_PARA =
            std.mem.zeroes(c.SSL_EXTRA_CERT_CHAIN_POLICY_PARA);
        ssl_para.unnamed_0.cbSize = @sizeOf(c.SSL_EXTRA_CERT_CHAIN_POLICY_PARA);
        ssl_para.dwAuthType = AUTHTYPE_SERVER;
        if (self.verify_host) {
            ssl_para.pwszServerName = server_name.?.ptr;
        } else {
            ssl_para.fdwChecks = SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        }

        var policy_para: c.CERT_CHAIN_POLICY_PARA =
            std.mem.zeroes(c.CERT_CHAIN_POLICY_PARA);
        policy_para.cbSize = @sizeOf(c.CERT_CHAIN_POLICY_PARA);
        policy_para.pvExtraPolicyPara = @ptrCast(&ssl_para);

        var status: c.CERT_CHAIN_POLICY_STATUS =
            std.mem.zeroes(c.CERT_CHAIN_POLICY_STATUS);
        status.cbSize = @sizeOf(c.CERT_CHAIN_POLICY_STATUS);
        if (c.CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            chain,
            &policy_para,
            &status,
        ) == 0) {
            return error.CertificateUntrusted;
        }
        if (status.dwError != 0) return error.CertificateUntrusted;
    }
};
