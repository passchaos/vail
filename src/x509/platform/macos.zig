//! macOS platform certificate verification through Security.framework.
//!
//! The SDK headers are declared manually because Zig's C importer currently
//! cannot translate this host's macOS SDK headers. The called ABI is stable
//! CoreFoundation/Security C API.

const std = @import("std");
const x509_verifier = @import("../verifier.zig");

const CFAllocatorRef = ?*const anyopaque;
const CFTypeRef = *const anyopaque;
const CFDataRef = *const anyopaque;
const CFStringRef = *const anyopaque;
const CFArrayRef = *const anyopaque;
const CFErrorRef = *const anyopaque;
const SecCertificateRef = *const anyopaque;
const SecPolicyRef = *const anyopaque;
const SecTrustRef = *const anyopaque;
const CFIndex = isize;
const CFStringEncoding = u32;
const Boolean = u8;
const OSStatus = i32;
const CFArrayCallBacks = opaque {};

const kCFStringEncodingUTF8: CFStringEncoding = 0x08000100;
const errSecSuccess: OSStatus = 0;

extern const kCFTypeArrayCallBacks: CFArrayCallBacks;

extern fn CFDataCreate(
    allocator: CFAllocatorRef,
    bytes: [*c]const u8,
    length: CFIndex,
) ?CFDataRef;
extern fn CFStringCreateWithCString(
    allocator: CFAllocatorRef,
    c_str: [*c]const u8,
    encoding: CFStringEncoding,
) ?CFStringRef;
extern fn CFArrayCreate(
    allocator: CFAllocatorRef,
    values: [*c]const ?*const anyopaque,
    num_values: CFIndex,
    callbacks: *const CFArrayCallBacks,
) ?CFArrayRef;
extern fn CFRelease(cf: ?*const anyopaque) void;

extern fn SecCertificateCreateWithData(
    allocator: CFAllocatorRef,
    data: CFDataRef,
) ?SecCertificateRef;
extern fn SecPolicyCreateSSL(
    server: Boolean,
    hostname: ?CFStringRef,
) ?SecPolicyRef;
extern fn SecTrustCreateWithCertificates(
    certificates: CFTypeRef,
    policies: CFTypeRef,
    trust: *?SecTrustRef,
) OSStatus;
extern fn SecTrustEvaluateWithError(
    trust: SecTrustRef,
    error_out: *?CFErrorRef,
) Boolean;

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
        if (trust.chain.len > 32) return error.CertificatePathTooManyCertificates;

        const server_name = if (self.verify_host)
            trust.server_name orelse return error.MissingServerName
        else
            null;

        var certificates: [32]?*const anyopaque = undefined;
        var certificate_count: usize = 0;
        defer {
            for (certificates[0..certificate_count]) |certificate| {
                CFRelease(certificate);
            }
        }

        for (trust.chain) |der| {
            const data = CFDataCreate(
                null,
                der.ptr,
                @intCast(der.len),
            ) orelse return error.OutOfMemory;
            defer CFRelease(data);
            const certificate = SecCertificateCreateWithData(
                null,
                data,
            ) orelse return error.InvalidCertificate;
            certificates[certificate_count] = certificate;
            certificate_count += 1;
        }

        const array = CFArrayCreate(
            null,
            @ptrCast(&certificates),
            @intCast(certificate_count),
            &kCFTypeArrayCallBacks,
        ) orelse return error.OutOfMemory;
        defer CFRelease(array);

        var hostname: ?[:0]u8 = null;
        defer if (hostname) |name| self.allocator.free(name);
        var cf_hostname: ?CFStringRef = null;
        defer if (cf_hostname) |value| CFRelease(value);

        if (server_name) |name| {
            hostname = try self.allocator.dupeZ(u8, name);
            cf_hostname = CFStringCreateWithCString(
                null,
                hostname.?.ptr,
                kCFStringEncodingUTF8,
            ) orelse return error.OutOfMemory;
        }

        const policy = SecPolicyCreateSSL(
            if (server_name != null) 1 else 0,
            cf_hostname,
        ) orelse return error.OutOfMemory;
        defer CFRelease(policy);

        var trust_ref: ?SecTrustRef = null;
        if (SecTrustCreateWithCertificates(
            array,
            policy,
            &trust_ref,
        ) != errSecSuccess) {
            return error.CertificateUntrusted;
        }
        defer CFRelease(trust_ref);

        var error_ref: ?CFErrorRef = null;
        const trusted = SecTrustEvaluateWithError(trust_ref.?, &error_ref);
        if (error_ref) |value| CFRelease(value);
        if (trusted == 0) return error.CertificateUntrusted;
    }
};
