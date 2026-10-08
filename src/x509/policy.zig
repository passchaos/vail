//! Allocation-free RFC 5280 certificate-policy path processing using the
//! linear policy graph required by RFC 9618.

const std = @import("std");

pub const any_policy_oid = [_]u8{ 0x55, 0x1d, 0x20, 0x00 };
const id_qt_cps = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01 };
const id_qt_unotice = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02 };

pub const hard_max_policy_identifiers = 128;
pub const hard_max_policy_nodes = 1024;

pub const Config = struct {
    /// DER OBJECT IDENTIFIER contents accepted by the relying party. `null`
    /// denotes the RFC `any-policy` initial set. An empty non-null slice is a
    /// valid empty initial set.
    initial_policy_set: ?[]const []const u8 = null,
    require_explicit_policy: bool = false,
    inhibit_policy_mapping: bool = false,
    inhibit_any_policy: bool = false,
    max_policy_identifiers: usize = 64,
    max_policy_nodes: usize = 256,
};

pub const Extension = struct {
    encoded: []const u8,
    critical: bool,
};

pub const Extensions = struct {
    certificate_policies: ?Extension = null,
    policy_mappings: ?Extension = null,
    policy_constraints: ?Extension = null,
    inhibit_any_policy: ?Extension = null,
};

pub const Certificate = struct {
    extensions: Extensions,
    self_issued: bool,
};

pub fn validateConfig(config: Config) !void {
    if (config.max_policy_identifiers == 0 or
        config.max_policy_identifiers > hard_max_policy_identifiers or
        config.max_policy_nodes == 0 or
        config.max_policy_nodes > hard_max_policy_nodes)
    {
        return error.InvalidCertificatePolicyConfiguration;
    }
    if (config.initial_policy_set) |initial| {
        for (initial, 0..) |identifier, index| {
            try validateOid(identifier);
            if (std.mem.eql(u8, identifier, &any_policy_oid)) {
                return error.InvalidCertificatePolicyConfiguration;
            }
            for (initial[0..index]) |prior| {
                if (std.mem.eql(u8, identifier, prior)) {
                    return error.InvalidCertificatePolicyConfiguration;
                }
            }
        }
    }
}

pub fn validateExtensions(extensions: Extensions) !void {
    if (extensions.certificate_policies) |value| {
        try validateCertificatePolicies(value.encoded, value.critical);
    }
    if (extensions.policy_mappings) |value| {
        try validatePolicyMappings(value.encoded);
    }
    if (extensions.policy_constraints) |value| {
        if (!value.critical) return error.InvalidCertificatePolicy;
        _ = try parsePolicyConstraints(value.encoded);
    }
    if (extensions.inhibit_any_policy) |value| {
        if (!value.critical) return error.InvalidCertificatePolicy;
        _ = try parseSkipCertsExtension(value.encoded);
    }
}

/// `certificates` is ordered from the certificate issued directly by the
/// trust anchor through the target certificate. Trust-anchor certificate
/// extensions are intentionally not included; callers may translate trusted
/// out-of-band constraints into `Config`.
pub noinline fn validatePath(
    config: Config,
    certificates: []const Certificate,
) !void {
    try validateConfig(config);
    if (certificates.len > std.math.maxInt(u8)) {
        return error.CertificatePolicyLimitExceeded;
    }
    if (certificates.len == 0) {
        if (config.require_explicit_policy) {
            return error.CertificatePolicyViolation;
        }
        return;
    }

    var requires_processing = config.require_explicit_policy;
    for (certificates, 0..) |certificate, index| {
        try validateExtensions(certificate.extensions);
        if (index + 1 == certificates.len and
            certificate.extensions.policy_mappings != null)
        {
            return error.InvalidCertificatePolicy;
        }
        if (certificate.extensions.policy_constraints) |constraints| {
            const values = try parsePolicyConstraints(constraints.encoded);
            requires_processing = requires_processing or
                values.require_explicit_policy != null;
        }
    }
    if (!requires_processing) return;
    return validateConstrainedPath(config, certificates);
}

noinline fn validateConstrainedPath(
    config: Config,
    certificates: []const Certificate,
) !void {
    var registry = Registry{ .limit = config.max_policy_identifiers };
    _ = try registry.intern(&any_policy_oid);
    if (config.initial_policy_set) |initial| {
        for (initial) |identifier| _ = try registry.intern(identifier);
    }
    for (certificates) |certificate| {
        try registry.collect(certificate.extensions);
    }

    var graph = PolicyGraph{
        .registry = &registry,
        .node_limit = config.max_policy_nodes,
    };
    try graph.init();
    const unconstrained = certificates.len + 1;
    var explicit_policy: usize = if (config.require_explicit_policy)
        0
    else
        unconstrained;
    var policy_mapping: usize = if (config.inhibit_policy_mapping)
        0
    else
        unconstrained;
    var inhibit_any_policy: usize = if (config.inhibit_any_policy)
        0
    else
        unconstrained;

    for (certificates, 0..) |certificate, index| {
        const depth = index + 1;
        const final = depth == certificates.len;
        try graph.processCertificatePolicies(
            certificate.extensions.certificate_policies,
            depth,
            final,
            certificate.self_issued,
            inhibit_any_policy,
        );
        if (explicit_policy == 0 and !graph.aliveAt(depth)) {
            return error.CertificatePolicyViolation;
        }

        if (!final) {
            if (certificate.extensions.policy_mappings) |mappings| {
                try graph.processPolicyMappings(
                    mappings.encoded,
                    depth,
                    policy_mapping,
                );
            }
            if (!certificate.self_issued) {
                explicit_policy -|= 1;
                policy_mapping -|= 1;
                inhibit_any_policy -|= 1;
            }
            if (certificate.extensions.policy_constraints) |constraints| {
                const values = try parsePolicyConstraints(constraints.encoded);
                if (values.require_explicit_policy) |skip| {
                    explicit_policy = @min(explicit_policy, skip);
                }
                if (values.inhibit_policy_mapping) |skip| {
                    policy_mapping = @min(policy_mapping, skip);
                }
            }
            if (certificate.extensions.inhibit_any_policy) |inhibit| {
                inhibit_any_policy = @min(
                    inhibit_any_policy,
                    try parseSkipCertsExtension(inhibit.encoded),
                );
            }
            continue;
        }

        explicit_policy -|= 1;
        if (certificate.extensions.policy_constraints) |constraints| {
            const values = try parsePolicyConstraints(constraints.encoded);
            if (values.require_explicit_policy == 0) explicit_policy = 0;
        }
        const intersects = try graph.intersectsInitialSet(
            config.initial_policy_set,
            depth,
        );
        if (explicit_policy == 0 and !intersects) {
            return error.CertificatePolicyViolation;
        }
    }
}

const PolicyId = u7;

const Registry = struct {
    identifiers: [hard_max_policy_identifiers][]const u8 = undefined,
    len: usize = 0,
    limit: usize,

    fn intern(self: *Registry, identifier: []const u8) !PolicyId {
        if (self.find(identifier)) |existing| return existing;
        if (self.len >= self.limit) {
            return error.CertificatePolicyLimitExceeded;
        }
        const id: PolicyId = @intCast(self.len);
        self.identifiers[self.len] = identifier;
        self.len += 1;
        return id;
    }

    fn find(self: *const Registry, identifier: []const u8) ?PolicyId {
        for (self.identifiers[0..self.len], 0..) |candidate, index| {
            if (std.mem.eql(u8, candidate, identifier)) return @intCast(index);
        }
        return null;
    }

    fn collect(self: *Registry, extensions: Extensions) !void {
        if (extensions.certificate_policies) |value| {
            var policies = try PolicyIterator.init(value.encoded, value.critical);
            while (try policies.next()) |information| {
                _ = try self.intern(information.identifier);
            }
        }
        if (extensions.policy_mappings) |value| {
            var mappings = try MappingIterator.init(value.encoded);
            while (try mappings.next()) |mapping_value| {
                _ = try self.intern(mapping_value.issuer);
                _ = try self.intern(mapping_value.subject);
            }
        }
    }
};

const Node = struct {
    valid_policy: PolicyId,
    expected: u128,
    parents: u128,
    depth: u8,
    active: bool = true,
};

const PolicyGraph = struct {
    registry: *const Registry,
    nodes: [hard_max_policy_nodes]Node = undefined,
    len: usize = 0,
    node_limit: usize,

    fn init(self: *PolicyGraph) !void {
        _ = try self.addNode(0, 0, policyBit(0), 0);
    }

    fn addNode(
        self: *PolicyGraph,
        depth: usize,
        valid_policy: PolicyId,
        expected: u128,
        parents: u128,
    ) !usize {
        if (self.findNode(depth, valid_policy)) |existing| {
            self.nodes[existing].expected |= expected;
            self.nodes[existing].parents |= parents;
            return existing;
        }
        if (self.len >= self.node_limit) {
            return error.CertificatePolicyLimitExceeded;
        }
        const index = self.len;
        self.nodes[index] = .{
            .valid_policy = valid_policy,
            .expected = expected,
            .parents = parents,
            .depth = @intCast(depth),
        };
        self.len += 1;
        return index;
    }

    fn processCertificatePolicies(
        self: *PolicyGraph,
        extension: ?Extension,
        depth: usize,
        final: bool,
        self_issued: bool,
        inhibit_any_policy: usize,
    ) !void {
        const encoded = extension orelse {
            self.deactivateAll();
            return;
        };
        if (!self.aliveAt(depth - 1)) return;

        const parent_limit = self.len;
        var any_policy_present = false;
        var policies = try PolicyIterator.init(encoded.encoded, encoded.critical);
        while (try policies.next()) |information| {
            const policy_id = self.registry.find(information.identifier) orelse
                unreachable;
            if (policy_id == 0) {
                any_policy_present = true;
                continue;
            }
            var parents: u128 = 0;
            for (self.nodes[0..parent_limit], 0..) |parent, parent_index| {
                if (!parent.active or parent.depth != depth - 1 or
                    parent.expected & policyBit(policy_id) == 0)
                {
                    continue;
                }
                _ = parent_index;
                parents |= policyBit(parent.valid_policy);
            }
            if (parents == 0) {
                for (self.nodes[0..parent_limit]) |parent| {
                    if (!parent.active or parent.depth != depth - 1 or
                        parent.valid_policy != 0)
                    {
                        continue;
                    }
                    parents = policyBit(0);
                    break;
                }
            }
            if (parents != 0) _ = try self.addNode(
                depth,
                policy_id,
                policyBit(policy_id),
                parents,
            );
        }

        if (any_policy_present and
            (inhibit_any_policy > 0 or !final and self_issued))
        {
            var expected_union: u128 = 0;
            for (self.nodes[0..parent_limit]) |parent| {
                if (!parent.active or parent.depth != depth - 1) continue;
                expected_union |= parent.expected;
            }
            while (expected_union != 0) {
                const policy_id: PolicyId = @intCast(@ctz(expected_union));
                expected_union &= expected_union - 1;
                if (self.findNode(depth, policy_id) != null) continue;
                var parents: u128 = 0;
                for (self.nodes[0..parent_limit]) |parent| {
                    if (parent.active and parent.depth == depth - 1 and
                        parent.expected & policyBit(policy_id) != 0)
                    {
                        parents |= policyBit(parent.valid_policy);
                    }
                }
                _ = try self.addNode(
                    depth,
                    policy_id,
                    policyBit(policy_id),
                    parents,
                );
            }
        }
        self.prune(depth - 1);
    }

    fn processPolicyMappings(
        self: *PolicyGraph,
        encoded: []const u8,
        depth: usize,
        policy_mapping: usize,
    ) !void {
        if (!self.aliveAt(depth)) return;
        var mappings = try MappingIterator.init(encoded);
        var mapping_index: usize = 0;
        while (try mappings.next()) |mapping_value| : (mapping_index += 1) {
            if (try mappingIssuerAppearedBefore(
                encoded,
                mapping_value.issuer,
                mapping_index,
            )) continue;
            const issuer_id = self.registry.find(mapping_value.issuer) orelse
                unreachable;
            const subjects = try mappedSubjects(
                self.registry,
                encoded,
                mapping_value.issuer,
            );
            if (policy_mapping != 0) {
                var found = false;
                for (self.nodes[0..self.len]) |*node| {
                    if (!node.active or node.depth != depth or
                        node.valid_policy != issuer_id)
                    {
                        continue;
                    }
                    node.expected = subjects;
                    found = true;
                }
                if (!found) {
                    if (self.findNode(depth, 0)) |any_node_index| {
                        const any_node = self.nodes[any_node_index];
                        _ = try self.addNode(
                            depth,
                            issuer_id,
                            subjects,
                            any_node.parents,
                        );
                    }
                }
            } else {
                const before_remove = self.len;
                for (0..before_remove) |node_index| {
                    const node = self.nodes[node_index];
                    if (node.active and node.depth == depth and
                        node.valid_policy == issuer_id)
                    {
                        self.deactivateSubgraph(node_index);
                    }
                }
                self.prune(depth - 1);
            }
        }
    }

    fn intersectsInitialSet(
        self: *const PolicyGraph,
        initial: ?[]const []const u8,
        final_depth: usize,
    ) !bool {
        if (!self.aliveAt(final_depth)) return false;
        var authority_policies: u128 = 0;
        for (self.nodes[1..self.len]) |node| {
            if (!node.active) continue;
            if (node.valid_policy != 0 and node.parents == policyBit(0)) {
                authority_policies |= policyBit(node.valid_policy);
            }
            if (node.depth == final_depth and node.valid_policy == 0) {
                authority_policies |= policyBit(0);
            }
        }
        if (initial == null) return authority_policies != 0;
        const accepted = initial.?;
        if (authority_policies & policyBit(0) != 0 and accepted.len != 0) {
            return true;
        }
        for (accepted) |identifier| {
            const policy_id = self.registry.find(identifier) orelse continue;
            if (authority_policies & policyBit(policy_id) != 0) return true;
        }
        return false;
    }

    fn aliveAt(self: *const PolicyGraph, depth: usize) bool {
        for (self.nodes[0..self.len]) |node| {
            if (node.active and node.depth == depth) return true;
        }
        return false;
    }

    fn findNode(
        self: *const PolicyGraph,
        depth: usize,
        valid_policy: PolicyId,
    ) ?usize {
        for (self.nodes[0..self.len], 0..) |node, index| {
            if (node.active and node.depth == depth and
                node.valid_policy == valid_policy)
            {
                return index;
            }
        }
        return null;
    }

    fn hasActiveChild(self: *const PolicyGraph, parent: usize) bool {
        const parent_node = self.nodes[parent];
        for (self.nodes[0..self.len]) |node| {
            if (node.active and node.depth == parent_node.depth + 1 and
                node.parents & policyBit(parent_node.valid_policy) != 0)
            {
                return true;
            }
        }
        return false;
    }

    fn prune(self: *PolicyGraph, starting_depth: usize) void {
        var depth = starting_depth;
        while (true) {
            for (0..self.len) |node_index| {
                const node = self.nodes[node_index];
                if (node.active and node.depth == depth and
                    !self.hasActiveChild(node_index))
                {
                    self.nodes[node_index].active = false;
                }
            }
            if (depth == 0) break;
            depth -= 1;
        }
    }

    fn deactivateSubgraph(self: *PolicyGraph, root: usize) void {
        const starting_depth = self.nodes[root].depth;
        self.nodes[root].active = false;
        var depth: usize = starting_depth + 1;
        while (depth <= std.math.maxInt(u8)) : (depth += 1) {
            var saw_node = false;
            const active_parents = self.activePolicyBits(depth - 1);
            for (self.nodes[0..self.len]) |*node| {
                if (!node.active or node.depth != depth) continue;
                saw_node = true;
                node.parents &= active_parents;
                if (node.parents == 0) node.active = false;
            }
            if (!saw_node) break;
        }
    }

    fn activePolicyBits(self: *const PolicyGraph, depth: usize) u128 {
        var result: u128 = 0;
        for (self.nodes[0..self.len]) |node| {
            if (node.active and node.depth == depth) {
                result |= policyBit(node.valid_policy);
            }
        }
        return result;
    }

    fn deactivateAll(self: *PolicyGraph) void {
        for (self.nodes[0..self.len]) |*node| node.active = false;
    }
};

fn policyBit(identifier: PolicyId) u128 {
    return @as(u128, 1) << identifier;
}

fn containsOid(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, candidate, needle)) return true;
    }
    return false;
}

fn mappedSubjects(
    registry: *const Registry,
    encoded: []const u8,
    issuer: []const u8,
) !u128 {
    var result: u128 = 0;
    var mappings = try MappingIterator.init(encoded);
    while (try mappings.next()) |mapping_value| {
        if (!std.mem.eql(u8, mapping_value.issuer, issuer)) continue;
        const subject = registry.find(mapping_value.subject) orelse unreachable;
        result |= policyBit(subject);
    }
    return result;
}

fn mappingIssuerAppearedBefore(
    encoded: []const u8,
    issuer: []const u8,
    current_index: usize,
) !bool {
    var mappings = try MappingIterator.init(encoded);
    var index: usize = 0;
    while (index < current_index) : (index += 1) {
        const prior = (try mappings.next()) orelse unreachable;
        if (std.mem.eql(u8, prior.issuer, issuer)) return true;
    }
    return false;
}

const PolicyInformation = struct {
    identifier: []const u8,
};

const PolicyIterator = struct {
    fields: DerReader,
    critical: bool,

    fn init(encoded: []const u8, critical: bool) !PolicyIterator {
        const sequence = try singleInner(encoded, 0x30);
        if (sequence.value.len == 0) return error.InvalidCertificatePolicy;
        return .{
            .fields = .{ .bytes = sequence.value },
            .critical = critical,
        };
    }

    fn next(self: *PolicyIterator) !?PolicyInformation {
        const encoded = try self.fields.next() orelse return null;
        if (encoded.tag != 0x30) return error.InvalidCertificatePolicy;
        var fields = DerReader{ .bytes = encoded.value };
        const identifier = try fields.require(0x06);
        try validateOid(identifier.value);
        if (try fields.next()) |qualifiers| {
            if (qualifiers.tag != 0x30 or qualifiers.value.len == 0 or
                try fields.next() != null)
            {
                return error.InvalidCertificatePolicy;
            }
            try validatePolicyQualifiers(
                qualifiers.value,
                self.critical or
                    std.mem.eql(u8, identifier.value, &any_policy_oid),
            );
        }
        return .{ .identifier = identifier.value };
    }
};

fn validateCertificatePolicies(encoded: []const u8, critical: bool) !void {
    var policies = try PolicyIterator.init(encoded, critical);
    var index: usize = 0;
    while (try policies.next()) |information| : (index += 1) {
        var prior = try PolicyIterator.init(encoded, critical);
        for (0..index) |_| {
            const candidate = (try prior.next()) orelse unreachable;
            if (std.mem.eql(u8, candidate.identifier, information.identifier)) {
                return error.InvalidCertificatePolicy;
            }
        }
    }
}

fn validatePolicyQualifiers(
    encoded: []const u8,
    reject_unknown: bool,
) !void {
    var qualifiers = DerReader{ .bytes = encoded };
    while (try qualifiers.next()) |encoded_qualifier| {
        if (encoded_qualifier.tag != 0x30) {
            return error.InvalidCertificatePolicy;
        }
        var fields = DerReader{ .bytes = encoded_qualifier.value };
        const identifier = try fields.require(0x06);
        try validateOid(identifier.value);
        const qualifier = (try fields.next()) orelse
            return error.InvalidCertificatePolicy;
        if (try fields.next() != null) return error.InvalidCertificatePolicy;
        if (std.mem.eql(u8, identifier.value, &id_qt_cps)) {
            if (qualifier.tag != 0x16 or
                !validAbsoluteIa5Uri(qualifier.value))
            {
                return error.InvalidCertificatePolicy;
            }
        } else if (std.mem.eql(u8, identifier.value, &id_qt_unotice)) {
            if (qualifier.tag != 0x30) return error.InvalidCertificatePolicy;
            try validateUserNotice(qualifier.value);
        } else if (reject_unknown) {
            return error.UnsupportedCertificatePolicyQualifier;
        }
    }
}

fn validAbsoluteIa5Uri(uri: []const u8) bool {
    if (uri.len < 2 or !std.ascii.isAlphabetic(uri[0])) return false;
    var saw_colon = false;
    for (uri, 0..) |byte, index| {
        if (byte <= 0x20 or byte >= 0x7f) return false;
        if (saw_colon) continue;
        if (byte == ':') {
            saw_colon = true;
        } else if (index != 0 and !std.ascii.isAlphanumeric(byte) and
            byte != '+' and byte != '-' and byte != '.')
        {
            return false;
        }
    }
    return saw_colon;
}

fn validateUserNotice(encoded: []const u8) !void {
    var fields = DerReader{ .bytes = encoded };
    var value = try fields.next() orelse return;
    if (value.tag == 0x30) {
        try validateNoticeReference(value.value);
        value = try fields.next() orelse return;
    }
    try validateDisplayText(value, true);
    if (try fields.next() != null) return error.InvalidCertificatePolicy;
}

fn validateNoticeReference(encoded: []const u8) !void {
    var fields = DerReader{ .bytes = encoded };
    const organization = (try fields.next()) orelse
        return error.InvalidCertificatePolicy;
    try validateDisplayText(organization, false);
    const numbers = try fields.require(0x30);
    if (numbers.value.len == 0 or try fields.next() != null) {
        return error.InvalidCertificatePolicy;
    }
    var values = DerReader{ .bytes = numbers.value };
    while (try values.next()) |number| {
        if (number.tag != 0x02) return error.InvalidCertificatePolicy;
        try validateInteger(number.value, true);
    }
}

fn validateDisplayText(value: Tlv, explicit_text: bool) !void {
    if (explicit_text and value.tag != 0x0c and value.tag != 0x16) {
        return error.InvalidCertificatePolicy;
    }
    var characters: usize = 0;
    switch (value.tag) {
        0x0c => {
            var index: usize = 0;
            while (index < value.value.len) : (characters += 1) {
                const len = std.unicode.utf8ByteSequenceLength(
                    value.value[index],
                ) catch return error.InvalidCertificatePolicy;
                const end = index + len;
                if (end > value.value.len) return error.InvalidCertificatePolicy;
                _ = std.unicode.utf8Decode(value.value[index..end]) catch
                    return error.InvalidCertificatePolicy;
                index = end;
            }
        },
        0x16, 0x1a => {
            for (value.value) |byte| {
                if (byte >= 0x80) return error.InvalidCertificatePolicy;
            }
            characters = value.value.len;
        },
        0x1e => {
            if (value.value.len % 2 != 0) return error.InvalidCertificatePolicy;
            var index: usize = 0;
            while (index < value.value.len) : (index += 2) {
                const scalar = std.mem.readInt(
                    u16,
                    value.value[index..][0..2],
                    .big,
                );
                if (scalar >= 0xd800 and scalar <= 0xdfff) {
                    return error.InvalidCertificatePolicy;
                }
            }
            characters = value.value.len / 2;
        },
        else => return error.InvalidCertificatePolicy,
    }
    if (characters == 0 or characters > 200) {
        return error.InvalidCertificatePolicy;
    }
}

const Mapping = struct {
    issuer: []const u8,
    subject: []const u8,
};

const MappingIterator = struct {
    fields: DerReader,

    fn init(encoded: []const u8) !MappingIterator {
        const sequence = try singleInner(encoded, 0x30);
        if (sequence.value.len == 0) return error.InvalidCertificatePolicy;
        return .{ .fields = .{ .bytes = sequence.value } };
    }

    fn next(self: *MappingIterator) !?Mapping {
        const encoded = try self.fields.next() orelse return null;
        if (encoded.tag != 0x30) return error.InvalidCertificatePolicy;
        var fields = DerReader{ .bytes = encoded.value };
        const issuer = try fields.require(0x06);
        const subject = try fields.require(0x06);
        if (try fields.next() != null) return error.InvalidCertificatePolicy;
        try validateOid(issuer.value);
        try validateOid(subject.value);
        if (std.mem.eql(u8, issuer.value, &any_policy_oid) or
            std.mem.eql(u8, subject.value, &any_policy_oid))
        {
            return error.InvalidCertificatePolicy;
        }
        return .{ .issuer = issuer.value, .subject = subject.value };
    }
};

fn validatePolicyMappings(encoded: []const u8) !void {
    var mappings = try MappingIterator.init(encoded);
    while (try mappings.next()) |_| {}
}

const PolicyConstraints = struct {
    require_explicit_policy: ?usize = null,
    inhibit_policy_mapping: ?usize = null,
};

fn parsePolicyConstraints(encoded: []const u8) !PolicyConstraints {
    const sequence = try singleInner(encoded, 0x30);
    if (sequence.value.len == 0) return error.InvalidCertificatePolicy;
    var result: PolicyConstraints = .{};
    var fields = DerReader{ .bytes = sequence.value };
    var previous_tag: u8 = 0x7f;
    while (try fields.next()) |field| {
        if (previous_tag != 0x7f and field.tag <= previous_tag) {
            return error.InvalidCertificatePolicy;
        }
        previous_tag = field.tag;
        switch (field.tag) {
            0x80 => {
                if (result.require_explicit_policy != null) {
                    return error.InvalidCertificatePolicy;
                }
                result.require_explicit_policy = try parseSkipCerts(field.value);
            },
            0x81 => {
                if (result.inhibit_policy_mapping != null) {
                    return error.InvalidCertificatePolicy;
                }
                result.inhibit_policy_mapping = try parseSkipCerts(field.value);
            },
            else => return error.InvalidCertificatePolicy,
        }
    }
    return result;
}

fn parseSkipCertsExtension(encoded: []const u8) !usize {
    const value = try singleInner(encoded, 0x02);
    return parseSkipCerts(value.value);
}

fn parseSkipCerts(value: []const u8) !usize {
    try validateInteger(value, false);
    var result: usize = 0;
    for (value) |byte| {
        result = std.math.mul(usize, result, 256) catch
            return std.math.maxInt(usize);
        result = std.math.add(usize, result, byte) catch
            return std.math.maxInt(usize);
    }
    return result;
}

fn validateInteger(value: []const u8, allow_negative: bool) !void {
    if (value.len == 0) return error.InvalidCertificatePolicy;
    if (!allow_negative and value[0] & 0x80 != 0) {
        return error.InvalidCertificatePolicy;
    }
    if (value.len > 1 and
        ((value[0] == 0 and value[1] & 0x80 == 0) or
            (value[0] == 0xff and value[1] & 0x80 != 0)))
    {
        return error.InvalidCertificatePolicy;
    }
}

fn validateOid(value: []const u8) !void {
    if (value.len == 0) return error.InvalidCertificatePolicy;
    var at_start = true;
    for (value) |byte| {
        if (at_start and byte == 0x80) return error.InvalidCertificatePolicy;
        at_start = byte & 0x80 == 0;
    }
    if (!at_start) return error.InvalidCertificatePolicy;
}

const Tlv = struct {
    tag: u8,
    value: []const u8,
};

fn singleInner(encoded: []const u8, tag: u8) !Tlv {
    var reader = DerReader{ .bytes = encoded };
    const value = try reader.require(tag);
    if (try reader.next() != null) return error.InvalidCertificatePolicy;
    return value;
}

const DerReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn next(self: *DerReader) !?Tlv {
        if (self.pos == self.bytes.len) return null;
        if (self.pos > self.bytes.len) return error.InvalidCertificatePolicy;
        const tag = self.bytes[self.pos];
        self.pos += 1;
        if (tag & 0x1f == 0x1f) return error.InvalidCertificatePolicy;
        const len = try self.readLength();
        const end = std.math.add(usize, self.pos, len) catch
            return error.InvalidCertificatePolicy;
        if (end > self.bytes.len) return error.InvalidCertificatePolicy;
        const value = self.bytes[self.pos..end];
        self.pos = end;
        return .{ .tag = tag, .value = value };
    }

    fn require(self: *DerReader, tag: u8) !Tlv {
        const value = try self.next() orelse
            return error.InvalidCertificatePolicy;
        if (value.tag != tag) return error.InvalidCertificatePolicy;
        return value;
    }

    fn readLength(self: *DerReader) !usize {
        if (self.pos >= self.bytes.len) return error.InvalidCertificatePolicy;
        const first = self.bytes[self.pos];
        self.pos += 1;
        if (first & 0x80 == 0) return first;
        const count: usize = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) {
            return error.InvalidCertificatePolicy;
        }
        const end = std.math.add(usize, self.pos, count) catch
            return error.InvalidCertificatePolicy;
        if (end > self.bytes.len or self.bytes[self.pos] == 0) {
            return error.InvalidCertificatePolicy;
        }
        var len: usize = 0;
        for (self.bytes[self.pos..end]) |byte| {
            len = std.math.mul(usize, len, 256) catch
                return error.InvalidCertificatePolicy;
            len = std.math.add(usize, len, byte) catch
                return error.InvalidCertificatePolicy;
        }
        self.pos = end;
        if (len < 128) return error.InvalidCertificatePolicy;
        return len;
    }
};

test "policy path requires an explicit common policy" {
    const policy_a = [_]u8{ 0x2a, 0x03, 0x04 };
    const policies_a = "\x30\x07\x30\x05\x06\x03\x2a\x03\x04";
    const policies_b = "\x30\x07\x30\x05\x06\x03\x2a\x03\x05";
    const initial = [_][]const u8{&policy_a};
    try validatePath(
        .{ .initial_policy_set = &initial, .require_explicit_policy = true },
        &.{
            .{ .extensions = .{ .certificate_policies = .{ .encoded = policies_a, .critical = false } }, .self_issued = false },
            .{ .extensions = .{ .certificate_policies = .{ .encoded = policies_a, .critical = false } }, .self_issued = false },
        },
    );
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        validatePath(
            .{ .initial_policy_set = &initial, .require_explicit_policy = true },
            &.{
                .{ .extensions = .{ .certificate_policies = .{ .encoded = policies_a, .critical = false } }, .self_issued = false },
                .{ .extensions = .{ .certificate_policies = .{ .encoded = policies_b, .critical = false } }, .self_issued = false },
            },
        ),
    );
}

test "policy mappings bridge issuer and subject domains" {
    const policy_a = [_]u8{ 0x2a, 0x03, 0x04 };
    const policies_a = "\x30\x07\x30\x05\x06\x03\x2a\x03\x04";
    const policies_b = "\x30\x07\x30\x05\x06\x03\x2a\x03\x05";
    const mapping_a_b =
        "\x30\x0c\x30\x0a\x06\x03\x2a\x03\x04\x06\x03\x2a\x03\x05";
    const initial = [_][]const u8{&policy_a};
    const path = [_]Certificate{
        .{
            .extensions = .{
                .certificate_policies = .{ .encoded = policies_a, .critical = false },
                .policy_mappings = .{ .encoded = mapping_a_b, .critical = true },
            },
            .self_issued = false,
        },
        .{
            .extensions = .{
                .certificate_policies = .{ .encoded = policies_b, .critical = false },
            },
            .self_issued = false,
        },
    };
    try validatePath(
        .{ .initial_policy_set = &initial, .require_explicit_policy = true },
        &path,
    );
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        validatePath(
            .{
                .initial_policy_set = &initial,
                .require_explicit_policy = true,
                .inhibit_policy_mapping = true,
            },
            &path,
        ),
    );
}

test "RFC 9618 policy graph remains linear under Cartesian mappings" {
    const policy_a = [_]u8{ 0x2a, 0x03, 0x01 };
    const policy_b = [_]u8{ 0x2a, 0x03, 0x02 };
    const both_policies =
        "\x30\x0e" ++
        "\x30\x05\x06\x03\x2a\x03\x01" ++
        "\x30\x05\x06\x03\x2a\x03\x02";
    const cartesian_mappings =
        "\x30\x30" ++
        "\x30\x0a\x06\x03\x2a\x03\x01\x06\x03\x2a\x03\x01" ++
        "\x30\x0a\x06\x03\x2a\x03\x01\x06\x03\x2a\x03\x02" ++
        "\x30\x0a\x06\x03\x2a\x03\x02\x06\x03\x2a\x03\x01" ++
        "\x30\x0a\x06\x03\x2a\x03\x02\x06\x03\x2a\x03\x02";
    const initial = [_][]const u8{ &policy_a, &policy_b };
    var path: [9]Certificate = @splat(.{
        .extensions = .{
            .certificate_policies = .{
                .encoded = both_policies,
                .critical = false,
            },
            .policy_mappings = .{
                .encoded = cartesian_mappings,
                .critical = true,
            },
        },
        .self_issued = false,
    });
    path[path.len - 1].extensions.policy_mappings = null;
    try validatePath(
        .{
            .initial_policy_set = &initial,
            .require_explicit_policy = true,
            // The equivalent RFC 5280 tree has 511 nodes; the RFC 9618 graph
            // needs only one node per asserted policy and depth.
            .max_policy_nodes = 32,
        },
        &path,
    );
}

test "policy constraints and inhibit anyPolicy update counters" {
    const policy_a = [_]u8{ 0x2a, 0x03, 0x04 };
    const any_policy = "\x30\x08\x30\x06\x06\x04\x55\x1d\x20\x00";
    const policies_a = "\x30\x07\x30\x05\x06\x03\x2a\x03\x04";
    const initial = [_][]const u8{&policy_a};
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        validatePath(
            .{ .initial_policy_set = &initial, .require_explicit_policy = true },
            &.{
                .{
                    .extensions = .{
                        .certificate_policies = .{ .encoded = policies_a, .critical = false },
                        .inhibit_any_policy = .{ .encoded = "\x02\x01\x00", .critical = true },
                    },
                    .self_issued = false,
                },
                .{ .extensions = .{ .certificate_policies = .{ .encoded = any_policy, .critical = false } }, .self_issued = false },
            },
        ),
    );
    try std.testing.expectError(
        error.CertificatePolicyViolation,
        validatePath(
            .{},
            &.{
                .{
                    .extensions = .{
                        .policy_constraints = .{ .encoded = "\x30\x03\x80\x01\x00", .critical = true },
                    },
                    .self_issued = false,
                },
                .{ .extensions = .{}, .self_issued = false },
            },
        ),
    );

    // RFC 5280 retains anyPolicy in a non-final self-issued certificate even
    // when the inhibit counter is already zero.
    try validatePath(
        .{
            .initial_policy_set = &initial,
            .require_explicit_policy = true,
            .inhibit_any_policy = true,
        },
        &.{
            .{ .extensions = .{ .certificate_policies = .{ .encoded = any_policy, .critical = false } }, .self_issued = true },
            .{ .extensions = .{ .certificate_policies = .{ .encoded = policies_a, .critical = false } }, .self_issued = false },
        },
    );
}

test "policy extension syntax rejects duplicates anyPolicy mappings and limits" {
    const duplicate =
        "\x30\x0e\x30\x05\x06\x03\x2a\x03\x04" ++
        "\x30\x05\x06\x03\x2a\x03\x04";
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        validateCertificatePolicies(duplicate, false),
    );
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        validatePolicyMappings(
            "\x30\x0d\x30\x0b\x06\x04\x55\x1d\x20\x00\x06\x03\x2a\x03\x04",
        ),
    );
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        parsePolicyConstraints("\x30\x00"),
    );
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        parsePolicyConstraints("\x30\x06\x81\x01\x00\x80\x01\x00"),
    );
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        parseSkipCertsExtension("\x02\x01\xff"),
    );
    try std.testing.expectError(
        error.InvalidCertificatePolicyConfiguration,
        validateConfig(.{ .max_policy_nodes = 0 }),
    );

    try std.testing.expectError(
        error.CertificatePolicyLimitExceeded,
        validatePath(
            .{ .require_explicit_policy = true, .max_policy_nodes = 1 },
            &.{.{
                .extensions = .{
                    .certificate_policies = .{
                        .encoded = "\x30\x07\x30\x05\x06\x03\x2a\x03\x04",
                        .critical = false,
                    },
                },
                .self_issued = false,
            }},
        ),
    );
}

test "policy qualifiers enforce critical and anyPolicy interpretation" {
    const valid_cps =
        "\x30\x2a\x30\x28\x06\x03\x2a\x03\x04\x30\x21\x30\x1f" ++
        "\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01" ++
        "\x16\x13https://ca.test/cps";
    try validateCertificatePolicies(valid_cps, true);
    try std.testing.expectError(
        error.InvalidCertificatePolicy,
        validateCertificatePolicies(
            "\x30\x1f\x30\x1d\x06\x03\x2a\x03\x04\x30\x16\x30\x14" ++
                "\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01" ++
                "\x16\x08relative",
            false,
        ),
    );
    const unknown =
        "\x30\x13\x30\x11\x06\x03\x2a\x03\x04" ++
        "\x30\x0a\x30\x08\x06\x03\x2a\x03\x09\x04\x01x";
    try validateCertificatePolicies(unknown, false);
    try std.testing.expectError(
        error.UnsupportedCertificatePolicyQualifier,
        validateCertificatePolicies(unknown, true),
    );
    try std.testing.expectError(
        error.UnsupportedCertificatePolicyQualifier,
        validateCertificatePolicies(
            "\x30\x14\x30\x12\x06\x04\x55\x1d\x20\x00" ++
                "\x30\x0a\x30\x08\x06\x03\x2a\x03\x09\x04\x01x",
            false,
        ),
    );
}
