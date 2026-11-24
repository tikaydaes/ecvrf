//! RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03) in Zig.
//! Uses std.crypto.ecc.Edwards25519 (constant-time proving) and Sha512.

const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Curve = std.crypto.ecc.Edwards25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const suite_byte: u8 = 0x03;
pub const secret_key_len: usize = 32;
pub const public_key_len: usize = 32;
pub const proof_len: usize = 80;
pub const beta_len: usize = 64;
const challenge_len: usize = 16;

// Group order q = 2^252 + 27742317777372353535851937790883648493 (little-endian)
const group_order_le = [32]u8{
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

pub const EcvrfError = error{
    InvalidSecretKey,
    EncodeToCurveFailed,
};

fn isAllZero(bytes: [32]u8) bool {
    var acc: u8 = 0;
    for (bytes) |b| acc |= b;
    return acc == 0;
}

/// Checks that 255-bit little-endian y is strictly less than p = 2^255 - 19.
fn isCanonicalPointY(bytes: [32]u8) bool {
    if ((bytes[31] & 0x7f) != 0x7f) return true;
    for (bytes[1..31]) |b| {
        if (b != 0xff) return true;
    }
    return bytes[0] < 0xed;
}

/// Checks that 256-bit little-endian scalar s is strictly less than group order q.
fn isCanonicalScalar(s: [32]u8) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (s[i] < group_order_le[i]) return true;
        if (s[i] > group_order_le[i]) return false;
    }
    return false;
}

/// Strictly decodes a canonical RFC 8032 compressed Edwards25519 point.
fn decodePoint(bytes: []const u8) ?Curve {
    if (bytes.len != 32) return null;
    var arr: [32]u8 = undefined;
    @memcpy(&arr, bytes);
    if (!isCanonicalPointY(arr)) return null;
    const pt = Curve.fromBytes(arr) catch return null;
    // Reject non-canonical x == 0 with sign bit 1
    const reencoded = pt.toBytes();
    if (!mem.eql(u8, &reencoded, &arr)) return null;
    return pt;
}

fn validateKey(pk: []const u8) ?Curve {
    const y = decodePoint(pk) orelse return null;
    const cof = y.clearCofactor();
    const cof_bytes = cof.toBytes();
    const id_bytes = Curve.identityElement.toBytes();
    if (mem.eql(u8, &cof_bytes, &id_bytes)) return null;
    return y;
}

pub fn isPublicKey(pk: []const u8) bool {
    return validateKey(pk) != null;
}

fn reduce32(s: [32]u8) [32]u8 {
    var wide = [_]u8{0} ** 64;
    @memcpy(wide[0..32], &s);
    return Curve.scalar.reduce64(wide);
}

fn expandSecretKey(sk: []const u8) EcvrfError!struct { x: [32]u8, prefix: [32]u8 } {
    if (sk.len != secret_key_len) return error.InvalidSecretKey;
    var h: [64]u8 = undefined;
    Sha512.hash(sk, &h, .{});

    var xb: [32]u8 = undefined;
    @memcpy(&xb, h[0..32]);
    xb[0] &= 248;
    xb[31] &= 127;
    xb[31] |= 64;

    var prefix: [32]u8 = undefined;
    @memcpy(&prefix, h[32..64]);

    return .{
        .x = reduce32(xb),
        .prefix = prefix,
    };
}

fn scalarMulPoint(pt: Curve, s: [32]u8) Curve {
    if (isAllZero(s)) return Curve.identityElement;
    return pt.mul(s) catch Curve.identityElement;
}

fn scalarMulBase(s: [32]u8) Curve {
    if (isAllZero(s)) return Curve.identityElement;
    return Curve.basePoint.mul(s) catch Curve.identityElement;
}

fn scalarMulPublic(pt: Curve, s: [32]u8) Curve {
    if (isAllZero(s)) return Curve.identityElement;
    return pt.mulPublic(s) catch |err| switch (err) {
        error.IdentityElement => Curve.identityElement,
        error.WeakPublicKey => switch (s[0] & 3) {
            0 => Curve.identityElement,
            1 => pt,
            2 => pt.dbl(),
            3 => pt.dbl().add(pt),
            else => unreachable,
        },
    };
}

fn encodeToCurveTAI(pk: [32]u8, alpha: []const u8) EcvrfError!Curve {
    for (0..256) |ctr| {
        var hasher = Sha512.init(.{});
        hasher.update(&[_]u8{ suite_byte, 0x01 });
        hasher.update(&pk);
        hasher.update(alpha);
        hasher.update(&[_]u8{ @intCast(ctr), 0x00 });
        var hash: [64]u8 = undefined;
        hasher.final(&hash);
        if (decodePoint(hash[0..32])) |pt| {
            return pt.clearCofactor();
        }
    }
    return error.EncodeToCurveFailed;
}

fn challengeGeneration(y: Curve, h: Curve, gamma: Curve, u: Curve, v: Curve) [challenge_len]u8 {
    var hasher = Sha512.init(.{});
    hasher.update(&[_]u8{ suite_byte, 0x02 });
    const yb = y.toBytes();
    const hb = h.toBytes();
    const gb = gamma.toBytes();
    const ub = u.toBytes();
    const vb = v.toBytes();
    hasher.update(&yb);
    hasher.update(&hb);
    hasher.update(&gb);
    hasher.update(&ub);
    hasher.update(&vb);
    hasher.update(&[_]u8{0x00});
    var hash: [64]u8 = undefined;
    hasher.final(&hash);
    var c_bytes: [challenge_len]u8 = undefined;
    @memcpy(&c_bytes, hash[0..challenge_len]);
    return c_bytes;
}

fn gammaToHash(gamma: Curve) [beta_len]u8 {
    const cof = gamma.clearCofactor();
    const cof_bytes = cof.toBytes();
    var hasher = Sha512.init(.{});
    hasher.update(&[_]u8{ suite_byte, 0x03 });
    hasher.update(&cof_bytes);
    hasher.update(&[_]u8{0x00});
    var beta: [beta_len]u8 = undefined;
    hasher.final(&beta);
    return beta;
}

fn decodeProof(pi: []const u8) ?struct { gamma: Curve, c_bytes: [challenge_len]u8, s: [32]u8 } {
    if (pi.len != proof_len) return null;
    const gamma = decodePoint(pi[0..32]) orelse return null;
    var c_bytes: [challenge_len]u8 = undefined;
    @memcpy(&c_bytes, pi[32..48]);
    var s: [32]u8 = undefined;
    @memcpy(&s, pi[48..80]);
    if (!isCanonicalScalar(s)) return null;
    return .{ .gamma = gamma, .c_bytes = c_bytes, .s = s };
}

pub fn derivePublicKey(sk: []const u8) EcvrfError![public_key_len]u8 {
    const expanded = try expandSecretKey(sk);
    return scalarMulBase(expanded.x).toBytes();
}

pub fn prove(sk: []const u8, alpha: []const u8) EcvrfError![proof_len]u8 {
    const expanded = try expandSecretKey(sk);
    const y = scalarMulBase(expanded.x);
    const pk = y.toBytes();

    const h = try encodeToCurveTAI(pk, alpha);
    const gamma = scalarMulPoint(h, expanded.x);

    var nonce_hasher = Sha512.init(.{});
    nonce_hasher.update(&expanded.prefix);
    const h_bytes = h.toBytes();
    nonce_hasher.update(&h_bytes);
    var k_hash: [64]u8 = undefined;
    nonce_hasher.final(&k_hash);
    const k = Curve.scalar.reduce64(k_hash);

    const u = scalarMulBase(k);
    const v = scalarMulPoint(h, k);
    const c_bytes = challengeGeneration(y, h, gamma, u, v);

    var c_padded = [_]u8{0} ** 32;
    @memcpy(c_padded[0..challenge_len], &c_bytes);
    const s = Curve.scalar.mulAdd(c_padded, expanded.x, k);

    var pi: [proof_len]u8 = undefined;
    const gamma_bytes = gamma.toBytes();
    @memcpy(pi[0..32], &gamma_bytes);
    @memcpy(pi[32..48], &c_bytes);
    @memcpy(pi[48..80], &s);
    return pi;
}

pub fn proofToHash(pi: []const u8) ?[beta_len]u8 {
    const decoded = decodeProof(pi) orelse return null;
    return gammaToHash(decoded.gamma);
}

pub fn verify(pk: []const u8, pi: []const u8, alpha: []const u8) ?[beta_len]u8 {
    const y = validateKey(pk) orelse return null;
    const decoded = decodeProof(pi) orelse return null;
    var pk_arr: [32]u8 = undefined;
    @memcpy(&pk_arr, pk);
    const h = encodeToCurveTAI(pk_arr, alpha) catch return null;

    var c_padded = [_]u8{0} ** 32;
    @memcpy(c_padded[0..challenge_len], &decoded.c_bytes);

    // U = s*B - c*Y, V = s*H - c*Gamma
    const u = scalarMulPublic(Curve.basePoint, decoded.s).sub(scalarMulPublic(y, c_padded));
    const v = scalarMulPublic(h, decoded.s).sub(scalarMulPublic(decoded.gamma, c_padded));
    const c_prime = challengeGeneration(y, h, decoded.gamma, u, v);

    if (!mem.eql(u8, &decoded.c_bytes, &c_prime)) return null;
    return gammaToHash(decoded.gamma);
}

// ── Tests against ../vectors/vectors.json ────────────────────────────────

const PositiveVector = struct {
    label: []const u8,
    sk: []const u8,
    pk: []const u8,
    alpha: []const u8,
    pi: []const u8,
    beta: []const u8,
};

const NegativeVector = struct {
    description: []const u8,
    pk: []const u8,
    alpha: []const u8,
    pi: []const u8,
    expected_verify: bool,
};

const VectorFile = struct {
    suite: []const u8,
    spec: []const u8,
    vectors: []const PositiveVector,
    negative_vectors: []const NegativeVector,
};

fn parseHexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => unreachable,
    };
}

fn hexDecode(allocator: mem.Allocator, hex: []const u8) ![]u8 {
    const len = hex.len / 2;
    const out = try allocator.alloc(u8, len);
    for (0..len) |i| {
        out[i] = (parseHexDigit(hex[2 * i]) << 4) | parseHexDigit(hex[2 * i + 1]);
    }
    return out;
}

fn bytesToHex(comptime N: usize, bytes: [N]u8) [N * 2]u8 {
    const charset = "0123456789abcdef";
    var out: [N * 2]u8 = undefined;
    for (0..N) |i| {
        out[2 * i] = charset[bytes[i] >> 4];
        out[2 * i + 1] = charset[bytes[i] & 0x0f];
    }
    return out;
}

test "vectors.json positive and negative" {
    const allocator = testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(allocator, "../vectors/vectors.json", 10 * 1024 * 1024);
    defer allocator.free(raw);

    const parsed = try std.json.parseFromSlice(VectorFile, allocator, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try testing.expectEqualStrings("ECVRF-EDWARDS25519-SHA512-TAI", parsed.value.suite);

    for (parsed.value.vectors) |vec| {
        const sk = try hexDecode(allocator, vec.sk);
        defer allocator.free(sk);
        const alpha = try hexDecode(allocator, vec.alpha);
        defer allocator.free(alpha);

        const pk = try derivePublicKey(sk);
        const pk_hex = bytesToHex(public_key_len, pk);
        try testing.expectEqualStrings(vec.pk, &pk_hex);
        try testing.expect(isPublicKey(&pk));

        const pi = try prove(sk, alpha);
        const pi_hex = bytesToHex(proof_len, pi);
        try testing.expectEqualStrings(vec.pi, &pi_hex);

        const beta_hash = proofToHash(&pi) orelse return error.TestUnexpectedResult;
        const beta_hash_hex = bytesToHex(beta_len, beta_hash);
        try testing.expectEqualStrings(vec.beta, &beta_hash_hex);

        const beta_verify = verify(&pk, &pi, alpha) orelse return error.TestUnexpectedResult;
        const beta_verify_hex = bytesToHex(beta_len, beta_verify);
        try testing.expectEqualStrings(vec.beta, &beta_verify_hex);
    }

    for (parsed.value.negative_vectors) |neg| {
        const pk = try hexDecode(allocator, neg.pk);
        defer allocator.free(pk);
        const alpha = try hexDecode(allocator, neg.alpha);
        defer allocator.free(alpha);
        const pi = try hexDecode(allocator, neg.pi);
        defer allocator.free(pi);

        const valid = verify(pk, pi, alpha) != null;
        try testing.expectEqual(neg.expected_verify, valid);
    }
}

test "rejects invalid sk length" {
    try testing.expectError(error.InvalidSecretKey, prove(&[_]u8{0} ** 31, "test"));
    try testing.expectError(error.InvalidSecretKey, prove(&[_]u8{0} ** 33, "test"));
}

test "scalarMulPublic handles order-2 and order-4 torsion points" {
    const order2_bytes = [32]u8{
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    const order4_bytes = [_]u8{0} ** 32;
    const neg_order4_bytes = [32]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    const id_bytes = Curve.identityElement.toBytes();
    const t2 = decodePoint(&order2_bytes) orelse return error.TestUnexpectedResult;
    const t4 = decodePoint(&order4_bytes) orelse return error.TestUnexpectedResult;

    var s = [_]u8{0} ** 32;
    s[0] = 1;
    const t2_1 = scalarMulPublic(t2, s).toBytes();
    const t4_1 = scalarMulPublic(t4, s).toBytes();
    try testing.expectEqualSlices(u8, &order2_bytes, &t2_1);
    try testing.expectEqualSlices(u8, &order4_bytes, &t4_1);

    s[0] = 2;
    const t2_2 = scalarMulPublic(t2, s).toBytes();
    const t4_2 = scalarMulPublic(t4, s).toBytes();
    try testing.expectEqualSlices(u8, &id_bytes, &t2_2);
    try testing.expectEqualSlices(u8, &order2_bytes, &t4_2);

    s[0] = 3;
    const t2_3 = scalarMulPublic(t2, s).toBytes();
    const t4_3 = scalarMulPublic(t4, s).toBytes();
    try testing.expectEqualSlices(u8, &order2_bytes, &t2_3);
    try testing.expectEqualSlices(u8, &neg_order4_bytes, &t4_3);

    s[0] = 4;
    const t2_4 = scalarMulPublic(t2, s).toBytes();
    const t4_4 = scalarMulPublic(t4, s).toBytes();
    try testing.expectEqualSlices(u8, &id_bytes, &t2_4);
    try testing.expectEqualSlices(u8, &id_bytes, &t4_4);
}
