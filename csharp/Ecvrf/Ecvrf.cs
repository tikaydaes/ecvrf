using System.Numerics;
using System.Security.Cryptography;

namespace Ecvrf;

/// <summary>
/// RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03) in pure C#.
/// Zero external runtime dependencies (uses System.Numerics.BigInteger and SHA512).
/// </summary>
public static class EcvrfEd25519
{
    public const byte SuiteByte = 0x03;
    public const int SecretKeyLen = 32;
    public const int PublicKeyLen = 32;
    public const int ProofLen = 80;
    public const int BetaLen = 64;
    private const int ChallengeLen = 16;

    private static readonly BigInteger P = (BigInteger.One << 255) - 19;
    private static readonly BigInteger Q = (BigInteger.One << 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger PMinus2 = P - 2;
    private static readonly BigInteger PPlus3Div8 = (P + 3) >> 3;
    private static readonly BigInteger SqrtM1 = BigInteger.ModPow(2, (P - 1) >> 2, P);
    private static readonly BigInteger D = Mod(-121665 * BigInteger.ModPow(121666, PMinus2, P), P);

    private readonly record struct Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T);

    private static readonly Point Identity = new(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
    private static readonly Point BasePoint = MakeBasePoint();

    private static Point MakeBasePoint()
    {
        var by = Mod(4 * BigInteger.ModPow(5, PMinus2, P), P);
        var bx = XRecover(by) ?? throw new InvalidOperationException("failed to recover base point");
        return new Point(bx, by, BigInteger.One, (bx * by) % P);
    }

    private static BigInteger Mod(BigInteger v, BigInteger m)
    {
        var r = v % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static BigInteger FromLE(ReadOnlySpan<byte> bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: false);

    private static byte[] ToLE(BigInteger v, int len)
    {
        var outBytes = new byte[len];
        if (!v.TryWriteBytes(outBytes, out _, isUnsigned: true, isBigEndian: false))
            throw new ArgumentOutOfRangeException(nameof(v), $"value does not fit in {len} bytes");
        return outBytes;
    }

    private static BigInteger? XRecover(BigInteger y)
    {
        var yy = (y * y) % P;
        var u = Mod(yy - 1, P);
        var v = Mod(D * yy + 1, P);
        var xx = Mod(u * BigInteger.ModPow(v, PMinus2, P), P);
        var x = BigInteger.ModPow(xx, PPlus3Div8, P);
        if (Mod(x * x - xx, P) != 0)
            x = (x * SqrtM1) % P;
        if (Mod(x * x - xx, P) != 0)
            return null;
        if (!x.IsEven)
            x = P - x;
        return x;
    }

    private static Point PointAdd(Point p1, Point p2)
    {
        var a = Mod((p1.Y - p1.X) * (p2.Y - p2.X), P);
        var b = Mod((p1.Y + p1.X) * (p2.Y + p2.X), P);
        var c = Mod(((2 * p1.T * p2.T) % P) * D, P);
        var dd = Mod(2 * p1.Z * p2.Z, P);
        var e = Mod(b - a, P);
        var f = Mod(dd - c, P);
        var g = Mod(dd + c, P);
        var h = Mod(b + a, P);
        return new Point((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P);
    }

    private static Point PointMulBy8(Point pt)
    {
        var p2 = PointAdd(pt, pt);
        var p4 = PointAdd(p2, p2);
        return PointAdd(p4, p4);
    }

    private static Point PointMulRaw(Point pt, BigInteger k)
    {
        var acc = Identity;
        var addend = pt;
        var cur = k;
        while (cur > 0)
        {
            if (!cur.IsEven)
                acc = PointAdd(acc, addend);
            addend = PointAdd(addend, addend);
            cur >>= 1;
        }
        return acc;
    }

    private static Point PointMul(Point pt, BigInteger k) =>
        PointMulRaw(pt, Mod(k, Q));

    private static bool IsIdentity(Point pt) =>
        Mod(pt.X, P) == 0 && Mod(pt.Y - pt.Z, P) == 0;

    private static byte[] EncodePoint(Point pt)
    {
        var zi = BigInteger.ModPow(pt.Z, PMinus2, P);
        var ax = (pt.X * zi) % P;
        var ay = (pt.Y * zi) % P;
        var outBytes = ToLE(ay, 32);
        if (!ax.IsEven)
            outBytes[31] |= 0x80;
        return outBytes;
    }

    private static Point? DecodePoint(ReadOnlySpan<byte> b)
    {
        if (b.Length != 32) return null;
        int sign = (b[31] >> 7) & 1;
        Span<byte> yBytes = stackalloc byte[32];
        b.CopyTo(yBytes);
        yBytes[31] &= 0x7f;
        var y = FromLE(yBytes);
        if (y >= P) return null;
        var xOpt = XRecover(y);
        if (xOpt is null) return null;
        var x = xOpt.Value;
        if (x == 0 && sign == 1) return null;
        if ((x.IsEven ? 0 : 1) != sign)
            x = P - x;
        return new Point(x, y, BigInteger.One, (x * y) % P);
    }

    private static Point? ValidateKey(ReadOnlySpan<byte> pk)
    {
        var y = DecodePoint(pk);
        if (y is null) return null;
        if (IsIdentity(PointMulBy8(y.Value))) return null;
        return y;
    }

    public static bool IsPublicKey(byte[] pk) => ValidateKey(pk) is not null;

    private static (BigInteger x, byte[] prefix) ExpandSecretKey(byte[] sk)
    {
        if (sk.Length != SecretKeyLen)
            throw new ArgumentException($"secret key must be {SecretKeyLen} bytes", nameof(sk));
        var h = SHA512.HashData(sk);
        var xb = h[..32];
        xb[0] &= 248;
        xb[31] &= 127;
        xb[31] |= 64;
        return (FromLE(xb), h[32..]);
    }

    private static Point EncodeToCurveTai(byte[] pk, byte[] alpha)
    {
        var buf = new byte[2 + pk.Length + alpha.Length + 2];
        buf[0] = SuiteByte;
        buf[1] = 0x01;
        Buffer.BlockCopy(pk, 0, buf, 2, pk.Length);
        Buffer.BlockCopy(alpha, 0, buf, 2 + pk.Length, alpha.Length);
        int ctrIdx = 2 + pk.Length + alpha.Length;
        buf[ctrIdx + 1] = 0x00;

        for (int ctr = 0; ctr <= 255; ctr++)
        {
            buf[ctrIdx] = (byte)ctr;
            var hash = SHA512.HashData(buf);
            var pt = DecodePoint(hash.AsSpan(0, 32));
            if (pt is not null)
                return PointMulBy8(pt.Value);
        }

        throw new InvalidOperationException("encode_to_curve failed after 256 iterations");
    }

    private static (BigInteger c, byte[] cBytes) ChallengeGeneration(
        Point y, Point h, Point gamma, Point u, Point v)
    {
        var buf = new byte[2 + 5 * 32 + 1];
        buf[0] = SuiteByte;
        buf[1] = 0x02;
        Buffer.BlockCopy(EncodePoint(y), 0, buf, 2, 32);
        Buffer.BlockCopy(EncodePoint(h), 0, buf, 34, 32);
        Buffer.BlockCopy(EncodePoint(gamma), 0, buf, 66, 32);
        Buffer.BlockCopy(EncodePoint(u), 0, buf, 98, 32);
        Buffer.BlockCopy(EncodePoint(v), 0, buf, 130, 32);
        buf[162] = 0x00;

        var hash = SHA512.HashData(buf);
        var cBytes = hash[..ChallengeLen];
        return (FromLE(cBytes), cBytes);
    }

    private static byte[] GammaToHash(Point gamma)
    {
        var buf = new byte[2 + 32 + 1];
        buf[0] = SuiteByte;
        buf[1] = 0x03;
        Buffer.BlockCopy(EncodePoint(PointMulBy8(gamma)), 0, buf, 2, 32);
        buf[34] = 0x00;
        return SHA512.HashData(buf);
    }

    private static (Point gamma, BigInteger c, byte[] cBytes, BigInteger s)? DecodeProof(byte[] pi)
    {
        if (pi.Length != ProofLen) return null;
        var gamma = DecodePoint(pi.AsSpan(0, 32));
        if (gamma is null) return null;
        var cBytes = pi[32..48];
        var c = FromLE(cBytes);
        var s = FromLE(pi.AsSpan(48, 32));
        if (s >= Q) return null;
        return (gamma.Value, c, cBytes, s);
    }

    public static byte[] DerivePublicKey(byte[] sk)
    {
        var (x, _) = ExpandSecretKey(sk);
        return EncodePoint(PointMulRaw(BasePoint, x));
    }

    public static byte[] Prove(byte[] sk, byte[] alpha)
    {
        var (x, prefix) = ExpandSecretKey(sk);
        var y = PointMulRaw(BasePoint, x);
        var pk = EncodePoint(y);
        var h = EncodeToCurveTai(pk, alpha);
        var gamma = PointMulRaw(h, x);

        var nonceIn = new byte[64];
        Buffer.BlockCopy(prefix, 0, nonceIn, 0, 32);
        Buffer.BlockCopy(EncodePoint(h), 0, nonceIn, 32, 32);
        var k = Mod(FromLE(SHA512.HashData(nonceIn)), Q);

        var u = PointMul(BasePoint, k);
        var v = PointMul(h, k);
        var (c, cBytes) = ChallengeGeneration(y, h, gamma, u, v);
        var s = Mod(k + c * x, Q);

        var pi = new byte[ProofLen];
        Buffer.BlockCopy(EncodePoint(gamma), 0, pi, 0, 32);
        Buffer.BlockCopy(cBytes, 0, pi, 32, ChallengeLen);
        Buffer.BlockCopy(ToLE(s, 32), 0, pi, 48, 32);
        return pi;
    }

    public static byte[] ProofToHash(byte[] pi)
    {
        var decoded = DecodeProof(pi) ?? throw new ArgumentException("invalid proof", nameof(pi));
        return GammaToHash(decoded.gamma);
    }

    public static (bool valid, byte[]? beta) Verify(byte[] pk, byte[] pi, byte[] alpha)
    {
        var y = ValidateKey(pk);
        if (y is null) return (false, null);
        var decoded = DecodeProof(pi);
        if (decoded is null) return (false, null);
        var (gamma, c, cBytes, s) = decoded.Value;
        var h = EncodeToCurveTai(pk, alpha);
        var negC = Mod(Q - c, Q);

        var u = PointAdd(PointMul(BasePoint, s), PointMul(y.Value, negC));
        var v = PointAdd(PointMul(h, s), PointMul(gamma, negC));
        var (_, cPrimeBytes) = ChallengeGeneration(y.Value, h, gamma, u, v);

        if (!CryptographicOperations.FixedTimeEquals(cBytes, cPrimeBytes))
            return (false, null);
        return (true, GammaToHash(gamma));
    }
}
