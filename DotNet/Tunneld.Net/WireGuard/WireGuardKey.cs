using System.Numerics;
using System.Security.Cryptography;

namespace Tunneld.Net.WireGuard;

public sealed class WireGuardKey
{
    public const int KeySize = 32;
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger A24 = 121665;
    private readonly byte[] _bytes;

    private WireGuardKey(byte[] bytes)
    {
        if (bytes.Length != KeySize)
        {
            throw new ArgumentException($"WireGuard keys must be {KeySize} bytes", nameof(bytes));
        }
        _bytes = bytes;
    }

    public string PublicKey => Convert.ToBase64String(X25519(_bytes, BasePoint()));

    public static WireGuardKey Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(KeySize);
        Clamp(bytes);
        return new WireGuardKey(bytes);
    }

    public static WireGuardKey ParseBase64(string value)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(value);
        }
        catch (FormatException ex)
        {
            throw new FormatException("invalid base64 WireGuard key", ex);
        }

        if (bytes.Length != KeySize)
        {
            throw new FormatException($"WireGuard key must decode to {KeySize} bytes, got {bytes.Length}");
        }
        return new WireGuardKey(bytes);
    }

    public static byte[] X25519(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u)
    {
        if (scalar.Length != KeySize || u.Length != KeySize)
        {
            throw new ArgumentException("X25519 inputs must be 32 bytes");
        }

        var k = scalar.ToArray();
        Clamp(k);
        var uBytes = u.ToArray();
        uBytes[31] &= 0x7f;

        var x1 = DecodeLittleEndian(uBytes);
        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        var swap = 0;

        for (var t = 254; t >= 0; t--)
        {
            var kt = (k[t / 8] >> (t & 7)) & 1;
            swap ^= kt;
            ConditionalSwap(swap, ref x2, ref x3);
            ConditionalSwap(swap, ref z2, ref z3);
            swap = kt;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + A24 * e));
        }

        ConditionalSwap(swap, ref x2, ref x3);
        ConditionalSwap(swap, ref z2, ref z3);
        return EncodeLittleEndian(Mod(x2 * BigInteger.ModPow(z2, P - 2, P)));
    }

    public override string ToString() => Convert.ToBase64String(_bytes);

    private static byte[] BasePoint()
    {
        var bp = new byte[KeySize];
        bp[0] = 9;
        return bp;
    }

    private static void Clamp(byte[] bytes)
    {
        bytes[0] &= 248;
        bytes[31] = (byte)((bytes[31] & 127) | 64);
    }

    private static BigInteger DecodeLittleEndian(byte[] bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: false);

    private static byte[] EncodeLittleEndian(BigInteger n)
    {
        var raw = n.ToByteArray(isUnsigned: true, isBigEndian: false);
        var output = new byte[KeySize];
        Array.Copy(raw, output, Math.Min(raw.Length, output.Length));
        return output;
    }

    private static BigInteger Mod(BigInteger n)
    {
        var result = n % P;
        return result.Sign < 0 ? result + P : result;
    }

    private static void ConditionalSwap(int swap, ref BigInteger a, ref BigInteger b)
    {
        if (swap == 0)
        {
            return;
        }
        (a, b) = (b, a);
    }
}
