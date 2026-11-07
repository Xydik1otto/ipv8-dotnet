// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Linq;
using System.Numerics;
using IPv8.Wallet.Primitives;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A18 (part 1): BigInteger byte-order conversion + ipack/iunpack + FP2Value algebra
    /// golden vectors (vectors-phase2.json → ipack / fp2).
    /// </summary>
    public class BigMathTests
    {
        [Fact]
        public void BigEndian_Conversion_Roundtrip()
        {
            var samples = new[]
            {
                BigInteger.Zero, BigInteger.One, new BigInteger(255), new BigInteger(256),
                new BigInteger(65535), new BigInteger(65536),
                BigInteger.Parse("123456789012345678901234567890"),
                BigInteger.Pow(2, 127) - 1
            };
            foreach (var value in samples)
            {
                var bytes = BigMath.ToBigEndianUnsigned(value);
                Assert.Equal(0, bytes[0] != 0 || bytes.Length == 1 ? 0 : 1); // minimal: no leading zero
                Assert.Equal(value, BigMath.FromBigEndianUnsigned(bytes));
            }
            // The constructor interpretation check: big-endian unsigned, NOT little-endian signed.
            Assert.Equal(new BigInteger(0x0100), BigMath.FromBigEndianUnsigned(new byte[] { 0x01, 0x00 }));
            Assert.Equal(new BigInteger(0x8080), BigMath.FromBigEndianUnsigned(new byte[] { 0x80, 0x80 }));
            Assert.Equal(new byte[] { 0x80 }, BigMath.ToBigEndianUnsigned(new BigInteger(128)));
            Assert.Equal(new byte[] { 0x00 }, BigMath.ToBigEndianUnsigned(BigInteger.Zero));
        }

        [Fact]
        public void Ipack_Golden_Vectors_Byte_Exact()
        {
            foreach (var (num, packedHex) in Vectors2.IpackVectors())
            {
                var packed = IPack.Pack(BigInteger.Parse(num));
                Assert.Equal(packedHex, Util.Hex(packed));

                var (unpacked, remainder) = IPack.Unpack(Util.Unhex(packedHex));
                Assert.Equal(BigInteger.Parse(num), unpacked);
                Assert.Empty(remainder);
            }
        }

        [Fact]
        public void PackPair_UnpackPair_Roundtrip()
        {
            var packed = IPack.PackPair(123, 456);
            var (a, b, remainder) = IPack.UnpackPair(packed);
            Assert.Equal(new BigInteger(123), a);
            Assert.Equal(new BigInteger(456), b);
            Assert.Empty(remainder);
        }

        [Fact]
        public void Fp2_Golden_Vectors()
        {
            foreach (var (mod, a, b, op, outA, outB) in Vectors2.Fp2Vectors())
            {
                var x = new FP2Value(mod, a, b);
                var y = new FP2Value(mod, b, a);
                FP2Value result;
                switch (op)
                {
                    case "add": result = x + y; break;
                    case "sub": result = x - y; break;
                    case "mul": result = x * y; break;
                    case "div": result = x / y; break;
                    case "pow3": result = x.IntPow(3); break;
                    case "pow_inv2": result = x.IntPow(-2); break;
                    case "norm": result = x.Normalize(); break;
                    case "inv": result = x.Inverse(); break;
                    case "wp_nom": result = x.WpNominator(); break;
                    case "wp_denom_inv": result = x.WpDenomInverse(); break;
                    case "compress": result = x.WpCompress(); break;
                    case "pow1000_a": result = new FP2Value(mod, a).IntPow(1000); break;
                    default: throw new InvalidOperationException("unknown fp2 op " + op);
                }
                var normalized = result.Normalize();
                Assert.Equal(outA, normalized.A.ToString());
                Assert.Equal(outB, normalized.B.ToString());
            }
        }

        [Fact]
        public void Fp2_Equality_Is_Normalize_Division_Based()
        {
            var mod = new BigInteger(1031);
            // py __eq__: (self // other).normalize() has a == aC etc.
            Assert.True(new FP2Value(mod, 20) == new FP2Value(mod, 20, 0, 0, 1));
            // 20/4 == 5 (the value lives in numerator/denominator form).
            Assert.True(new FP2Value(mod, 20, 0, 0, 4) == new FP2Value(mod, 5));
            Assert.False(new FP2Value(mod, 20) == new FP2Value(mod, 20, 0, 0, 4));
            Assert.False(new FP2Value(mod, 3, 5) == new FP2Value(mod, 3, 6));
            // Hashing is constant-zero like py (equality is the "heavy" check).
            Assert.Equal(0, new FP2Value(mod, 3, 5).GetHashCode());
        }

        [Fact]
        public void Sha_As_Int_Golden_Vectors()
        {
            var value = Util.Utf8("hello world");
            Assert.Equal(Vectors2.ShaAsInt("sha512_of_hex"), AttestationHash.Sha512AsInt(value).ToString());
            Assert.Equal(Vectors2.ShaAsInt("sha256_of_hex"), AttestationHash.Sha256AsInt(value).ToString());
            Assert.Equal(Vectors2.ShaAsInt("sha256_4_of_hex"), AttestationHash.Sha256_4AsInt(value).ToString());
        }

        [Fact]
        public void IsPrime_Basics()
        {
            Assert.False(BigMath.IsPrime(BigInteger.Zero));
            Assert.False(BigMath.IsPrime(BigInteger.One));
            Assert.True(BigMath.IsPrime(new BigInteger(2)));
            Assert.True(BigMath.IsPrime(new BigInteger(1031)));
            Assert.False(BigMath.IsPrime(new BigInteger(1031 * 1033)));
            Assert.True(BigMath.IsPrime(BigInteger.Parse("18446744073709551557"))); // largest 64-bit prime
            // Safe prime generation produces primes of the right bit length.
            var p = BigMath.GenerateSafePrime(32);
            Assert.True(BigMath.IsPrime(p));
            Assert.True(BigMath.IsPrime((p - 1) / 2));
            Assert.Equal(32, BigMath.ToBitLength(p));
        }
    }
}
