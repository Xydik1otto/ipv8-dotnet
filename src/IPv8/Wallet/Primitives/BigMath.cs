// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;
using System.Security.Cryptography;

namespace IPv8.Wallet.Primitives
{
    /// <summary>
    /// System.Numerics.BigInteger ↔ py-integer byte-string conversion helpers.
    ///
    /// CRITICAL WIRE FACT: Python turns wire bytes into ints with
    /// ``int(hexlify(b), 16)`` — a BIG-ENDIAN, UNSIGNED interpretation — and writes ints
    /// back as minimal big-endian byte strings (see primitives/structs._num_to_str).
    /// System.Numerics.BigInteger's byte-array constructor is LITTLE-ENDIAN and SIGNED
    /// (two's complement). Every conversion between the two worlds MUST go through
    /// this class or the golden vectors will not match.
    /// </summary>
    public static class BigMath
    {
        /// <summary>
        /// Interpret big-endian unsigned bytes exactly like Python's ``int(hexlify(b), 16)``
        /// (an empty byte string is 0).
        /// </summary>
        public static BigInteger FromBigEndianUnsigned(byte[] bigEndian)
        {
            if (bigEndian == null)
            {
                throw new ArgumentNullException(nameof(bigEndian));
            }
            // Reverse to little-endian; a set high bit in the most significant byte would
            // make the value negative, so pad with a zero byte in that case.
            var littleEndian = new byte[bigEndian.Length];
            for (var i = 0; i < bigEndian.Length; i++)
            {
                littleEndian[i] = bigEndian[bigEndian.Length - 1 - i];
            }
            if (littleEndian.Length > 0 && (littleEndian[littleEndian.Length - 1] & 0x80) != 0)
            {
                var padded = new byte[littleEndian.Length + 1];
                Array.Copy(littleEndian, padded, littleEndian.Length);
                return new BigInteger(padded);
            }
            return new BigInteger(littleEndian);
        }

        /// <summary>
        /// Minimal big-endian unsigned byte representation of a non-negative value
        /// (Python's ``hex(n)[2:]`` unhexlified; the empty string for 0).
        /// </summary>
        public static byte[] ToBigEndianUnsigned(BigInteger value)
        {
            if (value.Sign < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Python ints on the wire are never negative here");
            }
            var littleEndian = value.ToByteArray(); // little-endian, signed (may carry a 0x00 sign byte)
            var high = littleEndian[littleEndian.Length - 1];
            var length = littleEndian.Length;
            if (high == 0 && length > 1 && value.IsZero)
            {
                length = 1; // BigInteger(0).ToByteArray() == [0x00]
            }
            else if (high == 0x00 && length > 1)
            {
                length -= 1; // strip the sign byte (value is non-negative)
            }
            var bigEndian = new byte[length];
            for (var i = 0; i < length; i++)
            {
                bigEndian[i] = littleEndian[length - 1 - i];
            }
            return bigEndian;
        }

        /// <summary>
        /// A random integer in [min, max] (both INCLUSIVE, like Python's random.randint).
        /// </summary>
        public static BigInteger RandInt(BigInteger min, BigInteger max, Random random = null)
        {
            var range = max - min + 1;
            if (range <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(max), "empty randint range");
            }
            var byteLength = (ToBitLength(range) + 7) / 8;
            var candidate = RandomInRange(range, byteLength, random);
            return min + candidate;
        }

        /// <summary>A random integer in [min, max] drawn from a cryptographic RNG (py os.urandom-style).</summary>
        public static BigInteger SecureRandInt(BigInteger min, BigInteger max)
        {
            var range = max - min + 1;
            if (range <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(max), "empty randint range");
            }
            var byteLength = (ToBitLength(range) + 7) / 8;
            var buffer = new byte[byteLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                BigInteger candidate;
                do
                {
                    rng.GetBytes(buffer);
                    candidate = FromBigEndianUnsigned(buffer) % range;
                } while (false);
                return min + candidate;
            }
        }

        private static BigInteger RandomInRange(BigInteger range, int byteLength, Random random)
        {
            var buffer = new byte[byteLength];
            var rng = random ?? new Random();
            BigInteger candidate;
            do
            {
                rng.NextBytes(buffer);
                candidate = FromBigEndianUnsigned(buffer) % range;
            } while (false);
            return candidate;
        }

        /// <summary>The bit length of a non-negative BigInteger (Python's n.bit_length()).</summary>
        public static int ToBitLength(BigInteger value)
        {
            if (value.Sign < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }
            if (value.IsZero)
            {
                return 0;
            }
            var bytes = value.ToByteArray(); // little-endian
            var high = bytes[bytes.Length - 1];
            var bits = (bytes.Length - 1) * 8;
            while (high > 0)
            {
                bits++;
                high >>= 1;
            }
            return bits;
        }

        private static readonly BigInteger[] MillerRabinBases = { 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };

        /// <summary>
        /// Miller-Rabin primality test (replaces the ``ipv8_rust_tunnels.is_prime`` wheel
        /// function). Deterministic for arguments below 3.3 * 10^24 with the fixed base set;
        /// larger values get additional random rounds.
        /// </summary>
        public static bool IsPrime(BigInteger n)
        {
            if (n < 2)
            {
                return false;
            }
            foreach (var p in MillerRabinBases)
            {
                if (n % p == 0)
                {
                    return n == p;
                }
            }
            var d = n - 1;
            var r = 0;
            while (d.IsEven)
            {
                d /= 2;
                r++;
            }
            var rounds = MillerRabinBases;
            if (ToBitLength(n) > 80)
            {
                // Not covered by the fixed base set: add random witnesses.
                var all = new BigInteger[MillerRabinBases.Length + 24];
                for (var i = 0; i < MillerRabinBases.Length; i++)
                {
                    all[i] = MillerRabinBases[i];
                }
                using (var rng = RandomNumberGenerator.Create())
                {
                    for (var i = 0; i < 24; i++)
                    {
                        var buffer = new byte[(ToBitLength(n - 4) + 7) / 8];
                        rng.GetBytes(buffer);
                        all[MillerRabinBases.Length + i] = FromBigEndianUnsigned(buffer) % (n - 3) + 2;
                    }
                }
                rounds = all;
            }
            foreach (var a in rounds)
            {
                var x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == n - 1)
                {
                    continue;
                }
                var composite = true;
                for (var i = 0; i < r - 1; i++)
                {
                    x = x * x % n;
                    if (x == n - 1)
                    {
                        composite = false;
                        break;
                    }
                }
                if (composite)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Generate a safe prime p of ``keySize`` bits (p = 2q + 1 with q prime), replacing the
        /// ``ipv8_rust_tunnels.generate_safe_prime`` wheel function.
        /// </summary>
        public static BigInteger GenerateSafePrime(int keySize)
        {
            while (true)
            {
                var q = RandomPrime(keySize - 1);
                var p = 2 * q + 1;
                if (IsPrime(p))
                {
                    return p;
                }
            }
        }

        /// <summary>
        /// Generate a (probable) prime of ``keySize`` bits, replacing the
        /// ``ipv8_rust_tunnels.generate_rsa_prime`` wheel function.
        /// </summary>
        public static BigInteger GenerateRsaPrime(int keySize)
        {
            return RandomPrime(keySize);
        }

        private static BigInteger RandomPrime(int keySize)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var mask = (BigInteger.One << keySize) - 1;
                while (true)
                {
                    var bytes = new byte[(keySize + 7) / 8];
                    rng.GetBytes(bytes);
                    var candidate = FromBigEndianUnsigned(bytes) & mask;
                    // Force exactly keySize bits and odd.
                    candidate |= BigInteger.One << (keySize - 1);
                    candidate |= BigInteger.One;
                    if (IsPrime(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }
    }
}
