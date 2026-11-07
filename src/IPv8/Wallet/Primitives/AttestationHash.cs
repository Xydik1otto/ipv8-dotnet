// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace IPv8.Wallet.Primitives
{
    /// <summary>
    /// Hash-to-int helpers (port of ipv8/attestation/wallet/primitives/attestation.py).
    /// </summary>
    public static class AttestationHash
    {
        private static byte[] Sha512(byte[] value)
        {
            using var sha512 = System.Security.Cryptography.SHA512.Create();
            return sha512.ComputeHash(value);
        }

        private static byte[] Sha256(byte[] value)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            return sha256.ComputeHash(value);
        }

        /// <summary>Convert a SHA512 hash to an integer.</summary>
        public static BigInteger Sha512AsInt(byte[] value)
        {
            var result = BigInteger.Zero;
            var hashed = Sha512(value);
            foreach (var b in hashed)
            {
                result <<= 8;
                result |= b;
            }
            return result;
        }

        /// <summary>Convert a SHA256 hash to an integer.</summary>
        public static BigInteger Sha256AsInt(byte[] value)
        {
            var result = BigInteger.Zero;
            var hashed = Sha256(value);
            foreach (var b in hashed)
            {
                result <<= 8;
                result |= b;
            }
            return result;
        }

        /// <summary>Convert a SHA256 4-byte hash to an integer.</summary>
        public static BigInteger Sha256_4AsInt(byte[] value)
        {
            var result = BigInteger.Zero;
            var hashed = Sha256(value);
            for (var i = 0; i < 4; i++)
            {
                result <<= 8;
                result |= hashed[i];
            }
            return result;
        }

        /// <summary>String helper for the EL proof: py str(int).encode() → decimal digits, UTF-8.</summary>
        public static byte[] DecimalBytes(BigInteger value) => Encoding.UTF8.GetBytes(value.ToString());
    }
}
