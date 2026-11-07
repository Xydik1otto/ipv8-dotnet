// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;

namespace IPv8.Wallet.Primitives
{
    /// <summary>
    /// Implementation of the Boneh 2-DNF scheme ("Evaluating 2-DNF Formulas on Ciphertexts" by
    /// Boneh et al.) — port of ipv8/attestation/wallet/primitives/boneh.py.
    /// </summary>
    public static class Boneh
    {
        private static readonly Random Rng = new Random();

        /// <summary>
        /// Generate p = l * n - 1 such that p is "prime" and p mod 3 = 2, with l as small as possible.
        /// </summary>
        public static BigInteger GeneratePrime(BigInteger n)
        {
            var p = BigInteger.One;
            var l = BigInteger.Zero;
            while (p % 3 != 2 || !BigMath.IsPrime(p))
            {
                l += 1;
                p = l * n - 1;
            }
            return p;
        }

        /// <summary>Generate a bilinear group for two generators (py bilinear_group).</summary>
        public static FP2Value BilinearGroup(BigInteger n, BigInteger p, BigInteger g1x, BigInteger g1y,
                                             BigInteger g2x, BigInteger g2y)
        {
            try
            {
                // NOTE (py quirk, replicated): the second point's x-coordinate lands in the
                // FP2Value 'b' slot (a == 0).
                return Ec.WeilPairing(p, n,
                    new EcPoint(new FP2Value(p, g1x), new FP2Value(p, g1y)),
                    new EcPoint(new FP2Value(p, b: g2x), new FP2Value(p, g2y)),
                    new EcPoint(new FP2Value(p), new FP2Value(p)));
            }
            catch (Exception)
            {
                return new FP2Value(p);
            }
        }

        /// <summary>Create a random exponentiation of p in message space n.</summary>
        public static FP2Value GetRandomExponentiation(FP2Value p, BigInteger n)
        {
            var r = RandInt(4, n - 1);
            var test = p.IntPow(r);
            while (test == new FP2Value(p.Mod, 1))
            {
                test = p.IntPow(RandInt(4, n - 1));
            }
            return test;
        }

        /// <summary>Create a generator for the EC.</summary>
        public static (BigInteger X, BigInteger Y) GetRandomBase(BigInteger n)
        {
            var x = RandInt(2, n - 1);
            var y = RandInt(2, n - 1);
            return (x, y);
        }

        private static BigInteger RandInt(BigInteger min, BigInteger max)
        {
            // py random.randint: inclusive on both ends.
            var range = max - min + 1;
            var bytes = new byte[(BigMath.ToBitLength(range) + 7) / 8];
            BigInteger candidate;
            do
            {
                lock (Rng)
                {
                    Rng.NextBytes(bytes);
                }
                candidate = BigMath.FromBigEndianUnsigned(bytes) % range;
            } while (false);
            return min + candidate;
        }

        /// <summary>A good pairing is not 0 and has order n (py is_good_wp).</summary>
        public static bool IsGoodWp(BigInteger n, FP2Value wp)
        {
            var isOne = wp == new FP2Value(wp.Mod, 1);
            var isZero = wp == new FP2Value(wp.Mod);
            var goodOrder = wp.IntPow(n + 1) == wp;
            return goodOrder && !isZero && !isOne;
        }

        /// <summary>
        /// Instead of inspecting torsion points and checking for co-primality: just brute force
        /// generate pairings until we get a good one (py get_good_wp).
        /// </summary>
        public static (BigInteger P, FP2Value Wp) GetGoodWp(BigInteger n, BigInteger? p = null)
        {
            FP2Value wp = null;
            var modulus = p ?? 0;
            if (modulus.IsZero)
            {
                modulus = GeneratePrime(n);
            }
            while (wp == null || !IsGoodWp(n, wp))
            {
                var (g1x, g1y) = GetRandomBase(n);
                wp = BilinearGroup(n, modulus, g1x, g1y, g1x, g1y);
                if (!IsGoodWp(n, wp))
                {
                    wp = wp.IntPow((modulus + 1) / n);
                }
            }
            return (modulus, wp);
        }

        /// <summary>Generate some primes. Key size in bits (py generate_primes).</summary>
        public static (BigInteger Min, BigInteger Max) GeneratePrimes(int keySize)
        {
            BigInteger p, q;
            if (keySize >= 512)
            {
                p = BigMath.GenerateRsaPrime(keySize);
                q = BigMath.GenerateRsaPrime(keySize);
            }
            else
            {
                p = BigMath.GenerateSafePrime(keySize);
                q = BigMath.GenerateSafePrime(keySize);
            }
            return (BigInteger.Min(p, q), BigInteger.Max(p, q));
        }

        /// <summary>Generate a keypair for a certain prime bit space (py generate_keypair).</summary>
        public static (BonehPublicKey PublicKey, BonehPrivateKey PrivateKey) GenerateKeypair(int keySize = 32)
        {
            var (t1, t2) = GeneratePrimes(keySize);
            var n = t1 * t2;
            var (p, g) = GetGoodWp(n);
            FP2Value u = null;
            while (u == null || u.IntPow(t2) == new FP2Value(p, 1))
            {
                (_, u) = GetGoodWp(n, p);
            }
            var h = u.IntPow(t2);
            return (new BonehPublicKey(p, g, h), new BonehPrivateKey(p, g, h, t1 * t2, t1));
        }

        /// <summary>Encode a message m given a public key.</summary>
        public static FP2Value Encode(BonehPublicKey pubkey, BigInteger m)
            => pubkey.G.IntPow(m) * GetRandomExponentiation(pubkey.H, pubkey.P);

        /// <summary>Decode a ciphertext c given a private key and the possible source messages.</summary>
        public static BigInteger? Decode(BonehPrivateKey privkey, BigInteger[] msgspace, FP2Value c)
        {
            var d = c.IntPow(privkey.T1);
            var t = privkey.G.IntPow(privkey.T1);
            foreach (var m in msgspace)
            {
                if (d == t.IntPow(m))
                {
                    return m;
                }
            }
            return null;
        }
    }
}
