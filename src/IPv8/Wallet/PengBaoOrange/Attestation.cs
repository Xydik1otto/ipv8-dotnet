// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;
using System.Security.Cryptography;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.PengBaoOrange
{
    /// <summary>
    /// Attestation creation helpers (port of ipv8/attestation/wallet/pengbaorange/attestation.py).
    /// </summary>
    public static class PengBaoAttestationFactory
    {
        /// <summary>Generate a random integer of a given number of bytes (py _random_number).</summary>
        public static BigInteger RandomNumber(int byteLen)
        {
            var bytes = new byte[byteLen];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return BigMath.FromBigEndianUnsigned(bytes);
        }

        /// <summary>
        /// Create a proof that a &lt;= value &lt;= b, for a public key's value lying within a
        /// certain bitspace (py create_attest_pair).
        /// </summary>
        public static PengBaoAttestation CreateAttestPair(BonehPublicKey pk, BigInteger value,
                                                          BigInteger a, BigInteger b, int bitspace)
        {
            var bytespace = bitspace / 8;
            var r = RandomNumber(bytespace);
            var ra = RandomNumber(bytespace);
            var raa = RandomNumber(bitspace / 16);
            raa = raa * raa;

            var w = RandomNumber(bytespace);
            var w2 = w * w;

            var c = pk.G.IntPow(value) * pk.H.IntPow(r);

            var c1 = c / pk.G.IntPow(a - 1);
            var c2 = pk.G.IntPow(b + 1) / c;
            var ca = c1.IntPow(b - value + 1) * pk.H.IntPow(ra);
            var caa = ca.IntPow(w2) * pk.H.IntPow(raa);

            var mst = w2 * (value - a + 1) * (b - value + 1);
            var m4 = BigInteger.Zero;
            while (m4.IsZero)
            {
                // py: _random_number(bytespace) % (int(sqrt(mst)) - 1) — float sqrt like py.
                m4 = RandomNumber(bytespace) % TruncateSqrt(mst);
            }
            var m3 = m4 * m4;
            var m1 = BigInteger.Zero;
            while (m1.IsZero)
            {
                m1 = RandomNumber(bytespace) % (mst - m4);
            }
            var m2 = mst - m1 - m3;

            var rst = w2 * ((b - value + 1) * r + ra) + raa;
            var r1 = BigInteger.Zero;
            while (r1.IsZero)
            {
                r1 = RandomNumber(bytespace * bytespace) % (rst / 2 - 1);
            }
            var r2 = BigInteger.Zero;
            while (r2.IsZero)
            {
                r2 = RandomNumber(bytespace * bytespace) % (rst / 2 - 1);
            }
            var r3 = rst - r1 - r2;

            var ca1 = pk.G.IntPow(m1) * pk.H.IntPow(r1);
            var ca2 = pk.G.IntPow(m2) * pk.H.IntPow(r2);
            var ca3 = caa / (ca1 * ca2);

            var el = EL.Create(b - value + 1, -r, ra, pk.G, pk.H, c1, pk.H, b, bitspace);
            var sqr1 = SQR.Create(w, raa, ca, pk.H, b, bitspace);
            var sqr2 = SQR.Create(m4, r3, pk.G, pk.H, b, bitspace);

            var publicData = new PengBaoPublicData(pk, bitspace,
                new PengBaoCommitment(c, c1, c2, ca, ca1, ca2, ca3, caa), el, sqr1, sqr2);
            var privateData = new PengBaoCommitmentPrivate(m1, m2, m3, r1, r2, r3);

            return new PengBaoAttestation(publicData, privateData);
        }

        /// <summary>py int(sqrt(x)) over a (possibly large) non-negative integer, via float like py.</summary>
        private static BigInteger TruncateSqrt(BigInteger value)
        {
            return new BigInteger(Math.Floor(Math.Sqrt((double)value)));
        }
    }
}
