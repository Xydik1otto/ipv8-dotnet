// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.PengBaoOrange
{
    /// <summary>
    /// Implementation of proofs for checking commitment equality and if a commitment is a square
    /// ("Efficient Proofs that a Committed Number Lies in an Interval" by F. Boudot), modified for
    /// use with range proofs ("An efficient range proof scheme." by K. Peng and F. Bao) — port of
    /// ipv8/attestation/wallet/pengbaorange/boudot.py.
    /// </summary>
    public static class Boudot
    {
        /// <summary>Generate a secure random integer (py secure_randint).</summary>
        public static BigInteger SecureRandint(BigInteger nmin, BigInteger nmax)
        {
            var normalizedRange = nmax - nmin;
            // py: ceil(log2(normalized_range) / 8.0) — floating point, like the reference.
            var n = (int)Math.Ceiling(Math.Log((double)normalizedRange, 2) / 8.0);
            var bytes = new byte[n];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            var rbytesInt = BigMath.FromBigEndianUnsigned(bytes);
            return nmin + (rbytesInt % normalizedRange);
        }

        /// <summary>
        /// Pack a list of up to 8 ints to a bytes string, prepended with a byte for which each bit
        /// specifies if the packed int was negative (py _sipack). The packed ints are stored in
        /// REVERSE order; the sign bit of the LAST int is the least-significant bit.
        /// </summary>
        public static byte[] Sipack(params BigInteger[] n)
        {
            if (n.Length > 8)
            {
                throw new InvalidOperationException("More than 8 values specified to _sipack");
            }
            var signByte = 0;
            var packed = new List<byte[]>();
            foreach (var value in n)
            {
                signByte <<= 1;
                if (value.Sign < 0)
                {
                    signByte |= 1;
                }
                // py: packed = ipack(-i if i < 0 else i) + packed  (prepend → reverse order)
                packed.Insert(0, IPack.Pack(value.Sign < 0 ? -value : value));
            }
            var @out = new List<byte[]> { new[] { (byte)signByte } };
            @out.AddRange(packed);
            return Util.Concat(@out.ToArray());
        }

        /// <summary>
        /// Unpack a given number of integer values from a buffer packed with Sipack
        /// (py _siunpack): returns the values (original order) and the remainder.
        /// </summary>
        public static (List<BigInteger> Values, byte[] Remainder) Siunpack(byte[] buf, int amount)
        {
            var remainder = Util.SliceFrom(buf, 1);
            var nums = new List<BigInteger>();
            var signByte = buf[0];
            while (remainder.Length > 0 && nums.Count < amount)
            {
                BigInteger unpacked;
                (unpacked, remainder) = IPack.Unpack(remainder);
                var negative = signByte & 0x01;
                signByte >>= 1;
                nums.Add(negative != 0 ? -unpacked : unpacked);
            }
            nums.Reverse();
            return (nums, remainder);
        }
    }

    /// <summary>
    /// Proof that two commitments hide the same secret
    /// (port of ipv8/attestation/wallet/pengbaorange/boudot.py::EL).
    /// </summary>
    public sealed class EL
    {
        public readonly BigInteger C;
        public readonly BigInteger D;
        public readonly BigInteger D1;
        public readonly BigInteger D2;

        public EL(BigInteger c, BigInteger d, BigInteger d1, BigInteger d2)
        {
            C = c;
            D = d;
            D1 = d1;
            D2 = d2;
        }

        /// <summary>
        /// Create a new commitment that allows one to prove knowledge of secret integers x, r1
        /// and r2 (py EL.create).
        /// </summary>
        public static EL Create(BigInteger x, BigInteger r1, BigInteger r2,
                                FP2Value g1, FP2Value h1, FP2Value g2, FP2Value h2, BigInteger b,
                                int bitspace, int t = 80, int l = 40)
        {
            // NOTE (py-ipv8 bug, replicated per "source wins"): ``2 ^ (l + t) * b - 1`` uses the
            // Python XOR operator, NOT exponentiation; ``*``/``-`` bind tighter than ``^`` so the
            // XOR operand is ``(l + t) * b - 1`` (identical parse in C#).
            var maxrangeW = 2 ^ (l + t) * b - 1;
            var maxrangeN = 2 ^ (l + t + bitspace) * g1.Mod - 1;
            var w = Boudot.SecureRandint(1, maxrangeW);
            var n1 = Boudot.SecureRandint(1, maxrangeN);
            var n2 = Boudot.SecureRandint(1, maxrangeN);
            var w1 = g1.IntPow(w) * h1.IntPow(n1);
            var w2 = g2.IntPow(w) * h2.IntPow(n2);
            var cW1 = (w1.WpNominator() * w1.WpDenomInverse()).Normalize();
            var cW2 = (w2.WpNominator() * w2.WpDenomInverse()).Normalize();

            var c = AttestationHash.Sha256AsInt(Util.Concat(
                AttestationHash.DecimalBytes(cW1.A),
                AttestationHash.DecimalBytes(cW1.B),
                AttestationHash.DecimalBytes(cW2.A),
                AttestationHash.DecimalBytes(cW2.B)));
            var d = w + c * x;
            var d1 = n1 + c * r1;
            var d2 = n2 + c * r2;
            return new EL(c, d, d1, d2);
        }

        /// <summary>Check for equality with another commitment (py EL.check).</summary>
        public bool Check(FP2Value g1, FP2Value h1, FP2Value g2, FP2Value h2, FP2Value y1, FP2Value y2)
        {
            var cW1 = g1.IntPow(D) * h1.IntPow(D1) * y1.IntPow(-C);
            var cW2 = g2.IntPow(D) * h2.IntPow(D2) * y2.IntPow(-C);
            cW1 = (cW1.WpNominator() * cW1.WpDenomInverse()).Normalize();
            cW2 = (cW2.WpNominator() * cW2.WpDenomInverse()).Normalize();

            return C == AttestationHash.Sha256AsInt(Util.Concat(
                AttestationHash.DecimalBytes(cW1.A),
                AttestationHash.DecimalBytes(cW1.B),
                AttestationHash.DecimalBytes(cW2.A),
                AttestationHash.DecimalBytes(cW2.B)));
        }

        /// <summary>Convert this commitment to bytes (py EL.serialize).</summary>
        public byte[] Serialize() => Boudot.Sipack(C, D, D1, D2);

        /// <summary>Convert bytes to a commitment (py EL.unserialize).</summary>
        public static (EL El, byte[] Remainder) Unserialize(byte[] s)
        {
            var (values, remainder) = Boudot.Siunpack(s, 4);
            return (new EL(values[0], values[1], values[2], values[3]), remainder);
        }

        public override bool Equals(object other)
            => other is EL el && C == el.C && D == el.D && D1 == el.D1 && D2 == el.D2;

        // py __hash__: always 6976 to enforce a "heavy" equality check.
        public override int GetHashCode() => 6976;

        public override string ToString() => $"EL<{C},{D},{D1},{D2}>";
    }

    /// <summary>
    /// Proof that a committed number is a square
    /// (port of ipv8/attestation/wallet/pengbaorange/boudot.py::SQR).
    /// </summary>
    public sealed class SQR
    {
        public readonly FP2Value F;
        public readonly EL El;

        public SQR(FP2Value f, EL el)
        {
            F = f;
            El = el;
        }

        /// <summary>
        /// Create a new commitment that allows one to prove that the committed integer x is a
        /// square (py SQR.create).
        /// </summary>
        public static SQR Create(BigInteger x, BigInteger r1, FP2Value g, FP2Value h, BigInteger b,
                                 int bitspace)
        {
            // NOTE (py-ipv8 bug, replicated per "source wins"): ``-2 ^ bitspace * g.mod + 1`` /
            // ``2 ^ bitspace * g.mod - 1`` use the XOR operator (``*``/unary ``-``/``+`` bind
            // tighter than ``^``; identical parse in C#).
            var r2 = Boudot.SecureRandint(-2 ^ bitspace * g.Mod + 1, 2 ^ bitspace * g.Mod - 1);
            var f = g.IntPow(x) * h.IntPow(r2);
            var r3 = r1 - r2 * x;
            return new SQR(f, EL.Create(x, r2, r3, g, h, f, h, b, bitspace));
        }

        /// <summary>Check for a committed square (py SQR.check).</summary>
        public bool Check(FP2Value g, FP2Value h, FP2Value y) => El.Check(g, h, F, h, F, y);

        /// <summary>Convert this commitment to bytes (py SQR.serialize).</summary>
        public byte[] Serialize()
        {
            var minF = F.WpCompress();
            return Util.Concat(IPack.Pack(minF.Mod), IPack.Pack(minF.A), IPack.Pack(minF.B), El.Serialize());
        }

        /// <summary>Convert bytes to a commitment (py SQR.unserialize).</summary>
        public static (SQR Sqr, byte[] Remainder) Unserialize(byte[] s)
        {
            var remainder = s;
            BigInteger mod, fa, fb;
            (mod, remainder) = IPack.Unpack(remainder);
            (fa, remainder) = IPack.Unpack(remainder);
            (fb, remainder) = IPack.Unpack(remainder);
            var (el, remainder2) = EL.Unserialize(remainder);
            return (new SQR(new FP2Value(mod, fa, fb), el), remainder2);
        }

        public override bool Equals(object other) => other is SQR sqr && F == sqr.F && El == sqr.El;

        // py __hash__: always 838182 to enforce a "heavy" equality check.
        public override int GetHashCode() => 838182;

        public override string ToString() => $"SQR<{F},{El}>";
    }
}
