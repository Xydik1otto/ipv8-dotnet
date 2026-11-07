// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;

namespace IPv8.Wallet.Primitives
{
    /// <summary>A point over FP2 (or the point at infinity "O", py-ipv8 models it as the string "O").</summary>
    public sealed class EcPoint
    {
        public static readonly EcPoint O = new EcPoint { IsO = true };

        public bool IsO;
        public FP2Value X;
        public FP2Value Y;

        public EcPoint()
        {
        }

        public EcPoint(FP2Value x, FP2Value y)
        {
            X = x;
            Y = y;
        }
    }

    /// <summary>
    /// Ported from "The Weil Pairing on Elliptic Curves and Its Cryptographic Applications" -
    /// Appendix D by Alex Edward Aftuk
    /// (port of ipv8/attestation/wallet/primitives/ec.py).
    /// </summary>
    public static class Ec
    {
        /// <summary>Perform Elliptic Curve addition of points P and Q over Fp^2 (py esum).</summary>
        public static EcPoint Esum(BigInteger mod, EcPoint p, EcPoint q)
        {
            if (p.IsO && q.IsO)
            {
                return EcPoint.O;
            }
            if (p.IsO)
            {
                return q;
            }
            if (q.IsO)
            {
                return p;
            }
            var x1 = p.X;
            var y1 = p.Y;
            var x2 = q.X;
            var y2 = q.Y;
            if (x1 == x2 && y1 == new FP2Value(mod, -1) * y2)
            {
                return EcPoint.O;
            }
            FP2Value l;
            if (x1 == x2)
            {
                l = (new FP2Value(mod, 3) * x1 * x1 / (new FP2Value(mod, 2) * y1)).Normalize();
            }
            else
            {
                l = ((y1 - y2) / (x1 - x2)).Normalize();
            }
            var x3 = l * l - x1 - x2;
            var y3 = l * (x3 - x1) + y1;
            return new EcPoint(x3.Normalize(), (new FP2Value(mod, -1) * y3).Normalize());
        }

        /// <summary>
        /// Perform the h_{T,T} function for the Miller calculation with divisors P and Q for
        /// coordinate (x, y) (py H).
        /// </summary>
        public static FP2Value H(BigInteger mod, EcPoint p, EcPoint q, FP2Value x, FP2Value y)
        {
            var x1 = p.X;
            var y1 = p.Y;
            var x2 = q.X;
            var y2 = q.Y;
            if (x1 == x2 && y1 == new FP2Value(mod, -1) * y2)
            {
                return (x - x1).Normalize();
            }
            if (x1 == x2 && y1 == y2)
            {
                var l = new FP2Value(mod, 3) * x1 * x1 / (new FP2Value(mod, 2) * y1);
                return ((y - y1 - l * (x - x1)) / (x + (x1 + x2) - l * l)).Normalize();
            }
            var slope = (y2 - y1) / (x2 - x1);
            return ((y - y1 - slope * (x - x1)) / (x + (x1 + x2) - slope * slope)).Normalize();
        }

        /// <summary>
        /// Perform the Miller calculation for message M point P and coordinates given by R
        /// (py millercalc).
        /// </summary>
        public static FP2Value Millercalc(BigInteger mod, BigInteger m, EcPoint p, EcPoint r)
        {
            var mlist = BinaryDigitsLsbFirst(m);
            var t = p;
            var f = new FP2Value(mod, 1);
            for (var i = mlist.Count - 2; i >= 0; i--)
            {
                f = (f * f * H(mod, t, t, r.X, r.Y)).Normalize();
                t = Esum(mod, t, t);
                if (mlist[i] == 1)
                {
                    f = (f * H(mod, t, p, r.X, r.Y)).Normalize();
                    t = Esum(mod, t, p);
                }
            }
            return f;
        }

        /// <summary>py: [int(c) for c in str(bin(M))[2:]] — binary digits of M, most-significant first.</summary>
        private static System.Collections.Generic.List<int> BinaryDigitsLsbFirst(BigInteger m)
        {
            var msbFirst = new System.Collections.Generic.List<int>();
            if (m.IsZero)
            {
                msbFirst.Add(0);
            }
            else
            {
                var value = m;
                while (value > 0)
                {
                    msbFirst.Add(value.IsEven ? 0 : 1);
                    value >>= 1;
                }
                msbFirst.Reverse();
            }
            // py list(reversed(...)) → least-significant first.
            msbFirst.Reverse();
            return msbFirst;
        }

        /// <summary>
        /// Create a Weil pairing for message m, points P and Q and DH secret S (py weilpairing).
        /// </summary>
        public static FP2Value WeilPairing(BigInteger mod, BigInteger m, EcPoint p, EcPoint q, EcPoint s)
        {
            var nS = new EcPoint(s.X, new FP2Value(mod, -1) * s.Y);
            var a = Millercalc(mod, m, p, Esum(mod, q, s));
            var b = Millercalc(mod, m, p, s);
            var c = Millercalc(mod, m, q, Esum(mod, p, nS));
            var d = Millercalc(mod, m, q, nS);
            var wp = a * d / (b * c);
            return wp.WpNominator() * wp.WpDenomInverse();
        }
    }
}
