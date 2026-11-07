// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;
using System.Text;

namespace IPv8.Wallet.Primitives
{
    /// <summary>
    /// Defines a rational value (a + bx + cx^2)/(aC + bCx + cCx^2)(mod 1 + x + x^2, mod p)
    /// (port of ipv8/attestation/wallet/primitives/value.py::FP2Value).
    /// </summary>
    public sealed class FP2Value
    {
        public readonly BigInteger Mod;
        public readonly BigInteger A;
        public readonly BigInteger B;
        public readonly BigInteger C;
        public readonly BigInteger AC;
        public readonly BigInteger BC;
        public readonly BigInteger CC;

        public FP2Value(BigInteger mod, BigInteger? a = null, BigInteger? b = null, BigInteger? c = null,
                        BigInteger? aC = null, BigInteger? bC = null, BigInteger? cC = null)
        {
            Mod = mod;
            // py: a % mod for all six coefficients (Python's % wraps negatives, C#'s does not).
            A = PyMod(a ?? BigInteger.Zero, mod);
            B = PyMod(b ?? BigInteger.Zero, mod);
            C = PyMod(c ?? BigInteger.Zero, mod);
            AC = PyMod(aC ?? BigInteger.One, mod);
            BC = PyMod(bC ?? BigInteger.Zero, mod);
            CC = PyMod(cC ?? BigInteger.Zero, mod);
        }

        /// <summary>Python-style modulo: the result carries the sign of the modulus (never negative).</summary>
        public static BigInteger PyMod(BigInteger value, BigInteger mod)
        {
            var result = value % mod;
            if (result.Sign < 0)
            {
                result += BigInteger.Abs(mod);
            }
            return result;
        }

        public override string ToString()
        {
            var numerator = FormatPolynomial(A, B, C);
            var denominator = FormatPolynomial(AC, BC, CC);
            return denominator == "1" ? numerator : $"({numerator})/({denominator})";
        }

        /// <summary>Port of value.py::format_polynomial (cx^2 + bx + a pretty-printer).</summary>
        public static string FormatPolynomial(BigInteger a, BigInteger b, BigInteger c)
        {
            var @out = new StringBuilder();
            foreach (var (v, s) in new[] { (a, ""), (b, "x"), (c, "x^2") })
            {
                if (!v.IsZero)
                {
                    var fmtV = BigInteger.Abs(v).IsOne && s != "" ? "" : BigInteger.Abs(v).ToString();
                    if (@out.Length > 0)
                    {
                        @out.Append(" + ");
                    }
                    @out.Append(fmtV).Append(s);
                }
            }
            return @out.Length == 0 ? "0" : @out.ToString();
        }

        /// <summary>Modular multiplicative inverse (py _modinv; result in [0, m)).</summary>
        public static BigInteger ModInverse(BigInteger e, BigInteger m)
        {
            BigInteger x1 = 1, x2 = 0;
            var a = e;
            var b = m;
            while (b > 0)
            {
                var q = BigInteger.DivRem(a, b, out var r);
                var xn = x1 - q * x2;
                a = b;
                b = r;
                x1 = x2;
                x2 = xn;
            }
            // Python's % always yields a non-negative result for m > 0.
            var result = x1 % m;
            if (result < 0)
            {
                result += BigInteger.Abs(m);
            }
            return result;
        }

        public static FP2Value operator +(FP2Value self, FP2Value other)
        {
            if (self.Mod != other.Mod)
            {
                throw new InvalidOperationException("Assertion failed: self.mod == other.mod");
            }
            var a = self.AC * other.A - self.CC * other.A + self.A * other.AC - self.C * other.AC - self.BC * other.B
                     + self.CC * other.B - self.AC * other.C + self.BC * other.C - self.A * other.CC
                     + self.B * other.CC;
            var b = self.BC * other.A - self.CC * other.A + self.B * other.AC - self.C * other.AC + self.AC * other.B
                    - self.BC * other.B + self.A * other.BC - self.B * other.BC - self.AC * other.C
                    + self.CC * other.C - self.A * other.CC + self.C * other.CC;
            var aC = self.AC * other.AC - self.CC * other.AC - self.BC * other.BC
                     + self.CC * other.BC - self.AC * other.CC + self.BC * other.CC;
            var bC = self.BC * other.AC - self.CC * other.AC + self.AC * other.BC
                     - self.BC * other.BC - self.AC * other.CC + self.CC * other.CC;
            return new FP2Value(self.Mod, a, b, null, aC, bC);
        }

        public static FP2Value operator -(FP2Value self, FP2Value other)
        {
            if (self.Mod != other.Mod)
            {
                throw new InvalidOperationException("Assertion failed: self.mod == other.mod");
            }
            var a = -self.AC * other.A + self.CC * other.A + self.A * other.AC - self.C * other.AC + self.BC * other.B
                    - self.CC * other.B - self.B * other.BC + self.C * other.BC + self.AC * other.C
                    - self.BC * other.C - self.A * other.CC + self.B * other.CC;
            var b = -self.BC * other.A + self.CC * other.A + self.B * other.AC - self.C * other.AC - self.AC * other.B
                    + self.BC * other.B + self.A * other.BC - self.B * other.BC + self.AC * other.C
                    - self.CC * other.C - self.A * other.CC + self.C * other.CC;
            var aC = self.AC * other.AC - self.CC * other.AC - self.BC * other.BC
                     + self.CC * other.BC - self.AC * other.CC + self.BC * other.CC;
            var bC = self.BC * other.AC - self.CC * other.AC + self.AC * other.BC
                     - self.BC * other.BC - self.AC * other.CC + self.CC * other.CC;
            return new FP2Value(self.Mod, a, b, null, aC, bC);
        }

        public static FP2Value operator *(FP2Value self, FP2Value other)
        {
            if (self.Mod != other.Mod)
            {
                throw new InvalidOperationException("Assertion failed: self.mod == other.mod");
            }
            var a = self.A * other.A - self.C * other.A - self.B * other.B
                    + self.C * other.B - self.A * other.C + self.B * other.C;
            var b = self.B * other.A - self.C * other.A + self.A * other.B
                    - self.B * other.B - self.A * other.C + self.C * other.C;
            var aC = self.AC * other.AC - self.CC * other.AC - self.BC * other.BC
                     + self.CC * other.BC - self.AC * other.CC + self.BC * other.CC;
            var bC = self.BC * other.AC - self.CC * other.AC + self.AC * other.BC
                     - self.BC * other.BC - self.AC * other.CC + self.CC * other.CC;
            return new FP2Value(self.Mod, a, b, null, aC, bC);
        }

        /// <summary>py __floordiv__: FP2 division (multiplication with the expanded inverse).</summary>
        public static FP2Value operator /(FP2Value self, FP2Value other)
        {
            if (self.Mod != other.Mod)
            {
                throw new InvalidOperationException("Assertion failed: self.mod == other.mod");
            }
            var a = self.A * other.AC - self.C * other.AC - self.B * other.BC
                    + self.C * other.BC - self.A * other.CC + self.B * other.CC;
            var b = self.B * other.AC - self.C * other.AC + self.A * other.BC
                    - self.B * other.BC - self.A * other.CC + self.C * other.CC;
            var aC = self.AC * other.A - self.CC * other.A - self.BC * other.B
                     + self.CC * other.B - self.AC * other.C + self.BC * other.C;
            var bC = self.BC * other.A - self.CC * other.A + self.AC * other.B
                     - self.BC * other.B - self.AC * other.C + self.CC * other.C;
            return new FP2Value(self.Mod, a, b, null, aC, bC);
        }

        /// <summary>
        /// py __eq__: compare after normalizing (self // other).
        /// </summary>
        public bool Equals(FP2Value other)
        {
            if (other is null)
            {
                return false;
            }
            var divd = (this / other).Normalize();
            return divd.A == divd.AC && divd.B == divd.BC && divd.C == divd.CC;
        }

        /// <summary>Equality is not trivial: we hash everything to 0 for the full equality check (py __hash__).</summary>
        public override int GetHashCode() => 0;

        public override bool Equals(object obj) => obj is FP2Value other && Equals(other);

        public static bool operator ==(FP2Value left, FP2Value right)
            => left is null ? right is null : left.Equals(right);

        public static bool operator !=(FP2Value left, FP2Value right)
            => !(left == right);

        /// <summary>Raise this value by a given power (binary exponentiation; negative → inverse).</summary>
        public FP2Value IntPow(BigInteger power)
        {
            var n = power < 0 ? -power : power;
            var r = new FP2Value(Mod, 1);
            var u = this;
            while (n > 0)
            {
                if (n % 2 == BigInteger.One)
                {
                    r = r * u;
                }
                u = u * u;
                n /= 2;
            }
            return power < 0 ? r.Inverse().Normalize() : r;
        }

        /// <summary>
        /// Normalize to aC = 1: this is the best human-readable form (py normalize).
        /// </summary>
        public FP2Value Normalize()
        {
            var mp = ModInverse(AC % Mod, Mod);
            if (mp > 0)
            {
                var a = PyMod(A * mp, Mod);
                var b = PyMod(B * mp, Mod);
                var c = PyMod(C * mp, Mod);
                var bC = PyMod(BC * mp, Mod);
                var cC = PyMod(CC * mp, Mod);
                return new FP2Value(Mod, a, b, c, BigInteger.One, bC, cC);
            }
            return new FP2Value(Mod, A, B, C, AC, BC, CC);
        }

        /// <summary>Return the inverse of this value (py inverse).</summary>
        public FP2Value Inverse()
            => new FP2Value(Mod, AC, BC, CC, A, B, C);

        /// <summary>Return the '1' and 'x' coefficients as a new value (py wp_nominator).</summary>
        public FP2Value WpNominator() => new FP2Value(Mod, A, B);

        /// <summary>Return the '1^-1' and 'x^-1' coefficients modular inverse (py wp_denom_inverse).</summary>
        public FP2Value WpDenomInverse()
        {
            var iq = new FP2Value(Mod, AC * AC - AC * BC + BC * BC);
            var a = new FP2Value(Mod, AC - BC) / iq;
            var b = new FP2Value(Mod, -BC) / iq;
            // NOTE (py quirk, replicated): both components read ``.a`` of the normalized form.
            return new FP2Value(Mod, a.Normalize().A, b.Normalize().A);
        }

        /// <summary>
        /// Compress this FP2 value into an FP2Value only containing `a` and `b` values.
        /// This is an expensive operation (py wp_compress; requires c == cC == 0).
        /// </summary>
        public FP2Value WpCompress()
        {
            if (!C.IsZero || !CC.IsZero)
            {
                throw new InvalidOperationException("wp_compress requires c == 0 and cC == 0");
            }
            var normalized = Normalize();
            return normalized.WpNominator() * normalized.WpDenomInverse();
        }
    }
}
