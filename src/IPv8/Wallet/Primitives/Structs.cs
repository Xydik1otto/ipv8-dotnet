// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Numerics;

namespace IPv8.Wallet.Primitives
{
    /// <summary>
    /// Integer pack/unpack over the wire (port of
    /// ipv8/attestation/wallet/primitives/structs.py::ipack/iunpack/pack_pair/unpack_pair).
    ///
    /// py packs an integer as a big-endian byte string with EVEN length (hex-pair digits),
    /// length-prefixed by an even-length big-endian length, which itself is prefixed by its
    /// own one-byte length: ``>B len(len) len num``.
    /// </summary>
    public static class IPack
    {
        /// <summary>py _num_to_str: big-endian, even-length byte string of a non-negative int.</summary>
        public static byte[] NumToStr(BigInteger num)
        {
            if (num.Sign < 0)
            {
                // py would crash on negatives (struct.pack(">B", negative)); do the same.
                throw new ArgumentOutOfRangeException(nameof(num), "negative ints cannot be ipacked");
            }
            // py builds the hex string and pads it to an even number of DIGITS — which is
            // exactly the minimal big-endian unsigned byte string (the zero high nibble of an
            // odd digit count is implicit in the minimal representation), with 0 → b"\x00".
            return BigMath.ToBigEndianUnsigned(num);
        }

        /// <summary>py _str_to_num: big-endian unsigned bytes → int.</summary>
        public static BigInteger StrToNum(byte[] s, int offset, int length)
        {
            var result = BigInteger.Zero;
            for (var i = 0; i < length; i++)
            {
                result <<= 8;
                result |= s[offset + i];
            }
            return result;
        }

        /// <summary>Serialize an integer (py ipack).</summary>
        public static byte[] Pack(BigInteger num)
        {
            var pnum = NumToStr(num);
            var l = NumToStr(pnum.Length);
            if (l.Length > byte.MaxValue)
            {
                throw new InvalidOperationException("ipack length prefix overflow");
            }
            var @out = new byte[1 + l.Length + pnum.Length];
            @out[0] = (byte)l.Length;
            Array.Copy(l, 0, @out, 1, l.Length);
            Array.Copy(pnum, 0, @out, 1 + l.Length, pnum.Length);
            return @out;
        }

        /// <summary>
        /// Unserialize an integer from a buffer (py iunpack): returns the number and the remainder.
        /// </summary>
        public static (BigInteger Value, byte[] Remainder) Unpack(byte[] s, int offset = 0)
        {
            if (s == null || offset >= s.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), "iunpack out of data");
            }
            var llen = s[offset];
            var l = StrToNum(s, offset + 1, llen);
            if (!l.IsZero && l > int.MaxValue)
            {
                throw new InvalidOperationException("iunpack length overflow");
            }
            var valueLength = (int)l;
            var value = StrToNum(s, offset + 1 + llen, valueLength);
            var remainderStart = offset + llen + valueLength + 1;
            return (value, Util.SliceFrom(s, remainderStart));
        }

        /// <summary>Serialize a pair of two integers (py pack_pair).</summary>
        public static byte[] PackPair(BigInteger a, BigInteger b)
            => Util.Concat(Pack(a), Pack(b));

        /// <summary>Unserialize a pair of two integers (py unpack_pair).</summary>
        public static (BigInteger A, BigInteger B, byte[] Remainder) UnpackPair(byte[] s, int offset = 0)
        {
            var (a, remainder) = Unpack(s, offset);
            var (b, remainder2) = Unpack(remainder);
            return (a, b, remainder2);
        }
    }

    /// <summary>
    /// A public key for Boneh et al.'s cryptosystem
    /// (port of ipv8/attestation/wallet/primitives/structs.py::BonehPublicKey).
    /// </summary>
    public class BonehPublicKey
    {
        public const int Fields = 5;

        public readonly BigInteger P;
        public readonly FP2Value G;
        public readonly FP2Value H;

        public BonehPublicKey(BigInteger p, FP2Value g, FP2Value h)
        {
            P = p;
            G = g;
            H = h;
        }

        /// <summary>Convert this key to a bytes instance.</summary>
        public virtual byte[] Serialize()
            => Util.Concat(
                IPack.Pack(P),
                IPack.Pack(G.A), IPack.Pack(G.B),
                IPack.Pack(H.A), IPack.Pack(H.B));

        /// <summary>Convert the given bytes to a BonehPublicKey (py unserialize).</summary>
        public static BonehPublicKey Unserialize(byte[] s)
        {
            var remainder = s;
            var nums = new System.Collections.Generic.List<BigInteger>();
            while (remainder.Length > 0 && nums.Count < Fields)
            {
                BigInteger unpacked;
                (unpacked, remainder) = IPack.Unpack(remainder);
                nums.Add(unpacked);
            }
            if (nums.Count != Fields)
            {
                return null;
            }
            // NOTE (py quirk, replicated): the ``len(nums) > 5`` branch passes nums[5]/nums[6]
            // to a 3-argument constructor (would be a TypeError in py); unreachable in practice.
            return new BonehPublicKey(nums[0],
                new FP2Value(nums[0], nums[1], nums[2]),
                new FP2Value(nums[0], nums[3], nums[4]));
        }
    }

    /// <summary>
    /// A private key for Boneh et al.'s cryptosystem
    /// (port of ipv8/attestation/wallet/primitives/structs.py::BonehPrivateKey).
    /// </summary>
    public class BonehPrivateKey : BonehPublicKey
    {
        public new const int Fields = 7;

        public readonly BigInteger N;
        public readonly BigInteger T1;

        public BonehPrivateKey(BigInteger p, FP2Value g, FP2Value h, BigInteger n, BigInteger t1)
            : base(p, g, h)
        {
            N = n;
            T1 = t1;
        }

        /// <summary>Add the private n and t1 values to the binary format.</summary>
        public override byte[] Serialize()
            => Util.Concat(base.Serialize(), IPack.Pack(N), IPack.Pack(T1));

        /// <summary>Strip out the private information.</summary>
        public BonehPublicKey PublicKey() => new BonehPublicKey(P, G, H);

        /// <summary>Convert the given bytes to a BonehPrivateKey (py unserialize, FIELDS = 7).</summary>
        public static new BonehPrivateKey Unserialize(byte[] s)
        {
            var publicKey = BonehPublicKey.Unserialize(s);
            if (publicKey == null)
            {
                return null;
            }
            var remainder = Util.SliceFrom(s, publicKey.Serialize().Length);
            if (remainder.Length == 0)
            {
                // py: insufficient numbers → len(nums) != FIELDS → None.
                return null;
            }
            BigInteger n, t1;
            (n, remainder) = IPack.Unpack(remainder);
            (t1, _) = IPack.Unpack(remainder);
            return new BonehPrivateKey(publicKey.P, publicKey.G, publicKey.H, n, t1);
        }
    }
}
