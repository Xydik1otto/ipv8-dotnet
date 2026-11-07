// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Cryptography;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.BonehExact
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;

    /// <summary>
    /// An attestation of a single bitpair of a larger Attestation
    /// (port of ipv8/attestation/wallet/bonehexact/structs.py::BitPairAttestation).
    /// </summary>
    public sealed class BitPairAttestation
    {
        public readonly FP2Value A;
        public readonly FP2Value B;
        public readonly FP2Value Complement;

        public BitPairAttestation(FP2Value a, FP2Value b, FP2Value complement)
        {
            A = a;
            B = b;
            Complement = complement;
        }

        /// <summary>Compress this attestation.</summary>
        public FP2Value Compress() => A * B * Complement;

        /// <summary>Convert the attestation to bytes.</summary>
        public byte[] Serialize()
            => Util.Concat(IPack.Pack(A.A), IPack.Pack(A.B),
                           IPack.Pack(B.A), IPack.Pack(B.B),
                           IPack.Pack(Complement.A), IPack.Pack(Complement.B));

        /// <summary>Unserialize using a pre-known modulus p.</summary>
        public static BitPairAttestation Unserialize(byte[] s, BigInteger p)
        {
            var remainder = s;
            var nums = new List<BigInteger>();
            while (remainder.Length > 0 && nums.Count < 6)
            {
                BigInteger unpacked;
                (unpacked, remainder) = IPack.Unpack(remainder);
                nums.Add(unpacked);
            }
            return new BitPairAttestation(
                new FP2Value(p, nums[0], nums[1]),
                new FP2Value(p, nums[2], nums[3]),
                new FP2Value(p, nums[4], nums[5]));
        }
    }

    /// <summary>
    /// An attestation for a public key of a value consisting of multiple bitpairs
    /// (port of ipv8/attestation/wallet/bonehexact/structs.py::BonehAttestation).
    /// </summary>
    public sealed class BonehAttestation : Attestation
    {
        public readonly List<BitPairAttestation> BitPairs;

        public BonehAttestation(BonehPublicKey pk, List<BitPairAttestation> bitPairs, string idFormat = null)
        {
            BitPairs = bitPairs;
            PK = pk;
            IdFormat = idFormat;
        }

        /// <summary>Prototype instance for GetAttestationClass() dispatch (py class object).</summary>
        public BonehAttestation()
        {
            BitPairs = new List<BitPairAttestation>();
            PK = null;
            IdFormat = null;
        }

        /// <summary>Serialize this attestation to bytes.</summary>
        public override byte[] Serialize()
        {
            var parts = new List<byte[]> { ((BonehPublicKey)PK).Serialize() };
            foreach (var bitPair in BitPairs)
            {
                parts.Add(bitPair.Serialize());
            }
            return Util.Concat(parts.ToArray());
        }

        public override byte[] SerializePrivateKey(object privateKey) => Serialize();

        /// <summary>Unserialize the public format of this attestation (py unserialize).</summary>
        public override Attestation Unserialize(byte[] serialized, string idFormat)
        {
            var pk = BonehPublicKey.Unserialize(serialized);
            if (pk == null)
            {
                throw new InvalidOperationException("BonehAttestation: no public key");
            }
            var bitPairs = new List<BitPairAttestation>();
            var remainder = Util.SliceFrom(serialized, pk.Serialize().Length);
            while (remainder.Length > 0)
            {
                var bitPair = BitPairAttestation.Unserialize(remainder, pk.P);
                bitPairs.Add(bitPair);
                remainder = Util.SliceFrom(remainder, bitPair.Serialize().Length);
            }
            return new BonehAttestation(pk, bitPairs, idFormat);
        }

        /// <summary>
        /// Unserialize the private format of this attestation (py unserialize_private — the
        /// private form of a Boneh attestation IS the public form).
        /// </summary>
        public override Attestation UnserializePrivateKey(object secretKey, byte[] serialized, string idFormat)
            => Unserialize(serialized, idFormat);
    }
}
