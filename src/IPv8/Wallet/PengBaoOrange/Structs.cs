// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Cryptography;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.PengBaoOrange
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;

    /// <summary>py _serialize_fp2value: compressed (a, b) wire form of an FP2Value.</summary>
    public static class PengBaoSerialization
    {
        public static byte[] SerializeFP2Value(FP2Value value)
        {
            var normalized = value.WpCompress();
            return Util.Concat(IPack.Pack(normalized.A), IPack.Pack(normalized.B));
        }

        public static (FP2Value Value, byte[] Remainder) UnserializeFP2Value(BigInteger mod, byte[] value,
                                                                            int offset = 0)
        {
            var remainder = value;
            BigInteger a, b;
            (a, remainder) = IPack.Unpack(remainder, offset);
            (b, remainder) = IPack.Unpack(remainder);
            return (new FP2Value(mod, a, b), remainder);
        }
    }

    /// <summary>
    /// The proof structure that a commitment hides a value within a certain range
    /// (port of ipv8/attestation/wallet/pengbaorange/structs.py::PengBaoCommitment).
    /// </summary>
    public sealed class PengBaoCommitment
    {
        public readonly FP2Value C;
        public readonly FP2Value C1;
        public readonly FP2Value C2;
        public readonly FP2Value CA;
        public readonly FP2Value CA1;
        public readonly FP2Value CA2;
        public readonly FP2Value CA3;
        public readonly FP2Value CAA;

        public PengBaoCommitment(FP2Value c, FP2Value c1, FP2Value c2, FP2Value ca,
                                 FP2Value ca1, FP2Value ca2, FP2Value ca3, FP2Value caa)
        {
            C = c;
            C1 = c1;
            C2 = c2;
            CA = ca;
            CA1 = ca1;
            CA2 = ca2;
            CA3 = ca3;
            CAA = caa;
        }

        /// <summary>Convert this commitment to bytes.</summary>
        public byte[] Serialize()
        {
            return Util.Concat(
                IPack.Pack(C.Mod),
                PengBaoSerialization.SerializeFP2Value(C),
                PengBaoSerialization.SerializeFP2Value(C1),
                PengBaoSerialization.SerializeFP2Value(C2),
                PengBaoSerialization.SerializeFP2Value(CA),
                PengBaoSerialization.SerializeFP2Value(CA1),
                PengBaoSerialization.SerializeFP2Value(CA2),
                PengBaoSerialization.SerializeFP2Value(CA3),
                PengBaoSerialization.SerializeFP2Value(CAA));
        }

        /// <summary>Convert bytes to a commitment.</summary>
        public static (PengBaoCommitment Commitment, byte[] Remainder) Unserialize(byte[] s)
        {
            var remainder = s;
            BigInteger mod;
            (mod, remainder) = IPack.Unpack(remainder);
            FP2Value c, c1, c2, ca, ca1, ca2, ca3, caa;
            (c, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (c1, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (c2, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (ca, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (ca1, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (ca2, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (ca3, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            (caa, remainder) = PengBaoSerialization.UnserializeFP2Value(mod, remainder);
            return (new PengBaoCommitment(c, c1, c2, ca, ca1, ca2, ca3, caa), remainder);
        }
    }

    /// <summary>
    /// Private part of the PengBaoCommitment
    /// (port of ipv8/attestation/wallet/pengbaorange/structs.py::PengBaoCommitmentPrivate).
    /// </summary>
    public sealed class PengBaoCommitmentPrivate
    {
        public static readonly List<BigInteger> MsgSpace = MessageSpace();

        private static List<BigInteger> MessageSpace()
        {
            var space = new List<BigInteger>();
            for (var i = 0; i < 256; i++)
            {
                space.Add(i);
            }
            return space;
        }

        public readonly BigInteger M1;
        public readonly BigInteger M2;
        public readonly BigInteger M3;
        public readonly BigInteger R1;
        public readonly BigInteger R2;
        public readonly BigInteger R3;

        public PengBaoCommitmentPrivate(BigInteger m1, BigInteger m2, BigInteger m3,
                                        BigInteger r1, BigInteger r2, BigInteger r3)
        {
            M1 = m1;
            M2 = m2;
            M3 = m3;
            R1 = r1;
            R2 = r2;
            R3 = r3;
        }

        /// <summary>
        /// Given s and t and our private information, generate the appropriate response.
        /// </summary>
        public (BigInteger X, BigInteger Y, BigInteger U, BigInteger V) GenerateResponse(BigInteger s,
            BigInteger t)
        {
            return (s * M1 + M2 + M3,
                    M1 + t * M2 + M3,
                    s * R1 + R2 + R3,
                    R1 + t * R2 + R3);
        }

        /// <summary>Convert this commitment to bytes.</summary>
        public byte[] Serialize()
            => Util.Concat(IPack.Pack(M1), IPack.Pack(M2), IPack.Pack(M3),
                           IPack.Pack(R1), IPack.Pack(R2), IPack.Pack(R3));

        /// <summary>Convert bytes to a commitment.</summary>
        public static (PengBaoCommitmentPrivate Commitment, byte[] Remainder) Unserialize(byte[] s)
        {
            var remainder = s;
            BigInteger m1, m2, m3, r1, r2, r3;
            (m1, remainder) = IPack.Unpack(remainder);
            (m2, remainder) = IPack.Unpack(remainder);
            (m3, remainder) = IPack.Unpack(remainder);
            (r1, remainder) = IPack.Unpack(remainder);
            (r2, remainder) = IPack.Unpack(remainder);
            (r3, remainder) = IPack.Unpack(remainder);
            return (new PengBaoCommitmentPrivate(m1, m2, m3, r1, r2, r3), remainder);
        }

        /// <summary>Serialize and encode using a given public key (py PengBaoCommitmentPrivate.encode).</summary>
        public byte[] Encode(BonehPublicKey pk)
        {
            var serialized = Serialize();
            var hexSerialized = Util.Hex(serialized);
            var serializedEncodings = new List<byte[]> { new[] { (byte)(hexSerialized.Length / 2) } };
            for (var i = 0; i < hexSerialized.Length; i += 2)
            {
                var intval = Convert.ToByte(hexSerialized.Substring(i, 2), 16);
                serializedEncodings.Add(
                    PengBaoSerialization.SerializeFP2Value(Boneh.Encode(pk, intval)));
            }
            return Util.Concat(serializedEncodings.ToArray());
        }

        /// <summary>Decode an encoded PengBaoCommitmentPrivate using a secret key (py decode).</summary>
        public static PengBaoCommitmentPrivate Decode(BonehPrivateKey sk, byte[] s)
        {
            var serialized = new List<byte[]>();
            var count = s[0];
            var remainder = Util.SliceFrom(s, 1);
            for (var i = 0; i < count; i++)
            {
                FP2Value unpacked;
                (unpacked, remainder) = PengBaoSerialization.UnserializeFP2Value(sk.G.Mod, remainder);
                var decoded = Boneh.Decode(sk, MsgSpace.ToArray(), unpacked);
                if (decoded == null)
                {
                    // py: f"{None:x}" would crash; a failed decode is a corrupted stream.
                    throw new InvalidOperationException("decode failed for encoded commitment");
                }
                serialized.Add(BigMath.ToBigEndianUnsigned(decoded.Value));
            }
            var (commitment, _) = PengBaoCommitmentPrivate.Unserialize(Util.Concat(serialized.ToArray()));
            return commitment;
        }
    }

    /// <summary>
    /// Public data required to verify a Peng Bao proof
    /// (port of ipv8/attestation/wallet/pengbaorange/structs.py::PengBaoPublicData).
    /// </summary>
    public sealed class PengBaoPublicData
    {
        public readonly BonehPublicKey PK;
        public readonly int Bitspace;
        public readonly PengBaoCommitment Commitment;
        public readonly EL El;
        public readonly SQR Sqr1;
        public readonly SQR Sqr2;

        public PengBaoPublicData(BonehPublicKey pk, int bitspace, PengBaoCommitment commitment,
                                 EL el, SQR sqr1, SQR sqr2)
        {
            PK = pk;
            Bitspace = bitspace;
            Commitment = commitment;
            El = el;
            Sqr1 = sqr1;
            Sqr2 = sqr2;
        }

        /// <summary>Check whether the given range is correct (py PengBaoPublicData.check).</summary>
        public bool Check(BigInteger a, BigInteger b, BigInteger s, BigInteger t,
                          BigInteger x, BigInteger y, BigInteger u, BigInteger v)
        {
            var @out = true;
            @out &= El.Check(PK.G, PK.H, Commitment.C1, PK.H, Commitment.C2, Commitment.CA);
            @out &= Sqr1.Check(Commitment.CA, PK.H, Commitment.CAA);
            @out &= Sqr2.Check(PK.G, PK.H, Commitment.CA3);
            @out &= Commitment.C1 == Commitment.C / PK.G.IntPow(a - 1);
            @out &= Commitment.C2 == PK.G.IntPow(b + 1) / Commitment.C;
            @out &= Commitment.CAA == Commitment.CA1 * Commitment.CA2 * Commitment.CA3;
            @out &= (PK.G.IntPow(x) * PK.H.IntPow(u)) == (Commitment.CA1.IntPow(s) * Commitment.CA2
                                                          * Commitment.CA3);
            @out &= (PK.G.IntPow(y) * PK.H.IntPow(v)) == (Commitment.CA1 * Commitment.CA2.IntPow(t)
                                                          * Commitment.CA3);
            @out &= x > 0;
            @out &= y > 0;
            return @out;
        }

        /// <summary>Serialize this Attestation to a string.</summary>
        public byte[] Serialize()
            => Util.Concat(PK.Serialize(), IPack.Pack(Bitspace), Commitment.Serialize(),
                           El.Serialize(), Sqr1.Serialize(), Sqr2.Serialize());

        /// <summary>Given a string, create an Attestation object.</summary>
        public static (PengBaoPublicData PublicData, byte[] Remainder) Unserialize(byte[] s)
        {
            var remainder = s;
            var pk = BonehPublicKey.Unserialize(remainder);
            if (pk == null)
            {
                throw new InvalidOperationException("PengBaoPublicData: no public key");
            }
            remainder = Util.SliceFrom(remainder, pk.Serialize().Length);
            var bitspaceRaw = IPack.Unpack(remainder).Value;
            remainder = IPack.Unpack(remainder).Remainder;
            var commitment = PengBaoCommitment.Unserialize(remainder);
            remainder = commitment.Remainder;
            var el = EL.Unserialize(remainder);
            remainder = el.Remainder;
            var sqr1 = SQR.Unserialize(remainder);
            remainder = sqr1.Remainder;
            var sqr2 = SQR.Unserialize(remainder);
            remainder = sqr2.Remainder;
            return (new PengBaoPublicData(pk, (int)bitspaceRaw, commitment.Commitment, el.El, sqr1.Sqr,
                                          sqr2.Sqr), remainder);
        }
    }

    /// <summary>
    /// An attestation for a Peng Bao range proof
    /// (port of ipv8/attestation/wallet/pengbaorange/structs.py::PengBaoAttestation).
    /// </summary>
    public sealed class PengBaoAttestation : Attestation
    {
        public readonly PengBaoPublicData PublicData;
        public readonly PengBaoCommitmentPrivate PrivateData;

        public PengBaoAttestation(PengBaoPublicData publicData, PengBaoCommitmentPrivate privateData,
                                  string idFormat = null)
        {
            PublicData = publicData;
            PrivateData = privateData;
            IdFormat = idFormat;
            PK = publicData.PK;
        }

        /// <summary>Prototype instance for GetAttestationClass() dispatch (py class object).</summary>
        public PengBaoAttestation()
        {
            PublicData = null;
            PrivateData = null;
            IdFormat = null;
            PK = null;
        }

        public override byte[] Serialize() => PublicData.Serialize();

        public override byte[] SerializePrivateKey(object privateKey)
        {
            if (PrivateData == null)
            {
                throw new InvalidOperationException("assertion failed: privatedata");
            }
            return Util.Concat(PublicData.Serialize(), PrivateData.Encode((BonehPublicKey)privateKey));
        }

        /// <summary>Unserialize the public form (py unserialize).</summary>
        public override Attestation Unserialize(byte[] serialized, string idFormat)
        {
            var (publicData, _) = PengBaoPublicData.Unserialize(serialized);
            return new PengBaoAttestation(publicData, null, idFormat);
        }

        /// <summary>Unserialize the private form, including shared secrets (py unserialize_private).</summary>
        public override Attestation UnserializePrivateKey(object secretKey, byte[] serialized, string idFormat)
        {
            var (publicData, remainder) = PengBaoPublicData.Unserialize(serialized);
            var privateData = PengBaoCommitmentPrivate.Decode((BonehPrivateKey)secretKey, remainder);
            return new PengBaoAttestation(publicData, privateData, idFormat);
        }
    }
}
