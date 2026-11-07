// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;
using IPv8.Messaging;

namespace IPv8.Wallet
{
    /// <summary>Request an attestation based on some metadata (msg_id = 5).</summary>
    public sealed class RequestAttestationPayload : Payload
    {
        public static readonly int MsgId = 5;

        public byte[] Metadata;

        public RequestAttestationPayload()
        {
            Metadata = Util.EmptyBytes;
        }

        public RequestAttestationPayload(byte[] metadata)
        {
            Metadata = metadata;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("raw", Metadata) };

        public override void FromUnpackList(object[] values)
        {
            Metadata = (byte[])values[0];
        }
    }

    /// <summary>Request an attestation by hash (published with metadata somewhere) (msg_id = 1).</summary>
    public sealed class VerifyAttestationRequestPayload : Payload
    {
        public static readonly int MsgId = 1;

        public byte[] AttestationHash;

        public VerifyAttestationRequestPayload()
        {
            AttestationHash = new byte[20];
        }

        public VerifyAttestationRequestPayload(byte[] attestationHash)
        {
            AttestationHash = attestationHash;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("20s", AttestationHash) };

        public override void FromUnpackList(object[] values)
        {
            AttestationHash = (byte[])values[0];
        }
    }

    /// <summary>A chunk of Attestation (msg_id = 2).</summary>
    public sealed class AttestationChunkPayload : Payload
    {
        public static readonly int MsgId = 2;

        public byte[] AttestationHash;
        public int SequenceNumber;
        public byte[] Data;

        public AttestationChunkPayload()
        {
            AttestationHash = new byte[20];
            SequenceNumber = 0;
            Data = Util.EmptyBytes;
        }

        public AttestationChunkPayload(byte[] attestationHash, int sequenceNumber, byte[] data)
        {
            AttestationHash = attestationHash;
            SequenceNumber = sequenceNumber;
            Data = data;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "20s", "H", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("20s", AttestationHash),
                new PackEntry("H", SequenceNumber),
                new PackEntry("raw", Data)
            };

        public override void FromUnpackList(object[] values)
        {
            AttestationHash = (byte[])values[0];
            SequenceNumber = ToInt(values[1]);
            Data = (byte[])values[2];
        }
    }

    /// <summary>A challenge for an Attestee by a Verifier (msg_id = 3).</summary>
    public sealed class ChallengePayload : Payload
    {
        public static readonly int MsgId = 3;

        public byte[] AttestationHash;
        public byte[] Challenge;

        public ChallengePayload()
        {
            AttestationHash = new byte[20];
            Challenge = Util.EmptyBytes;
        }

        public ChallengePayload(byte[] attestationHash, byte[] challenge)
        {
            AttestationHash = attestationHash;
            Challenge = challenge;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "20s", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("20s", AttestationHash),
                new PackEntry("raw", Challenge)
            };

        public override void FromUnpackList(object[] values)
        {
            AttestationHash = (byte[])values[0];
            Challenge = (byte[])values[1];
        }
    }

    /// <summary>A challenge response from an Attestee to a Verifier (msg_id = 4).</summary>
    public sealed class ChallengeResponsePayload : Payload
    {
        public static readonly int MsgId = 4;

        public byte[] ChallengeHash;
        public byte[] Response;

        public ChallengeResponsePayload()
        {
            ChallengeHash = new byte[20];
            Response = Util.EmptyBytes;
        }

        public ChallengeResponsePayload(byte[] challengeHash, byte[] response)
        {
            ChallengeHash = challengeHash;
            Response = response;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "20s", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("20s", ChallengeHash),
                new PackEntry("raw", Response)
            };

        public override void FromUnpackList(object[] values)
        {
            ChallengeHash = (byte[])values[0];
            Response = (byte[])values[1];
        }
    }
}
