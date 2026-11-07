// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;
using IPv8.Messaging;

namespace IPv8.Attestation.Identity
{
    /// <summary>A payload used for disclosure of identity meta information (msg_id = 1).</summary>
    public sealed class DisclosePayload : Payload
    {
        public static readonly int MsgId = 1;

        public byte[] Metadata;
        public byte[] Tokens;
        public byte[] Attestations;
        public byte[] Authorities;

        public DisclosePayload()
        {
            Metadata = Util.EmptyBytes;
            Tokens = Util.EmptyBytes;
            Attestations = Util.EmptyBytes;
            Authorities = Util.EmptyBytes;
        }

        public DisclosePayload(byte[] metadata, byte[] tokens, byte[] attestations, byte[] authorities)
        {
            Metadata = metadata;
            Tokens = tokens;
            Attestations = attestations;
            Authorities = authorities;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "varlenH", "varlenH", "varlenH", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("varlenH", Metadata),
                new PackEntry("varlenH", Tokens),
                new PackEntry("varlenH", Attestations),
                new PackEntry("varlenH", Authorities)
            };

        public override void FromUnpackList(object[] values)
        {
            Metadata = (byte[])values[0];
            Tokens = (byte[])values[1];
            Attestations = (byte[])values[2];
            Authorities = (byte[])values[3];
        }
    }

    /// <summary>A payload used for attestation (msg_id = 2).</summary>
    public sealed class AttestPayload : Payload
    {
        public static readonly int MsgId = 2;

        public byte[] Attestation;

        public AttestPayload()
        {
            Attestation = Util.EmptyBytes;
        }

        public AttestPayload(byte[] attestation)
        {
            Attestation = attestation;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("varlenH", Attestation) };

        public override void FromUnpackList(object[] values)
        {
            Attestation = (byte[])values[0];
        }
    }

    /// <summary>A payload used to request missing identity meta information (msg_id = 3).</summary>
    public sealed class RequestMissingPayload : Payload
    {
        public static readonly int MsgId = 3;

        public long Known;

        public RequestMissingPayload()
        {
        }

        public RequestMissingPayload(long known)
        {
            Known = known;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("I", Known) };

        public override void FromUnpackList(object[] values)
        {
            Known = ToLong(values[0]);
        }
    }

    /// <summary>A payload to respond with missing identity meta information (msg_id = 4).</summary>
    public sealed class MissingResponsePayload : Payload
    {
        public static readonly int MsgId = 4;

        public byte[] Tokens;

        public MissingResponsePayload()
        {
            Tokens = Util.EmptyBytes;
        }

        public MissingResponsePayload(byte[] tokens)
        {
            Tokens = tokens;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("raw", Tokens) };

        public override void FromUnpackList(object[] values)
        {
            Tokens = (byte[])values[0];
        }
    }
}
