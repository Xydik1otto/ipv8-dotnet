// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;
using IPv8.Messaging;

namespace IPv8.Messaging
{
    /// <summary>
    /// Public key (bytes) storage payload (ipv8/messaging/payload_headers.py).
    /// </summary>
    public sealed class BinMemberAuthenticationPayload : Payload
    {
        public byte[] PublicKeyBin;

        public BinMemberAuthenticationPayload()
        {
            PublicKeyBin = Util.EmptyBytes;
        }

        public BinMemberAuthenticationPayload(byte[] publicKeyBin)
        {
            PublicKeyBin = publicKeyBin;
        }

        public override IReadOnlyList<object> FormatList => new object[] { "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("varlenH", PublicKeyBin) };

        public override void FromUnpackList(object[] values)
        {
            PublicKeyBin = (byte[])values[0];
        }
    }

    /// <summary>
    /// Payload to communicate (and synchronize) Lamport timestamps (ipv8/messaging/payload_headers.py).
    /// </summary>
    public sealed class GlobalTimeDistributionPayload : Payload
    {
        public ulong GlobalTime;

        public GlobalTimeDistributionPayload()
        {
            GlobalTime = 0;
        }

        public GlobalTimeDistributionPayload(ulong globalTime)
        {
            GlobalTime = globalTime;
        }

        public override IReadOnlyList<object> FormatList => new object[] { "Q" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("Q", GlobalTime) };

        public override void FromUnpackList(object[] values)
        {
            GlobalTime = ConvertToUlong(values[0]);
        }

        internal static ulong ConvertToUlong(object value)
        {
            switch (value)
            {
                case ulong ul: return ul;
                case uint u: return u;
                case int i: return (ulong)i;
                case long l: return (ulong)l;
                default:
                    throw new PackError($"'Q' format requires a number, got {value?.GetType().Name ?? "null"}");
            }
        }
    }
}
