// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;

namespace IPv8.Messaging
{
    /// <summary>Convert a type string to a tuple of connection-type bits (ipv8/messaging/payload.py).</summary>
    public static class ConnectionTypeCodec
    {
        public static (int Bit0, int Bit1) EncodeConnectionType(string connType)
        {
            if (connType == "public")
            {
                return (1, 0);
            }
            if (connType == "symmetric-NAT")
            {
                return (1, 1);
            }
            return (0, 0);
        }

        /// <summary>Convert connection type flags to a type string.</summary>
        public static string DecodeConnectionType(int bit0, int bit1)
        {
            if (bit0 == 0 && bit1 == 0)
            {
                return "unknown";
            }
            if (bit0 == 1 && bit1 == 0)
            {
                return "public";
            }
            if (bit0 == 1 && bit1 == 1)
            {
                return "symmetric-NAT";
            }
            return "N/A";
        }
    }

    /// <summary>
    /// Payload sent to peers that we are not connected to yet but have been punctured for us
    /// (old IPv4-only style, msg_id = 246).
    /// </summary>
    public sealed class IntroductionRequestPayload : Payload
    {
        public static readonly int MsgId = 246;

        public Address DestinationAddress;
        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public bool Advice;
        public bool SupportsNewStyle;
        public string ConnectionType;
        public long Identifier;
        public byte[] ExtraBytes;

        public IntroductionRequestPayload()
        {
            DestinationAddress = Address.Zero;
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
            Advice = false;
            SupportsNewStyle = true;
            ConnectionType = "unknown";
            Identifier = 0;
            ExtraBytes = Util.EmptyBytes;
        }

        public IntroductionRequestPayload(Address destinationAddress, Address sourceLanAddress,
                                          Address sourceWanAddress, bool advice, string connectionType,
                                          long identifier, byte[] extraBytes, bool supportsNewStyle = true)
        {
            DestinationAddress = destinationAddress;
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            Advice = advice;
            SupportsNewStyle = supportsNewStyle;
            ConnectionType = connectionType;
            Identifier = identifier % 65536;
            ExtraBytes = extraBytes ?? Util.EmptyBytes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "ipv4", "ipv4", "ipv4", "bits", "H", "raw" };

        public override IList<PackEntry> ToPackList()
        {
            var encodedConnectionType = ConnectionTypeCodec.EncodeConnectionType(ConnectionType);
            return new List<PackEntry>
            {
                new PackEntry("ipv4", DestinationAddress),
                new PackEntry("ipv4", SourceLanAddress),
                new PackEntry("ipv4", SourceWanAddress),
                new PackEntry("bits", encodedConnectionType.Bit0, encodedConnectionType.Bit1,
                              SupportsNewStyle, 0, 0, 0, 0, Advice),
                new PackEntry("H", Identifier),
                new PackEntry("raw", ExtraBytes),
            };
        }

        public override void FromUnpackList(object[] values)
        {
            var destinationAddress = (Address)values[0];
            var sourceLanAddress = (Address)values[1];
            var sourceWanAddress = (Address)values[2];
            var connectionType0 = ToInt(values[3]);
            var connectionType1 = ToInt(values[4]);
            var supportsNewStyle = ToInt(values[5]);
            var advice = ToInt(values[10]);
            var identifier = ToLong(values[11]);
            var extraBytes = (byte[])values[12];
            // py-ipv8 quirk, replicated exactly: ``[True, False][advice]`` inverts the advice bit.
            new IntroductionRequestPayload(destinationAddress,
                                           sourceLanAddress,
                                           sourceWanAddress,
                                           !DefaultStruct.Truthy(advice),
                                           ConnectionTypeCodec.DecodeConnectionType(connectionType0, connectionType1),
                                           identifier,
                                           extraBytes,
                                           DefaultStruct.Truthy(supportsNewStyle))
                .CopyTo(this);
        }

        private void CopyTo(IntroductionRequestPayload other)
        {
            other.DestinationAddress = DestinationAddress;
            other.SourceLanAddress = SourceLanAddress;
            other.SourceWanAddress = SourceWanAddress;
            other.Advice = Advice;
            other.SupportsNewStyle = SupportsNewStyle;
            other.ConnectionType = ConnectionType;
            other.Identifier = Identifier;
            other.ExtraBytes = ExtraBytes;
        }
    }

    /// <summary>
    /// New introduction request that supports non-IPv4 addresses (VariablePayloadWID, msg_id = 234).
    /// </summary>
    public sealed class NewIntroductionRequestPayload : Payload
    {
        public static readonly int MsgId = 234;

        public Address DestinationAddress;
        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public long Identifier;
        public int ConnectionType0;
        public int ConnectionType1;
        public int SupportsNewStyle;
        public int Dflag1;
        public int Dflag2;
        public int Tunnel;
        public int Sync;
        public int Advice;
        public byte[] ExtraBytes;

        public NewIntroductionRequestPayload()
        {
            DestinationAddress = Address.Zero;
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
            Identifier = 0;
            ExtraBytes = Util.EmptyBytes;
        }

        public NewIntroductionRequestPayload(Address destinationAddress, Address sourceLanAddress,
                                             Address sourceWanAddress, long identifier, int connectionType0,
                                             int connectionType1, int supportsNewStyle, int dflag1, int dflag2,
                                             int tunnel, int sync, int advice, byte[] extraBytes)
        {
            DestinationAddress = destinationAddress;
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            Identifier = identifier;
            ConnectionType0 = connectionType0;
            ConnectionType1 = connectionType1;
            SupportsNewStyle = supportsNewStyle;
            Dflag1 = dflag1;
            Dflag2 = dflag2;
            Tunnel = tunnel;
            Sync = sync;
            Advice = advice;
            ExtraBytes = extraBytes ?? Util.EmptyBytes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "ip_address", "ip_address", "ip_address", "H", "bits", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", DestinationAddress),
                new PackEntry("ip_address", SourceLanAddress),
                new PackEntry("ip_address", SourceWanAddress),
                new PackEntry("H", Identifier),
                new PackEntry("bits", ConnectionType0, ConnectionType1, SupportsNewStyle, Dflag1, Dflag2,
                              Tunnel, Sync, Advice),
                new PackEntry("raw", ExtraBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            // names = ["destination_address", "source_lan_address", "source_wan_address", "identifier",
            //          "connection_type_0", "connection_type_1", "supports_new_style", "dflag1", "dflag2",
            //          "tunnel", "sync", "advice", "extra_bytes"]
            DestinationAddress = (Address)values[0];
            SourceLanAddress = (Address)values[1];
            SourceWanAddress = (Address)values[2];
            Identifier = ToLong(values[3]);
            ConnectionType0 = ToInt(values[4]);
            ConnectionType1 = ToInt(values[5]);
            SupportsNewStyle = ToInt(values[6]);
            Dflag1 = ToInt(values[7]);
            Dflag2 = ToInt(values[8]);
            Tunnel = ToInt(values[9]);
            Sync = ToInt(values[10]);
            Advice = ToInt(values[11]);
            ExtraBytes = (byte[])values[12];
        }
    }

    /// <summary>Response to introduction requests (old IPv4-only style, msg_id = 245).</summary>
    public sealed class IntroductionResponsePayload : Payload
    {
        public static readonly int MsgId = 245;

        public Address DestinationAddress;
        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public Address LanIntroductionAddress;
        public Address WanIntroductionAddress;
        public string ConnectionType;
        public bool SupportsNewStyle;
        public bool IntroSupportsNewStyle;
        public bool PeerLimitReached;
        public long Identifier;
        public byte[] ExtraBytes;

        public IntroductionResponsePayload()
        {
            DestinationAddress = Address.Zero;
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
            LanIntroductionAddress = Address.Zero;
            WanIntroductionAddress = Address.Zero;
            ConnectionType = "unknown";
            SupportsNewStyle = true;
            ExtraBytes = Util.EmptyBytes;
        }

        public IntroductionResponsePayload(Address destinationAddress, Address sourceLanAddress,
                                           Address sourceWanAddress, Address lanIntroductionAddress,
                                           Address wanIntroductionAddress, string connectionType, long identifier,
                                           byte[] extraBytes, bool supportsNewStyle = true,
                                           bool introSupportsNewStyle = false, bool peerLimitReached = false)
        {
            DestinationAddress = destinationAddress;
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            LanIntroductionAddress = lanIntroductionAddress;
            WanIntroductionAddress = wanIntroductionAddress;
            ConnectionType = connectionType;
            SupportsNewStyle = supportsNewStyle;
            IntroSupportsNewStyle = introSupportsNewStyle;
            PeerLimitReached = peerLimitReached;
            Identifier = identifier % 65536;
            ExtraBytes = extraBytes ?? Util.EmptyBytes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "ipv4", "ipv4", "ipv4", "ipv4", "ipv4", "bits", "H", "raw" };

        public override IList<PackEntry> ToPackList()
        {
            var encodedConnectionType = ConnectionTypeCodec.EncodeConnectionType(ConnectionType);
            return new List<PackEntry>
            {
                new PackEntry("ipv4", DestinationAddress),
                new PackEntry("ipv4", SourceLanAddress),
                new PackEntry("ipv4", SourceWanAddress),
                new PackEntry("ipv4", LanIntroductionAddress),
                new PackEntry("ipv4", WanIntroductionAddress),
                new PackEntry("bits", encodedConnectionType.Bit0, encodedConnectionType.Bit1, 0,
                              SupportsNewStyle, IntroSupportsNewStyle, PeerLimitReached, 0, 0),
                new PackEntry("H", Identifier),
                new PackEntry("raw", ExtraBytes),
            };
        }

        public override void FromUnpackList(object[] values)
        {
            var destinationAddress = (Address)values[0];
            var sourceLanAddress = (Address)values[1];
            var sourceWanAddress = (Address)values[2];
            var introductionLanAddress = (Address)values[3];
            var introductionWanAddress = (Address)values[4];
            var connectionType0 = ToInt(values[5]);
            var connectionType1 = ToInt(values[6]);
            var supportsNewStyle = ToInt(values[8]);
            var introSupportsNewStyle = ToInt(values[9]);
            var peerLimitReached = ToInt(values[10]);
            var identifier = ToLong(values[13]);
            var extraBytes = (byte[])values[14];
            new IntroductionResponsePayload(destinationAddress,
                                            sourceLanAddress,
                                            sourceWanAddress,
                                            introductionLanAddress,
                                            introductionWanAddress,
                                            ConnectionTypeCodec.DecodeConnectionType(connectionType0, connectionType1),
                                            identifier,
                                            extraBytes,
                                            DefaultStruct.Truthy(supportsNewStyle),
                                            DefaultStruct.Truthy(introSupportsNewStyle),
                                            DefaultStruct.Truthy(peerLimitReached))
                .CopyTo(this);
        }

        private void CopyTo(IntroductionResponsePayload other)
        {
            other.DestinationAddress = DestinationAddress;
            other.SourceLanAddress = SourceLanAddress;
            other.SourceWanAddress = SourceWanAddress;
            other.LanIntroductionAddress = LanIntroductionAddress;
            other.WanIntroductionAddress = WanIntroductionAddress;
            other.ConnectionType = ConnectionType;
            other.SupportsNewStyle = SupportsNewStyle;
            other.IntroSupportsNewStyle = IntroSupportsNewStyle;
            other.PeerLimitReached = PeerLimitReached;
            other.Identifier = Identifier;
            other.ExtraBytes = ExtraBytes;
        }
    }

    /// <summary>
    /// New introduction response that supports non-IPv4 addresses (VariablePayloadWID, msg_id = 233).
    /// </summary>
    public sealed class NewIntroductionResponsePayload : Payload
    {
        public static readonly int MsgId = 233;

        public Address DestinationAddress;
        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public Address LanIntroductionAddress;
        public Address WanIntroductionAddress;
        public long Identifier;
        public bool IntroSupportsNewStyle;
        public int Flag1;
        public int Flag2;
        public int Flag3;
        public int Flag4;
        public int Flag5;
        public int Flag6;
        public int Flag7;
        public byte[] ExtraBytes;

        public NewIntroductionResponsePayload()
        {
            DestinationAddress = Address.Zero;
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
            LanIntroductionAddress = Address.Zero;
            WanIntroductionAddress = Address.Zero;
            ExtraBytes = Util.EmptyBytes;
        }

        public NewIntroductionResponsePayload(Address destinationAddress, Address sourceLanAddress,
                                              Address sourceWanAddress, Address lanIntroductionAddress,
                                              Address wanIntroductionAddress, long identifier,
                                              bool introSupportsNewStyle, int flag1, int flag2, int flag3,
                                              int flag4, int flag5, int flag6, int flag7, byte[] extraBytes)
        {
            DestinationAddress = destinationAddress;
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            LanIntroductionAddress = lanIntroductionAddress;
            WanIntroductionAddress = wanIntroductionAddress;
            Identifier = identifier;
            IntroSupportsNewStyle = introSupportsNewStyle;
            Flag1 = flag1;
            Flag2 = flag2;
            Flag3 = flag3;
            Flag4 = flag4;
            Flag5 = flag5;
            Flag6 = flag6;
            Flag7 = flag7;
            ExtraBytes = extraBytes ?? Util.EmptyBytes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "ip_address", "ip_address", "ip_address", "ip_address", "ip_address", "H", "bits", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", DestinationAddress),
                new PackEntry("ip_address", SourceLanAddress),
                new PackEntry("ip_address", SourceWanAddress),
                new PackEntry("ip_address", LanIntroductionAddress),
                new PackEntry("ip_address", WanIntroductionAddress),
                new PackEntry("H", Identifier),
                new PackEntry("bits", IntroSupportsNewStyle, Flag1, Flag2, Flag3, Flag4, Flag5, Flag6, Flag7),
                new PackEntry("raw", ExtraBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            // names = ["destination_address", "source_lan_address", "source_wan_address",
            //          "lan_introduction_address", "wan_introduction_address", "identifier",
            //          "intro_supports_new_style", "flag1", "flag2", "flag3", "flag4", "flag5", "flag6",
            //          "flag7", "extra_bytes"]
            DestinationAddress = (Address)values[0];
            SourceLanAddress = (Address)values[1];
            SourceWanAddress = (Address)values[2];
            LanIntroductionAddress = (Address)values[3];
            WanIntroductionAddress = (Address)values[4];
            Identifier = ToLong(values[5]);
            IntroSupportsNewStyle = DefaultStruct.Truthy(values[6]);
            Flag1 = ToInt(values[7]);
            Flag2 = ToInt(values[8]);
            Flag3 = ToInt(values[9]);
            Flag4 = ToInt(values[10]);
            Flag5 = ToInt(values[11]);
            Flag6 = ToInt(values[12]);
            Flag7 = ToInt(values[13]);
            ExtraBytes = (byte[])values[14];
        }
    }

    /// <summary>Payload to ask someone to puncture a third party for us (msg_id = 250).</summary>
    public sealed class PunctureRequestPayload : Payload
    {
        public static readonly int MsgId = 250;

        public Address LanWalkerAddress;
        public Address WanWalkerAddress;
        public long Identifier;

        public PunctureRequestPayload()
        {
            LanWalkerAddress = Address.Zero;
            WanWalkerAddress = Address.Zero;
        }

        public PunctureRequestPayload(Address lanWalkerAddress, Address wanWalkerAddress, long identifier)
        {
            LanWalkerAddress = lanWalkerAddress;
            WanWalkerAddress = wanWalkerAddress;
            Identifier = identifier % 65536;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "ipv4", "ipv4", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ipv4", LanWalkerAddress),
                new PackEntry("ipv4", WanWalkerAddress),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            LanWalkerAddress = (Address)values[0];
            WanWalkerAddress = (Address)values[1];
            Identifier = ToLong(values[2]);
        }
    }

    /// <summary>
    /// New puncture request that supports non-IPv4 addresses (VariablePayloadWID, msg_id = 232).
    /// </summary>
    public sealed class NewPunctureRequestPayload : Payload
    {
        public static readonly int MsgId = 232;

        public Address LanWalkerAddress;
        public Address WanWalkerAddress;
        public long Identifier;

        public NewPunctureRequestPayload()
        {
            LanWalkerAddress = Address.Zero;
            WanWalkerAddress = Address.Zero;
        }

        public NewPunctureRequestPayload(Address lanWalkerAddress, Address wanWalkerAddress, long identifier)
        {
            LanWalkerAddress = lanWalkerAddress;
            WanWalkerAddress = wanWalkerAddress;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "ip_address", "ip_address", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", LanWalkerAddress),
                new PackEntry("ip_address", WanWalkerAddress),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            LanWalkerAddress = (Address)values[0];
            WanWalkerAddress = (Address)values[1];
            Identifier = ToLong(values[2]);
        }
    }

    /// <summary>Attempt to puncture a NAT layer (msg_id = 249).</summary>
    public sealed class PuncturePayload : Payload
    {
        public static readonly int MsgId = 249;

        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public long Identifier;

        public PuncturePayload()
        {
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
        }

        public PuncturePayload(Address sourceLanAddress, Address sourceWanAddress, long identifier)
        {
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            Identifier = identifier % 65536;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "ipv4", "ipv4", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ipv4", SourceLanAddress),
                new PackEntry("ipv4", SourceWanAddress),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            SourceLanAddress = (Address)values[0];
            SourceWanAddress = (Address)values[1];
            Identifier = ToLong(values[2]);
        }
    }

    /// <summary>
    /// New puncture payload that supports non-IPv4 addresses (VariablePayloadWID, msg_id = 231).
    /// </summary>
    public sealed class NewPuncturePayload : Payload
    {
        public static readonly int MsgId = 231;

        public Address SourceLanAddress;
        public Address SourceWanAddress;
        public long Identifier;

        public NewPuncturePayload()
        {
            SourceLanAddress = Address.Zero;
            SourceWanAddress = Address.Zero;
        }

        public NewPuncturePayload(Address sourceLanAddress, Address sourceWanAddress, long identifier)
        {
            SourceLanAddress = sourceLanAddress;
            SourceWanAddress = sourceWanAddress;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "ip_address", "ip_address", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", SourceLanAddress),
                new PackEntry("ip_address", SourceWanAddress),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            SourceLanAddress = (Address)values[0];
            SourceWanAddress = (Address)values[1];
            Identifier = ToLong(values[2]);
        }
    }

    /// <summary>Numeric coercion helpers live on the Payload base class.</summary>
}
