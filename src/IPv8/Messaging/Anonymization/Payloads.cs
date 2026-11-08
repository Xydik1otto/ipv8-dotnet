// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Messaging.Interfaces;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// Base class for payloads that can be wrapped in a <see cref="CellPayload"/>
    /// (py-ipv8 CellablePayload: a VariablePayloadWID carrying a circuit_id).
    /// </summary>
    public abstract class CellablePayload : Payload
    {
        public long CircuitId;
    }

    /// <summary>
    /// Payload to piggyback onto introduction messages (payload.py::ExtraIntroductionPayload).
    /// </summary>
    public sealed class ExtraIntroductionPayload : Payload
    {
        public List<int> Flags;

        public ExtraIntroductionPayload()
        {
        }

        public ExtraIntroductionPayload(List<int> flags)
        {
            Flags = flags;
        }

        public override IReadOnlyList<object> FormatList => new object[] { "flags" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("flags", Flags ?? new List<int>()),
            };

        public override void FromUnpackList(object[] values)
        {
            var flags = new List<int>();
            foreach (var value in (List<object>)values[0])
            {
                flags.Add(ToInt(value));
            }
            Flags = flags;
        }
    }

    /// <summary>Payload to transfer raw data over a circuit (msg_id = 1).</summary>
    public sealed class DataPayload : CellablePayload
    {
        public static readonly int MsgId = 1;

        public Address DestAddress;
        public Address OrgAddress;
        public byte[] Data;

        public DataPayload()
        {
        }

        public DataPayload(long circuitId, Address destAddress, Address orgAddress, byte[] data)
        {
            CircuitId = circuitId;
            DestAddress = destAddress;
            OrgAddress = orgAddress;
            Data = data;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "address", "address", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("address", DestAddress),
                new PackEntry("address", OrgAddress),
                new PackEntry("raw", Data ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            DestAddress = (Address)values[1];
            OrgAddress = (Address)values[2];
            Data = (byte[])values[3];
        }
    }

    /// <summary>Payload to initiate circuit creation (msg_id = 2).</summary>
    public sealed class CreatePayload : CellablePayload
    {
        public static readonly int MsgId = 2;

        public long Identifier;
        public byte[] NodePublicKey;
        public byte[] Key;

        public CreatePayload()
        {
        }

        public CreatePayload(long circuitId, long identifier, byte[] nodePublicKey, byte[] key)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            NodePublicKey = nodePublicKey;
            Key = key;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "varlenH", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("varlenH", NodePublicKey),
                new PackEntry("varlenH", Key),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            NodePublicKey = (byte[])values[2];
            Key = (byte[])values[3];
        }
    }

    /// <summary>Payload to signal initial circuit first-hop completion (msg_id = 3).</summary>
    public sealed class CreatedPayload : CellablePayload
    {
        public static readonly int MsgId = 3;

        public long Identifier;
        public byte[] Key;
        public byte[] Auth;
        public byte[] CandidatesEnc;

        public CreatedPayload()
        {
        }

        public CreatedPayload(long circuitId, long identifier, byte[] key, byte[] auth, byte[] candidatesEnc)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            Key = key;
            Auth = auth;
            CandidatesEnc = candidatesEnc;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "varlenH", "32s", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("varlenH", Key),
                new PackEntry("32s", Auth),
                new PackEntry("raw", CandidatesEnc ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            Key = (byte[])values[2];
            Auth = (byte[])values[3];
            CandidatesEnc = (byte[])values[4];
        }
    }

    /// <summary>Payload to initiate circuit extension (msg_id = 4).</summary>
    public sealed class ExtendPayload : CellablePayload
    {
        public static readonly int MsgId = 4;

        public long Identifier;
        public byte[] NodePublicKey;
        public byte[] Key;
        public Address NodeAddr;

        public ExtendPayload()
        {
        }

        public ExtendPayload(long circuitId, long identifier, byte[] nodePublicKey, byte[] key, Address nodeAddr)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            NodePublicKey = nodePublicKey;
            Key = key;
            NodeAddr = nodeAddr;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "varlenH", "varlenH", "ip_address" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("varlenH", NodePublicKey),
                new PackEntry("varlenH", Key),
                new PackEntry("ip_address", NodeAddr),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            NodePublicKey = (byte[])values[2];
            Key = (byte[])values[3];
            NodeAddr = (Address)values[4];
        }
    }

    /// <summary>Payload to signal extension completion (msg_id = 5).</summary>
    public sealed class ExtendedPayload : CellablePayload
    {
        public static readonly int MsgId = 5;

        public long Identifier;
        public byte[] Key;
        public byte[] Auth;
        public byte[] CandidatesEnc;

        public ExtendedPayload()
        {
        }

        public ExtendedPayload(long circuitId, long identifier, byte[] key, byte[] auth, byte[] candidatesEnc)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            Key = key;
            Auth = auth;
            CandidatesEnc = candidatesEnc;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "varlenH", "32s", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("varlenH", Key),
                new PackEntry("32s", Auth),
                new PackEntry("raw", CandidatesEnc ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            Key = (byte[])values[2];
            Auth = (byte[])values[3];
            CandidatesEnc = (byte[])values[4];
        }
    }

    /// <summary>Payload to ping over a circuit (msg_id = 6).</summary>
    public sealed class PingPayload : CellablePayload
    {
        public static readonly int MsgId = 6;

        public long Identifier;

        public PingPayload()
        {
        }

        public PingPayload(long circuitId, long identifier)
        {
            CircuitId = circuitId;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
        }
    }

    /// <summary>Payload to pong over a circuit (msg_id = 7).</summary>
    public sealed class PongPayload : CellablePayload
    {
        public static readonly int MsgId = 7;

        public long Identifier;

        public PongPayload()
        {
        }

        public PongPayload(long circuitId, long identifier)
        {
            CircuitId = circuitId;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
        }
    }

    /// <summary>Payload to signal destruction of a circuit (msg_id = 8).</summary>
    public sealed class DestroyPayload : CellablePayload
    {
        public static readonly int MsgId = 8;

        public long Reason;

        public DestroyPayload()
        {
        }

        public DestroyPayload(long circuitId, long reason)
        {
            CircuitId = circuitId;
            Reason = reason;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Reason),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Reason = ToLong(values[1]);
        }
    }

    /// <summary>Payload to initiate establishment of an introduction point (msg_id = 9).</summary>
    public sealed class EstablishIntroPayload : CellablePayload
    {
        public static readonly int MsgId = 9;

        public long Identifier;
        public byte[] InfoHash;
        public byte[] PublicKey;

        public EstablishIntroPayload()
        {
        }

        public EstablishIntroPayload(long circuitId, long identifier, byte[] infoHash, byte[] publicKey)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            InfoHash = infoHash;
            PublicKey = publicKey;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "20s", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("20s", InfoHash),
                new PackEntry("varlenH", PublicKey),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            InfoHash = (byte[])values[2];
            PublicKey = (byte[])values[3];
        }
    }

    /// <summary>Payload to signal completion of introduction point establishment (msg_id = 10).</summary>
    public sealed class IntroEstablishedPayload : CellablePayload
    {
        public static readonly int MsgId = 10;

        public long Identifier;

        public IntroEstablishedPayload()
        {
        }

        public IntroEstablishedPayload(long circuitId, long identifier)
        {
            CircuitId = circuitId;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
        }
    }

    /// <summary>Payload to initiate creation of a rendezvous point (msg_id = 11).</summary>
    public sealed class EstablishRendezvousPayload : CellablePayload
    {
        public static readonly int MsgId = 11;

        public long Identifier;
        public byte[] Cookie;

        public EstablishRendezvousPayload()
        {
        }

        public EstablishRendezvousPayload(long circuitId, long identifier, byte[] cookie)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            Cookie = cookie;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("20s", Cookie),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            Cookie = (byte[])values[2];
        }
    }

    /// <summary>Payload to signal completion of a rendezvous point (msg_id = 12).</summary>
    public sealed class RendezvousEstablishedPayload : CellablePayload
    {
        public static readonly int MsgId = 12;

        public long Identifier;
        public Address RendezvousPointAddr;

        public RendezvousEstablishedPayload()
        {
        }

        public RendezvousEstablishedPayload(long circuitId, long identifier, Address rendezvousPointAddr)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            RendezvousPointAddr = rendezvousPointAddr;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "ip_address" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("ip_address", RendezvousPointAddr),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            RendezvousPointAddr = (Address)values[2];
        }
    }

    /// <summary>Payload to initiate e2e hookup (msg_id = 13; NOT cellable, no circuit_id).</summary>
    public sealed class CreateE2EPayload : Payload
    {
        public static readonly int MsgId = 13;

        public long Identifier;
        public byte[] InfoHash;
        public byte[] NodePublicKey;
        public byte[] Key;

        public CreateE2EPayload()
        {
        }

        public CreateE2EPayload(long identifier, byte[] infoHash, byte[] nodePublicKey, byte[] key)
        {
            Identifier = identifier;
            InfoHash = infoHash;
            NodePublicKey = nodePublicKey;
            Key = key;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "H", "20s", "varlenH", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("H", Identifier),
                new PackEntry("20s", InfoHash),
                new PackEntry("varlenH", NodePublicKey),
                new PackEntry("varlenH", Key),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToLong(values[0]);
            InfoHash = (byte[])values[1];
            NodePublicKey = (byte[])values[2];
            Key = (byte[])values[3];
        }
    }

    /// <summary>Payload to signal completion of e2e hookup (msg_id = 14; NOT cellable).</summary>
    public sealed class CreatedE2EPayload : Payload
    {
        public static readonly int MsgId = 14;

        public long Identifier;
        public byte[] Key;
        public byte[] Auth;
        public byte[] RpInfoEnc;

        public CreatedE2EPayload()
        {
        }

        public CreatedE2EPayload(long identifier, byte[] key, byte[] auth, byte[] rpInfoEnc)
        {
            Identifier = identifier;
            Key = key;
            Auth = auth;
            RpInfoEnc = rpInfoEnc;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "H", "varlenH", "32s", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("H", Identifier),
                new PackEntry("varlenH", Key),
                new PackEntry("32s", Auth),
                new PackEntry("raw", RpInfoEnc ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToLong(values[0]);
            Key = (byte[])values[1];
            Auth = (byte[])values[2];
            RpInfoEnc = (byte[])values[3];
        }
    }

    /// <summary>Payload to initiate completion linking of an e2e hookup (msg_id = 15).</summary>
    public sealed class LinkE2EPayload : CellablePayload
    {
        public static readonly int MsgId = 15;

        public long Identifier;
        public byte[] Cookie;

        public LinkE2EPayload()
        {
        }

        public LinkE2EPayload(long circuitId, long identifier, byte[] cookie)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            Cookie = cookie;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("20s", Cookie),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            Cookie = (byte[])values[2];
        }
    }

    /// <summary>Payload to signal completion of the final linking of the e2e circuit (msg_id = 16).</summary>
    public sealed class LinkedE2EPayload : CellablePayload
    {
        public static readonly int MsgId = 16;

        public long Identifier;

        public LinkedE2EPayload()
        {
        }

        public LinkedE2EPayload(long circuitId, long identifier)
        {
            CircuitId = circuitId;
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
        }
    }

    /// <summary>Request for peer lookup for the given info hash (msg_id = 17).</summary>
    public sealed class PeersRequestPayload : CellablePayload
    {
        public static readonly int MsgId = 17;

        public long Identifier;
        public byte[] InfoHash;

        public PeersRequestPayload()
        {
        }

        public PeersRequestPayload(long circuitId, long identifier, byte[] infoHash)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            InfoHash = infoHash;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "H", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("20s", InfoHash),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            InfoHash = (byte[])values[2];
        }
    }

    /// <summary>Payload for introduction info (peers response item).</summary>
    public sealed class IntroductionInfo : Payload
    {
        public Address Address;
        public byte[] Key;
        public byte[] SeederPk;
        public int Source;

        public IntroductionInfo()
        {
        }

        public IntroductionInfo(Address address, byte[] key, byte[] seederPk, int source)
        {
            Address = address;
            Key = key;
            SeederPk = seederPk;
            Source = source;
        }

        public override IReadOnlyList<object> FormatList
            => new object[] { "ip_address", "varlenH", "varlenH", "B" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", Address),
                new PackEntry("varlenH", Key),
                new PackEntry("varlenH", SeederPk),
                new PackEntry("B", Source),
            };

        public override void FromUnpackList(object[] values)
        {
            Address = (Address)values[0];
            Key = (byte[])values[1];
            SeederPk = (byte[])values[2];
            Source = ToInt(values[3]);
        }
    }

    /// <summary>Payload to respond with introduction info of peers for a given info hash (msg_id = 18).</summary>
    public sealed class PeersResponsePayload : CellablePayload
    {
        public static readonly int MsgId = 18;

        public long Identifier;
        public byte[] InfoHash;
        public List<IntroductionInfo> Peers;

        public PeersResponsePayload()
        {
        }

        public PeersResponsePayload(long circuitId, long identifier, byte[] infoHash, List<IntroductionInfo> peers)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            InfoHash = infoHash;
            Peers = peers;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "20s", new object[] { typeof(IntroductionInfo) } };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("20s", InfoHash),
                new PackEntry("payload-list", Peers == null
                    ? new List<Serializable>()
                    : new List<Serializable>(Peers)),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            InfoHash = (byte[])values[2];
            Peers = new List<IntroductionInfo>();
            foreach (var item in (List<object>)values[3])
            {
                Peers.Add((IntroductionInfo)item);
            }
        }
    }

    /// <summary>Payload for rendezvous info.</summary>
    public sealed class RendezvousInfo : Payload
    {
        public Address Address;
        public byte[] Key;
        public byte[] Cookie;

        public RendezvousInfo()
        {
        }

        public RendezvousInfo(Address address, byte[] key, byte[] cookie)
        {
            Address = address;
            Key = key;
            Cookie = cookie;
        }

        public override IReadOnlyList<object> FormatList
            => new object[] { "ip_address", "varlenH", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", Address),
                new PackEntry("varlenH", Key),
                new PackEntry("20s", Cookie),
            };

        public override void FromUnpackList(object[] values)
        {
            Address = (Address)values[0];
            Key = (byte[])values[1];
            Cookie = (byte[])values[2];
        }
    }

    /// <summary>Speedtest initiation (msg_id = 19).</summary>
    public sealed class TestRequestPayload : CellablePayload
    {
        public static readonly int MsgId = 19;

        public long Identifier;
        public int ResponseSize;
        public byte[] Data;

        public TestRequestPayload()
        {
        }

        public TestRequestPayload(long circuitId, long identifier, int responseSize, byte[] data)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            ResponseSize = responseSize;
            Data = data;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "H", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("H", ResponseSize),
                new PackEntry("raw", Data ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            ResponseSize = ToInt(values[2]);
            Data = (byte[])values[3];
        }
    }

    /// <summary>Speedtest response (msg_id = 20).</summary>
    public sealed class TestResponsePayload : CellablePayload
    {
        public static readonly int MsgId = 20;

        public long Identifier;
        public byte[] Data;

        public TestResponsePayload()
        {
        }

        public TestResponsePayload(long circuitId, long identifier, byte[] data)
        {
            CircuitId = circuitId;
            Identifier = identifier;
            Data = data;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "H", "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", CircuitId),
                new PackEntry("H", Identifier),
                new PackEntry("raw", Data ?? Util.EmptyBytes),
            };

        public override void FromUnpackList(object[] values)
        {
            CircuitId = ToLong(values[0]);
            Identifier = ToLong(values[1]);
            Data = (byte[])values[2];
        }
    }

    /// <summary>
    /// Packer for flags (payload.py::Flags): the individual flag integers are OR-ed into a
    /// single big-endian integer; unpacking expands the bits into their power-of-two values.
    /// </summary>
    public sealed class FlagsPacker : IPacker
    {
        private readonly string _format;
        private readonly int _size;

        public FlagsPacker(string fmt = ">H")
        {
            _format = fmt;
            _size = fmt switch
            {
                ">H" => 2,
                ">I" => 4,
                ">B" => 1,
                _ => throw new PackError($"Unsupported flags format '{fmt}'"),
            };
        }

        public byte[] Pack(object[] args)
        {
            var accumulated = 0L;
            // Accept ANY non-generic iterable (List<int>, HashSet<int>, int[], ...):
            // IEnumerable<object> would reject List<int> (generic invariance) and
            // silently pack an all-zero bitmask (py-ipv8 reduce(or, flags) accepts all).
            if (args.Length > 0 && args[0] is System.Collections.IEnumerable values)
            {
                foreach (var value in values)
                {
                    accumulated |= value switch
                    {
                        int i => (long)i,
                        uint u => (long)u,
                        long l => l,
                        ulong ul => (long)ul,
                        bool b => b ? 1L : 0L,
                        _ => throw new PackError($"Flags require a number, got {value?.GetType().Name ?? "null"}"),
                    };
                }
            }
            return _size switch
            {
                1 => new[] { (byte)(accumulated & 0xFF) },
                2 => new[] { (byte)((accumulated >> 8) & 0xFF), (byte)(accumulated & 0xFF) },
                4 => new[]
                {
                    (byte)((accumulated >> 24) & 0xFF), (byte)((accumulated >> 16) & 0xFF),
                    (byte)((accumulated >> 8) & 0xFF), (byte)(accumulated & 0xFF),
                },
                _ => throw new PackError($"Unsupported flags format '{_format}'"),
            };
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var number = 0;
            for (var i = 0; i < _size; i++)
            {
                number = (number << 8) | data[offset + i];
            }
            var flags = new List<object>();
            for (var i = 0; i < _size * 8; i++)
            {
                var flag = number & (1 << i);
                if (flag != 0)
                {
                    flags.Add(flag);
                }
            }
            unpackList.Add(flags);
            return _size;
        }
    }

    /// <summary>
    /// Raw circuit data (payload.py::CellPayload). The wire format is
    /// prefix (22) + msg_id 0 (1) + circuit_id (4, BE) + plaintext (1) + relay_early (1)
    /// + message, where message = msg_id (1) + payload bytes without the leading circuit_id.
    /// </summary>
    public sealed class CellPayload
    {
        public const int MsgId = 0;

        public long CircuitId;
        public byte[] Message;
        public bool Plaintext;
        public bool RelayEarly;

        public CellPayload(long circuitId, byte[] message, bool plaintext = false, bool relayEarly = false)
        {
            CircuitId = circuitId;
            Message = message;
            Plaintext = plaintext;
            RelayEarly = relayEarly;
        }

        /// <summary>
        /// Reorder the binary format of this cell, injecting its prefix and circuit id
        /// (the standard IPv8 packet layout: prefix + msg_num + payload-from-offset-23).
        /// </summary>
        public byte[] Unwrap(byte[] prefix)
        {
            var result = new byte[prefix.Length + 1 + 4 + Message.Length - 1];
            Array.Copy(prefix, 0, result, 0, prefix.Length);
            result[prefix.Length] = Message[0];
            WriteU32Be(result, prefix.Length + 1, (uint)CircuitId);
            Array.Copy(Message, 1, result, prefix.Length + 5, Message.Length - 1);
            return result;
        }

        /// <summary>
        /// Reorder the binary format of this cell, injecting its message id, circuit id and flags.
        /// </summary>
        public byte[] ToBin(byte[] prefix)
        {
            var result = new byte[prefix.Length + 1 + 6 + Message.Length];
            Array.Copy(prefix, 0, result, 0, prefix.Length);
            result[prefix.Length] = (byte)MsgId;
            WriteU32Be(result, prefix.Length + 1, (uint)CircuitId);
            result[prefix.Length + 5] = Plaintext ? (byte)1 : (byte)0;
            result[prefix.Length + 6] = RelayEarly ? (byte)1 : (byte)0;
            Array.Copy(Message, 0, result, prefix.Length + 7, Message.Length);
            return result;
        }

        /// <summary>
        /// Reconstruct a CellPayload from the given binary format, ordered using <see cref="ToBin"/>.
        /// </summary>
        public static CellPayload FromBin(byte[] packet)
        {
            var circuitId = ReadU32Be(packet, 23);
            var plaintext = packet[27] != 0;
            var relayEarly = packet[28] != 0;
            var message = new byte[packet.Length - 29];
            Array.Copy(packet, 29, message, 0, message.Length);
            return new CellPayload(circuitId, message, plaintext, relayEarly);
        }

        internal static void WriteU32Be(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        internal static uint ReadU32Be(byte[] data, int offset)
        {
            return ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16)
                   | ((uint)data[offset + 2] << 8) | data[offset + 3];
        }
    }

    /// <summary>Message ids that travel without cell encryption (payload.py::NO_CRYPTO_PACKETS).</summary>
    public static class AnonymizationCells
    {
        public static readonly int[] NoCryptoPackets = { CreatePayload.MsgId, CreatedPayload.MsgId };

        public static bool IsNoCrypto(int msgId)
        {
            return msgId == CreatePayload.MsgId || msgId == CreatedPayload.MsgId;
        }
    }
}
