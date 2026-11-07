// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/payload.py: the ten DHT message payloads (msg ids 1-10), the value serialization
// payloads (StrPayload / SignedStrPayload) and the NodePacker ("node-list" item packer).

using System.Collections.Generic;
using IPv8.Messaging;

namespace IPv8.Dht
{
    /// <summary>Payload to send ping messages with a given identifier nonce (msg_id = 1).</summary>
    public sealed class PingRequestPayload : Payload
    {
        public static readonly int MsgId = 1;

        public int Identifier;

        public PingRequestPayload()
        {
        }

        public PingRequestPayload(int identifier)
        {
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("I", Identifier) };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
        }
    }

    /// <summary>Payload to respond to pings with a given identifier (msg_id = 2).</summary>
    public sealed class PingResponsePayload : Payload
    {
        public static readonly int MsgId = 2;

        public int Identifier;

        public PingResponsePayload()
        {
        }

        public PingResponsePayload(int identifier)
        {
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("I", Identifier) };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
        }
    }

    /// <summary>
    /// Payload for a token-holder to send a target certain values to store, with a given identifier
    /// nonce (msg_id = 3).
    /// </summary>
    public sealed class StoreRequestPayload : Payload
    {
        public static readonly int MsgId = 3;

        public int Identifier;
        public byte[] Token;
        public byte[] Target;
        public List<byte[]> Values;

        public StoreRequestPayload()
        {
        }

        public StoreRequestPayload(int identifier, byte[] token, byte[] target, List<byte[]> values)
        {
            Identifier = identifier;
            Token = token;
            Target = target;
            Values = values;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "20s", "20s", "varlenH-list" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("20s", Token),
                new PackEntry("20s", Target),
                new PackEntry("varlenH-list", new List<object>(Values)),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            Token = (byte[])values[1];
            Target = (byte[])values[2];
            Values = new List<byte[]>();
            foreach (var item in (List<object>)values[3])
            {
                Values.Add((byte[])item);
            }
        }
    }

    /// <summary>Response that the previously-given values have been stored (msg_id = 4).</summary>
    public sealed class StoreResponsePayload : Payload
    {
        public static readonly int MsgId = 4;

        public int Identifier;

        public StoreResponsePayload()
        {
        }

        public StoreResponsePayload(int identifier)
        {
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("I", Identifier) };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
        }
    }

    /// <summary>
    /// Attempt for our lan address to have the given target fetch values and nodes for us from a
    /// given starting offset, potentially with a request to force new node connections (msg_id = 5).
    /// </summary>
    public sealed class FindRequestPayload : Payload
    {
        public static readonly int MsgId = 5;

        public int Identifier;
        public Address LanAddress;
        public byte[] Target;
        public int Offset;
        public bool ForceNodes;

        public FindRequestPayload()
        {
        }

        public FindRequestPayload(int identifier, Address lanAddress, byte[] target, int offset,
                                  bool forceNodes)
        {
            Identifier = identifier;
            LanAddress = lanAddress;
            Target = target;
            Offset = offset;
            ForceNodes = forceNodes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "ip_address", "20s", "I", "?" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("ip_address", LanAddress),
                new PackEntry("20s", Target),
                new PackEntry("I", Offset),
                new PackEntry("?", ForceNodes),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            LanAddress = (Address)values[1];
            Target = (byte[])values[2];
            Offset = ToInt(values[3]);
            ForceNodes = (bool)values[4];
        }
    }

    /// <summary>Response to a find request with the known values and nodes (msg_id = 6).</summary>
    public sealed class FindResponsePayload : Payload
    {
        public static readonly int MsgId = 6;

        public int Identifier;
        public byte[] Token;
        public List<byte[]> Values;
        public List<DhtNode> Nodes;

        public FindResponsePayload()
        {
        }

        public FindResponsePayload(int identifier, byte[] token, List<byte[]> values, List<DhtNode> nodes)
        {
            Identifier = identifier;
            Token = token;
            Values = values;
            Nodes = nodes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList
            => new object[] { "I", "20s", "varlenH-list", "node-list" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("20s", Token),
                new PackEntry("varlenH-list", new List<object>(Values)),
                new PackEntry("node-list", new List<object>(Nodes)),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            Token = (byte[])values[1];
            Values = new List<byte[]>();
            foreach (var item in (List<object>)values[2])
            {
                Values.Add((byte[])item);
            }
            Nodes = new List<DhtNode>();
            foreach (var item in (List<object>)values[3])
            {
                Nodes.Add((DhtNode)item);
            }
        }
    }

    /// <summary>
    /// Request to another node to register our own node (id) as a server of the given target
    /// (msg_id = 7).
    /// </summary>
    public sealed class StorePeerRequestPayload : Payload
    {
        public static readonly int MsgId = 7;

        public int Identifier;
        public byte[] Token;
        public byte[] Target;

        public StorePeerRequestPayload()
        {
        }

        public StorePeerRequestPayload(int identifier, byte[] token, byte[] target)
        {
            Identifier = identifier;
            Token = token;
            Target = target;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "20s", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("20s", Token),
                new PackEntry("20s", Target),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            Token = (byte[])values[1];
            Target = (byte[])values[2];
        }
    }

    /// <summary>Confirmation that a node (id) has been stored as part of our tree (msg_id = 8).</summary>
    public sealed class StorePeerResponsePayload : Payload
    {
        public static readonly int MsgId = 8;

        public int Identifier;

        public StorePeerResponsePayload()
        {
        }

        public StorePeerResponsePayload(int identifier)
        {
            Identifier = identifier;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("I", Identifier) };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
        }
    }

    /// <summary>Request for our lan address to be introduced to peers in the target range (msg_id = 9).</summary>
    public sealed class ConnectPeerRequestPayload : Payload
    {
        public static readonly int MsgId = 9;

        public int Identifier;
        public Address LanAddress;
        public byte[] Target;

        public ConnectPeerRequestPayload()
        {
        }

        public ConnectPeerRequestPayload(int identifier, Address lanAddress, byte[] target)
        {
            Identifier = identifier;
            LanAddress = lanAddress;
            Target = target;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "ip_address", "20s" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("ip_address", LanAddress),
                new PackEntry("20s", Target),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            LanAddress = (Address)values[1];
            Target = (byte[])values[2];
        }
    }

    /// <summary>
    /// A response to a connection request, with the nodes that have been punctured (msg_id = 10).
    /// </summary>
    public sealed class ConnectPeerResponsePayload : Payload
    {
        public static readonly int MsgId = 10;

        public int Identifier;
        public List<DhtNode> Nodes;

        public ConnectPeerResponsePayload()
        {
        }

        public ConnectPeerResponsePayload(int identifier, List<DhtNode> nodes)
        {
            Identifier = identifier;
            Nodes = nodes;
        }

        public override int MsgNum => MsgId;

        public override IReadOnlyList<object> FormatList => new object[] { "I", "node-list" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("I", Identifier),
                new PackEntry("node-list", new List<object>(Nodes)),
            };

        public override void FromUnpackList(object[] values)
        {
            Identifier = ToInt(values[0]);
            Nodes = new List<DhtNode>();
            foreach (var item in (List<object>)values[1])
            {
                Nodes.Add((DhtNode)item);
            }
        }
    }

    /// <summary>Payload to pack bytes (py-ipv8 StrPayload).</summary>
    public sealed class StrPayload : Payload
    {
        public byte[] Data;

        public StrPayload()
        {
        }

        public StrPayload(byte[] data)
        {
            Data = data;
        }

        public override IReadOnlyList<object> FormatList => new object[] { "raw" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry> { new PackEntry("raw", Data) };

        public override void FromUnpackList(object[] values)
        {
            Data = (byte[])values[0];
        }
    }

    /// <summary>Payload to pack bytes with a version and a public key (py-ipv8 SignedStrPayload).</summary>
    public sealed class SignedStrPayload : Payload
    {
        public byte[] Data;
        public int Version;
        public byte[] PublicKey;

        public SignedStrPayload()
        {
        }

        public SignedStrPayload(byte[] data, int version, byte[] publicKey)
        {
            Data = data;
            Version = version;
            PublicKey = publicKey;
        }

        public override IReadOnlyList<object> FormatList
            => new object[] { "varlenH", "I", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("varlenH", Data),
                new PackEntry("I", Version),
                new PackEntry("varlenH", PublicKey),
            };

        public override void FromUnpackList(object[] values)
        {
            Data = (byte[])values[0];
            Version = ToInt(values[1]);
            PublicKey = (byte[])values[2];
        }
    }

    /// <summary>Serialization packing format for DHT nodes (py-ipv8 NodePacker).</summary>
    public class NodePacker : IPacker
    {
        private readonly Serializer _serializer;

        public NodePacker(Serializer serializer)
        {
            _serializer = serializer;
        }

        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is DhtNode node))
            {
                throw new PackError("'node-list' format requires a Node");
            }
            var addressBytes = _serializer.GetPackerFor("ip_address").Pack(new object[] { node.Address });
            var keyBytes = _serializer.GetPackerFor("varlenH").Pack(new object[] { node.PublicKey.KeyToBin() });
            return Util.Concat(addressBytes, keyBytes);
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var (address, nextOffset) = _serializer.Unpack("ip_address", data, offset);
            var (key, lastOffset) = _serializer.Unpack("varlenH", data, nextOffset);
            unpackList.Add(new DhtNode((byte[])key, (Address)address));
            return lastOffset;
        }
    }
}
