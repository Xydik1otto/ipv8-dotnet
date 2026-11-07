// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A9: the 7 DHT golden packets (msg 1, 2, 3, 5, 6, 9, 10) byte-exact pack AND unpack, plus the
    /// varlenH-list/node-list serializer vectors and tamper-signature negatives.
    /// </summary>
    public class DhtGoldenPacketTests : IDisposable
    {
        private static byte[] Hex(string hex) => Util.Unhex(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        // The same RFC-fixed key material as contract/gen_vectors_phase1b.py: Alice = RFC 8032 TEST 1
        // Ed25519 seed, RFC 7748 §6.1 alice X25519 private; Bob = RFC 8032 TEST 2 / §6.1 bob.
        private const string AliceXPrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        private const string BobXPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

        private readonly UDPEndpoint _endpoint = OpenEndpoint();
        private readonly List<DhtCommunity> _communities = new List<DhtCommunity>();

        private static UDPEndpoint OpenEndpoint()
        {
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(endpoint.Open());
            return endpoint;
        }

        private DhtCommunity BuildCommunity(string xPrivHex, string edSeedHex, string pubBinHex)
        {
            var privateKeyBin = Util.Concat(LibNaclPrivateKey.Prefix, Hex(xPrivHex), Hex(edSeedHex));
            var myPeer = new Peer(ECCrypto.Default.KeyFromPrivateBin(privateKeyBin));
            Assert.Equal(pubBinHex, Hexlify(myPeer.PublicKey.KeyToBin()));

            var community = new DhtCommunity(
                new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, _endpoint, new Network()));
            community.MyEstimatedLan = _endpoint.GetAddress();
            community.MyEstimatedWan = _endpoint.GetAddress();
            _communities.Add(community);
            return community;
        }

        public void Dispose()
        {
            foreach (var community in _communities)
            {
                community.Unload();
            }
            _endpoint.Close();
        }

        private DhtCommunity AliceCommunity()
            => BuildCommunity(AliceXPrivHex, Vectors1b.MetaKey("alice_ed_seed_hex"),
                              Vectors1b.MetaKey("alice_pub_bin_hex"));

        private DhtCommunity BobCommunity()
            => BuildCommunity(BobXPrivHex, Vectors1b.MetaKey("bob_ed_seed_hex"),
                              Vectors1b.MetaKey("bob_pub_bin_hex"));

        private static DhtNode NodeA
            => new DhtNode(Hex(Vectors1b.MetaKey("alice_pub_bin_hex")), Address.Udpv4("127.0.0.1", 7000));

        private static DhtNode NodeB
            => new DhtNode(Hex(Vectors1b.MetaKey("bob_pub_bin_hex")), Address.Udpv4("127.0.0.1", 7001));

        private static byte[] TokenA => Hex(Vectors1b.TokenHex);

        private static byte[] Target => Vectors1b.Target();

        private static Address LanA => Address.Udpv4("127.0.0.1", 7000);

        /// <summary>The signed golden packet layout: [auth, payload] + Ed25519 signature.
        /// DHT messages carry NO GlobalTimeDistribution header (py-ipv8 DHT uses lazy_wrapper).</summary>
        private static byte[] PackSigned(DhtCommunity community, int msgNum, Payload payload)
        {
            var auth = new BinMemberAuthenticationPayload(community.MyPeer.PublicKey.KeyToBin());
            return community.EzPack(community.Prefix, msgNum, new Payload[] { auth, payload }, sig: true);
        }

        public static IEnumerable<object[]> PacketNames()
            => new[]
            {
                new object[] { "ping_request", 1 },
                new object[] { "ping_response", 2 },
                new object[] { "store_request", 3 },
                new object[] { "find_request", 5 },
                new object[] { "find_response", 6 },
                new object[] { "connect_peer_request", 9 },
                new object[] { "connect_peer_response", 10 },
            };

        [Theory]
        [MemberData(nameof(PacketNames))]
        public void Golden_Packet_Pack_Is_Byte_Exact(string name, int msgNum)
        {
            var community = name is "ping_response" or "find_response" or "connect_peer_response"
                ? BobCommunity()
                : AliceCommunity();
            byte[] packet;
            switch (name)
            {
                case "ping_request":
                    packet = PackSigned(community, msgNum, new PingRequestPayload(1001));
                    break;
                case "ping_response":
                    packet = PackSigned(community, msgNum, new PingResponsePayload(1001));
                    break;
                case "store_request":
                    packet = PackSigned(community, msgNum,
                        new StoreRequestPayload(1002, TokenA, Target,
                                                new List<byte[]> { Util.Utf8("value-one"), Util.Utf8("value-two") }));
                    break;
                case "find_request":
                    packet = PackSigned(community, msgNum,
                        new FindRequestPayload(1003, LanA, Target, 5, true));
                    break;
                case "find_response":
                    packet = PackSigned(community, msgNum,
                        new FindResponsePayload(1003, TokenA, new List<byte[]> { Util.Utf8("value-one") },
                                                new List<DhtNode> { NodeA, NodeB }));
                    break;
                case "connect_peer_request":
                    packet = PackSigned(community, msgNum,
                        new ConnectPeerRequestPayload(1004, LanA, Target));
                    break;
                case "connect_peer_response":
                    packet = PackSigned(community, msgNum,
                        new ConnectPeerResponsePayload(1004, new List<DhtNode> { NodeB }));
                    break;
                default:
                    throw new ArgumentException(name);
            }
            Assert.Equal(Vectors1b.Packet(name), Hexlify(packet));
        }

        [Theory]
        [MemberData(nameof(PacketNames))]
        public void Golden_Packet_Unpacks_To_The_Original_Fields(string name, int msgNum)
        {
            var data = Hex(Vectors1b.Packet(name));
            var community = name is "ping_response" or "find_response" or "connect_peer_response"
                ? BobCommunity()
                : AliceCommunity();
            var source = Address.Udpv4("127.0.0.1", 12345);

            // Prefix and message id structural checks.
            Assert.Equal(Vectors1b.Meta("prefix_hex"), Hexlify(Util.Slice(data, 0, 22)));
            Assert.Equal(msgNum, data[22]);

            switch (name)
            {
                case "ping_request":
                {
                    var decoded = community.EzUnpackAuthNoDist<PingRequestPayload>(source, data);
                    Assert.Equal(1001, decoded.Payload.Identifier);
                    break;
                }
                case "ping_response":
                {
                    var decoded = community.EzUnpackAuthNoDist<PingResponsePayload>(source, data);
                    Assert.Equal(1001, decoded.Payload.Identifier);
                    break;
                }
                case "store_request":
                {
                    var decoded = community.EzUnpackAuthNoDist<StoreRequestPayload>(source, data);
                    Assert.Equal(1002, decoded.Payload.Identifier);
                    Assert.Equal(Vectors1b.TokenHex, Hexlify(decoded.Payload.Token));
                    Assert.Equal(Hexlify(Target), Hexlify(decoded.Payload.Target));
                    Assert.Equal(new List<byte[]> { Util.Utf8("value-one"), Util.Utf8("value-two") },
                                 decoded.Payload.Values);
                    break;
                }
                case "find_request":
                {
                    var decoded = community.EzUnpackAuthNoDist<FindRequestPayload>(source, data);
                    Assert.Equal(1003, decoded.Payload.Identifier);
                    Assert.Equal(LanA, decoded.Payload.LanAddress);
                    Assert.Equal(Hexlify(Target), Hexlify(decoded.Payload.Target));
                    Assert.Equal(5, decoded.Payload.Offset);
                    Assert.True(decoded.Payload.ForceNodes);
                    break;
                }
                case "find_response":
                {
                    var decoded = community.EzUnpackAuthNoDist<FindResponsePayload>(source, data);
                    Assert.Equal(1003, decoded.Payload.Identifier);
                    Assert.Equal(Vectors1b.TokenHex, Hexlify(decoded.Payload.Token));
                    Assert.Equal(new List<byte[]> { Util.Utf8("value-one") }, decoded.Payload.Values);
                    Assert.Equal(2, decoded.Payload.Nodes.Count);
                    Assert.Equal(Address.Udpv4("127.0.0.1", 7000), decoded.Payload.Nodes[0].Address);
                    Assert.Equal(Vectors1b.MetaKey("alice_pub_bin_hex"),
                                 Hexlify(decoded.Payload.Nodes[0].PublicKey.KeyToBin()));
                    Assert.Equal(Address.Udpv4("127.0.0.1", 7001), decoded.Payload.Nodes[1].Address);
                    Assert.Equal(Vectors1b.MetaKey("bob_pub_bin_hex"),
                                 Hexlify(decoded.Payload.Nodes[1].PublicKey.KeyToBin()));
                    break;
                }
                case "connect_peer_request":
                {
                    var decoded = community.EzUnpackAuthNoDist<ConnectPeerRequestPayload>(source, data);
                    Assert.Equal(1004, decoded.Payload.Identifier);
                    Assert.Equal(LanA, decoded.Payload.LanAddress);
                    Assert.Equal(Hexlify(Target), Hexlify(decoded.Payload.Target));
                    break;
                }
                case "connect_peer_response":
                {
                    var decoded = community.EzUnpackAuthNoDist<ConnectPeerResponsePayload>(source, data);
                    Assert.Equal(1004, decoded.Payload.Identifier);
                    Assert.Single(decoded.Payload.Nodes);
                    Assert.Equal(Address.Udpv4("127.0.0.1", 7001), decoded.Payload.Nodes[0].Address);
                    Assert.Equal(Vectors1b.MetaKey("bob_pub_bin_hex"),
                                 Hexlify(decoded.Payload.Nodes[0].PublicKey.KeyToBin()));
                    break;
                }
                default:
                    throw new ArgumentException(name);
            }
        }

        [Theory]
        [MemberData(nameof(PacketNames))]
        public void Tampered_Signature_Is_Rejected(string name, int _)
        {
            var data = Hex(Vectors1b.Packet(name));
            var community = name is "ping_response" or "find_response" or "connect_peer_response"
                ? BobCommunity()
                : AliceCommunity();
            var source = Address.Udpv4("127.0.0.1", 12345);

            // Decode with the packet's real payload type: the flipped bit must not change any
            // field length, so the structural unpack succeeds and the SIGNATURE check fails.
            switch (name)
            {
                case "ping_request":
                    AssertEzUnpackTampered<PingRequestPayload>(community, source, data);
                    break;
                case "ping_response":
                    AssertEzUnpackTampered<PingResponsePayload>(community, source, data);
                    break;
                case "store_request":
                    AssertEzUnpackTampered<StoreRequestPayload>(community, source, data);
                    break;
                case "find_request":
                    AssertEzUnpackTampered<FindRequestPayload>(community, source, data);
                    break;
                case "find_response":
                    AssertEzUnpackTampered<FindResponsePayload>(community, source, data);
                    break;
                case "connect_peer_request":
                    AssertEzUnpackTampered<ConnectPeerRequestPayload>(community, source, data);
                    break;
                case "connect_peer_response":
                    AssertEzUnpackTampered<ConnectPeerResponsePayload>(community, source, data);
                    break;
                default:
                    throw new ArgumentException(name);
            }
        }

        private static void AssertEzUnpackTampered<TPayload>(DhtCommunity community, Address source, byte[] data)
            where TPayload : Payload, new()
        {
            // Flip a bit in the 64-byte signature trailer.
            var tamperedSig = (byte[])data.Clone();
            tamperedSig[^1] ^= 0x01;
            var exception = Assert.Throws<PacketDecodingError>(() =>
                community.EzUnpackAuthNoDist<TPayload>(source, tamperedSig));
            Assert.Contains("invalid signature", exception.Message);

            // Flip a bit inside the (signed) header/payload area: the packet is rejected as well —
            // either by the signature check (PacketDecodingError) or, when the flip lands inside a
            // structurally sensitive area (e.g. a node's public key), already at unpack time
            // (PackError "Could not unpack item: ..." — py wraps item errors the same way).
            var tamperedPayload = (byte[])data.Clone();
            tamperedPayload[data.Length - 70] ^= 0x01;
            var rejected = Record.Exception(()
                => community.EzUnpackAuthNoDist<TPayload>(source, tamperedPayload));
            Assert.True(rejected is PacketDecodingError or PackError,
                        $"expected a decoding rejection, got: {rejected?.GetType().Name ?? "null"}");
            if (rejected is PacketDecodingError)
            {
                Assert.Contains("invalid signature", ((PacketDecodingError)rejected).Message);
            }
        }

        [Fact]
        public void VarlenH_List_Vectors()
        {
            var serializer = new Serializer();
            var two = serializer.Pack("varlenH-list",
                new List<object> { Util.Utf8("alpha"), Util.Utf8("beta") });
            Assert.Equal(Vectors1b.SerializerExtras("varlenH_list_two_hex"), Hexlify(two));

            var empty = serializer.Pack("varlenH-list", new List<object>());
            Assert.Equal(Vectors1b.SerializerExtras("varlenH_list_empty_hex"), Hexlify(empty));

            // Roundtrip.
            var (value, offset) = serializer.Unpack("varlenH-list", two);
            Assert.Equal(two.Length, offset);
            var list = Assert.IsType<List<object>>(value);
            Assert.Equal(new List<object> { Util.Utf8("alpha"), Util.Utf8("beta") }, list);
        }

        [Fact]
        public void Node_List_Vector_Pack_And_Unpack()
        {
            // The node-list packer must be registered exactly like dht/community.py:294.
            var community = AliceCommunity();
            var serializer = community.Serializer;

            var packed = serializer.Pack("node-list", new List<object> { NodeA, NodeB });
            Assert.Equal(Vectors1b.SerializerExtras("node_list_two_hex"), Hexlify(packed));

            var (value, offset) = serializer.Unpack("node-list", packed);
            Assert.Equal(packed.Length, offset);
            var nodes = Assert.IsType<List<object>>(value);
            Assert.Equal(2, nodes.Count);
            var unpackedA = Assert.IsType<DhtNode>(nodes[0]);
            Assert.Equal(Address.Udpv4("127.0.0.1", 7000), unpackedA.Address);
            Assert.Equal(Vectors1b.MetaKey("alice_pub_bin_hex"), Hexlify(unpackedA.PublicKey.KeyToBin()));
            var unpackedB = Assert.IsType<DhtNode>(nodes[1]);
            Assert.Equal(Address.Udpv4("127.0.0.1", 7001), unpackedB.Address);
            Assert.Equal(Vectors1b.MetaKey("bob_pub_bin_hex"), Hexlify(unpackedB.PublicKey.KeyToBin()));
        }
    }
}
