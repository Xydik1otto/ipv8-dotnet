// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A3: full-packet roundtrip with fixed key material and fixed global_time. The golden hex
    /// packets were generated independently with the py-ipv8 packet algorithm (prefix + msg_num +
    /// BinMemberAuthenticationPayload(varlenH pubkey_bin) + GlobalTimeDistributionPayload(Q) +
    /// payload + Ed25519 signature), signed with RFC-fixed key material — so these tests pin the
    /// C# port to the py-ipv8 wire format byte-for-byte.
    /// </summary>
    public class PacketRoundtripTests
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        private static byte[] GoldenPrivateKeyBin()
            => Util.Concat(LibNaclPrivateKey.Prefix, Hex(GoldenPackets.XPrivHex), Hex(GoldenPackets.EdSeedHex));

        private sealed class GoldenCommunity : Community
        {
            public GoldenCommunity(CommunitySettings settings, byte[] communityId)
                : base(settings, communityId)
            {
            }
        }

        private static GoldenCommunity BuildGoldenCommunity()
        {
            var privateKey = ECCrypto.Default.KeyFromPrivateBin(GoldenPrivateKeyBin());
            var myPeer = new Peer(privateKey);
            Assert.Equal(GoldenPackets.PubBinHex, Hexlify(myPeer.PublicKey.KeyToBin()));

            var communityId = Hex(GoldenPackets.CommunityIdHex);
            var community = new GoldenCommunity(
                new CommunitySettings(communityId, myPeer, new UDPEndpoint(0, "127.0.0.1"), new Network()),
                communityId);

            // Fixed addresses for the golden vectors.
            community.MyEstimatedLan = new Address(AddressType.Udpv4, "10.0.0.1", 1000);
            community.MyEstimatedWan = new Address(AddressType.Udpv4, "85.85.85.85", 2000);
            // Lamport clock 42: the next claim_global_time() returns 43 == the vectors' global time.
            community.MyPeer.UpdateClock(42);
            return community;
        }

        [Fact]
        public void Signed_Introduction_Request_Is_Byte_Exact_And_Reparses()
        {
            var community = BuildGoldenCommunity();

            var packet = community.CreateIntroductionRequest(new Address(AddressType.Udpv4, "1.2.3.4", 5000),
                                                             extraBytes: new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });
            Assert.Equal(GoldenPackets.IntroRequestHex, Hexlify(packet));

            // Reparse: same values come back out (through the exact lazy_community slicing).
            var decoded = community.EzUnpackAuth<IntroductionRequestPayload>(
                new Address(AddressType.Udpv4, "10.0.0.1", 1000), packet);
            Assert.Equal(new Address(AddressType.Udpv4, "1.2.3.4", 5000), decoded.Payload.DestinationAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), decoded.Payload.SourceLanAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2000), decoded.Payload.SourceWanAddress);
            Assert.Equal(43, decoded.Payload.Identifier);
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, decoded.Payload.ExtraBytes);
            Assert.Equal("unknown", decoded.Payload.ConnectionType);
            Assert.False(decoded.Payload.SupportsNewStyle);
            // py-ipv8 quirk ([True, False][advice] in unpack): sent advice=True reparses as False.
            Assert.False(decoded.Payload.Advice);
            Assert.Equal(43UL, decoded.Dist.GlobalTime);
            Assert.Equal(GoldenPackets.PubBinHex, Hexlify(decoded.Peer.PublicKey.KeyToBin()));
        }

        [Fact]
        public void Signed_Introduction_Response_Is_Byte_Exact_And_Reparses()
        {
            var community = BuildGoldenCommunity();
            // The golden response was generated with the RESPONDER's estimated lan/wan addresses.
            community.MyEstimatedLan = new Address(AddressType.Udpv4, "10.0.0.2", 2002);
            community.MyEstimatedWan = new Address(AddressType.Udpv4, "85.85.85.85", 2002);

            var packet = community.CreateIntroductionResponse(
                new Address(AddressType.Udpv4, "10.0.0.2", 2002),
                new Address(AddressType.Udpv4, "55.1.2.3", 9001),
                43);
            Assert.Equal(GoldenPackets.IntroResponseHex, Hexlify(packet));

            var decoded = community.EzUnpackAuth<IntroductionResponsePayload>(
                new Address(AddressType.Udpv4, "10.0.0.2", 2002), packet);
            Assert.Equal(new Address(AddressType.Udpv4, "55.1.2.3", 9001), decoded.Payload.DestinationAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.2", 2002), decoded.Payload.SourceLanAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2002), decoded.Payload.SourceWanAddress);
            Assert.Equal(Address.Zero, decoded.Payload.LanIntroductionAddress);
            Assert.Equal(Address.Zero, decoded.Payload.WanIntroductionAddress);
            Assert.Equal(43, decoded.Payload.Identifier);
            Assert.True(decoded.Payload.SupportsNewStyle);
            Assert.False(decoded.Payload.IntroSupportsNewStyle);
            Assert.False(decoded.Payload.PeerLimitReached);
            Assert.Empty(decoded.Payload.ExtraBytes);
        }

        [Fact]
        public void Signed_New_Style_Introduction_Request_Is_Byte_Exact_And_Reparses()
        {
            var community = BuildGoldenCommunity();

            var packet = community.CreateIntroductionRequest(new Address(AddressType.Udpv4, "1.2.3.4", 5000),
                                                             newStyle: true);
            Assert.Equal(GoldenPackets.NewIntroRequestHex, Hexlify(packet));

            var decoded = community.EzUnpackAuth<NewIntroductionRequestPayload>(
                new Address(AddressType.Udpv4, "10.0.0.1", 1000), packet);
            Assert.Equal(new Address(AddressType.Udpv4, "1.2.3.4", 5000), decoded.Payload.DestinationAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), decoded.Payload.SourceLanAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2000), decoded.Payload.SourceWanAddress);
            Assert.Equal(43, decoded.Payload.Identifier);
            Assert.Empty(decoded.Payload.ExtraBytes);
        }

        [Fact]
        public void Unsigned_New_Style_Puncture_Request_Is_Byte_Exact_And_Reparses()
        {
            var community = BuildGoldenCommunity();

            var packet = community.CreatePunctureRequest(
                new Address(AddressType.Udpv4, "10.0.0.1", 1000),
                new Address(AddressType.Udpv4, "85.85.85.85", 2000),
                43, newStyle: true);
            Assert.Equal(GoldenPackets.NewPunctureRequestHex, Hexlify(packet));
            // Unsigned: packet length == prefix(22) + msg(1) + dist(8) + payload(16).
            Assert.Equal(47, packet.Length);

            var (dist, payload) = community.EzUnpackNoAuth<NewPunctureRequestPayload>(
                new Address(AddressType.Udpv4, "10.0.0.1", 1000), packet);
            Assert.Equal(43UL, dist.GlobalTime);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), payload.LanWalkerAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2000), payload.WanWalkerAddress);
            Assert.Equal(43, payload.Identifier);
        }

        [Fact]
        public void Tampered_Packet_Fails_Signature_Check()
        {
            var community = BuildGoldenCommunity();
            var packet = community.CreateIntroductionRequest(new Address(AddressType.Udpv4, "1.2.3.4", 5000));

            var tampered = (byte[])packet.Clone();
            tampered[40] ^= 0xFF; // flip a bit inside the X25519 key block (still a valid LibNaCLPK bin)
            var exception = Assert.Throws<PacketDecodingError>(() =>
                community.EzUnpackAuth<IntroductionRequestPayload>(
                    new Address(AddressType.Udpv4, "10.0.0.1", 1000), tampered));
            Assert.Contains("invalid signature", exception.Message);

            // Flipping a bit inside the "LibNaCLPK:" magic prefix fails earlier, at key parsing.
            var tamperedPrefix = (byte[])packet.Clone();
            tamperedPrefix[30] ^= 0xFF;
            Assert.Throws<ArgumentException>(() =>
                community.EzUnpackAuth<IntroductionRequestPayload>(
                    new Address(AddressType.Udpv4, "10.0.0.1", 1000), tamperedPrefix));
        }

        [Fact]
        public void Wrong_Prefix_Packet_Is_Not_Routed()
        {
            var community = BuildGoldenCommunity();
            var packet = community.CreateIntroductionRequest(new Address(AddressType.Udpv4, "1.2.3.4", 5000));

            // Corrupt the community id in the prefix: on_packet must drop the message silently.
            var wrongPrefix = (byte[])packet.Clone();
            wrongPrefix[10] ^= 0xFF;
            community.OnPacket(new Packet(new Address(AddressType.Udpv4, "10.0.0.1", 1000), wrongPrefix));
            Assert.Empty(community.GetPeers());
        }
    }
}
