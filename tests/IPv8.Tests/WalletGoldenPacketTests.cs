// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A18 (wire part): the 5 wallet golden packets (msg 1–5) byte-exact pack AND unpack.
    /// Wallet messages carry [auth, dist, payload] + signature MANUALLY (unlike identity
    /// ez_send); handlers unpack via EzUnpackAuth (with dist).
    /// </summary>
    public class WalletGoldenPacketTests : IDisposable
    {
        private static byte[] Hex(string hex) => Util.Unhex(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        // Same RFC-fixed Bob key material as contract/gen_vectors_phase2.py (the wallet packets
        // are all signed by Bob).
        private const string BobXPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

        private readonly UDPEndpoint _endpoint = OpenEndpoint();
        private readonly List<AttestationCommunity> _communities = new List<AttestationCommunity>();

        private static UDPEndpoint OpenEndpoint()
        {
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(endpoint.Open());
            return endpoint;
        }

        private AttestationCommunity BobCommunity()
        {
            var privateKeyBin = Util.Concat(LibNaclPrivateKey.Prefix, Hex(BobXPrivHex),
                                            Hex(Vectors2.MetaKey("bob_ed_seed_hex")));
            var myPeer = new Peer(ECCrypto.Default.KeyFromPrivateBin(privateKeyBin));
            Assert.Equal(Vectors2.MetaKey("bob_pub_bin_hex"), Hexlify(myPeer.PublicKey.KeyToBin()));

            var community = new AttestationCommunity(new AttestationSettings(
                Hex(Vectors2.Meta("wallet_community_id_hex")), myPeer, _endpoint, new Network())
            {
                WorkingDirectory = ":memory:"
            });
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

        /// <summary>py: packet = WALLET_PREFIX + msgByte + pack([auth, dist, payload]) + sig.</summary>
        private static byte[] PackWalletMessage(AttestationCommunity community, int msgNum,
                                                Payload payload, ulong globalTime)
        {
            var auth = new BinMemberAuthenticationPayload(community.MyPeer.PublicKey.KeyToBin());
            var dist = new GlobalTimeDistributionPayload(globalTime);
            return community.EzPack(community.Prefix, msgNum, new Payload[] { auth, dist, payload });
        }

        private static byte[] TwentyBytes()
        {
            var twenty = new byte[20];
            for (var i = 0; i < 20; i++)
            {
                twenty[i] = (byte)i;
            }
            return twenty;
        }

        private static Payload BuildPayload(int msgId)
            => msgId switch
            {
                1 => new VerifyAttestationRequestPayload(TwentyBytes()),
                2 => new AttestationChunkPayload(TwentyBytes(), 3, Util.Utf8("chunk-data-123")),
                3 => new ChallengePayload(TwentyBytes(), Util.Utf8("challenge-bytes")),
                4 => new ChallengeResponsePayload(TwentyBytes(), Util.Utf8("response-bytes")),
                5 => new RequestAttestationPayload(Util.Utf8(
                    "{\"attribute\": \"id\", \"id_format\": \"id_metadata\", " +
                    "\"public_key\": \"cHVia2V5\", \"meta\": \"data\"}")),
                _ => throw new ArgumentException("unknown msg id " + msgId)
            };

        private static string PacketHexOf(int msgId)
            => Vectors2.Section("wallet_packets").EnumerateArray()
                .First(entry => entry.GetProperty("msg_id").GetInt32() == msgId)
                .GetProperty("packet_hex").GetString();

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void Wallet_Packet_Pack_Is_Byte_Exact(int msgId)
        {
            var community = BobCommunity();
            var packet = PackWalletMessage(community, msgId, BuildPayload(msgId), 12345UL);
            Assert.Equal(PacketHexOf(msgId), Hexlify(packet));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void Wallet_Packet_Unpack_Is_Byte_Exact(int msgId)
        {
            var community = BobCommunity();
            var data = Hex(PacketHexOf(msgId));
            var source = Address.Udpv4("127.0.0.1", 12345);
            Assert.Equal(msgId, data[22]);

            // The community handler path: EzUnpackAuth = auth at offset 23, then
            // [dist, payload] from the re-offset remainder. The signature verifies.
            switch (msgId)
            {
                case 1:
                {
                    var decoded = community.EzUnpackAuth<VerifyAttestationRequestPayload>(source, data);
                    Assert.Equal(12345UL, decoded.Dist.GlobalTime);
                    Assert.Equal(TwentyBytes(), decoded.Payload.AttestationHash);
                    break;
                }
                case 2:
                {
                    var decoded = community.EzUnpackAuth<AttestationChunkPayload>(source, data);
                    Assert.Equal(12345UL, decoded.Dist.GlobalTime);
                    Assert.Equal(3, decoded.Payload.SequenceNumber);
                    Assert.Equal(Util.Utf8("chunk-data-123"), decoded.Payload.Data);
                    break;
                }
                case 3:
                {
                    var decoded = community.EzUnpackAuth<ChallengePayload>(source, data);
                    Assert.Equal(12345UL, decoded.Dist.GlobalTime);
                    Assert.Equal(Util.Utf8("challenge-bytes"), decoded.Payload.Challenge);
                    break;
                }
                case 4:
                {
                    var decoded = community.EzUnpackAuth<ChallengeResponsePayload>(source, data);
                    Assert.Equal(12345UL, decoded.Dist.GlobalTime);
                    Assert.Equal(Util.Utf8("response-bytes"), decoded.Payload.Response);
                    break;
                }
                case 5:
                {
                    var decoded = community.EzUnpackAuth<RequestAttestationPayload>(source, data);
                    Assert.Equal(12345UL, decoded.Dist.GlobalTime);
                    Assert.Equal(Util.Utf8("{\"attribute\": \"id\", \"id_format\": \"id_metadata\", " +
                                           "\"public_key\": \"cHVia2V5\", \"meta\": \"data\"}"),
                                 decoded.Payload.Metadata);
                    break;
                }
            }
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void Tampered_Wallet_Packet_Signature_Is_Rejected(int msgId)
        {
            var community = BobCommunity();
            var data = Hex(PacketHexOf(msgId));
            var source = Address.Udpv4("127.0.0.1", 12345);

            // Flip a bit in the 64-byte signature trailer: structural unpack succeeds, the
            // signature check must fail.
            var tampered = (byte[])data.Clone();
            tampered[^1] ^= 0x01;
            switch (msgId)
            {
                case 1:
                    AssertTamperRejected<VerifyAttestationRequestPayload>(community, source, tampered);
                    break;
                case 2:
                    AssertTamperRejected<AttestationChunkPayload>(community, source, tampered);
                    break;
                case 3:
                    AssertTamperRejected<ChallengePayload>(community, source, tampered);
                    break;
                case 4:
                    AssertTamperRejected<ChallengeResponsePayload>(community, source, tampered);
                    break;
                case 5:
                    AssertTamperRejected<RequestAttestationPayload>(community, source, tampered);
                    break;
            }
        }

        private static void AssertTamperRejected<TPayload>(AttestationCommunity community, Address source,
                                                           byte[] tampered)
            where TPayload : Payload, new()
        {
            var exception = Record.Exception(() =>
                community.EzUnpackAuth<TPayload>(source, tampered));
            Assert.NotNull(exception);
            Assert.IsType<PacketDecodingError>(exception);
        }
    }
}
