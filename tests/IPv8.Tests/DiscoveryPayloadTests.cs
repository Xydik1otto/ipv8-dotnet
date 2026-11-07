// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Text;
using IPv8.Messaging;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// Byte-exact pack/unpack roundtrips for the discovery payloads
    /// (py-ipv8 ipv8/messaging/payload.py, old and new style).
    /// </summary>
    public class DiscoveryPayloadTests
    {
        private static readonly Serializer Serializer = new Serializer();

        private static byte[] Roundtrip(Serializable payload, Action<Serializable> repair = null)
        {
            var packed = Serializer.PackSerializable(payload);
            var unpacked = Serializer.UnpackSerializable(payload.GetType(), packed, 0).Item1;
            // Byte-exactness: repacking the unpacked instance must give identical bytes. The optional
            // "repair" callback undoes py-ipv8 unpack quirks (e.g. the inverted advice bit) first.
            repair?.Invoke(unpacked);
            Assert.Equal(packed, Serializer.PackSerializable(unpacked));
            return packed;
        }

        [Fact]
        public void IntroductionRequestPayload_Roundtrip_With_Connection_Type_And_Mod()
        {
            var payload = new IntroductionRequestPayload(
                Address.Udpv4("1.2.3.4", 5000),
                Address.Udpv4("10.0.0.1", 1000),
                Address.Udpv4("85.85.85.85", 2000),
                advice: true,
                connectionType: "symmetric-NAT",
                identifier: 70000, // % 65536 == 4464
                extraBytes: new byte[] { 1, 2, 3 },
                supportsNewStyle: false);

            var packed = Roundtrip(payload, s =>
            {
                // py-ipv8 quirk: unpack inverts the advice bit ([True, False][advice]) — un-invert
                // before the re-pack equality check.
                var request = (IntroductionRequestPayload)s;
                request.Advice = !request.Advice;
            });
            // 3 ipv4 (18) + bits (1) + H (2) + raw (3) = 24 bytes.
            Assert.Equal(24, packed.Length);

            var unpacked = Serializer.UnpackSerializableAs<IntroductionRequestPayload>(packed);
            Assert.Equal("1.2.3.4", unpacked.DestinationAddress.Host);
            Assert.Equal(5000, unpacked.DestinationAddress.Port);
            Assert.Equal("10.0.0.1", unpacked.SourceLanAddress.Host);
            Assert.Equal("85.85.85.85", unpacked.SourceWanAddress.Host);
            Assert.Equal("symmetric-NAT", unpacked.ConnectionType);
            Assert.Equal(4464, unpacked.Identifier);
            Assert.Equal(new byte[] { 1, 2, 3 }, unpacked.ExtraBytes);
            Assert.False(unpacked.SupportsNewStyle);
            // py-ipv8 quirk: unpacking inverts the advice bit ([True, False][advice]).
            Assert.False(unpacked.Advice);
        }

        [Fact]
        public void IntroductionResponsePayload_Roundtrip_With_Introductions()
        {
            var payload = new IntroductionResponsePayload(
                Address.Udpv4("55.1.2.3", 9001),
                Address.Udpv4("10.0.0.2", 2002),
                Address.Udpv4("85.85.85.85", 2000),
                Address.Udpv4("10.0.0.9", 3000),
                Address.Udpv4("77.77.77.77", 3000),
                "public",
                identifier: 42,
                extraBytes: Array.Empty<byte>(),
                supportsNewStyle: true,
                introSupportsNewStyle: true,
                peerLimitReached: true);

            var packed = Roundtrip(payload);
            // 5 ipv4 (30) + bits (1) + H (2) = 33 bytes.
            Assert.Equal(33, packed.Length);

            var unpacked = Serializer.UnpackSerializableAs<IntroductionResponsePayload>(packed);
            Assert.Equal("public", unpacked.ConnectionType);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.9", 3000), unpacked.LanIntroductionAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "77.77.77.77", 3000), unpacked.WanIntroductionAddress);
            Assert.True(unpacked.SupportsNewStyle);
            Assert.True(unpacked.IntroSupportsNewStyle);
            Assert.True(unpacked.PeerLimitReached);
            Assert.Equal(42, unpacked.Identifier);
        }

        [Fact]
        public void Puncture_Payloads_Roundtrip()
        {
            var request = new PunctureRequestPayload(Address.Udpv4("10.0.0.1", 1000),
                                                     Address.Udpv4("85.85.85.85", 2000), 777);
            var requestPacked = Roundtrip(request);
            Assert.Equal(14, requestPacked.Length);
            var requestUnpacked = Serializer.UnpackSerializableAs<PunctureRequestPayload>(requestPacked);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), requestUnpacked.LanWalkerAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2000), requestUnpacked.WanWalkerAddress);
            Assert.Equal(777, requestUnpacked.Identifier);

            var puncture = new PuncturePayload(Address.Udpv4("10.0.0.2", 2002),
                                               Address.Udpv4("77.77.77.77", 3000), 778);
            var puncturePacked = Roundtrip(puncture);
            var punctureUnpacked = Serializer.UnpackSerializableAs<PuncturePayload>(puncturePacked);
            Assert.Equal(778, punctureUnpacked.Identifier);
            Assert.Equal(new Address(AddressType.Udpv4, "77.77.77.77", 3000),
                         punctureUnpacked.SourceWanAddress);
        }

        [Fact]
        public void New_Style_Payloads_Roundtrip()
        {
            var newRequest = new NewIntroductionRequestPayload(
                Address.Udpv4("1.2.3.4", 5000),
                Address.Udpv4("10.0.0.1", 1000),
                Address.Udpv4("85.85.85.85", 2000),
                identifier: 43,
                connectionType0: 1, connectionType1: 0, // "public"
                supportsNewStyle: 1, dflag1: 0, dflag2: 0, tunnel: 0, sync: 0, advice: 1,
                extraBytes: new byte[] { 0xEE });
            var packed = Roundtrip(newRequest);
            // 3 ip_address (7 each) + H (2) + bits (1) + raw (1) = 25 bytes.
            Assert.Equal(25, packed.Length);

            var unpacked = Serializer.UnpackSerializableAs<NewIntroductionRequestPayload>(packed);
            Assert.Equal(AddressType.Udpv4, unpacked.DestinationAddress.Type);
            Assert.Equal("1.2.3.4", unpacked.DestinationAddress.Host);
            Assert.Equal(43, unpacked.Identifier);
            Assert.Equal(1, unpacked.ConnectionType0);
            Assert.Equal(1, unpacked.SupportsNewStyle);
            Assert.Equal(1, unpacked.Advice);
            Assert.Equal(new byte[] { 0xEE }, unpacked.ExtraBytes);

            var newResponse = new NewIntroductionResponsePayload(
                Address.Udpv4("55.1.2.3", 9001),
                Address.Udpv4("10.0.0.2", 2002),
                Address.Udpv4("85.85.85.85", 2000),
                Address.Udpv4("10.0.0.9", 3000),
                Address.Udpv4("77.77.77.77", 3000),
                identifier: 44,
                introSupportsNewStyle: true,
                flag1: 0, flag2: 0, flag3: 0, flag4: 0, flag5: 0, flag6: 0, flag7: 0,
                extraBytes: Array.Empty<byte>());
            var responsePacked = Roundtrip(newResponse);
            // 5 ip_address (35) + H (2) + bits (1) = 38 bytes.
            Assert.Equal(38, responsePacked.Length);
            var responseUnpacked = Serializer.UnpackSerializableAs<NewIntroductionResponsePayload>(responsePacked);
            Assert.True(responseUnpacked.IntroSupportsNewStyle);
            Assert.Equal(44, responseUnpacked.Identifier);
            Assert.Equal(new Address(AddressType.Udpv4, "77.77.77.77", 3000),
                         responseUnpacked.WanIntroductionAddress);

            var newPunctureRequest = new NewPunctureRequestPayload(Address.Udpv4("10.0.0.1", 1000),
                                                                   Address.Udpv4("85.85.85.85", 2000), 45);
            var puncturePacked = Roundtrip(newPunctureRequest);
            Assert.Equal(16, puncturePacked.Length);
            var punctureUnpacked = Serializer.UnpackSerializableAs<NewPunctureRequestPayload>(puncturePacked);
            Assert.Equal(45, punctureUnpacked.Identifier);

            var newPuncture = new NewPuncturePayload(Address.Udpv4("10.0.0.2", 2002),
                                                     Address.Udpv4("77.77.77.77", 3000), 46);
            var packedPuncture = Roundtrip(newPuncture);
            var punctureUnpacked2 = Serializer.UnpackSerializableAs<NewPuncturePayload>(packedPuncture);
            Assert.Equal(46, punctureUnpacked2.Identifier);
        }

        [Fact]
        public void Connection_Type_Codec_Matches_Py_Ipv8()
        {
            Assert.Equal((1, 0), ConnectionTypeCodec.EncodeConnectionType("public"));
            Assert.Equal((1, 1), ConnectionTypeCodec.EncodeConnectionType("symmetric-NAT"));
            Assert.Equal((0, 0), ConnectionTypeCodec.EncodeConnectionType("unknown"));
            Assert.Equal("unknown", ConnectionTypeCodec.DecodeConnectionType(0, 0));
            Assert.Equal("public", ConnectionTypeCodec.DecodeConnectionType(1, 0));
            Assert.Equal("symmetric-NAT", ConnectionTypeCodec.DecodeConnectionType(1, 1));
            Assert.Equal("N/A", ConnectionTypeCodec.DecodeConnectionType(0, 1));
        }

        [Fact]
        public void Unpack_Golden_New_Style_Puncture_Request()
        {
            // Golden unsigned packet (generated against the py-ipv8 algorithm).
            var packet = Convert.FromHexString(GoldenPackets.NewPunctureRequestHex);
            Assert.Equal(47, packet.Length);
            var (dist, payload) = new UnpackHarness().Unpack(packet);
            Assert.Equal(43UL, dist.GlobalTime);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), payload.LanWalkerAddress);
            Assert.Equal(new Address(AddressType.Udpv4, "85.85.85.85", 2000), payload.WanWalkerAddress);
            Assert.Equal(43, payload.Identifier);
        }

        /// <summary>Minimal unpack harness standing in for an overlay (offset-23 unpack).</summary>
        private sealed class UnpackHarness
        {
            public (GlobalTimeDistributionPayload Dist, NewPunctureRequestPayload Payload) Unpack(byte[] data)
            {
                var unpacked = Serializer.UnpackSerializableList(
                    new[] { typeof(GlobalTimeDistributionPayload), typeof(NewPunctureRequestPayload) },
                    data, 23);
                return ((GlobalTimeDistributionPayload)unpacked[0],
                        (NewPunctureRequestPayload)unpacked[1]);
            }
        }
    }
}
