// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A4: loopback UDP smoke test — two in-process endpoints (127.0.0.1, ephemeral ports) exchange
    /// a signed introduction request/response and both register each other as verified peers.
    /// </summary>
    public class LoopbackSmokeTests
    {
        /// <summary>Community subclass that records the decoded introduction callbacks.</summary>
        private sealed class RecordingCommunity : Community
        {
            public int RequestsReceived;
            public int ResponsesReceived;

            public RecordingCommunity(CommunitySettings settings, byte[] communityId)
                : base(settings, communityId)
            {
            }

            protected override void OnIntroductionRequestCore(Peer peer, GlobalTimeDistributionPayload dist,
                                                              Payload payload,
                                                              Address destinationAddress, Address sourceLanAddress,
                                                              long identifier)
            {
                RequestsReceived++;
                base.OnIntroductionRequestCore(peer, dist, payload, destinationAddress, sourceLanAddress, identifier);
            }

            protected override void OnIntroductionResponseCore(Peer peer, GlobalTimeDistributionPayload dist,
                                                               Payload payload,
                                                               Address destinationAddress, Address sourceWanAddress,
                                                               Address lanIntroductionAddress,
                                                               Address wanIntroductionAddress, long identifier,
                                                               bool introSupportsNewStyle)
            {
                ResponsesReceived++;
                base.OnIntroductionResponseCore(peer, dist, payload, destinationAddress, sourceWanAddress,
                                                lanIntroductionAddress, wanIntroductionAddress, identifier,
                                                introSupportsNewStyle);
            }
        }

        private sealed class TestNode : IDisposable
        {
            public RecordingCommunity Community;
            public UDPEndpoint Endpoint;
            public Peer MyPeer;

            public static TestNode Create(byte[] communityId)
            {
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var community = new RecordingCommunity(
                    new CommunitySettings(communityId, myPeer, endpoint, new Network()), communityId);
                // A well-configured node knows its own (loopback) addresses in this test setup.
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new TestNode { Community = community, Endpoint = endpoint, MyPeer = myPeer };
            }

            public Address Address => Endpoint.GetAddress();

            public void Dispose() => Endpoint.Close();
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 5000)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(10);
            }
        }

        private static byte[] CommunityIdFor(string name) => Util.Sha1(Encoding.UTF8.GetBytes("ipv8-dotnet:" + name));

        [Fact]
        public async Task Two_Loopback_Nodes_Exchange_Signed_Introductions()
        {
            using var nodeA = TestNode.Create(CommunityIdFor("smoke"));
            using var nodeB = TestNode.Create(CommunityIdFor("smoke"));
            Assert.NotEqual(nodeA.Address, nodeB.Address);

            // Minimal walk: send an introduction request to the seed address.
            nodeA.Community.WalkTo(nodeB.Address);

            // Node B answers with a signed introduction response; both nodes verify each other.
            await WaitUntilAsync(() => nodeA.Community.GetPeers().Count > 0
                                       && nodeB.Community.GetPeers().Count > 0,
                                 "peers verified on both nodes");

            Assert.Equal(1, nodeB.Community.RequestsReceived);
            Assert.Equal(1, nodeA.Community.ResponsesReceived);

            // The verified peers are each other, keyed by public key material.
            var peerOfA = nodeA.Community.GetPeers().Single();
            var peerOfB = nodeB.Community.GetPeers().Single();
            Assert.Equal(nodeB.MyPeer.Mid, peerOfA.Mid);
            Assert.Equal(nodeA.MyPeer.Mid, peerOfB.Mid);

            // Node A learned its own (loopback) address from the response's destination_address.
            Assert.Equal(nodeA.Address.Host, nodeA.Community.MyPeer.Address.Host);
            Assert.Equal(nodeA.Address.Port, nodeA.Community.MyPeer.Address.Port);

            // The Lamport clocks: each node claimed global time exactly once (py-ipv8's base
            // Community does not fold incoming dist payloads into its own clock).
            Assert.Equal(1UL, nodeA.Community.GlobalTime);
            Assert.Equal(1UL, nodeB.Community.GlobalTime);

            Assert.Null(nodeA.Community.LastHandlerException);
            Assert.Null(nodeB.Community.LastHandlerException);
        }

        [Fact]
        public async Task Prefix_Dispatch_Routes_Only_To_The_Matching_Overlay()
        {
            var idOne = CommunityIdFor("overlay-one");
            var idTwo = CommunityIdFor("overlay-two");

            using var nodeA = TestNode.Create(idOne);
            // Node B hosts TWO overlays with different community ids on the SAME endpoint.
            var myPeerB = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
            var communityTwo = new RecordingCommunity(
                new CommunitySettings(idTwo, myPeerB, nodeA.Endpoint, new Network()), idTwo);
            communityTwo.MyEstimatedLan = nodeA.Address;
            communityTwo.MyEstimatedWan = nodeA.Address;

            // Walk into overlay one only (to our own address: a pure dispatch exercise).
            nodeA.Community.WalkTo(nodeA.Address);

            // The walker talks to overlay-one's prefix; overlay-two must stay silent.
            await WaitUntilAsync(() => nodeA.Community.ResponsesReceived > 0, "response received");
            Assert.Equal(1, nodeA.Community.RequestsReceived);
            Assert.Equal(0, communityTwo.RequestsReceived);
            Assert.Equal(0, communityTwo.ResponsesReceived);
        }

        [Fact]
        public async Task RandomWalk_Takes_A_Step_To_A_Known_Address()
        {
            using var nodeA = TestNode.Create(CommunityIdFor("walk"));
            using var nodeB = TestNode.Create(CommunityIdFor("walk"));

            // Seed the network with a walkable address (as a tracker/bootstrapper would), tagged
            // with the overlay's service id so it passes the service-filtered walkable-address list.
            nodeA.Community.Network.DiscoverServices(nodeA.Community.MyPeer,
                                                     new[] { nodeA.Community.CommunityId });
            nodeA.Community.Network.DiscoverAddress(nodeA.Community.MyPeer, nodeB.Address,
                                                    nodeA.Community.CommunityId, false);
            var strategy = new RandomWalk(nodeA.Community, resetChance: 0);
            strategy.TakeStep();

            // The walk resulted in an (in-flight) introduction request to node B, which answers.
            await WaitUntilAsync(() => nodeA.Community.GetPeers().Count > 0, "node A verified node B");
            Assert.True(strategy.GetPeerCount() > 0);
        }
    }
}
