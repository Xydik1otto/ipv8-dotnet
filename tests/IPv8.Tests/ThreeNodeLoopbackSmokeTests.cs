// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A10: three-node loopback smoke test. Alice and Bob join the overlay; Alice stores a value and
    /// the DHT routes it to the closest known node(s). Carol joins LATER, learns the DHT routing table
    /// through FIND-requests and still resolves the value. PingChurn keeps the routing tables alive.
    /// </summary>
    public class ThreeNodeLoopbackSmokeTests : IDisposable
    {
        private sealed class Node : IDisposable
        {
            public UDPEndpoint Endpoint;
            public Peer MyPeer;
            public DhtCommunity Community;

            public static Node Create()
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var community = new DhtCommunity(
                    new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, endpoint, new Network()));
                // A well-configured node knows its own (loopback) addresses in this test setup.
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new Node { Endpoint = endpoint, MyPeer = myPeer, Community = community };
            }

            public Address Address => Endpoint.GetAddress();

            /// <summary>The DHT routing-table node for the given other node, if present.</summary>
            public DhtNode RoutingNodeFor(Node other)
            {
                var nodeId = DhtRouting.CalcNodeId(other.Address, other.MyPeer.Mid);
                return Community.RoutingTables.TryGetValue(AddressType.Udpv4, out var routingTable)
                    ? routingTable.Get(nodeId)
                    : null;
            }

            public void Dispose()
            {
                Community.Unload();
                Endpoint.Close();
            }
        }

        private readonly List<Node> _nodes = new List<Node>();

        private Node MakeNode()
        {
            var node = Node.Create();
            _nodes.Add(node);
            return node;
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 8000)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(5);
            }
        }

        public void Dispose()
        {
            foreach (var node in _nodes)
            {
                node.Dispose();
            }
        }

        [Fact]
        public async Task Store_Lands_At_Closest_Node_And_Late_Joiner_Finds_It()
        {
            var target = Vectors1b.Target();
            var value = Encoding.UTF8.GetBytes("hello dht loopback");

            var alice = MakeNode();
            var bob = MakeNode();

            // Wire A and B together through the usual (signed) introduction request/response.
            alice.Community.WalkTo(bob.Address);
            await WaitUntilAsync(() => alice.Community.GetPeers().Any(p => p.Mid.SequenceEqual(bob.MyPeer.Mid))
                                       && bob.Community.GetPeers().Any(p => p.Mid.SequenceEqual(alice.MyPeer.Mid)),
                                 "alice and bob verified each other");

            // Both sides learn the other's DHT routing-table entry (introduction callbacks ping them).
            await WaitUntilAsync(() => alice.RoutingNodeFor(bob) != null && bob.RoutingNodeFor(alice) != null,
                                 "routing-table entries on both sides");

            // A store → the value lands in the store AND propagates to the closest node (bob).
            var storingNodes = await alice.Community.StoreValueAsync(target, value);
            Assert.Contains(storingNodes, node => node.Mid.SequenceEqual(bob.MyPeer.Mid));
            await WaitUntilAsync(
                () => alice.Community.Storages.TryGetValue(AddressType.Udpv4, out var aliceStorage)
                      && aliceStorage.Get(target).Count > 0,
                "alice stored the value locally");
            await WaitUntilAsync(
                () => bob.Community.Storages.TryGetValue(AddressType.Udpv4, out var bobStorage)
                      && bobStorage.Get(target).Count > 0,
                "the value reached bob as the closest node");

            // C joins LATE: walks to the (already running) seed node alice.
            var carol = MakeNode();
            carol.Community.WalkTo(alice.Address);
            await WaitUntilAsync(() => carol.Community.GetPeers().Any(p => p.Mid.SequenceEqual(alice.MyPeer.Mid)),
                                 "carol verified alice");
            await WaitUntilAsync(() => carol.RoutingNodeFor(alice) != null,
                                 "carol learned alice's routing-table entry");

            // C FINDS and retrieves the value through the DHT.
            var found = await carol.Community.FindValuesAsync(target);
            Assert.Contains(found, pair => pair.Data.SequenceEqual(value));

            // Ping churn keeps the routing table alive: ping everyone, wait for the responses, then
            // check the nodes are still GOOD (not failed/bad) and still present.
            var churn = new PingChurn(carol.Community, pingInterval: 0.1);
            churn.TakeStep();
            await WaitUntilAsync(() => carol.RoutingNodeFor(alice) != null
                                       && carol.RoutingNodeFor(alice).Failed == 0
                                       && carol.RoutingNodeFor(alice).Status == DhtRouting.NodeStatusGood,
                                 "carol's routing-table node for alice is GOOD after churn");

            // A second churn cycle (after the ping interval) keeps the table alive as well.
            await Task.Delay(150);
            churn.TakeStep();
            await WaitUntilAsync(() => carol.RoutingNodeFor(alice) != null
                                       && carol.RoutingNodeFor(alice).Status == DhtRouting.NodeStatusGood,
                                 "the routing table stayed alive over two churn cycles");

            // And the value is still retrievable through the DHT afterwards.
            var foundAgain = await carol.Community.FindValuesAsync(target);
            Assert.Contains(foundAgain, pair => pair.Data.SequenceEqual(value));

            Assert.Null(carol.Community.LastHandlerException);
            Assert.Null(alice.Community.LastHandlerException);
            Assert.Null(bob.Community.LastHandlerException);
        }
    }
}
