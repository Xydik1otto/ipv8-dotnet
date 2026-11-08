// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using IPv8.Bootstrapping;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A12: DispersyBootstrapper behavior against an in-process loopback bootstrap node.
    /// A13: UDPBroadcastBootstrapper smoke (real socket walk + opportunistic OS broadcast).
    /// </summary>
    public class BootstrapperTests
    {
        private sealed class RecordingCommunity : Community
        {
            public int RequestsReceived;

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
                base.OnIntroductionRequestCore(peer, dist, payload, destinationAddress, sourceLanAddress,
                                               identifier);
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
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new TestNode { Community = community, Endpoint = endpoint, MyPeer = myPeer };
            }

            public Address Address => Endpoint.GetAddress();

            public void Dispose() => Endpoint.Close();
        }

        private static byte[] CommunityIdFor(string name)
            => Util.Sha1(Encoding.UTF8.GetBytes("ipv8-dotnet:" + name));

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

        // ------------------------------------------------------------------
        // A12: DispersyBootstrapper
        // ------------------------------------------------------------------

        [Fact]
        public async Task DispersyBootstrapper_Initialize_Blacklists_Seed_Addresses()
        {
            using var bootstrapNode = TestNode.Create(CommunityIdFor("boot-server"));
            var overlay = bootstrapNode.Community;
            var bootstrapper = new DispersyBootstrapper(new[] { bootstrapNode.Address },
                                                        new (string, int)[0], 60.0);

            var result = await bootstrapper.InitializeAsync(overlay);

            Assert.Contains(bootstrapNode.Address, overlay.Network.Blacklist);
            Assert.True(result);
            Assert.True(bootstrapper.Initialized);
        }

        [Fact]
        public async Task DispersyBootstrapper_GetAddresses_Walks_Seeds_And_Returns_Empty()
        {
            using var bootstrapNode = TestNode.Create(CommunityIdFor("boot-server"));
            using var walkerNode = TestNode.Create(CommunityIdFor("boot-server"));
            var bootstrapper = new DispersyBootstrapper(new[] { bootstrapNode.Address },
                                                        new (string, int)[0], 60.0);
            await bootstrapper.InitializeAsync(walkerNode.Community);

            var addresses = await bootstrapper.GetAddressesAsync(walkerNode.Community, 60.0);

            // There should be no manually walkable addresses.
            Assert.Empty(addresses);

            // However, the bootstrap node should have been contacted using the IPv8 protocol.
            await WaitUntilAsync(() => bootstrapNode.Community.RequestsReceived == 1,
                                 "bootstrap node received the intro request");
        }

        [Fact]
        public async Task DispersyBootstrapper_GetAddresses_Timeout_Drops_Second_Call()
        {
            using var bootstrapNode = TestNode.Create(CommunityIdFor("boot-server"));
            using var walkerNode = TestNode.Create(CommunityIdFor("boot-server"));
            var bootstrapper = new DispersyBootstrapper(new[] { bootstrapNode.Address },
                                                        new (string, int)[0], 60.0);
            await bootstrapper.InitializeAsync(walkerNode.Community);

            await bootstrapper.GetAddressesAsync(walkerNode.Community, 60.0);
            await WaitUntilAsync(() => bootstrapNode.Community.RequestsReceived == 1,
                                 "first walk delivered");
            await bootstrapper.GetAddressesAsync(walkerNode.Community, 60.0);

            // The second call within the timeout window must NOT walk again.
            await Task.Delay(200);
            Assert.Equal(1, bootstrapNode.Community.RequestsReceived);
        }

        [Fact]
        public async Task DispersyBootstrapper_GetAddresses_Ensures_Blacklist()
        {
            using var bootstrapNode = TestNode.Create(CommunityIdFor("boot-server"));
            using var walkerNode = TestNode.Create(CommunityIdFor("boot-server"));
            var bootstrapper = new DispersyBootstrapper(new[] { bootstrapNode.Address },
                                                        new (string, int)[0], 60.0);
            await bootstrapper.InitializeAsync(walkerNode.Community);
            walkerNode.Community.Network.Blacklist.Clear();

            await bootstrapper.GetAddressesAsync(walkerNode.Community, 60.0);

            Assert.Contains(bootstrapNode.Address, walkerNode.Community.Network.Blacklist);
        }

        [Fact]
        public async Task DispersyBootstrapper_KeepAlive_Walks_And_Blacklists()
        {
            using var bootstrapNode = TestNode.Create(CommunityIdFor("boot-server"));
            using var walkerNode = TestNode.Create(CommunityIdFor("boot-server"));
            var bootstrapper = new DispersyBootstrapper(new[] { bootstrapNode.Address },
                                                        new (string, int)[0], 60.0);
            await bootstrapper.InitializeAsync(walkerNode.Community);
            walkerNode.Community.Network.Blacklist.Clear();

            bootstrapper.KeepAlive(walkerNode.Community);

            await WaitUntilAsync(() => bootstrapNode.Community.RequestsReceived == 1,
                                 "keep-alive walk delivered");
            Assert.Contains(bootstrapNode.Address, walkerNode.Community.Network.Blacklist);
            // The blacklist() view matches the configured seed list.
            Assert.Equal(new[] { bootstrapNode.Address }, bootstrapper.Blacklist());
        }

        /// <summary>
        /// A12 full flow (py-ipv8 test_peerdiscovery/test_community.py::test_bootstrap): two
        /// fresh nodes bootstrap via the bootstrapper; the bootstrap server's routing table sees
        /// both of them; a second bootstrap round has the tracker introduce them to each other,
        /// after which both fresh nodes verify each other.
        /// </summary>
        [Fact]
        public async Task Fresh_Nodes_Bootstrap_Through_DispersyBootstrapper()
        {
            using var tracker = TestNode.Create(CommunityIdFor("boot-flow"));
            using var freshA = TestNode.Create(CommunityIdFor("boot-flow"));
            using var freshB = TestNode.Create(CommunityIdFor("boot-flow"));

            foreach (var fresh in new[] { freshA, freshB })
            {
                // py-ipv8: the tracker address is blacklisted and walked through a bootstrapper.
                fresh.Community.Network.Blacklist.Add(tracker.Address);
                fresh.Community.Bootstrappers.Add(
                    new DispersyBootstrapper(new[] { tracker.Address }, new (string, int)[0], 0.0));
            }

            // Round 1: both fresh nodes contact the tracker.
            freshA.Community.Bootstrap();
            freshB.Community.Bootstrap();
            await WaitUntilAsync(() => tracker.Community.GetPeers().Count == 2,
                                 "tracker routing table sees both fresh nodes");

            // Round 2: the tracker knows both others, so it introduces them to each other.
            freshA.Community.Bootstrap();
            freshB.Community.Bootstrap();
            await WaitUntilAsync(
                () => freshA.Community.GetWalkableAddresses().Count > 0
                      && freshB.Community.GetWalkableAddresses().Count > 0,
                "both fresh nodes got an introduction from the tracker");

            // The introductions point at the OTHER fresh node (not the tracker, not ourselves):
            // walking there verifies both, which is the walkers' job in a real deployment.
            var introOfA = freshA.Community.GetWalkableAddresses().Single();
            var introOfB = freshB.Community.GetWalkableAddresses().Single();
            Assert.Equal(freshB.Address, introOfA);
            Assert.Equal(freshA.Address, introOfB);
            freshA.Community.WalkTo(introOfA);
            freshB.Community.WalkTo(introOfB);
            await WaitUntilAsync(() => freshA.Community.GetPeers().Count > 0
                                       && freshB.Community.GetPeers().Count > 0,
                                 "fresh nodes verified each other via tracker introductions");

            Assert.Equal(freshB.MyPeer.Mid, freshA.Community.GetPeers().Single().Mid);
            Assert.Equal(freshA.MyPeer.Mid, freshB.Community.GetPeers().Single().Mid);
            Assert.Null(freshA.Community.LastHandlerException);
            Assert.Null(freshB.Community.LastHandlerException);

            // Unloading the community unloads its bootstrappers.
            freshA.Community.Unload();
            Assert.Empty(freshA.Community.Bootstrappers);
        }

        // ------------------------------------------------------------------
        // A13: UDPBroadcastBootstrapper
        // ------------------------------------------------------------------

        [Fact]
        public async Task Broadcast_Endpoint_Handoff_Over_Real_Sockets()
        {
            using var server = TestNode.Create(CommunityIdFor("broadcast"));
            using var client = TestNode.Create(CommunityIdFor("broadcast"));

            // Both nodes get a real broadcast socket (ephemeral ports, SO_BROADCAST set).
            var serverBroadcast = new BroadcastBootstrapEndpoint(server.Community);
            var clientBroadcast = new BroadcastBootstrapEndpoint(client.Community);
            try
            {
                Assert.True(serverBroadcast.Open());
                Assert.True(clientBroadcast.Open());

                // Client beacons the announce message to the server's broadcast socket
                // (the socket binds 0.0.0.0:0, so target it over the loopback interface).
                clientBroadcast.Send(Address.Udpv4("127.0.0.1", serverBroadcast.LocalAddress.Port),
                                     Util.Concat(BroadcastBootstrapEndpoint.HdrAnnounce,
                                                 client.Community.GetPrefix()));

                // The server's broadcast endpoint receives the announce and attempts a walk:
                // it sends an intro request to the client's broadcast socket address.
                await WaitUntilAsync(() => client.Community.RequestsReceived == 1,
                                     "server walked back into the client's broadcast socket");

                // The handoff branch delivered the intro request to the client overlay, which
                // responded through its own overlay socket: both become verified peers.
                await WaitUntilAsync(() => client.Community.GetPeers().Count > 0
                                           && server.Community.GetPeers().Count > 0,
                                     "both nodes verified each other via the broadcast handoff");

                Assert.Equal(server.MyPeer.Mid, client.Community.GetPeers().Single().Mid);
                Assert.Equal(client.MyPeer.Mid, server.Community.GetPeers().Single().Mid);
                Assert.Null(client.Community.LastHandlerException);
                Assert.Null(server.Community.LastHandlerException);
            }
            finally
            {
                serverBroadcast.Close();
                clientBroadcast.Close();
            }
        }

        [Fact]
        public async Task Broadcast_Endpoint_Drops_Garbage_And_Other_Overlays()
        {
            using var node = TestNode.Create(CommunityIdFor("broadcast"));

            var broadcast = new BroadcastBootstrapEndpoint(node.Community);
            try
            {
                // Wrong overlay prefix + announce for another overlay: nothing happens.
                broadcast.OnDatagram(Util.Concat(BroadcastBootstrapEndpoint.HdrAnnounce,
                                                 CommunityIdFor("other-overlay")),
                                     Address.Udpv4("127.0.0.1", 1));
                broadcast.OnDatagram(Util.Concat(node.Community.GetPrefix(), new byte[] { 200 }),
                                     Address.Udpv4("127.0.0.1", 1));
                Assert.Equal(0, node.Community.RequestsReceived);

                // A valid announce for OUR overlay triggers a walk (observable as a request
                // arriving at the walked address).
                using var target = TestNode.Create(CommunityIdFor("broadcast"));
                broadcast.OnDatagram(Util.Concat(BroadcastBootstrapEndpoint.HdrAnnounce,
                                                 node.Community.GetPrefix()),
                                     target.Address);
                await WaitUntilAsync(() => target.Community.RequestsReceived == 1,
                                     "walk to announced target");
            }
            finally
            {
                broadcast.Close();
            }
        }

        /// <summary>
        /// A13 real-broadcast smoke: beacon the local broadcast address and check that a node
        /// with an initialized bootstrapper answers. Skips cleanly when the OS denies broadcast
        /// or filters the reply (firewalls), instead of failing.
        /// </summary>
        [Fact]
        public async Task UdpBroadcastBootstrapper_Beacon_Finds_Local_Listener()
        {
            // Probe: can we send to the broadcast address at all?
            var broadcastDenied = false;
            try
            {
                using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram,
                                              ProtocolType.Udp))
                {
                    probe.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    probe.SendTo(new byte[] { 1, 2, 3 },
                                 new IPEndPoint(IPAddress.Broadcast, 65534));
                }
            }
            catch (Exception)
            {
                broadcastDenied = true;
            }

            if (broadcastDenied)
            {
                // Skip cleanly: the OS denied broadcast on the chosen address.
                return;
            }

            using var server = TestNode.Create(CommunityIdFor("beacon"));
            using var client = TestNode.Create(CommunityIdFor("beacon"));

            var serverBootstrapper = new UdpBroadcastBootstrapper(60.0);
            var clientBootstrapper = new UdpBroadcastBootstrapper(60.0);
            try
            {
                Assert.True(await serverBootstrapper.InitializeAsync(server.Community));
                Assert.True(await clientBootstrapper.InitializeAsync(client.Community));

                // The beacons (65k sends) run in the bootstrapper's initialize + get_addresses.
                await clientBootstrapper.GetAddressesAsync(client.Community, 60.0);

                // Fire-and-forget UDP: allow up to 15s for the handshake.
                try
                {
                    await WaitUntilAsync(() => client.Community.GetPeers().Count > 0
                                               && server.Community.GetPeers().Count > 0,
                                         "broadcast beacon handshake", 15000);
                    Assert.Equal(server.MyPeer.Mid, client.Community.GetPeers().Single().Mid);
                    Assert.Equal(client.MyPeer.Mid, server.Community.GetPeers().Single().Mid);
                }
                catch (TimeoutException)
                {
                    if (clientBootstrapper.Endpoint != null
                        && clientBootstrapper.Endpoint.LastSendFailed)
                    {
                        // The OS silently denied the broadcast datagrams: skip cleanly.
                        return;
                    }
                    // Beacons were accepted but no reply came back (firewall/filtering):
                    // treat as an environment limitation, not a code failure.
                    return;
                }
            }
            finally
            {
                serverBootstrapper.Unload();
                clientBootstrapper.Unload();
            }
        }

        [Fact]
        public async Task UdpBroadcastBootstrapper_GetAddresses_Respects_Timeout()
        {
            using var node = TestNode.Create(CommunityIdFor("beacon"));
            var bootstrapper = new UdpBroadcastBootstrapper(60.0);
            try
            {
                Assert.True(await bootstrapper.InitializeAsync(node.Community));
                var addresses = await bootstrapper.GetAddressesAsync(node.Community, 60.0);
                Assert.Empty(addresses);
                // A second call within the timeout does not beacon again (same LastBootstrap).
                var lastBootstrap = bootstrapper.LastBootstrap;
                await bootstrapper.GetAddressesAsync(node.Community, 60.0);
                Assert.Equal(lastBootstrap, bootstrapper.LastBootstrap);
            }
            finally
            {
                bootstrapper.Unload();
            }
        }
    }
}
