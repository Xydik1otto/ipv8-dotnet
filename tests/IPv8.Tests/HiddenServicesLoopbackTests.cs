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
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// D3: hidden-services end-to-end over the real loopback with a REAL DHT. The seeder creates an
    /// introduction point and announces it through its DhtDiscoveryCommunity (DhtCommunityProvider
    /// adapter), the downloader performs do_peer_discovery, the peers-request is answered by the
    /// exit node doing a real DHT lookup, the e2e rendezvous circuits get created and linked, and
    /// raw data flows in both directions through the (2-hop) circuits while every relayed wire
    /// packet stays encrypted.
    /// </summary>
    public class HiddenServicesLoopbackTests : IDisposable
    {
        /// <summary>Sniffs FINAL outgoing wire packets (post encryption) for the wire-level assertions.</summary>
        public sealed class SniffingCryptoEndpoint : PythonCryptoEndpoint
        {
            public readonly List<byte[]> SentWires = new List<byte[]>();

            public SniffingCryptoEndpoint(Endpoint endpoint) : base(endpoint)
            {
            }

            protected override void OnWireSent(byte[] packet)
            {
                lock (SentWires)
                {
                    SentWires.Add(packet);
                }
            }
        }

        private sealed class TestHiddenCommunity : HiddenTunnelCommunity
        {
            public SniffingCryptoEndpoint Sniffer { get; private set; }

            public readonly List<(Circuit Circuit, Address Origin, byte[] Data)> RawData =
                new List<(Circuit, Address, byte[])>();

            public TestHiddenCommunity(HiddenTunnelSettings settings) : base(settings)
            {
            }

            protected override ICryptoEndpoint CreateCryptoEndpoint(Endpoint endpoint)
            {
                Sniffer = new SniffingCryptoEndpoint(endpoint);
                return Sniffer;
            }

            public override void OnRawData(Circuit circuit, Address origin, byte[] data)
            {
                lock (RawData)
                {
                    RawData.Add((circuit, origin, data));
                }
            }
        }

        private sealed class HsNode : IDisposable
        {
            public UDPEndpoint Endpoint;
            public Peer MyPeer;
            public DhtDiscoveryCommunity Dht;
            public TestHiddenCommunity Community;

            public static HsNode Create(HashSet<int> peerFlags)
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));

                // A real DHT overlay rides on the same UDP endpoint as the tunnel community.
                var dht = new DhtDiscoveryCommunity(
                    new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, endpoint, new Network()));
                dht.MyEstimatedLan = address;
                dht.MyEstimatedWan = address;

                var settings = new HiddenTunnelSettings
                {
                    MyPeer = myPeer,
                    Endpoint = endpoint,
                    Network = new Network(),
                    PeerFlags = peerFlags,
                    RemoveTunnelDelay = 0,
                    DhtProvider = new TunnelDhtProvider(new DhtCommunityProvider(dht, address.Port))
                };
                var community = new TestHiddenCommunity(settings);
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new HsNode { Endpoint = endpoint, MyPeer = myPeer, Dht = dht, Community = community };
            }

            public Address Address => Endpoint.GetAddress();

            /// <summary>The DHT routing-table node for the given other node, if present.</summary>
            public DhtNode RoutingNodeFor(HsNode other)
            {
                var nodeId = DhtRouting.CalcNodeId(other.Address, other.MyPeer.Mid);
                return Dht.RoutingTables.TryGetValue(AddressType.Udpv4, out var routingTable)
                    ? routingTable.Get(nodeId)
                    : null;
            }

            public void Dispose()
            {
                Community.Unload();
                Dht.Unload();
                Endpoint.Close();
            }
        }

        private readonly List<HsNode> _nodes = new List<HsNode>();

        private HsNode MakeNode(HashSet<int> peerFlags)
        {
            var node = HsNode.Create(peerFlags);
            _nodes.Add(node);
            return node;
        }

        private static readonly HashSet<int> RelayExitFlags =
            new HashSet<int> { Tunnel.PeerFlagRelay, Tunnel.PeerFlagExitBt, Tunnel.PeerFlagSpeedTest };

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 15000)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(10);
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
        public async Task Real_Dht_Lookup_With_Counterparty_E2e_Data_Flows_Encrypted()
        {
            // Node roles (mirroring py's test_dht_lookup_with_counterparty):
            //   A = downloader, B = the deterministic introduction point, C = seeder,
            //   E = an extra relay/exit so the seeder's 2-hop intro circuit has a first hop
            //       that differs from the required exit. A deliberately has NO relay flag so the
            //       rendezvous point can never land on the downloader itself.
            var a = MakeNode(new HashSet<int> { Tunnel.PeerFlagSpeedTest });
            var b = MakeNode(RelayExitFlags);
            var c = MakeNode(new HashSet<int> { Tunnel.PeerFlagSpeedTest });
            var e = MakeNode(RelayExitFlags);
            var all = new[] { a, b, c, e };
            var service = new byte[20]; // all zeros, like py's b"0" * 20

            // Walk every pair on both the tunnel and the DHT overlays.
            for (var i = 0; i < all.Length; i++)
            {
                for (var j = i + 1; j < all.Length; j++)
                {
                    all[i].Community.WalkTo(all[j].Address);
                    all[j].Community.WalkTo(all[i].Address);
                    all[i].Dht.WalkTo(all[j].Address);
                    all[j].Dht.WalkTo(all[i].Address);
                }
            }
            await WaitUntilAsync(() =>
            {
                foreach (var node in all)
                {
                    if (node.Community.GetPeers().Count() != all.Length - 1)
                    {
                        return false;
                    }
                    foreach (var other in all)
                    {
                        if (!ReferenceEquals(other, node) && node.RoutingNodeFor(other) == null)
                        {
                            return false;
                        }
                    }
                }
                return true;
            }, "all tunnel peers verified and all DHT routing tables populated");

            // The seeder joins the swarm and creates an introduction point pinned to node B.
            c.Community.JoinSwarm(service, 1);
            var bPeer = new Peer(b.MyPeer.PublicKey, b.Address);
            await c.Community.CreateIntroductionPointAsync(service, bPeer);

            var seederPk = c.Community.Swarms[service].SeederSk.Pub().KeyToBin();
            await WaitUntilAsync(() => b.Community.IntroPointFor.ContainsKey(seederPk),
                                 "the intro point landed on node B");
            Assert.Equal(2, c.Community.FindCircuits(Tunnel.CircuitTypeIpSeeder).Single().Hops.Count);
            Assert.Null(b.Community.LastHandlerException);

            // The intro announcement went through the REAL DHT store on B.
            await WaitUntilAsync(() => b.Dht.Storages.TryGetValue(AddressType.Udpv4, out var storage)
                                       && storage.Get(service).Count > 0,
                                 "B announced the introduction point on the DHT");

            // The downloader gets a dedicated 1-hop data circuit (py assign_exit_node + build_tunnels(1)).
            a.Community.CreateCircuit(1);
            await WaitUntilAsync(() => a.Community.FindCircuits(Tunnel.CircuitTypeData,
                                       state: null, hops: 1).Count == 1
                                       && a.Community.FindCircuits(Tunnel.CircuitTypeData,
                                       state: null, hops: 1)[0].State
                                          == Tunnel.CircuitStateReady,
                                 "the downloader's 1-hop data circuit is READY");

            // The e2e callback fires once the circuits are linked.
            var e2eAddress = new TaskCompletionSource<Address>(TaskCreationOptions.RunContinuationsAsynchronously);
            a.Community.JoinSwarm(service, 1, address => e2eAddress.TrySetResult(address), seeding: false);

            await a.Community.DhtLookupAsync(service);
            await a.Community.DoPeerDiscoveryAsync();
            await WaitUntilAsync(() => e2eAddress.Task.IsCompleted,
                                 "the e2e link callback fired on the downloader");

            var callbackAddress = e2eAddress.Task.Result;
            Assert.Equal(Tunnel.CircuitIdPort, callbackAddress.Port);

            // ip_to_circuit_id <-> circuit_id_to_ip roundtrip on the real LINK flow.
            var aRp = a.Community.FindCircuits(Tunnel.CircuitTypeRpDownloader).Single();
            Assert.True(aRp.E2e, "the downloader's rendezvous circuit carries the e2e flag");
            Assert.Equal(2, aRp.Hops.Count);
            Assert.Equal(HiddenTunnelCommunity.IpToCircuitId(callbackAddress.Host), aRp.CircuitId);
            Assert.True(callbackAddress.Host.SequenceEqual(
                HiddenTunnelCommunity.CircuitIdToIp(aRp.CircuitId)));

            // The rendezvous node relays both e2e circuits into each other (the real LINK flow).
            // py's get_e2e_circuit_path walks hop-by-hop: every relay rewrites circuit ids, so the
            // relay keys are each node's LOCAL ids. In py only on_linked_e2e (the downloader) sets
            // circuit.e2e — the seeder's RP circuit never carries the flag.
            var visited = new List<HsNode> { a };
            var relayHops = new List<(HsNode Node, long IncomingId, RelayRoute Route)>();
            var curId = aRp.CircuitId;
            var curAddr = aRp.Hop.Address;
            while (true)
            {
                var nextNode = all.Single(n => n.Address.Equals(curAddr));
                if (visited.Contains(nextNode))
                {
                    break;
                }
                visited.Add(nextNode);
                if (!nextNode.Community.RelayFromTo.TryGetValue(curId, out var route))
                {
                    break; // the end of the e2e circuit (the seeder)
                }
                relayHops.Add((nextNode, curId, route));
                curId = route.CircuitId;
                curAddr = route.Hop.Address;
            }
            Assert.Equal(4, visited.Count);
            Assert.Same(c, visited[3]);
            Assert.Equal(2, relayHops.Count);
            // The RP node's two relay routes point at each other (py on_link_e2e mutual mapping).
            var rpHop = relayHops[1];
            Assert.Equal(rpHop.IncomingId,
                (long)rpHop.Node.Community.RelayFromTo[rpHop.Route.CircuitId].CircuitId);

            // The downloader connected to the discovered introduction point (DHT source).
            var aSwarm = a.Community.Swarms[service];
            Assert.Contains(aSwarm.IntroPoints, ip => ip.Source == Tunnel.PeerSourceDht
                && ip.Peer.Address.Equals(b.Address));

            // Raw data travels both ways through the linked circuits.
            var cRp = c.Community.FindCircuits(Tunnel.CircuitTypeRpSeeder).Single();
            var downMarker = Encoding.UTF8.GetBytes("DOWNLOADER-TO-SEEDER " + Guid.NewGuid());
            var seedMarker = Encoding.UTF8.GetBytes("SEEDER-TO-DOWNLOADER " + Guid.NewGuid());
            a.Community.SendData(aRp.Hop.Address, aRp.CircuitId, Address.Zero, Address.Zero, downMarker);
            c.Community.SendData(cRp.Hop.Address, cRp.CircuitId, Address.Zero, Address.Zero, seedMarker);
            await WaitUntilAsync(() => c.Community.RawData.Count > 0 && a.Community.RawData.Count > 0,
                                 "raw data flowed through the e2e circuits in both directions");
            Assert.Contains(c.Community.RawData, r => r.Data.SequenceEqual(downMarker));
            Assert.Contains(a.Community.RawData, r => r.Data.SequenceEqual(seedMarker));

            // Wire encryption: no node ever put the raw markers on the wire in plaintext.
            foreach (var node in all)
            {
                byte[][] wires;
                lock (node.Community.Sniffer.SentWires)
                {
                    wires = node.Community.Sniffer.SentWires.ToArray();
                }
                Assert.NotEmpty(wires);
                foreach (var wire in wires)
                {
                    Assert.DoesNotContain(downMarker, b => StartsWith(wire, new[] { b }));
                    Assert.DoesNotContain(seedMarker, b => StartsWith(wire, new[] { b }));
                }
            }
            foreach (var node in all)
            {
                Assert.Null(node.Community.LastHandlerException);
                Assert.Null(node.Dht.LastHandlerException);
            }

            // Leaving the swarm tears down the hidden circuits on the downloader.
            a.Community.LeaveSwarm(service);
            Assert.DoesNotContain(service, a.Community.Swarms.Keys);
            await WaitUntilAsync(
                () => a.Community.FindCircuits(Tunnel.CircuitTypeIpSeeder).Count == 0
                      && a.Community.FindCircuits(Tunnel.CircuitTypeRpDownloader).Count == 0,
                "the downloader's hidden circuits are gone after leaving the swarm");
        }

        private static bool StartsWith(byte[] haystack, byte[] needle)
        {
            if (haystack.Length < needle.Length)
            {
                return false;
            }
            for (var i = 0; i < needle.Length; i++)
            {
                if (haystack[i] != needle[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
