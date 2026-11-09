// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// D1: hidden-service models + caches — Swarm bookkeeping (intro points deduped by
    /// (peer, seeder_pk), connections, transfer history, lookup policy), RendezvousPoint state
    /// and the five HS request caches (identifiers + on_timeout behaviors).
    /// </summary>
    public class HiddenSwarmTests : IDisposable
    {
        /// <summary>TunnelCommunity with recorded RemoveCircuit calls and an owned swarms map.</summary>
        private sealed class TestTunnelCommunity : TunnelCommunity, IHiddenSwarmRegistry
        {
            public readonly List<long> RemovedCircuits = new List<long>();
            public readonly List<long> RemovedExitSockets = new List<long>();
            public Dictionary<byte[], Swarm> Swarms { get; } = new Dictionary<byte[], Swarm>(new ByteArrayEqualityComparer());

            public TestTunnelCommunity(TunnelSettings settings) : base(settings)
            {
            }

            public override void RemoveCircuit(long circuitId, string additionalInfo = "",
                                               bool removeNow = false, object destroy = null)
            {
                lock (RemovedCircuits)
                {
                    RemovedCircuits.Add(circuitId);
                }
            }

            public override void RemoveExitSocket(long circuitId, string additionalInfo = "",
                                                  bool removeNow = false, object destroy = null)
            {
                lock (RemovedExitSockets)
                {
                    RemovedExitSockets.Add(circuitId);
                }
            }
        }

        private sealed class Node : IDisposable
        {
            public UDPEndpoint Endpoint;
            public TestTunnelCommunity Community;

            public static Node Create()
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var community = new TestTunnelCommunity(new TunnelSettings
                {
                    MyPeer = myPeer,
                    Endpoint = endpoint,
                    Network = new Network()
                });
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new Node { Endpoint = endpoint, Community = community };
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

        public void Dispose()
        {
            foreach (var node in _nodes)
            {
                node.Dispose();
            }
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 5000)
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

        private static IntroductionPoint MakeIp(string host, int port, string seederPkHex = "aa")
        {
            var peer = new Peer(ECCrypto.Default.GenerateKey("curve25519"), Address.Udpv4(host, port));
            return new IntroductionPoint(peer, Util.Unhex(seederPkHex.PadRight(64, '0')), Tunnel.PeerSourceDht);
        }

        // ------------------------------------------------------------------
        // Swarm bookkeeping (tunnel.py:294-457)
        // ------------------------------------------------------------------

        [Fact]
        public void Swarm_AddIntroPoint_Dedups_By_Peer_And_SeederPk()
        {
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()));
            var ipA = MakeIp("127.0.0.1", 1000);
            var returnedA = swarm.AddIntroPoint(ipA);
            Assert.Same(ipA, returnedA);

            // Same (peer, seeder_pk): no duplicate, last_seen refreshed to NOW (not to the
            // new instance's timestamp), and the OLD instance is returned.
            var originalLastSeen = ipA.LastSeen;
            var sameIdentity = new IntroductionPoint(ipA.Peer, ipA.SeederPk, Tunnel.PeerSourcePex,
                                                     Util.NowEpoch() + 5);
            var returnedB = swarm.AddIntroPoint(sameIdentity);
            Assert.Same(ipA, returnedB);
            Assert.Single(swarm.IntroPoints);
            Assert.True(ipA.LastSeen >= originalLastSeen,
                        "last_seen must be refreshed to at least the original time");
            Assert.NotEqual(sameIdentity.LastSeen, ipA.LastSeen, precision: 3);

            // Different seeder_pk: a second entry.
            var otherSeeder = new IntroductionPoint(ipA.Peer, Util.Unhex(new string('2', 32)));
            swarm.AddIntroPoint(otherSeeder);
            Assert.Equal(2, swarm.IntroPoints.Count);

            // Different peer: a third entry.
            var otherPeer = new IntroductionPoint(
                new Peer(ECCrypto.Default.GenerateKey("curve25519"), Address.Udpv4("127.0.0.1", 1000)),
                ipA.SeederPk);
            swarm.AddIntroPoint(otherPeer);
            Assert.Equal(3, swarm.IntroPoints.Count);
        }

        [Fact]
        public void Swarm_RemoveIntroPoint_And_Old_Intro_Point_Cleanup()
        {
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()),
                                  maxIpAge: 100.0);
            var fresh = MakeIp("127.0.0.1", 1000);
            var stale = MakeIp("127.0.0.1", 1001);
            stale.LastSeen = Util.NowEpoch() - 1000.0; // way past max_ip_age
            swarm.AddIntroPoint(fresh);
            swarm.AddIntroPoint(stale);

            swarm.RemoveOldIntroPoints();
            Assert.Single(swarm.IntroPoints);
            Assert.Same(fresh, swarm.IntroPoints[0]);

            // A stale intro point that is USED by a ready e2e circuit is kept.
            var staleButUsed = MakeIp("127.0.0.1", 1002);
            staleButUsed.LastSeen = Util.NowEpoch() - 1000.0;
            swarm.AddIntroPoint(staleButUsed);
            var circuit = new Circuit(1, 1, Tunnel.CircuitTypeRpDownloader);
            circuit.AddHop(new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519")),
                                   TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32))));
            circuit.E2e = true;
            swarm.AddConnection(circuit, staleButUsed);
            swarm.RemoveOldIntroPoints();
            Assert.Contains(swarm.IntroPoints, ip => ip == staleButUsed || ip.Equals(staleButUsed));

            // Explicit removal always works.
            swarm.RemoveIntroPoint(staleButUsed);
            Assert.DoesNotContain(swarm.IntroPoints, ip => ip.Equals(staleButUsed));
        }

        [Fact]
        public void Swarm_Connections_Bookkeeping_And_Transfer_History()
        {
            var seederSk = ECCrypto.Default.GenerateKey("curve25519");
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()),
                                  seederSk: (PrivateKey)seederSk);
            Assert.True(swarm.Seeding);
            Assert.False(new Swarm(Util.Unhex("11"), 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>())).Seeding);

            var ip = MakeIp("127.0.0.1", 1000);

            // A pending e2e circuit (2 hops needed, 1 present → EXTENDING): not active yet.
            var pending = new Circuit(7, 2, Tunnel.CircuitTypeRpDownloader);
            pending.AddHop(new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519")),
                                   TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32))));
            pending.E2e = true;
            swarm.AddConnection(pending, ip);
            Assert.True(swarm.HasConnection(ip.SeederPk));
            Assert.False(swarm.HasConnection(Util.Unhex(new string('9', 32))));
            // Duplicate circuit id: ignored.
            swarm.AddConnection(pending, ip);
            Assert.Single(swarm.Connections);
            Assert.Equal(0, swarm.GetNumConnections());
            Assert.Equal(1, swarm.GetNumConnectionsIncomplete());

            // A READY, non-e2e circuit also does not count (py filters on e2e).
            var plainCircuit = new Circuit(8, 1, Tunnel.CircuitTypeData);
            plainCircuit.AddHop(new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519")),
                                        TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32))));
            Assert.Equal(Tunnel.CircuitStateReady, plainCircuit.State);
            swarm.AddConnection(plainCircuit, ip);
            Assert.Equal(0, swarm.GetNumConnections());
            Assert.Equal(2, swarm.GetNumConnectionsIncomplete());

            // Completing the pending e2e circuit makes it active.
            pending.AddHop(new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519")),
                                   TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32))));
            Assert.Equal(Tunnel.CircuitStateReady, pending.State);
            Assert.Equal(1, swarm.GetNumConnections());

            Assert.Equal(1, swarm.GetNumSeeders());
            Assert.Equal(0, swarm.GetTotalUp());
            Assert.Equal(0, swarm.GetTotalDown());

            pending.BytesUp = 111;
            pending.BytesDown = 222;
            Assert.True(swarm.RemoveConnection(pending));
            Assert.False(swarm.RemoveConnection(pending));
            Assert.Equal(111, swarm.TransferHistory[0]);
            Assert.Equal(222, swarm.TransferHistory[1]);
            Assert.Equal(111, swarm.GetTotalUp());
            Assert.Equal(222, swarm.GetTotalDown());
            // The plain (non-e2e) connection still holds the intro point...
            Assert.True(swarm.HasConnection(ip.SeederPk));
            Assert.True(swarm.RemoveConnection(plainCircuit));
            // ...until every connection for it is gone.
            Assert.False(swarm.HasConnection(ip.SeederPk));
        }

        [Fact]
        public void Swarm_GetNumSeeders_Counts_Distinct_Keys()
        {
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()));
            swarm.AddIntroPoint(MakeIp("127.0.0.1", 1000, "aa"));
            swarm.AddIntroPoint(MakeIp("127.0.0.1", 1001, "aa")); // same seeder
            swarm.AddIntroPoint(MakeIp("127.0.0.1", 1002, "bb"));
            Assert.Equal(2, swarm.GetNumSeeders());
        }

        // ------------------------------------------------------------------
        // Swarm.lookup policy (tunnel.py:421-441)
        // ------------------------------------------------------------------

        [Fact]
        public async Task Swarm_Lookup_Manual_Target_Goes_Straight_To_LookupFunc()
        {
            var calls = new List<IntroductionPoint>();
            var target = MakeIp("127.0.0.1", 1000);
            var swarm = new Swarm(Util.Unhex("11"), 2, (_, t, hops) =>
            {
                calls.Add(t);
                Assert.Equal(2, hops);
                return Task.FromResult(new List<IntroductionPoint> { target });
            });

            var result = await swarm.Lookup(target);
            Assert.Single(calls);
            Assert.Same(target, calls[0]);
            Assert.Single(result);
            // Manual lookups do not touch the time bookkeeping.
            Assert.Equal(0.0, swarm.LastLookup, precision: 3);
        }

        [Fact]
        public async Task Swarm_Lookup_Dht_When_No_Intro_Points_After_Max_Interval()
        {
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, _, _) =>
                Task.FromResult(new List<IntroductionPoint> { MakeIp("127.0.0.1", 1000) }),
                minDhtLookupInterval: 300.0, maxDhtLookupInterval: 120.0);

            // Fresh swarm, nothing responded yet, but the max interval has not elapsed:
            // the lookup is SKIPPED (py returns None).
            swarm.LastDhtResponse = Util.NowEpoch();
            var result = await swarm.Lookup();
            Assert.Null(result);

            // Past the max interval (or past the min interval): a DHT lookup happens.
            swarm.LastDhtResponse = Util.NowEpoch() - 1000.0;
            result = await swarm.Lookup();
            Assert.NotNull(result);
            Assert.Single(result);
            Assert.True(result[0].Source == Tunnel.PeerSourceDht);
            // A DHT response refreshes last_dht_response.
            Assert.True(swarm.LastDhtResponse > Util.NowEpoch() - 5.0);
        }

        [Fact]
        public async Task Swarm_Lookup_Pex_Targets_Every_Known_Intro_Point()
        {
            var targets = new List<IntroductionPoint>();
            var ip1 = MakeIp("127.0.0.1", 1000);
            var ip2 = MakeIp("127.0.0.1", 1001);
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, target, _) =>
            {
                targets.Add(target);
                if (target.Equals(ip2))
                {
                    // py gather(..., return_exceptions=True): failures are swallowed.
                    throw new InvalidOperationException("pex failure");
                }
                return Task.FromResult(new List<IntroductionPoint> { MakeIp("127.0.0.1", 2000, "cc") });
            },
            minDhtLookupInterval: 1.0, maxDhtLookupInterval: 1.0);

            swarm.AddIntroPoint(ip1);
            swarm.AddIntroPoint(ip2);
            // Fresh DHT response → the PEX path is taken (within min_dht_lookup_interval).
            swarm.LastDhtResponse = Util.NowEpoch();

            var result = await swarm.Lookup();
            Assert.Equal(2, targets.Count);
            Assert.Equal(new List<IntroductionPoint> { ip1, ip2 }, targets);
            Assert.Single(result);
        }

        [Fact]
        public async Task Swarm_Lookup_Min_Interval_Triggers_Dht_Even_With_Intro_Points()
        {
            var calledWith = new List<IntroductionPoint>();
            var swarm = new Swarm(Util.Unhex("11"), 1, (_, target, _) =>
            {
                calledWith.Add(target);
                return Task.FromResult(new List<IntroductionPoint>());
            });
            swarm.AddIntroPoint(MakeIp("127.0.0.1", 1000));
            // No recent DHT response and older than min_dht_lookup_interval → DHT (target null).
            swarm.LastDhtResponse = Util.NowEpoch() - 400.0;

            await swarm.Lookup();
            Assert.Single(calledWith);
            Assert.Null(calledWith[0]);
        }

        // ------------------------------------------------------------------
        // RendezvousPoint state (tunnel.py:239-252)
        // ------------------------------------------------------------------

        [Fact]
        public void RendezvousPoint_Ready_Future_Resolves()
        {
            var circuit = new Circuit(1, 1);
            var rp = new RendezvousPoint(circuit, Util.Unhex(new string('a', 40)));
            Assert.Same(circuit, rp.Circuit);
            Assert.Equal(Address.Zero, rp.Address);
            Assert.False(rp.Ready.Task.IsCompleted);

            rp.Address = Address.Udpv4("127.0.0.1", 2048);
            rp.Ready.TrySetResult(rp);
            Assert.True(rp.Ready.Task.IsCompleted);
            Assert.Same(rp, rp.Ready.Task.Result);

            // The timeout path resolves to null.
            var rp2 = new RendezvousPoint(circuit, Util.Unhex(new string('b', 40)));
            rp2.Ready.TrySetResult(null);
            Assert.True(rp2.Ready.Task.IsCompleted);
            Assert.Null(rp2.Ready.Task.Result);
        }

        // ------------------------------------------------------------------
        // HS caches (caches.py HS section)
        // ------------------------------------------------------------------

        [Fact]
        public void HS_Caches_Register_With_Distinct_16Bit_Identifiers()
        {
            var node = MakeNode();
            var community = node.Community;
            var circuit = new Circuit(1, 1);

            using (community.RequestCache.Passthrough(10.0))
            {
                var ipCache = new IpRequestCache(community, circuit);
                var rpCache = new RpRequestCache(community, new RendezvousPoint(circuit, Util.RandomBytes(20)));
                var peersCache = new PeersRequestCache(community, circuit, Util.Unhex("11"), null);
                var e2eCache = new E2eRequestCache(community, Util.Unhex("11"),
                                                   new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519"))), null);
                var linkCache = new LinkRequestCache(community, circuit, Util.Unhex("11"),
                                                     TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32)));

                Assert.All(new NumberCache[] { ipCache, rpCache, peersCache, e2eCache, linkCache },
                           cache =>
                           {
                               // Cache numbers are C#-32-bit-safe, but the wire identifier is an
                               // "H" (u16): the random identifiers must fit it exactly.
                               Assert.InRange(cache.Number, 0, 65535);
                           });
                Assert.All(new NumberCache[] { ipCache, rpCache, peersCache, e2eCache, linkCache },
                           cache => Assert.NotNull(community.RequestCache.Add(cache)));
                Assert.All(new NumberCache[] { ipCache, rpCache, peersCache, e2eCache, linkCache },
                           cache =>
                           {
                               Assert.True(community.RequestCache.Has(cache.Prefix, cache.Number));
                           });
                Assert.Equal("establish-intro", ipCache.Prefix);
                Assert.Equal("establish-rendezvous", rpCache.Prefix);
                Assert.Equal("peers-request", peersCache.Prefix);
                Assert.Equal("e2e-request", e2eCache.Prefix);
                Assert.Equal("link-request", linkCache.Prefix);

                Assert.Same(ipCache, community.RequestCache.Pop(IpRequestCache.Name, ipCache.Number));
                Assert.Same(rpCache, community.RequestCache.Pop(RpRequestCache.Name, rpCache.Number));
                Assert.Same(peersCache, community.RequestCache.Pop(PeersRequestCache.Name, peersCache.Number));
                Assert.Same(e2eCache, community.RequestCache.Pop(E2eRequestCache.Name, e2eCache.Number));
                Assert.Same(linkCache, community.RequestCache.Pop(LinkRequestCache.Name, linkCache.Number));
            }
        }

        [Fact]
        public async Task IpRequestCache_Timeout_Removes_The_Circuit()
        {
            var node = MakeNode();
            var community = node.Community;
            var circuit = new Circuit(42, 1);
            var cache = new IpRequestCache(community, circuit);
            using (community.RequestCache.Passthrough(0.05))
            {
                Assert.NotNull(community.RequestCache.Add(cache));
            }

            await WaitUntilAsync(() =>
            {
                lock (community.RemovedCircuits)
                {
                    return community.RemovedCircuits.Contains(42L);
                }
            }, "IPRequestCache timeout removed the circuit");
        }

        [Fact]
        public async Task RpRequestCache_Timeout_Fails_The_Point_And_Removes_The_Circuit()
        {
            var node = MakeNode();
            var community = node.Community;
            var circuit = new Circuit(43, 1);
            var rp = new RendezvousPoint(circuit, Util.RandomBytes(20));
            var cache = new RpRequestCache(community, rp);
            using (community.RequestCache.Passthrough(0.05))
            {
                Assert.NotNull(community.RequestCache.Add(cache));
            }

            var ready = await rp.Ready.Task;
            Assert.Null(ready);
            await WaitUntilAsync(() =>
            {
                lock (community.RemovedCircuits)
                {
                    return community.RemovedCircuits.Contains(43L);
                }
            }, "RPRequestCache timeout removed the circuit");
        }

        [Fact]
        public async Task PeersRequestCache_Timeout_Drops_The_Target_From_The_Swarm()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('7', 40));
            var swarm = new Swarm(infoHash, 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()));
            community.Swarms[infoHash] = swarm;

            var target = MakeIp("127.0.0.1", 1000);
            swarm.AddIntroPoint(target);
            var circuit = new Circuit(44, 1);
            var cache = new PeersRequestCache(community, circuit, infoHash, target);
            using (community.RequestCache.Passthrough(0.05))
            {
                Assert.NotNull(community.RequestCache.Add(cache));
            }

            await WaitUntilAsync(() => swarm.IntroPoints.Count == 0,
                                 "PeersRequestCache timeout dropped the unresponsive intro point");
            // The managed future fails with the py RuntimeError-equivalent.
            await Assert.ThrowsAnyAsync<Exception>(() => cache.Future.Task);
        }

        [Fact]
        public async Task PeersRequestCache_Timeout_Keeps_Target_Without_Swarm()
        {
            var node = MakeNode();
            var community = node.Community;
            var target = MakeIp("127.0.0.1", 1000);
            var cache = new PeersRequestCache(community, new Circuit(45, 1), Util.Unhex(new string('8', 40)), target);
            using (community.RequestCache.Passthrough(0.05))
            {
                Assert.NotNull(community.RequestCache.Add(cache));
            }
            // No swarm registered: the timeout must not throw into the task manager.
            await Task.Delay(150);
        }

        [Fact]
        public void E2e_And_Link_Caches_Carry_Their_Flow_State()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('9', 40));
            var introPoint = MakeIp("127.0.0.1", 1000);
            var hop = new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519")));
            var keys = TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32));

            var e2eCache = new E2eRequestCache(community, infoHash, hop, introPoint);
            Assert.Equal(infoHash, e2eCache.InfoHash);
            Assert.Same(hop, e2eCache.Hop);
            Assert.Same(introPoint, e2eCache.IntroPoint);

            var circuit = new Circuit(46, 1);
            var linkCache = new LinkRequestCache(community, circuit, infoHash, keys);
            Assert.Same(circuit, linkCache.Circuit);
            Assert.Equal(infoHash, linkCache.InfoHash);
            Assert.Same(keys, linkCache.HsSessionKeys);
        }
    }
}
