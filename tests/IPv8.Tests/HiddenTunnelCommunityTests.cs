// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
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
    /// D2: HiddenTunnelCommunity unit coverage — handler registration, swarm join/leave,
    /// the byte-exact "!I" IP↔circuit-id conversion, circuit-type hop counting, the peers
    /// request/response handlers, the intro/rendezvous/link cell handlers and the swarm
    /// bookkeeping hooks. The full E2E flow is exercised in the hidden-services loopback test.
    /// </summary>
    public class HiddenTunnelCommunityTests : IDisposable
    {
        /// <summary>HiddenTunnelCommunity that records circuit creation and raw data.</summary>
        private sealed class TestHiddenCommunity : HiddenTunnelCommunity
        {
            public readonly List<(int GoalHops, string CType, byte[] InfoHash, Peer RequiredExit)> Created =
                new List<(int, string, byte[], Peer)>();

            public readonly List<(Circuit Circuit, Address Origin, byte[] Data)> RawData =
                new List<(Circuit, Address, byte[])>();

            /// <summary>Optional stub for the peers-request pipeline (py monkeypatch).</summary>
            public Func<IntroductionPoint, Task<List<IntroductionPoint>>> StubbedPeersResponse;

            public TestHiddenCommunity(HiddenTunnelSettings settings) : base(settings)
            {
            }

            protected override Circuit CreateCircuitImpl(int goalHops, string ctype = Tunnel.CircuitTypeData,
                                                         int[] exitFlags = null, Peer requiredExit = null,
                                                         byte[] infoHash = null)
            {
                lock (Created)
                {
                    Created.Add((goalHops, ctype, infoHash, requiredExit));
                }
                return null;
            }

            public override Task<List<IntroductionPoint>> SendPeersRequest(byte[] infoHash,
                                                                           IntroductionPoint target, int hops)
            {
                if (StubbedPeersResponse != null)
                {
                    return StubbedPeersResponse(target);
                }
                return base.SendPeersRequest(infoHash, target, hops);
            }

            public override void OnRawData(Circuit circuit, Address origin, byte[] data)
            {
                lock (RawData)
                {
                    RawData.Add((circuit, origin, data));
                }
            }
        }

        private sealed class Node : IDisposable
        {
            public UDPEndpoint Endpoint;
            public TestHiddenCommunity Community;

            public static Node Create(Action<HiddenTunnelSettings> configure = null)
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var settings = new HiddenTunnelSettings
                {
                    MyPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519")),
                    Endpoint = endpoint,
                    Network = new Network()
                };
                configure?.Invoke(settings);
                var community = new TestHiddenCommunity(settings);
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new Node { Endpoint = endpoint, Community = community };
            }

            public Address Address => Endpoint.GetAddress();

            public void Dispose()
            {
                Community.Unload();
                Endpoint.Close();
            }
        }

        private readonly List<Node> _nodes = new List<Node>();

        private Node MakeNode(Action<HiddenTunnelSettings> configure = null)
        {
            var node = Node.Create(configure);
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

        /// <summary>A real session-keys hop for manually inserted circuits/exit sockets.</summary>
        private static Hop MakeHop(int portSuffix)
        {
            return new Hop(new Peer(ECCrypto.Default.GenerateKey("curve25519"),
                                   Address.Udpv4("127.0.0.1", 10000 + portSuffix)),
                           TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32)));
        }

        /// <summary>Pack a full tunnel packet: prefix + msg_id + serialized payload.</summary>
        private static byte[] PackPacket(TunnelCommunity community, int msgId, Payload payload)
        {
            return Util.Concat(community.GetPrefix(),
                               new[] { (byte)msgId },
                               community.Serializer.PackSerializable(payload));
        }

        private static IntroductionPoint MakeIp(string host, int port)
        {
            return new IntroductionPoint(new Peer(ECCrypto.Default.GenerateKey("curve25519"),
                                                  Address.Udpv4(host, port)),
                                         new Peer(ECCrypto.Default.GenerateKey("curve25519")).PublicKey.KeyToBin());
        }

        // ------------------------------------------------------------------
        // Structure: handlers + settings
        // ------------------------------------------------------------------

        [Fact]
        public void All_Hidden_Cell_And_Socket_Handlers_Are_Registered()
        {
            var node = MakeNode();
            var handlers = node.Community.DecodeMapPrivate;

            Assert.All(new[]
            {
                EstablishIntroPayload.MsgId, IntroEstablishedPayload.MsgId,
                EstablishRendezvousPayload.MsgId, RendezvousEstablishedPayload.MsgId,
                CreateE2EPayload.MsgId, CreatedE2EPayload.MsgId,
                LinkE2EPayload.MsgId, LinkedE2EPayload.MsgId,
                PeersRequestPayload.MsgId, PeersResponsePayload.MsgId
            }, msgId => Assert.True(handlers.ContainsKey(msgId), $"missing cell handler for {msgId}"));
        }

        [Fact]
        public void Join_Leave_Swarm_Bookkeeping()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('1', 40));
            var called = new List<Address>();

            community.JoinSwarm(infoHash, 2, callback: called.Add, seeding: true);
            Assert.True(community.Swarms.ContainsKey(infoHash));
            Assert.True(community.Swarms[infoHash].Seeding, "seeding swarm carries a seeder key");
            Assert.Equal(2, community.Swarms[infoHash].Hops);

            // Joining again replaces the swarm (py drops the pre-existing connections).
            var first = community.Swarms[infoHash];
            community.JoinSwarm(infoHash, 3, seeding: false);
            Assert.NotSame(first, community.Swarms[infoHash]);
            Assert.False(community.Swarms[infoHash].Seeding);
            Assert.Equal(3, community.Swarms[infoHash].Hops);

            community.LeaveSwarm(infoHash);
            Assert.False(community.Swarms.ContainsKey(infoHash));
            Assert.False(community.E2eCallbacks.ContainsKey(infoHash));
        }

        [Fact]
        public void Ip_Circuit_Id_Conversion_Is_Byte_Exact_Be_U32()
        {
            // struct "!I" of the IPv4: big-endian u32 of the four octets.
            Assert.Equal(0x01020304L, HiddenTunnelCommunity.IpToCircuitId("1.2.3.4"));
            Assert.Equal(0x0A000001L, HiddenTunnelCommunity.IpToCircuitId("10.0.0.1"));
            Assert.Equal(0xFFFFFFFFL, HiddenTunnelCommunity.IpToCircuitId("255.255.255.255"));
            Assert.Equal(0x7F000001L, HiddenTunnelCommunity.IpToCircuitId("127.0.0.1"));

            Assert.Equal("1.2.3.4", HiddenTunnelCommunity.CircuitIdToIp(0x01020304L));
            Assert.Equal("255.255.255.255", HiddenTunnelCommunity.CircuitIdToIp(0xFFFFFFFFL));

            // Roundtrip over a spread of addresses (incl. the "172.16.x" e2e range).
            foreach (var ip in new[] { "1.2.3.4", "10.11.12.13", "42.43.44.45", "127.0.0.1",
                                       "172.16.1.1", "192.168.1.1", "254.253.252.251" })
            {
                Assert.Equal(ip, HiddenTunnelCommunity.CircuitIdToIp(HiddenTunnelCommunity.IpToCircuitId(ip)));
            }
        }

        [Fact]
        public void Select_Circuit_For_Infohash_Requires_A_Swarm_With_Hops()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('2', 40));

            Assert.Null(community.SelectCircuitForInfohash(infoHash));

            community.JoinSwarm(infoHash, 0);
            Assert.Null(community.SelectCircuitForInfohash(infoHash));

            community.JoinSwarm(infoHash, 2);
            // No circuits exist: the selection fails (None), but the swarm was consulted.
            Assert.Null(community.SelectCircuitForInfohash(infoHash));
        }

        [Fact]
        public void Create_Circuit_For_Infohash_Adds_A_Hop_For_Ip_And_Rp_Downloader()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('3', 40));
            community.JoinSwarm(infoHash, 1);
            var requiredExit = new Peer(ECCrypto.Default.GenerateKey("curve25519"));

            // The test double records the CreateCircuit arguments (and returns null).
            community.CreateCircuitForInfohash(infoHash, Tunnel.CircuitTypeIpSeeder, requiredExit: requiredExit);
            community.CreateCircuitForInfohash(infoHash, Tunnel.CircuitTypeRpDownloader, requiredExit: requiredExit);
            community.CreateCircuitForInfohash(infoHash, Tunnel.CircuitTypeRpSeeder);
            community.CreateCircuitForInfohash(Util.Unhex(new string('4', 40)), Tunnel.CircuitTypeRpSeeder);

            var created = community.Created;
            Assert.Equal(3, created.Count);
            Assert.Equal(2, created[0].GoalHops);
            Assert.Equal(Tunnel.CircuitTypeIpSeeder, created[0].CType);
            Assert.True(Util.BytesEqual(created[0].InfoHash, infoHash));
            Assert.Equal(requiredExit, created[0].RequiredExit);
            Assert.Equal(2, created[1].GoalHops);
            Assert.Equal(Tunnel.CircuitTypeRpDownloader, created[1].CType);
            Assert.True(Util.BytesEqual(created[1].InfoHash, infoHash));
            Assert.Equal(requiredExit, created[1].RequiredExit);
            Assert.Equal(1, created[2].GoalHops);
            Assert.Equal(Tunnel.CircuitTypeRpSeeder, created[2].CType);
            Assert.True(Util.BytesEqual(created[2].InfoHash, infoHash));
        }

        [Fact]
        public async Task Do_Peer_Discovery_Populates_Intro_Points_And_Attempts_E2e()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('5', 40));

            // The swarm's lookup_func is injected: a canned DHT-style response.
            var discovered = MakeIp("127.0.0.1", 12345);
            community.Swarms[infoHash] = new Swarm(infoHash, 1, (_, _, _) =>
                Task.FromResult(new List<IntroductionPoint> { discovered }));

            await community.DoPeerDiscoveryAsync();

            Assert.Single(community.Swarms[infoHash].IntroPoints);
            Assert.True(community.Swarms[infoHash].IntroPoints[0].Equals(discovered));
            // CreateE2e was attempted for the discovered intro point (and failed: no circuits).
            Assert.Null(community.LastHandlerException);
        }

        // ------------------------------------------------------------------
        // Overrides of the base community
        // ------------------------------------------------------------------

        [Fact]
        public void Get_MaxTime_Applies_MaxTimeIp_To_Ip_Circuits_And_Sockets()
        {
            var node = MakeNode();
            var community = node.Community;

            var ipCircuit = new Circuit(500, 1, Tunnel.CircuitTypeIpSeeder);
            community.Circuits[500] = ipCircuit;
            var dataCircuit = new Circuit(501, 1, Tunnel.CircuitTypeData);
            community.Circuits[501] = dataCircuit;

            Assert.Equal(node.Community.Settings.MaxTimeIp, community.GetMaxTime(500));
            Assert.Equal(node.Community.Settings.MaxTime, community.GetMaxTime(501));

            // An exit socket that serves as an introduction point also gets MaxTimeIp.
            community.ExitSockets[502] = new TunnelExitSocket(502, MakeHop(2), community);
            community.IntroPointFor[Util.RandomBytes(32)] =
                new IntroPointForEntry(community.ExitSockets[502], Util.Unhex(new string('6', 40)));
            Assert.Equal(node.Community.Settings.MaxTimeIp, community.GetMaxTime(502));
        }

        [Fact]
        public async Task Remove_Circuit_Of_Rp_Downloader_Drops_The_Swarm_Connection()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('7', 40));
            var swarm = new Swarm(infoHash, 1, (_, _, _) => Task.FromResult(new List<IntroductionPoint>()));
            community.Swarms[infoHash] = swarm;

            var circuit = new Circuit(600, 1, Tunnel.CircuitTypeRpDownloader, infoHash: infoHash);
            circuit.AddHop(MakeHop(3));
            circuit.E2e = true;
            circuit.BytesUp = 10;
            circuit.BytesDown = 20;
            community.Circuits[600] = circuit;
            swarm.AddConnection(circuit, MakeIp("127.0.0.1", 1000));

            community.Settings.RemoveTunnelDelay = 0;
            community.RemoveCircuit(600, "test");
            await WaitUntilAsync(() => swarm.Connections.Count == 0 && !community.Circuits.ContainsKey(600),
                                 "the swarm connection was dropped and the circuit removed");
            Assert.Equal(10, swarm.TransferHistory[0]);
            Assert.Equal(20, swarm.TransferHistory[1]);
            Assert.False(community.Circuits.ContainsKey(600));
        }

        [Fact]
        public void Do_Ping_Excludes_Pending_E2e_Circuits()
        {
            var node = MakeNode();
            var community = node.Community;

            var pendingRp = new Circuit(700, 1, Tunnel.CircuitTypeRpSeeder);
            pendingRp.AddHop(MakeHop(4));
            community.Circuits[700] = pendingRp;
            var pendingDownloader = new Circuit(701, 1, Tunnel.CircuitTypeRpDownloader);
            pendingDownloader.AddHop(MakeHop(5));
            community.Circuits[701] = pendingDownloader;
            var normal = new Circuit(702, 1, Tunnel.CircuitTypeData);
            normal.AddHop(MakeHop(6));
            community.Circuits[702] = normal;

            var activityBefore = normal.LastActivity;
            community.DoPing();
            Assert.True(normal.LastActivity >= activityBefore, "the DATA circuit was pinged");
            // The pending RP circuits are excluded from pings; no exceptions expected.
            Assert.Null(community.LastHandlerException);
        }

        // ------------------------------------------------------------------
        // Wire-level handler checks (packets built the py way)
        // ------------------------------------------------------------------

        [Fact]
        public void Peers_Response_Handler_Resolves_The_Cache_Future()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('8', 40));
            var circuit = new Circuit(800, 1);
            circuit.AddHop(MakeHop(7));

            var cache = new PeersRequestCache(community, circuit, infoHash, null);
            Assert.NotNull(community.RequestCache.Add(cache));

            var responder = MakeIp("10.0.0.9", 9999);
            var payload = new PeersResponsePayload(800, cache.Number, infoHash, new List<IntroductionInfo>
            {
                new IntroductionInfo(responder.Peer.Address, responder.Peer.PublicKey.KeyToBin(),
                                     responder.SeederPk, Tunnel.PeerSourceDht),
                new IntroductionInfo(Address.Zero, Util.RandomBytes(32), Util.RandomBytes(32), 0)
            });
            // Cell path (over a circuit).
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, PeersResponsePayload.MsgId, payload), 800);

            var ips = (List<IntroductionPoint>)cache.Future.Task.Result;
            Assert.Single(ips); // the zero-address peer is filtered out
            Assert.True(ips[0].Equals(responder));
            Assert.Equal(Tunnel.PeerSourceDht, ips[0].Source);
            Assert.False(community.RequestCache.Has(PeersRequestCache.Name, cache.Number));
        }

        [Fact]
        public void Peers_Response_Handler_Ignores_Unknown_Identifiers()
        {
            var node = MakeNode();
            var community = node.Community;
            var payload = new PeersResponsePayload(1, 12345, Util.Unhex(new string('9', 40)),
                                                   new List<IntroductionInfo>());
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, PeersResponsePayload.MsgId, payload), 1);
            Assert.Null(community.LastHandlerException);
        }

        [Fact]
        public void Establish_Rendezvous_Handler_Registers_The_Cookie_And_Answers()
        {
            var node = MakeNode();
            var community = node.Community;
            community.ExitSockets[900] = new TunnelExitSocket(900, MakeHop(9), community);

            var cookie = Util.RandomBytes(20);
            var payload = new EstablishRendezvousPayload(900, 77, cookie);
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, EstablishRendezvousPayload.MsgId, payload), 900);

            Assert.True(community.RendezvousPointFor.ContainsKey(cookie));
            Assert.Equal(900L, community.RendezvousPointFor[cookie].CircuitId);
            // A RendezvousEstablished was sent back to the source (into the tunnel); no errors.
            Assert.Null(community.LastHandlerException);
        }

        [Fact]
        public void Establish_Intro_Handler_Registers_The_Intro_Point_And_Announces()
        {
            PexCommunity created = null;
            var node = MakeNode(settings =>
            {
                settings.PexCommunityFactory = infoHash =>
                {
                    created = new PexCommunity(new PexSettings
                    {
                        MyPeer = settings.MyPeer,
                        Endpoint = settings.Endpoint,
                        Network = new Network(),
                        InfoHash = infoHash
                    });
                    return created;
                };
            });
            var community = node.Community;
            community.ExitSockets[910] = new TunnelExitSocket(910, MakeHop(10), community);

            var infoHash = Util.Unhex(new string('a', 40));
            var seederPk = new Peer(ECCrypto.Default.GenerateKey("curve25519")).PublicKey.KeyToBin();
            var payload = new EstablishIntroPayload(910, 78, infoHash, seederPk);
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, EstablishIntroPayload.MsgId, payload), 910);

            Assert.True(community.IntroPointFor.ContainsKey(seederPk));
            Assert.Equal(910L, community.IntroPointFor[seederPk].Socket.CircuitId);
            Assert.NotNull(created);
            Assert.Same(created, community.Pex[infoHash]);

            // The announced seeder key made it into the PEX community (its announce list is
            // non-empty → StartAnnounce ran; the community is not "done" while announcing).
            Assert.False(created.IsDone);
            Assert.NotEmpty(created.GetSeederPks());

            // Without a DHT provider the announce logs an error but must not crash the handler.
            Assert.Null(community.LastHandlerException);
        }

        [Fact]
        public async Task Link_E2e_Handler_Links_The_Two_Exit_Sockets()
        {
            var node = MakeNode(settings => settings.RemoveTunnelDelay = 0);
            var community = node.Community;
            var cookie = Util.RandomBytes(20);

            community.ExitSockets[1000] = new TunnelExitSocket(1000, MakeHop(11), community);
            community.ExitSockets[2000] = new TunnelExitSocket(2000, MakeHop(12), community);
            community.RendezvousPointFor[cookie] = community.ExitSockets[2000];

            var payload = new LinkE2EPayload(1000, 5, cookie);
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, LinkE2EPayload.MsgId, payload), 1000);

            Assert.True(community.RelayFromTo.ContainsKey(1000));
            Assert.True(community.RelayFromTo.ContainsKey(2000));
            Assert.Equal(2000L, community.RelayFromTo[1000].CircuitId);
            Assert.Equal(1000L, community.RelayFromTo[2000].CircuitId);
            Assert.True(community.RelayFromTo[1000].RendezvousRelay);
            Assert.True(community.RelayFromTo[2000].RendezvousRelay);

            // Both exit sockets are removed (asynchronously; delay disabled in this test).
            await WaitUntilAsync(() => !community.ExitSockets.ContainsKey(1000)
                                       && !community.ExitSockets.ContainsKey(2000),
                                 "both linked exit sockets were removed");
            Assert.Null(community.LastHandlerException);
        }

        [Fact]
        public void Link_E2e_Handler_Rejects_Unknown_Cookies_And_Enabled_Sockets()
        {
            var node = MakeNode();
            var community = node.Community;
            var cookie = Util.RandomBytes(20);

            // Unknown cookie: rejected.
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, LinkE2EPayload.MsgId,
                                                     new LinkE2EPayload(1000, 5, cookie)), 1000);
            Assert.False(community.RelayFromTo.ContainsKey(1000));

            // Known cookie but an ENABLED exit socket: rejected (no linking).
            community.ExitSockets[1100] = new TunnelExitSocket(1100, MakeHop(13), community);
            community.ExitSockets[1100].Enable();
            community.RendezvousPointFor[cookie] = community.ExitSockets[1100];
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, LinkE2EPayload.MsgId,
                                                     new LinkE2EPayload(1100, 6, cookie)), 1100);
            Assert.False(community.RelayFromTo.ContainsKey(1100));
            Assert.Null(community.LastHandlerException);
        }

        [Fact]
        public void Linked_E2e_Handler_Completes_The_Circuit_And_Fires_The_Callback()
        {
            var e2eAddresses = new List<Address>();
            var node = MakeNode(settings =>
            {
                settings.E2eCallbacks = new Dictionary<byte[], Action<Address>>(ByteArrayEqualityComparer.Instance);
            });
            var community = node.Community;
            var infoHash = Util.Unhex(new string('b', 40));
            community.JoinSwarm(infoHash, 1, e2eAddresses.Add);

            var circuit = new Circuit(3000, 1, Tunnel.CircuitTypeRpDownloader, infoHash: infoHash);
            circuit.AddHop(MakeHop(14));
            community.Circuits[3000] = circuit;
            var keys = TunnelSessionCrypto.GenerateSessionKeys(Util.RandomBytes(32));
            var cache = new LinkRequestCache(community, circuit, infoHash, keys);
            Assert.NotNull(community.RequestCache.Add(cache));

            var payload = new LinkedE2EPayload(3000, cache.Number);
            community.OnPacketFromCircuit(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, LinkedE2EPayload.MsgId, payload), 3000);

            // The e2e callback fired with the circuit-id-encoded address at the CIRCUIT_ID_PORT.
            Assert.Single(e2eAddresses);
            Assert.Equal(HiddenTunnelCommunity.IpToCircuitId(HiddenTunnelCommunity.CircuitIdToIp(3000)),
                         HiddenTunnelCommunity.IpToCircuitId(e2eAddresses[0].Host));
            Assert.Equal((int)Tunnel.CircuitIdPort, e2eAddresses[0].Port);

            // The circuit is marked e2e and carries the HS session keys.
            Assert.True(circuit.E2e);
            Assert.Same(keys, circuit.HsSessionKeys);
            Assert.False(community.RequestCache.Has(LinkRequestCache.Name, cache.Number));
        }

        [Fact]
        public void Create_E2e_Raw_Handler_Forwards_Into_The_Intro_Circuit()
        {
            var node = MakeNode();
            var community = node.Community;
            var infoHash = Util.Unhex(new string('c', 40));

            // A seeder intro circuit: the (fake) intro point is a peer on the loopback.
            var introHop = MakeHop(15);
            var introCircuit = new Circuit(4000, 1, Tunnel.CircuitTypeIpSeeder, infoHash: infoHash);
            introCircuit.AddHop(introHop);
            community.ExitSockets[4000] = new TunnelExitSocket(4000, introHop, community);
            community.IntroPointFor[introHop.Peer.PublicKey.KeyToBin()] =
                new IntroPointForEntry(community.ExitSockets[4000], infoHash);

            var seederPk = introHop.Peer.PublicKey.KeyToBin();
            var payload = new CreateE2EPayload(33, infoHash, seederPk, Util.RandomBytes(32));
            community.OnPacket(new Packet(Address.Udpv4("127.0.0.1", 1),
                                          PackPacket(community, CreateE2EPayload.MsgId, payload)));

            // The message was forwarded INTO the intro circuit (tunnel_data) — the handler did
            // not crash and the forwarding consumed no rendezvous machinery.
            Assert.Null(community.LastHandlerException);
            Assert.True(community.IntroPointFor.ContainsKey(seederPk));
        }

        [Fact]
        public async Task Estimate_Swarm_Size_Counts_Pex_Seeders()
        {
            var infoHash = Util.Unhex(new string('d', 40));

            // Stub the peers-request pipeline (py tests monkeypatch send_peers_request): the
            // DHT lookup (target None) returns one DHT-source intro point; the targeted (PEX)
            // lookups return PEX-source intro points that all belong to the same seeder key.
            var seederPk = new Peer(ECCrypto.Default.GenerateKey("curve25519")).PublicKey.KeyToBin();
            var dhtIp = new IntroductionPoint(new Peer(ECCrypto.Default.GenerateKey("curve25519"),
                                                       Address.Udpv4("127.0.0.1", 20000)),
                                              seederPk, Tunnel.PeerSourceDht);
            var pexIp1 = new IntroductionPoint(new Peer(ECCrypto.Default.GenerateKey("curve25519"),
                                                        Address.Udpv4("127.0.0.1", 20001)),
                                               seederPk, Tunnel.PeerSourcePex);
            var pexIp2 = new IntroductionPoint(new Peer(ECCrypto.Default.GenerateKey("curve25519"),
                                                        Address.Udpv4("127.0.0.1", 20002)),
                                               seederPk, Tunnel.PeerSourcePex);

            var node = MakeNode();
            var community = node.Community;
            community.StubbedPeersResponse = target => Task.FromResult(target == null
                ? new List<IntroductionPoint> { dhtIp }
                : new List<IntroductionPoint> { pexIp1, pexIp2 });

            var size = await community.EstimateSwarmSize(infoHash, hops: 1, maxRequests: 5);
            Assert.Equal(1, size); // all intro points share the single seeder key
        }
    }
}
