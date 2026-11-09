// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/messaging/anonymization/hidden_services.py: the hidden tunnel community that
// links up circuits and creates closed-loop e2e circuits for hidden services (swarm
// membership, introduction/rendezvous point establishment, peers discovery and the
// create-e2e/link-e2e flow).
//
// Port deviations (documented):
//  - py's ``settings.ipv8`` (an IPv8Service) does not exist in this port; overlays are
//    assembled directly. PEX community creation for established introduction points is
//    delegated to an optional factory on the settings; with no factory the py "No IPv8
//    service object available" branch applies.
//  - The DHT provider is pluggable (py settings.dht_provider): an interface the tests (or
//    the application) implement, with an adapter over the DhtDiscoveryCommunity.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IPv8.Dht;
using IPv8.Keyvault;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>Settings for the hidden tunnel community (py HiddenTunnelSettings).</summary>
    public class HiddenTunnelSettings : TunnelSettings
    {
        /// <summary>
        /// Factory creating (and registering) a PexCommunity for the given info hash. Mirrors
        /// py's ipv8-driven PEX creation inside on_establish_intro; null behaves like py's
        /// ``ipv8 is None`` branch (PEX skipped, DHT-only discovery).
        /// </summary>
        public Func<byte[], PexCommunity> PexCommunityFactory { get; set; }

        /// <summary>Callbacks invoked with the (circuit-id-encoded) e2e address per info hash
        /// (py e2e_callbacks).</summary>
        public Dictionary<byte[], Action<Address>> E2eCallbacks { get; set; }

        /// <summary>The pluggable DHT provider used for dht_lookup/dht_announce
        /// (py TunnelSettings.dht_provider). When null, the concrete DhtProvider (if any) is
        /// wrapped automatically.</summary>
        public new ITunnelDhtProvider DhtProvider { get; set; }
    }

    /// <summary>
    /// The DHT provider surface the hidden services need (py DHTCommunityProvider.lookup and
    /// .announce, as consumed by HiddenTunnelCommunity.dht_lookup/dht_announce).
    /// </summary>
    public interface ITunnelDhtProvider
    {
        /// <summary>Attempt to find introduction points for the given info hash. Returns null on failure.</summary>
        Task<(byte[] InfoHash, List<IntroductionPoint> IntroPoints)> LookupAsync(byte[] infoHash);

        /// <summary>Announce the given introduction point for the given info hash.</summary>
        Task AnnounceAsync(byte[] infoHash, IntroductionPoint introPoint);
    }

    /// <summary>
    /// Adapter presenting a <see cref="DhtCommunityProvider"/> as the hidden services'
    /// <see cref="ITunnelDhtProvider"/> (the DHT module's IntroductionPoint mapped onto the
    /// tunnel module's one).
    /// </summary>
    public sealed class TunnelDhtProvider : ITunnelDhtProvider
    {
        private readonly DhtCommunityProvider _provider;

        public TunnelDhtProvider(DhtCommunityProvider provider)
        {
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        }

        public async Task<(byte[] InfoHash, List<IntroductionPoint> IntroPoints)> LookupAsync(byte[] infoHash)
        {
            var (hash, ips) = await _provider.LookupAsync(infoHash).ConfigureAwait(false);
            var result = new List<IntroductionPoint>();
            foreach (var ip in ips)
            {
                result.Add(new IntroductionPoint(ip.Peer, ip.SeederPk, ip.Source, ip.LastSeen));
            }
            return (hash, result);
        }

        public Task AnnounceAsync(byte[] infoHash, IntroductionPoint introPoint)
            => _provider.AnnounceAsync(infoHash, new Dht.IntroductionPoint(
                introPoint.Peer,
                introPoint.SeederPk,
                Tunnel.PeerSourceDht,
                (int)introPoint.LastSeen));
    }

    /// <summary>The intro_point_for entry: {seeder_pk: (TunnelExitSocket, info_hash)}.</summary>
    public sealed class IntroPointForEntry
    {
        public TunnelExitSocket Socket { get; }
        public byte[] InfoHash { get; }

        public IntroPointForEntry(TunnelExitSocket socket, byte[] infoHash)
        {
            Socket = socket;
            InfoHash = infoHash;
        }
    }

    /// <summary>
    /// Extension of TunnelCommunity logic to link up circuits and create closed-loop e2e
    /// circuits (py hidden_services.py::HiddenTunnelCommunity).
    /// </summary>
    public class HiddenTunnelCommunity : TunnelCommunity, IHiddenSwarmRegistry
    {
        private static readonly TraceSource Log = new TraceSource("HiddenTunnelCommunity");

        private static readonly Random Random = new Random();

        public new HiddenTunnelSettings Settings { get; }

        public new ITunnelDhtProvider DhtProvider { get; }

        public Dictionary<byte[], Action<Address>> E2eCallbacks { get; }

        public Dictionary<byte[], Swarm> Swarms { get; } =
            new Dictionary<byte[], Swarm>(ByteArrayEqualityComparer.Instance);

        public Dictionary<byte[], PexCommunity> Pex { get; } =
            new Dictionary<byte[], PexCommunity>(ByteArrayEqualityComparer.Instance);

        /// <summary>{seeder_pk: (TunnelExitSocket, info_hash)} (py intro_point_for).</summary>
        public Dictionary<byte[], IntroPointForEntry> IntroPointFor { get; } =
            new Dictionary<byte[], IntroPointForEntry>(ByteArrayEqualityComparer.Instance);

        /// <summary>{cookie: TunnelExitSocket} (py rendezvous_point_for).</summary>
        public Dictionary<byte[], TunnelExitSocket> RendezvousPointFor { get; } =
            new Dictionary<byte[], TunnelExitSocket>(ByteArrayEqualityComparer.Instance);

        private int _peerDiscoveryRunning;

        public HiddenTunnelCommunity(HiddenTunnelSettings settings)
            : base(settings)
        {
            Settings = settings;
            E2eCallbacks = settings.E2eCallbacks ?? new Dictionary<byte[], Action<Address>>(ByteArrayEqualityComparer.Instance);
            DhtProvider = settings.DhtProvider
                          ?? (settings.DhtProvider == null && ((TunnelSettings)settings).DhtProvider != null
                              ? new TunnelDhtProvider(((TunnelSettings)settings).DhtProvider)
                              : null);

            // Messages that can arrive from the socket
            AddMessageHandler(CreateE2EPayload.MsgId, OnCreateE2eRaw);
            AddMessageHandler(PeersRequestPayload.MsgId, OnPeersRequestRaw);
            AddMessageHandler(PeersResponsePayload.MsgId, OnPeersResponseRaw);

            // Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
            AddCellHandler(EstablishIntroPayload.MsgId, OnEstablishIntro);
            AddCellHandler(IntroEstablishedPayload.MsgId, OnIntroEstablished);
            AddCellHandler(EstablishRendezvousPayload.MsgId, OnEstablishRendezvous);
            AddCellHandler(RendezvousEstablishedPayload.MsgId, OnRendezvousEstablished);
            AddCellHandler(CreateE2EPayload.MsgId, OnCreateE2eCell);
            AddCellHandler(CreatedE2EPayload.MsgId, OnCreatedE2e);
            AddCellHandler(LinkE2EPayload.MsgId, OnLinkE2e);
            AddCellHandler(LinkedE2EPayload.MsgId, OnLinkedE2e);
            AddCellHandler(PeersRequestPayload.MsgId, OnPeersRequestCell);
            AddCellHandler(PeersResponsePayload.MsgId, OnPeersResponseCell);

            RegisterTask("do_peer_discovery", () =>
            {
                // py loops the coroutine; avoid overlapping runs (a slow DHT lookup must not stack).
                if (Interlocked.CompareExchange(ref _peerDiscoveryRunning, 1, 0) != 0)
                {
                    return;
                }
                _ = RunPeerDiscoverySafeAsync();
            }, interval: 10);
        }

        private async Task RunPeerDiscoverySafeAsync()
        {
            try
            {
                await DoPeerDiscoveryAsync().ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Log.TraceEvent(TraceEventType.Information, 0,
                    "Failed to do peer discovery: " + e.GetType().Name);
            }
            finally
            {
                Interlocked.Exchange(ref _peerDiscoveryRunning, 0);
            }
        }

        // ------------------------------------------------------------------
        // Swarm management (hidden_services.py:126-234)
        // ------------------------------------------------------------------

        /// <summary>
        /// Join a hidden swarm. This should be called by both the downloader and the seeder.
        /// Calling this method while already part of the swarm will cause the community to
        /// drop all pre-existing connections. Note that the seeder should also create
        /// introduction points by calling CreateIntroductionPoint.
        /// </summary>
        public void JoinSwarm(byte[] infoHash, int hops, Action<Address> callback = null, bool seeding = true)
        {
            if (Swarms.ContainsKey(infoHash))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Already part of hidden swarm {Serializer.Hexlify(infoHash)}, leaving existing");
                LeaveSwarm(infoHash);
            }

            Swarms[infoHash] = new Swarm(infoHash, hops, SendPeersRequest,
                                         seeding ? ECCrypto.Default.GenerateKey("curve25519") : null);
            E2eCallbacks[infoHash] = callback;
        }

        /// <summary>Leave a hidden swarm. Can be called by both the downloader and the seeder.</summary>
        public void LeaveSwarm(byte[] infoHash)
        {
            // Remove all introduction points and e2e circuits for this swarm
            foreach (var circuit in Circuits.Values.ToList())
            {
                if (circuit.InfoHash != null && Util.BytesEqual(circuit.InfoHash, infoHash)
                    && (circuit.CType == Tunnel.CircuitTypeIpSeeder
                        || circuit.CType == Tunnel.CircuitTypeRpSeeder
                        || circuit.CType == Tunnel.CircuitTypeRpDownloader))
                {
                    RemoveCircuit(circuit.CircuitId, "leaving hidden swarm",
                                  destroy: Tunnel.DestroyReasonUnneeded);
                }
            }
            // Remove swarm and callback
            Swarms.Remove(infoHash);
            E2eCallbacks.Remove(infoHash);
        }

        /// <summary>Estimate the number of unique seeders that are part of a hidden swarm.</summary>
        public async Task<int> EstimateSwarmSize(byte[] infoHash, int hops = 1, int maxRequests = 10)
        {
            var swarm = new Swarm(infoHash, hops, SendPeersRequest);

            // None represents a DHT request (C#: a null entry in the list).
            var all = new List<IntroductionPoint> { null };
            var tried = new List<IntroductionPoint>();

            while (tried.Count < maxRequests)
            {
                var notTried = all
                    .Where(ip => ip == null ? !tried.Contains(null) : !tried.Contains(ip))
                    .Distinct()
                    .ToList();
                if (notTried.Count == 0)
                {
                    break;
                }

                // Issue as many requests as possible in parallel (py random.sample).
                var sample = Sample(notTried, Math.Min(notTried.Count, maxRequests - tried.Count));
                foreach (var ip in sample)
                {
                    List<IntroductionPoint> result;
                    try
                    {
                        // py gather(..., return_exceptions=True): failures are skipped.
                        result = await swarm.Lookup(ip).ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        tried.Add(ip);
                        continue;
                    }
                    if (result != null && result.Count > 0)
                    {
                        all.AddRange(result);
                    }
                    tried.Add(ip);
                }
            }

            var seederPks = new List<byte[]>();
            foreach (var ip in all)
            {
                if (ip != null && ip.Source == Tunnel.PeerSourcePex && !seederPks.Any(pk => Util.BytesEqual(pk, ip.SeederPk)))
                {
                    seederPks.Add(ip.SeederPk);
                }
            }
            return seederPks.Count;
        }

        /// <summary>Get a circuit that connects to the swarm of the given SHA-1 hash.</summary>
        public Circuit SelectCircuitForInfohash(byte[] infoHash)
        {
            Swarms.TryGetValue(infoHash, out var swarm);
            if (swarm == null || swarm.Hops == 0)
            {
                Log.TraceEvent(TraceEventType.Information, 0, "Can\"t get hop count, download cancelled?");
                return null;
            }

            return SelectCircuit(Address.Zero, swarm.Hops);
        }

        /// <summary>Create a circuit that connects to the swarm given by the SHA-1 (info) hash.</summary>
        public Circuit CreateCircuitForInfohash(byte[] infoHash, string ctype, int[] exitFlags = null,
                                                Peer requiredExit = null)
        {
            Swarms.TryGetValue(infoHash, out var swarm);
            if (swarm == null || swarm.Hops == 0)
            {
                Log.TraceEvent(TraceEventType.Information, 0, "Can\"t get hop count, download cancelled?");
                return null;
            }

            // Introduction point circuits need an additional hop, or we will talk directly to
            // the introduction point. Also, rendezvous circuits need an additional hop, since
            // the seeder chooses the rendezvous_point.
            var hops = swarm.Hops;
            if (ctype == Tunnel.CircuitTypeIpSeeder || ctype == Tunnel.CircuitTypeRpDownloader)
            {
                hops += 1;
            }

            return CreateCircuit(hops, ctype, exitFlags, requiredExit, infoHash);
        }

        /// <summary>Convert an IP to a (special) circuit id: struct "!I" of the IPv4 (BE u32).</summary>
        public static long IpToCircuitId(string ipStr)
        {
            var parts = ipStr.Split('.');
            if (parts.Length != 4)
            {
                throw new ArgumentException($"Not an IPv4 address: {ipStr}");
            }
            return ((long)uint.Parse(parts[0]) << 24) | ((long)uint.Parse(parts[1]) << 16)
                   | ((long)uint.Parse(parts[2]) << 8) | (long)uint.Parse(parts[3]);
        }

        /// <summary>Convert an IP-embedded circuit id back to the original IP.</summary>
        public static string CircuitIdToIp(long circuitId)
        {
            return $"{(circuitId >> 24) & 0xFF}.{(circuitId >> 16) & 0xFF}.{(circuitId >> 8) & 0xFF}.{circuitId & 0xFF}";
        }

        // ------------------------------------------------------------------
        // Discovery / data plumbing (hidden_services.py:235-345)
        // ------------------------------------------------------------------

        /// <summary>Find peers in the swarms that we are a part of.</summary>
        public async Task DoPeerDiscoveryAsync()
        {
            var now = Util.NowEpoch();
            foreach (var infoHash in Swarms.Keys.ToList())
            {
                var swarm = Swarms[infoHash];
                if (!swarm.Seeding
                    && swarm.LastLookup + Settings.SwarmLookupInterval <= now
                    && swarm.GetNumConnections() < Settings.SwarmConnectionLimit)
                {
                    List<IntroductionPoint> ips;
                    try
                    {
                        ips = await swarm.Lookup().ConfigureAwait(false);
                    }
                    catch (Exception e)
                    {
                        Log.TraceEvent(TraceEventType.Information, 0,
                            $"Failed to do peer discovery for swarm {Serializer.Hexlify(infoHash)}: {e.GetType().Name}");
                        continue;
                    }

                    if (ips == null)
                    {
                        Log.TraceEvent(TraceEventType.Information, 0,
                            $"Skipping peer discovery for swarm {Serializer.Hexlify(infoHash)}");
                        continue;
                    }
                    foreach (var ip in Distinct(ips))
                    {
                        swarm.AddIntroPoint(ip);
                    }
                    foreach (var ip in swarm.IntroPoints.ToList())
                    {
                        if (!swarm.HasConnection(ip.SeederPk))
                        {
                            CreateE2e(infoHash, ip);
                        }
                    }
                }
            }
        }

        /// <summary>Beyond normal circuit creation, make sure we have circuits for introduction points.</summary>
        public override void DoCircuits()
        {
            base.DoCircuits();

            // Make sure we have at least 1 data circuit for every hop count. This circuit will
            // be used for communication with introduction points.
            foreach (var hopCount in Swarms.Values.Select(swarm => swarm.Hops).Distinct().ToList())
            {
                if (FindCircuits(state: null, hops: hopCount).Count == 0)
                {
                    CreateCircuit(hopCount);
                }
            }
        }

        /// <summary>Ping all circuits, except pending e2e circuits.</summary>
        public override void DoPing(int[] exclude = null)
        {
            var excluded = new List<int>(exclude ?? Array.Empty<int>());
            foreach (var circuit in Circuits.Values)
            {
                if (circuit.CType == Tunnel.CircuitTypeRpSeeder
                    || (circuit.CType == Tunnel.CircuitTypeRpDownloader && !circuit.E2e))
                {
                    excluded.Add((int)circuit.CircuitId);
                }
            }
            base.DoPing(excluded.ToArray());
        }

        /// <summary>Remove the given circuit and update any swarms it may be part of.</summary>
        public override void RemoveCircuit(long circuitId, string additionalInfo = "", bool removeNow = false,
                                           object destroy = null)
        {
            Circuits.TryGetValue(circuitId, out var circuit);
            if (circuit != null && circuit.CType == Tunnel.CircuitTypeRpDownloader
                && circuit.InfoHash != null && Swarms.TryGetValue(circuit.InfoHash, out var swarm))
            {
                swarm.RemoveConnection(circuit);
            }
            base.RemoveCircuit(circuitId, additionalInfo, removeNow, destroy);
        }

        /// <summary>
        /// Remove the given exit circuit, remove associated rendezvous points and update any
        /// PEX communities it may be part of.
        /// </summary>
        public override void RemoveExitSocket(long circuitId, string additionalInfo = "", bool removeNow = false,
                                              object destroy = null)
        {
            foreach (var seederPk in IntroPointFor.Keys.ToList())
            {
                var entry = IntroPointFor[seederPk];
                if (entry.Socket.CircuitId == circuitId)
                {
                    IntroPointFor.Remove(seederPk);

                    // Stop announcing in PEX community
                    if (Pex.TryGetValue(entry.InfoHash, out var pex))
                    {
                        pex.StopAnnounce(seederPk);

                        // Unload PEX community
                        if (pex.IsDone)
                        {
                            Pex.Remove(entry.InfoHash);
                            RegisterAnonymousTask("unload_pex", () =>
                            {
                                try
                                {
                                    pex.Unload();
                                }
                                catch (Exception e)
                                {
                                    Log.TraceEvent(TraceEventType.Error, 0, "unload_pex failed: " + e.Message);
                                }
                            });
                        }
                    }
                }
            }

            foreach (var cookie in RendezvousPointFor.Keys.ToList())
            {
                if (RendezvousPointFor[cookie].CircuitId == circuitId)
                {
                    RendezvousPointFor.Remove(cookie);
                }
            }

            base.RemoveExitSocket(circuitId, additionalInfo, removeNow, destroy);
        }

        /// <summary>Get the maximum time that a given circuit is allowed to exist.</summary>
        public override double GetMaxTime(long circuitId)
        {
            if (Circuits.TryGetValue(circuitId, out var circuit)
                && circuit.CType == Tunnel.CircuitTypeIpSeeder)
            {
                return Settings.MaxTimeIp;
            }
            if (ExitSockets.ContainsKey(circuitId)
                && IntroPointFor.Values.Any(entry => entry.Socket.CircuitId == circuitId))
            {
                return Settings.MaxTimeIp;
            }
            return base.GetMaxTime(circuitId);
        }

        /// <summary>Send any serializable payload to the next hop in the circuit.</summary>
        public void TunnelData(Circuit circuit, Address destination, Payload payload)
            => TunnelDataImpl(circuit.Hop, circuit.CircuitId, false, destination, payload);

        /// <summary>Send any serializable payload back through the given exit socket.</summary>
        public void TunnelData(TunnelExitSocket exitSocket, Address destination, Payload payload)
            => TunnelDataImpl(exitSocket.Hop, exitSocket.CircuitId, true, destination, payload);

        private void TunnelDataImpl(Hop hop, long circuitId, bool isExitSocket, Address destination,
                                    Payload payload)
        {
            var packet = EzrPack(payload.MsgNum, false, payload);
            var pre = Address.Zero;
            var post = Address.Zero;
            if (isExitSocket)
            {
                post = destination;
            }
            else
            {
                pre = destination;
            }
            SendData(hop.Address, circuitId, pre, post, packet);
        }

        /// <summary>Make sure that we select the right circuit when dealing with an e2e connection.</summary>
        public Circuit SelectCircuit(Address destination, int hops)
        {
            // py: ``destination is not None and destination[1] == CIRCUIT_ID_PORT`` — the port
            // embeds the e2e address sentinel; callers without a destination pass the zero
            // address (C# structs cannot hold None).
            if (!destination.Equals(Address.Zero) && destination.Port == Tunnel.CircuitIdPort)
            {
                var circuitId = IpToCircuitId(destination.Host);
                Circuits.TryGetValue(circuitId, out var circuit);

                if (circuit != null && circuit.State == Tunnel.CircuitStateReady
                    && circuit.CType == Tunnel.CircuitTypeRpDownloader)
                {
                    return circuit;
                }
            }

            var circuits = FindCircuits(hops: hops);
            return circuits.Count > 0 ? circuits[Random.Next(circuits.Count)] : null;
        }

        // ------------------------------------------------------------------
        // Peers + e2e flow (hidden_services.py:346-590)
        // ------------------------------------------------------------------

        /// <summary>Attempt to find peers for a given SHA-1 (info) hash. Virtual so tests can
        /// stub the peers-request pipeline (py tests monkeypatch this method).</summary>
        public virtual Task<List<IntroductionPoint>> SendPeersRequest(byte[] infoHash, IntroductionPoint target,
                                                                      int hops)
        {
            var circuit = SelectCircuit(Address.Zero, hops);
            if (circuit == null)
            {
                Log.TraceEvent(TraceEventType.Information, 0, "No circuit for peers-request");
                return Task.FromException<List<IntroductionPoint>>(
                    new InvalidOperationException("No circuit for peers-request"));
            }

            // Send a peers-request message over this circuit
            var cache = new PeersRequestCache(this, circuit, infoHash, target);
            RequestCache.Add(cache);
            var payload = new PeersRequestPayload(circuit.CircuitId, cache.Number, infoHash);

            // Ask an introduction point if available (in which case we'll use PEX), otherwise
            // let the exit node do a DHT request.
            if (target != null && !Util.BytesEqual(target.Peer.PublicKey.KeyToBin(),
                                                   circuit.Hops[circuit.Hops.Count - 1].PublicKeyBin))
            {
                TunnelData(circuit, target.Peer.Address, payload);
                Log.TraceEvent(TraceEventType.Information, 0, $"Sending peers request (intro point {target.Peer})");
            }
            else
            {
                SendCell(circuit.Hop.Address, payload);
                Log.TraceEvent(TraceEventType.Information, 0, "Sending peers request as cell");
            }
            return AwaitPeersFuture(cache.Future.Task);
        }

        private static async Task<List<IntroductionPoint>> AwaitPeersFuture(Task<object> future)
        {
            var result = await future.ConfigureAwait(false);
            return (List<IntroductionPoint>)result;
        }

        private Task OnPeersRequestRaw(Address sourceAddress, byte[] data)
        {
            HandlePeersRequest(sourceAddress, data, null);
            return Task.CompletedTask;
        }

        private void OnPeersRequestCell(Address sourceAddress, byte[] data, long? circuitId)
        {
            HandlePeersRequest(sourceAddress, data, circuitId);
        }

        private void HandlePeersRequest(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<PeersRequestPayload>(data, 23);
            _ = RunCellTask(OnPeersRequestAsync(sourceAddress, payload, circuitId));
        }

        private async Task OnPeersRequestAsync(Address sourceAddress, PeersRequestPayload payload, long? circuitId)
        {
            var infoHash = payload.InfoHash;
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Doing hidden seeders lookup for info_hash {Serializer.Hexlify(infoHash)}");
            if (Pex.TryGetValue(infoHash, out var pexCommunity))
            {
                // Get peers from PEX community
                SendPeersResponse(sourceAddress, payload, pexCommunity.GetIntroPoints(), circuitId);
            }
            else if (circuitId != null && ExitSockets.ContainsKey(circuitId.Value))
            {
                // Get peers from DHT community
                var results = await DhtLookupAsync(infoHash).ConfigureAwait(false);
                if (results.IntroPoints != null)
                {
                    SendPeersResponse(sourceAddress, payload, results.IntroPoints, circuitId);
                }
            }
            else if (circuitId != null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received a peers-request over circuit {circuitId}, but unable to do a DHT lookup");
            }
            else
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Received a peers-request over the socket, but unable to do a PEX lookup");
            }
        }

        /// <summary>Send a response with the peers that we found through the DHT.</summary>
        private void SendPeersResponse(Address targetAddr, PeersRequestPayload request,
                                       List<IntroductionPoint> introPoints, long? circuitId)
        {
            var peers = Sample(introPoints, Math.Min(introPoints.Count, 7))
                .Select(ip => new IntroductionInfo(ip.Peer.Address, ip.Peer.PublicKey.KeyToBin(),
                                                   ip.SeederPk, ip.Source))
                .ToList();
            var payload = new PeersResponsePayload(request.CircuitId, request.Identifier, request.InfoHash, peers);

            if (circuitId != null)
            {
                // Send back to origin
                SendCell(targetAddr, payload);
            }
            else
            {
                // Send back to exit node
                SendPacket(targetAddr, EzrPack(PeersResponsePayload.MsgId, false, payload));
            }
        }

        private Task OnPeersResponseRaw(Address sourceAddress, byte[] data)
        {
            HandlePeersResponse(sourceAddress, data, null);
            return Task.CompletedTask;
        }

        private void OnPeersResponseCell(Address sourceAddress, byte[] data, long? circuitId)
        {
            HandlePeersResponse(sourceAddress, data, circuitId);
        }

        /// <summary>Callback for when someone performed a DHT lookup for us.</summary>
        private void HandlePeersResponse(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<PeersResponsePayload>(data, 23);
            if (!RequestCache.Has(PeersRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Got a peers-response with an unknown identifier");
                return;
            }
            var cache = (PeersRequestCache)RequestCache.Pop(PeersRequestCache.Name, (int)payload.Identifier);

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Received peers-response containing {payload.Peers.Count} peers");
            var ips = new List<IntroductionPoint>();
            foreach (var peer in payload.Peers)
            {
                if (!peer.Address.Equals(Address.Zero))
                {
                    ips.Add(new IntroductionPoint(new Peer(peer.Key, peer.Address), peer.SeederPk, peer.Source));
                }
            }
            cache.Future.TrySetResult(ips);
        }

        /// <summary>Create an e2e bridge for the given SHA-1 (info) hash over the given introduction point.</summary>
        public void CreateE2e(byte[] infoHash, IntroductionPoint introPoint)
        {
            var circuit = SelectCircuitForInfohash(infoHash);
            if (circuit == null)
            {
                Log.TraceEvent(TraceEventType.Error, 0, "No circuit for contacting the introduction point");
                return;
            }

            var hop = new Hop(new Peer(introPoint.SeederPk));
            var (dhSecret, dhFirstPart) = Crypto.GenerateDiffieSecret();
            hop.DhSecret = dhSecret;
            hop.DhFirstPart = dhFirstPart;
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Creating e2e circuit for introduction point {introPoint.Peer}");
            var cache = new E2eRequestCache(this, infoHash, hop, introPoint);
            RequestCache.Add(cache);
            TunnelData(circuit, introPoint.Peer.Address,
                       new CreateE2EPayload(cache.Number, infoHash, hop.PublicKeyBin, hop.DhFirstPart));
        }

        private Task OnCreateE2eRaw(Address sourceAddress, byte[] data)
        {
            HandleCreateE2e(sourceAddress, data, null);
            return Task.CompletedTask;
        }

        private void OnCreateE2eCell(Address sourceAddress, byte[] data, long? circuitId)
            => HandleCreateE2e(sourceAddress, data, circuitId);

        private void HandleCreateE2e(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<CreateE2EPayload>(data, 23);
            // If we have received this message over a socket, we need to forward it
            if (circuitId == null)
            {
                if (IntroPointFor.TryGetValue(payload.NodePublicKey, out var entry))
                {
                    Log.TraceEvent(TraceEventType.Information, 0,
                        "On create-e2e: forwarding message because received over socket");
                    TunnelData(entry.Socket, sourceAddress, payload);
                }
                else
                {
                    Log.TraceEvent(TraceEventType.Information, 0,
                        $"On create-e2e: dropping message for unknown seeder key {Serializer.Hexlify(payload.NodePublicKey)}");
                }
            }
            else
            {
                _ = RunCellTask(OnCreateE2eCellAsync(sourceAddress, payload, circuitId.Value));
            }
        }

        private async Task OnCreateE2eCellAsync(Address sourceAddress, CreateE2EPayload payload, long circuitId)
        {
            Log.TraceEvent(TraceEventType.Information, 0, "On create-e2e: creating rendezvous point");
            Swarms.TryGetValue(payload.InfoHash, out var swarm);
            if (swarm != null && swarm.Seeding)
            {
                var rp = await CreateRendezvousPointAsync(payload.InfoHash).ConfigureAwait(false);
                if (rp != null)
                {
                    RendezvousPoint ready;
                    try
                    {
                        ready = await rp.Ready.Task.ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        return; // cancelled during shutdown
                    }
                    if (ready != null)
                    {
                        CreateCreatedE2e(rp, sourceAddress, payload, circuitId);
                    }
                }
            }
        }

        /// <summary>Callback for when we receive "create" or "created" payloads.</summary>
        private void CreateCreatedE2e(RendezvousPoint rp, Address sourceAddress,
                                      CreateE2EPayload payload, long circuitId)
        {
            var key = Swarms[payload.InfoHash].SeederSk;
            var (sharedSecret, y, auth) = Crypto.GenerateDiffieSharedSecret(payload.Key, key);
            var sesskeys = TunnelCrypto.GenerateSessionKeys(sharedSecret);
            rp.Circuit.HsSessionKeys = sesskeys;

            var rpInfo = new RendezvousInfo(rp.Address, rp.Circuit.Hops[rp.Circuit.Hops.Count - 1].PublicKeyBin,
                                            rp.Cookie);
            var rpInfoBin = Serializer.PackSerializable(rpInfo);
            var rpInfoEnc = sesskeys.EncryptStr(rpInfoBin, Tunnel.Forward);

            var circuit = Circuits[circuitId];
            TunnelData(circuit, sourceAddress, new CreatedE2EPayload(payload.Identifier, y, auth, rpInfoEnc));
        }

        private void OnCreatedE2e(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<CreatedE2EPayload>(data, 23);
            _ = RunCellTask(OnCreatedE2eAsync(sourceAddress, payload, circuitId));
        }

        /// <summary>Callback for when peers signal that they have created an e2e circuit.</summary>
        private async Task OnCreatedE2eAsync(Address sourceAddress, CreatedE2EPayload payload, long? circuitId)
        {
            if (!RequestCache.Has(E2eRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid created-e2e identifier");
                return;
            }

            var cache = (E2eRequestCache)RequestCache.Pop(E2eRequestCache.Name, (int)payload.Identifier);
            byte[] sharedSecret;
            try
            {
                sharedSecret = TunnelCrypto.VerifyAndGenerateSharedSecret(cache.Hop.DhSecret,
                                                                          payload.Key,
                                                                          payload.Auth,
                                                                          cache.Hop.PublicKey.GetCryptPk());
            }
            catch (Exception e)
            {
                // py: the raised CryptoException is swallowed by the anonymous-task wrapper.
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Failed to verify the created-e2e shared secret: " + e.Message);
                return;
            }
            var sessionKeys = TunnelCrypto.GenerateSessionKeys(sharedSecret);

            var rpInfoBin = sessionKeys.DecryptStr(payload.RpInfoEnc, Tunnel.Forward);
            var rpInfo = Serializer.UnpackSerializableAs<RendezvousInfo>(rpInfoBin);

            var requiredExit = new Peer(rpInfo.Key, rpInfo.Address);
            var circuit = CreateCircuitForInfohash(cache.InfoHash, Tunnel.CircuitTypeRpDownloader,
                                                   requiredExit: requiredExit);
            if (circuit != null)
            {
                Swarms[cache.InfoHash].AddConnection(circuit, cache.IntroPoint);
                Circuit ready;
                try
                {
                    ready = await circuit.Ready.Task.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return; // cancelled during shutdown
                }
                if (ready != null)
                {
                    var linkCache = new LinkRequestCache(this, circuit, cache.InfoHash, sessionKeys);
                    RequestCache.Add(linkCache);
                    SendCell(circuit.Hop.Address,
                             new LinkE2EPayload(circuit.CircuitId, linkCache.Number, rpInfo.Cookie));
                }
            }
        }

        private void OnLinkE2e(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<LinkE2EPayload>(data, 23);
            // Callback for when an e2e circuit attempts to link up sender and receiver.
            if (!RendezvousPointFor.TryGetValue(payload.Cookie, out var relayCircuit))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Not a rendezvous point for this cookie");
                return;
            }

            if (circuitId == null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Attempted link without circuit id");
                return;
            }

            var exitSocket = ExitSockets[circuitId.Value];
            if (exitSocket.Enabled)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Exit socket for circuit is enabled, cannot link");
                return;
            }

            var exitSocketRp = ExitSockets[relayCircuit.CircuitId];
            if (exitSocketRp.Enabled)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Exit socket for relay_circuit is enabled, cannot link");
                return;
            }

            RemoveExitSocket(exitSocket.CircuitId, "linking circuit");
            RemoveExitSocket(exitSocketRp.CircuitId, "linking circuit");

            RelayFromTo[exitSocket.CircuitId] = new RelayRoute(exitSocketRp.CircuitId,
                new Hop(exitSocketRp.Hop.Peer, exitSocket.Hop.Keys), Tunnel.Forward, true);
            RelayFromTo[exitSocketRp.CircuitId] = new RelayRoute(exitSocket.CircuitId,
                new Hop(exitSocket.Hop.Peer, exitSocketRp.Hop.Keys), Tunnel.Forward, true);

            SendCell(sourceAddress, new LinkedE2EPayload(exitSocket.CircuitId, payload.Identifier));
        }

        private void OnLinkedE2e(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<LinkedE2EPayload>(data, 23);
            // Callback for when a sender and receiver circuit have been linked up.
            if (!RequestCache.Has(LinkRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid linked-e2e identifier");
                return;
            }

            var cache = (LinkRequestCache)RequestCache.Pop(LinkRequestCache.Name, (int)payload.Identifier);
            var circuit = cache.Circuit;
            circuit.E2e = true;
            circuit.HsSessionKeys = cache.HsSessionKeys;

            E2eCallbacks.TryGetValue(cache.InfoHash, out var callback);
            if (callback != null)
            {
                callback(Address.Udpv4(CircuitIdToIp(circuit.CircuitId), (int)Tunnel.CircuitIdPort));
            }
            else
            {
                Log.TraceEvent(TraceEventType.Error, 0,
                    $"On linked e2e: could not find download for {Serializer.Hexlify(cache.InfoHash)}!");
            }
        }

        // ------------------------------------------------------------------
        // Intro / rendezvous / DHT (hidden_services.py:591-733)
        // ------------------------------------------------------------------

        /// <summary>Create an introduction point for the given SHA-1 (info) hash.</summary>
        public async Task CreateIntroductionPointAsync(byte[] infoHash, Peer requiredIp = null)
        {
            Log.TraceEvent(TraceEventType.Information, 0, "Creating introduction point");

            if (!Swarms.TryGetValue(infoHash, out var swarm))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Cannot create introduction point for unknown swarm");
                return;
            }
            if (!swarm.Seeding)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Cannot create introduction point for swarm that is not seeding");
                return;
            }

            var circuit = CreateCircuitForInfohash(infoHash, Tunnel.CircuitTypeIpSeeder, requiredExit: requiredIp);

            if (circuit != null)
            {
                Circuit ready;
                try
                {
                    ready = await circuit.Ready.Task.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return; // cancelled during shutdown
                }
                if (ready != null)
                {
                    // We got a circuit, now let's create an introduction point
                    var seedPk = swarm.SeederSk.Pub().KeyToBin();
                    var circuitId = circuit.CircuitId;
                    var cache = new IpRequestCache(this, circuit);
                    RequestCache.Add(cache);
                    SendCell(circuit.Hop.Address,
                             new EstablishIntroPayload(circuitId, cache.Number, infoHash, seedPk));
                    Log.TraceEvent(TraceEventType.Information, 0, $"Established introduction tunnel {circuitId}");
                }
            }
        }

        private void OnEstablishIntro(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<EstablishIntroPayload>(data, 23);
            // Callback for when we are asked to be an introduction point.
            if (IntroPointFor.ContainsKey(payload.PublicKey))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Already have an introduction point for {Serializer.Hexlify(payload.PublicKey)}");
                return;
            }

            if (circuitId == null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Trying to establish an introduction point without a circuit id");
                return;
            }
            if (!ExitSockets.TryGetValue(circuitId.Value, out var circuit))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received establish-intro for unknown exit socket {circuitId}");
                return;
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Established introduction point for {Serializer.Hexlify(payload.PublicKey)}");

            IntroPointFor[payload.PublicKey] = new IntroPointForEntry(circuit, payload.InfoHash);

            if (Settings.PexCommunityFactory == null)
            {
                Log.TraceEvent(TraceEventType.Error, 0,
                    "No IPv8 service object available, cannot start PexCommunity");
            }
            else if (!Pex.ContainsKey(payload.InfoHash))
            {
                Pex[payload.InfoHash] = Settings.PexCommunityFactory(payload.InfoHash);
            }

            // PEX announce
            if (Pex.TryGetValue(payload.InfoHash, out var pexCommunity))
            {
                pexCommunity.StartAnnounce(payload.PublicKey);
            }

            // DHT announce
            _ = RunCellTask(DhtAnnounceAsync(payload.InfoHash,
                                             new IntroductionPoint(new Peer(MyPeer.Key, MyEstimatedWan),
                                                                   payload.PublicKey)));

            SendCell(sourceAddress, new IntroEstablishedPayload(circuit.CircuitId, payload.Identifier));
        }

        private void OnIntroEstablished(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<IntroEstablishedPayload>(data, 23);
            // Callback for when a peer signals that an introduction point has been created for us.
            if (!RequestCache.Has(IpRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid intro-established request identifier");
                return;
            }

            RequestCache.Pop(IpRequestCache.Name, (int)payload.Identifier);
            Log.TraceEvent(TraceEventType.Information, 0, $"Got intro-established from {sourceAddress}");
        }

        /// <summary>Create a new rendezvous point for the given SHA-1 (info) hash.</summary>
        public async Task<RendezvousPoint> CreateRendezvousPointAsync(byte[] infoHash)
        {
            // Create a new circuit to be used for transferring data
            var circuit = CreateCircuitForInfohash(infoHash, Tunnel.CircuitTypeRpSeeder);

            if (circuit != null)
            {
                Circuit ready;
                try
                {
                    ready = await circuit.Ready.Task.ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return null; // cancelled during shutdown
                }
                if (ready != null)
                {
                    // We got a circuit, now let's create a rendezvous point
                    var rp = new RendezvousPoint(circuit, Util.RandomBytes(20));
                    var cache = new RpRequestCache(this, rp);
                    RequestCache.Add(cache);
                    SendCell(circuit.Hop.Address,
                             new EstablishRendezvousPayload(circuit.CircuitId, cache.Number, rp.Cookie));
                    return rp;
                }
            }
            return null;
        }

        private void OnEstablishRendezvous(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<EstablishRendezvousPayload>(data, 23);
            // Callback for when we are requested to be a rendezvous point.
            if (circuitId == null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Trying to establish a rendezvous point without a circuit id");
                return;
            }
            if (!ExitSockets.TryGetValue(circuitId.Value, out var circuit))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received establish-rendezvous for unknown exit socket {circuitId}");
                return;
            }

            RendezvousPointFor[payload.Cookie] = circuit;

            SendCell(sourceAddress,
                     new RendezvousEstablishedPayload(circuit.CircuitId, payload.Identifier, MyEstimatedWan));
        }

        private void OnRendezvousEstablished(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<RendezvousEstablishedPayload>(data, 23);
            // Callback for when a peer signals that they act as a rendezvous point for us.
            if (!RequestCache.Has(RpRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid rendezvous-established request identifier");
                return;
            }

            var cache = (RpRequestCache)RequestCache.Pop(RpRequestCache.Name, (int)payload.Identifier);
            cache.Rp.Address = payload.RendezvousPointAddr;
            cache.Rp.Ready.TrySetResult(cache.Rp);
        }

        /// <summary>Attempt to find introduction points for the given SHA-1 (info) hash.</summary>
        public async Task<(byte[] InfoHash, List<IntroductionPoint> IntroPoints)> DhtLookupAsync(byte[] infoHash)
        {
            if (DhtProvider != null)
            {
                return await DhtProvider.LookupAsync(infoHash).ConfigureAwait(false);
            }

            Log.TraceEvent(TraceEventType.Error, 0, "Need a DHT provider to lookup on the DHT");
            return (infoHash, null);
        }

        /// <summary>Announce ourselves as a candidate for the given SHA-1 (info) hash.</summary>
        public async Task DhtAnnounceAsync(byte[] infoHash, IntroductionPoint introPoint)
        {
            if (DhtProvider != null)
            {
                await DhtProvider.AnnounceAsync(infoHash, introPoint).ConfigureAwait(false);
            }
            else
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Need a DHT provider to announce to the DHT");
            }
        }

        // ------------------------------------------------------------------
        // Helpers
        // ------------------------------------------------------------------

        /// <summary>Fire-and-forget a cell handler task, logging failures (py anonymous task).</summary>
        private async Task RunCellTask(Task task)
        {
            try
            {
                await task.ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Log.TraceEvent(TraceEventType.Error, 0,
                    "Exception occurred while handling cell: " + e.Message);
                LastHandlerException = e;
            }
        }

        /// <summary>py random.sample(population, k).</summary>
        private static List<T> Sample<T>(List<T> population, int k)
        {
            var pool = new List<T>(population);
            var result = new List<T>();
            for (var i = 0; i < k && pool.Count > 0; i++)
            {
                var index = Random.Next(pool.Count);
                result.Add(pool[index]);
                pool.RemoveAt(index);
            }
            return result;
        }

        /// <summary>Distinct by (peer, seeder_pk) equality (py set(ips)).</summary>
        private static List<IntroductionPoint> Distinct(List<IntroductionPoint> ips)
        {
            var result = new List<IntroductionPoint>();
            foreach (var ip in ips)
            {
                if (!result.Contains(ip))
                {
                    result.Add(ip);
                }
            }
            return result;
        }
    }
}
