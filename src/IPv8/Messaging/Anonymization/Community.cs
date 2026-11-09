// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging.Interfaces;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// Settings to forward to the TunnelCommunity (community.py::TunnelSettings).
    /// </summary>
    public class TunnelSettings : CommunitySettings
    {
        public int MinCircuits { get; set; } = 1;
        public int MaxCircuits { get; set; } = 8;
        public int MaxJoinedCircuits { get; set; } = 100;

        /// <summary>Maximum number of seconds that a circuit should exist.</summary>
        public double MaxTime { get; set; } = 60 * 60;

        /// <summary>Maximum number of seconds that an introduction point should exist.</summary>
        public double MaxTimeIp { get; set; } = 24 * 60 * 60;

        /// <summary>Maximum number of seconds before a circuit is considered inactive (and is removed).</summary>
        public double MaxTimeInactive { get; set; } = 20;

        public long MaxTraffic { get; set; } = 10L * 1024 * 1024 * 1024;

        /// <summary>
        /// Maximum number of seconds circuit creation is allowed to take. Within this time period, the unverified
        /// hop of the circuit can still change in case it is unresponsive.
        /// </summary>
        public double CircuitTimeout { get; set; } = 60;

        /// <summary>Maximum number of seconds that a hop allows us to change the next hop.</summary>
        public double UnstableTimeout { get; set; } = 60;

        /// <summary>Maximum number of seconds adding a single hop to a circuit is allowed to take.</summary>
        public double NextHopTimeout { get; set; } = 10;

        public double SwarmLookupInterval { get; set; } = 30;

        public int SwarmConnectionLimit { get; set; } = 15;

        /// <summary>
        /// We have a small delay when removing circuits/relays/exit nodes. This is to allow some post-mortem data
        /// to flow over the circuit (i.e. bandwidth payouts to intermediate nodes in a circuit).
        /// </summary>
        public double RemoveTunnelDelay { get; set; } = 5;

        private HashSet<int> _peerFlags = new HashSet<int> { Tunnel.PeerFlagRelay, Tunnel.PeerFlagSpeedTest };

        private int _maxRelayEarly = 8;

        public DhtCommunityProvider DhtProvider { get; set; }

        /// <summary>The maximum number of relay_early cells that are allowed to pass a relay.</summary>
        public int MaxRelayEarly
        {
            get => _maxRelayEarly;
            set => _maxRelayEarly = value;
        }

        /// <summary>The peer flags.</summary>
        public HashSet<int> PeerFlags
        {
            get => _peerFlags;
            set => _peerFlags = value ?? new HashSet<int>();
        }
    }

    /// <summary>
    /// Community to create circuits of intermediate peers (hops) that send data into (exit) and receive from
    /// the Internet (community.py::TunnelCommunity).
    /// </summary>
    public class TunnelCommunity : Community
    {
        private static readonly TraceSource Log = new TraceSource("TunnelCommunity");

        private static readonly Random Random = new Random();

        public new const byte Version = 0x02;

        private static readonly byte[] CommunityIdBytes =
            Util.Unhex("81ded07332bdc775aa5a46f96de9f8f390bbc9f3");

        public new TunnelSettings Settings { get; }

        public DhtCommunityProvider DhtProvider { get; }

        public RequestCache RequestCache { get; } = new RequestCache();

        /// <summary>Handler for messages that are exclusively tunneled (i.e., never handled plaintext).</summary>
        public delegate void CellHandler(Address sourceAddress, byte[] data, long? circuitId);

        private readonly Dictionary<int, CellHandler> _decodeMapPrivate =
            new Dictionary<int, CellHandler>();

        /// <summary>The cell decode map (py decode_map_private; public for test access).</summary>
        public IReadOnlyDictionary<int, CellHandler> DecodeMapPrivate => _decodeMapPrivate;

        /// <summary>Wanted circuits per hop count (py defaultdict(int)).</summary>
        private readonly Dictionary<int, int> _circuitsNeeded = new Dictionary<int, int>();

        /// <summary>Keeps track of the candidates that want to be a relay/exit node.</summary>
        private readonly Dictionary<Peer, List<int>> _candidates = new Dictionary<Peer, List<int>>();

        public TunnelCrypto Crypto { get; }

        public ICryptoEndpoint CryptoEndpoint { get; }

        public Dictionary<long, Circuit> Circuits => CryptoEndpoint.Circuits;

        public Dictionary<long, RelayRoute> RelayFromTo => CryptoEndpoint.Relays;

        public Dictionary<long, TunnelExitSocket> ExitSockets => CryptoEndpoint.ExitSockets;

        public IReadOnlyDictionary<Peer, List<int>> Candidates => _candidates;

        /// <summary>Wanted circuits per hop count, keyed by the hop count.</summary>
        public IReadOnlyDictionary<int, int> CircuitsNeeded => _circuitsNeeded;

        /// <summary>Factory for the crypto endpoint (tests override this to sniff outgoing cells).</summary>
        protected virtual ICryptoEndpoint CreateCryptoEndpoint(Endpoint endpoint)
        {
            return new PythonCryptoEndpoint(endpoint);
        }

        public TunnelCommunity(TunnelSettings settings)
            : base(settings, CommunityIdBytes)
        {
            Settings = settings;
            DhtProvider = settings.DhtProvider;

            // Messages that can arrive from the socket
            AddMessageHandler(CellPayload.MsgId, OnCell);
            AddMessageHandler(typeof(DestroyPayload), OnDestroyRaw);

            // Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
            AddCellHandler(DataPayload.MsgId, OnData);
            AddCellHandler(CreatePayload.MsgId, OnCreate);
            AddCellHandler(CreatedPayload.MsgId, OnCreated);
            AddCellHandler(ExtendPayload.MsgId, OnExtend);
            AddCellHandler(ExtendedPayload.MsgId, OnExtended);
            AddCellHandler(PingPayload.MsgId, OnPing);
            AddCellHandler(PongPayload.MsgId, OnPong);
            AddCellHandler(TestRequestPayload.MsgId, OnTestRequest);
            AddCellHandler(TestResponsePayload.MsgId, OnTestResponse);

            Crypto = new TunnelCrypto();
            Crypto.Initialize((PrivateKey)MyPeer.Key);

            // For now, the TunnelCommunity only supports IPv4 for control messages.
            // Data packets can still be sent to IPv6 destinations.
            CryptoEndpoint = Endpoint is ICryptoEndpoint existing
                ? existing
                : CreateCryptoEndpoint(Endpoint);
            CryptoEndpoint.Settings = Settings;
            CryptoEndpoint.SetupTunnels(this, Settings);

            if (Endpoint is TunnelEndpoint tunnelEndpoint)
            {
                tunnelEndpoint.SetTunnelCommunity(this);
                tunnelEndpoint.SetAnonymity(GetPrefix(), false);
            }

            RegisterTask("do_circuits", DoCircuits, delay: 0, interval: 5);
            RegisterTask("do_ping", () => DoPing(), interval: Tunnel.PingInterval);
        }

        /// <summary>Extend our serializer with the ability to (un)pack exit node flags.</summary>
        protected override Serializer GetSerializer()
        {
            var serializer = base.GetSerializer();
            serializer.AddPacker("flags", new FlagsPacker());
            return serializer;
        }

        /// <summary>Handler for messages that are exclusively tunneled (i.e., never handled plaintext).</summary>
        protected void AddCellHandler(int msgId, CellHandler handler)
        {
            _decodeMapPrivate[msgId] = handler;
        }

        private long GenerateCircuitId()
        {
            long circuitId = Random.Next(1 << 30) | (Random.Next(1 << 2) << 30);
            circuitId &= 0xFFFFFFFF;

            // Prevent collisions.
            while (Circuits.ContainsKey(circuitId))
            {
                circuitId = Random.Next(1 << 30) | (Random.Next(1 << 2) << 30);
                circuitId &= 0xFFFFFFFF;
            }

            return circuitId;
        }

        /// <summary>
        /// Check if we have sufficient circuits and attempt to create new circuits if we have too little.
        /// </summary>
        public virtual void DoCircuits()
        {
            foreach (var needed in _circuitsNeeded)
            {
                var circuitLength = needed.Key;
                var numCircuits = needed.Value;
                var numToBuild = Math.Max(0, numCircuits - FindCircuits(state: null, hops: circuitLength).Count);
                if (numToBuild == 0)
                {
                    continue;
                }
                Log.TraceEvent(TraceEventType.Information, 0,
                    $"Want {numToBuild} data circuits of length {circuitLength}");
                for (var i = 0; i < numToBuild; i++)
                {
                    if (CreateCircuit(circuitLength) == null)
                    {
                        Log.TraceEvent(TraceEventType.Information, 0,
                            "Circuit creation of " + numToBuild + " circuits failed, no need to continue");
                        break;
                    }
                }
            }
            DoRemove();
        }

        /// <summary>Signal that we want circuits of a given number of hops.</summary>
        public void BuildTunnels(int hops)
        {
            if (hops > 0)
            {
                _circuitsNeeded[hops] = Settings.MaxCircuits;
                DoCircuits();
            }
        }

        /// <summary>Fraction of circuits that are available for the given hop count.</summary>
        public double TunnelsReady(int hops)
        {
            if (hops > 0 && _circuitsNeeded.TryGetValue(hops, out var needed) && needed > 0)
            {
                return FindCircuits(hops: hops).Count / (double)needed;
            }
            return 1.0;
        }

        /// <summary>
        /// Remove all circuits that are inactive, old or overused and remove old peers from our candidate list.
        /// </summary>
        public void DoRemove()
        {
            var now = Util.NowEpoch();

            // Remove circuits that are inactive / are too old / have transferred too many bytes.
            foreach (var circuitId in Circuits.Keys.ToList())
            {
                var circuit = Circuits[circuitId];
                if (circuit.State == Tunnel.CircuitStateReady
                    && circuit.LastActivity < now - Settings.MaxTimeInactive)
                {
                    RemoveCircuit(circuitId, "no activity");
                }
                else if (circuit.CreationTime < now - GetMaxTime(circuitId))
                {
                    RemoveCircuit(circuitId, "too old");
                }
                else if (circuit.BytesUp + circuit.BytesDown > Settings.MaxTraffic)
                {
                    RemoveCircuit(circuitId, "traffic limit exceeded", destroy: true);
                }
            }

            // Remove relays that are inactive / have transferred too many bytes.
            foreach (var circuitId in RelayFromTo.Keys.ToList())
            {
                var relay = RelayFromTo[circuitId];
                if (relay.LastActivity < now - Settings.MaxTimeInactive)
                {
                    RemoveRelay(circuitId, "no activity");
                }
                else if (relay.BytesUp + relay.BytesDown > Settings.MaxTraffic)
                {
                    RemoveRelay(circuitId, "traffic limit exceeded", destroy: true);
                }
            }

            // Remove exit sockets that are too old / have transferred too many bytes.
            foreach (var circuitId in ExitSockets.Keys.ToList())
            {
                var exitSocket = ExitSockets[circuitId];
                if (exitSocket.LastActivity < now - Settings.MaxTimeInactive)
                {
                    RemoveExitSocket(circuitId, "no activity");
                }
                else if (exitSocket.CreationTime < now - GetMaxTime(circuitId))
                {
                    RemoveExitSocket(circuitId, "too old");
                }
                else if (exitSocket.BytesUp + exitSocket.BytesDown > Settings.MaxTraffic)
                {
                    RemoveExitSocket(circuitId, "traffic limit exceeded", destroy: true);
                }
            }

            // Remove candidates that are not returned as verified peers
            var currentPeers = GetPeers();
            foreach (var peer in _candidates.Keys.ToList())
            {
                if (!currentPeers.Contains(peer))
                {
                    _candidates.Remove(peer);
                }
            }
        }

        /// <summary>Get all the peers that we can create circuits with.</summary>
        public List<Peer> GetCandidates(params int[] requestedFlags)
        {
            var requested = new HashSet<int>(requestedFlags);
            return _candidates.Where(kv => requested.IsSubsetOf(kv.Value)
                                           && Crypto.IsKeyCompatible(kv.Key.PublicKey))
                              .Select(kv => kv.Key)
                              .ToList();
        }

        /// <summary>Get the maximum time (in seconds) that the given circuit is allowed to exist.</summary>
        public virtual double GetMaxTime(long circuitId)
        {
            return Settings.MaxTime;
        }

        /// <summary>
        /// Get circuits of the given type and state (and potentially exit flags and a given number of hops).
        /// </summary>
        public List<Circuit> FindCircuits(string ctype = Tunnel.CircuitTypeData,
                                          string state = Tunnel.CircuitStateReady,
                                          int[] exitFlags = null, int? hops = null)
        {
            return Circuits.Values.Where(c => (state == null || c.State == state)
                                              && (ctype == null || c.CType == ctype)
                                              && (exitFlags == null
                                                  || new HashSet<int>(exitFlags).IsSubsetOf(c.ExitFlags))
                                              && (hops == null || hops == c.GoalHops))
                                  .ToList();
        }

        /// <summary>
        /// Create a circuit of a given number of hops. The circuit will be created immediately but not be
        /// available for transmission of data immediately. Note that not all circuits exist to send data.
        ///
        /// Returns null if we are supposed to find an exit node and know of none.
        /// </summary>
        public Circuit CreateCircuit(int goalHops, string ctype = Tunnel.CircuitTypeData,
                                     int[] exitFlags = null, Peer requiredExit = null, byte[] infoHash = null)
        {
            return CreateCircuitImpl(goalHops, ctype, exitFlags, requiredExit, infoHash);
        }

        /// <summary>Overridable circuit creation core (hidden services observe the hop count).</summary>
        protected virtual Circuit CreateCircuitImpl(int goalHops, string ctype = Tunnel.CircuitTypeData,
                                                    int[] exitFlags = null, Peer requiredExit = null,
                                                    byte[] infoHash = null)
        {
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Creating a new circuit of length {goalHops} (type: {ctype})");

            if (ctype == Tunnel.CircuitTypeIpSeeder && requiredExit == null)
            {
                requiredExit = SelectExit(ctype: ctype);
            }
            else if (exitFlags != null)
            {
                requiredExit = SelectExit(exitFlags: exitFlags);
            }

            List<Peer> possibleFirstHops;
            if (goalHops == 1)
            {
                if (requiredExit == null)
                {
                    requiredExit = SelectExit(exitFlags, ctype);
                    if (requiredExit == null)
                    {
                        Log.TraceEvent(TraceEventType.Information, 0,
                            "Could not create circuit, no available exit-nodes");
                        return null;
                    }
                }
                // If the number of hops is 1, it should immediately be the required_exit hop.
                Log.TraceEvent(TraceEventType.Information, 0, "First hop is required exit");
                possibleFirstHops = new List<Peer> { requiredExit };
            }
            else
            {
                Log.TraceEvent(TraceEventType.Information, 0,
                    "Look for a first hop that is not an exit node and is least frequently used");
                // First build a list of hops, then filter the list. Avoids issues when create_circuit is called
                // from a different thread (caused by circuit.peer being reset to None).
                var firstHops = Circuits.Values
                    .Where(c => c.CType == ctype && c.Hop != null && c.Hop.Peer != null)
                    .Select(c => c.Hop.Peer)
                    .ToList();
                // Note that peers that are both relay and exit are in the list twice.
                // This will lower the likelihood that these peers are picked as first hop.
                var candidateList = new List<Peer>(firstHops);
                candidateList.AddRange(GetCandidates(Tunnel.PeerFlagRelay));
                candidateList.AddRange(GetCandidates(Tunnel.PeerFlagRelay, Tunnel.PeerFlagExitBt));

                var shuffled = candidateList.OrderBy(_ => Random.Next()).ToList();
                // Build a list of possible first hops, with the least frequently used hops first.
                // py: Counter.most_common() (count DESC) then reversed (count ASC).
                var counts = new List<(Peer Peer, int Count)>();
                foreach (var peer in shuffled)
                {
                    var found = false;
                    for (var i = 0; i < counts.Count; i++)
                    {
                        if (counts[i].Peer.Equals(peer))
                        {
                            counts[i] = (peer, counts[i].Count + 1);
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                    {
                        counts.Add((peer, 1));
                    }
                }
                var ordered = counts.OrderByDescending(kv => kv.Count).ToList();
                ordered.Reverse();
                possibleFirstHops = ordered.Where(kv => requiredExit == null || !kv.Peer.Equals(requiredExit))
                                           .Select(kv => kv.Peer)
                                           .ToList();
            }

            if (possibleFirstHops.Count == 0)
            {
                Log.TraceEvent(TraceEventType.Information, 0, "Could not create circuit, no first hop available");
                return null;
            }

            // Finally, construct the Circuit object and send the CREATE message
            var circuitId = GenerateCircuitId();
            var circuit = new Circuit(circuitId, goalHops, ctype, requiredExit, infoHash);
            Circuits[circuitId] = circuit;
            SendInitialCreate(circuit, possibleFirstHops,
                              (int)(Settings.CircuitTimeout / Settings.NextHopTimeout));

            return circuit;
        }

        /// <summary>Select an exit node based on the required peer flags and circuit type.</summary>
        public Peer SelectExit(int[] exitFlags = null, string ctype = Tunnel.CircuitTypeData)
        {
            List<Peer> exitCandidates;
            if (exitFlags != null)
            {
                exitCandidates = GetCandidates(exitFlags);
            }
            else if (ctype == Tunnel.CircuitTypeData)
            {
                exitCandidates = GetCandidates(Tunnel.PeerFlagExitBt);
            }
            else if (ctype == Tunnel.CircuitTypeIpSeeder)
            {
                // For introduction points we prefer exit nodes, but perhaps a relay peer would also suffice.
                exitCandidates = GetCandidates(Tunnel.PeerFlagExitBt);
                if (exitCandidates.Count == 0)
                {
                    exitCandidates = GetCandidates(Tunnel.PeerFlagExitIpv8);
                }
                if (exitCandidates.Count == 0)
                {
                    exitCandidates = GetCandidates(Tunnel.PeerFlagRelay);
                }
            }
            else
            {
                // For exit nodes that don't exit actual data, we prefer relay candidates,
                // but we also consider exit candidates.
                exitCandidates = GetCandidates(Tunnel.PeerFlagRelay);
                if (exitCandidates.Count == 0)
                {
                    exitCandidates = GetCandidates(Tunnel.PeerFlagExitBt);
                }
            }
            return exitCandidates.Count > 0 ? exitCandidates[Random.Next(exitCandidates.Count)] : null;
        }

        /// <summary>Attempt to establish the first hop in a Circuit.</summary>
        public void SendInitialCreate(Circuit circuit, List<Peer> candidatePeers, int maxTries)
        {
            if (RequestCache.Has(RetryRequestCache.Name, (int)circuit.CircuitId))
            {
                RequestCache.Pop(RetryRequestCache.Name, (int)circuit.CircuitId);
                Log.TraceEvent(TraceEventType.Information, 0,
                    $"Retrying first hop for circuit {circuit.CircuitId}");
            }

            var firstHop = candidatePeers[0];
            var altFirstHops = candidatePeers.Where(c => !c.Equals(firstHop)).ToList();

            circuit.UnverifiedHop = new Hop(firstHop, flags: _candidates.TryGetValue(firstHop, out var flags)
                                                               ? flags
                                                               : null);
            var (dhSecret, dhFirstPart) = Crypto.GenerateDiffieSecret();
            circuit.UnverifiedHop.DhSecret = dhSecret;
            circuit.UnverifiedHop.DhFirstPart = dhFirstPart;

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Adding first hop {firstHop.Address} to circuit {circuit.CircuitId}");

            var cache = new RetryRequestCache(this, circuit, altFirstHops.Cast<object>().ToList(),
                                              maxTries - 1,
                                              (retryCircuit, retryCandidates, retryMaxTries)
                                                  => SendInitialCreate(retryCircuit,
                                                                       retryCandidates.Cast<Peer>().ToList(),
                                                                       retryMaxTries),
                                              Settings.NextHopTimeout);
            RequestCache.Add(cache);

            SendCell(firstHop.Address,
                     new CreatePayload(circuit.CircuitId,
                                       cache.PacketIdentifier,
                                       MyPeer.PublicKey.KeyToBin(),
                                       circuit.UnverifiedHop.DhFirstPart));
        }

        /// <summary>Remove a circuit and optionally send a destroy message.</summary>
        public virtual void RemoveCircuit(long circuitId, string additionalInfo = "", bool removeNow = false,
                                          object destroy = null)
        {
            RunAnonymousIgnoringErrors("remove_circuit",
                () => RemoveCircuitAsync(circuitId, additionalInfo, removeNow, destroy));
        }

        /// <summary>
        /// Fire-and-forget an async task the py-ipv8 way: anonymous tasks are registered with
        /// ignore=(Exception,), so late failures (e.g. sending a destroy on an endpoint that was
        /// closed during shutdown) are swallowed instead of crashing the process.
        /// </summary>
        private void RunAnonymousIgnoringErrors(string name, Func<Task> taskFactory)
        {
            RegisterAnonymousTask(name, () =>
            {
                _ = taskFactory().ContinueWith(t =>
                {
                    var error = t.Exception?.GetBaseException();
                    if (error != null)
                    {
                        Log.TraceEvent(TraceEventType.Error, 0,
                            $"Anonymous task '{name}' failed: {error.GetType().Name}: {error.Message}");
                    }
                }, TaskContinuationOptions.OnlyOnFaulted);
            });
        }

        private async Task RemoveCircuitAsync(long circuitId, string additionalInfo = "",
                                              bool removeNow = false, object destroy = null)
        {
            if (RequestCache.Has(RetryRequestCache.Name, (int)circuitId))
            {
                RequestCache.Pop(RetryRequestCache.Name, (int)circuitId);
            }

            var circuitToRemove = Circuits.TryGetValue(circuitId, out var found) ? found : null;
            if (circuitToRemove == null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, $"Cannot remove unknown circuit {circuitId}");
                return;
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Removing {circuitToRemove.CType} circuit {circuitId} {additionalInfo}");

            var reason = DestroyReasonOf(destroy);
            if (destroy != null && (reason != 0 || destroy is bool))
            {
                DestroyCircuit(circuitToRemove, reason);
            }

            circuitToRemove.Close(additionalInfo);

            if (!removeNow || Settings.RemoveTunnelDelay > 0)
            {
                await Task.Delay((int)(Settings.RemoveTunnelDelay * 1000)).ConfigureAwait(false);
            }

            if (Circuits.Remove(circuitId))
            {
                Log.TraceEvent(TraceEventType.Information, 0,
                    $"Removed circuit {circuitId} {additionalInfo}");
            }
        }

        /// <summary>Remove a relay and all information associated with the relay.</summary>
        public void RemoveRelay(long circuitId, string additionalInfo = "", bool removeNow = false,
                                object destroy = null)
        {
            RunAnonymousIgnoringErrors("remove_relay",
                () => RemoveRelayAsync(circuitId, additionalInfo, removeNow, destroy));
        }

        private async Task<RelayRoute> RemoveRelayAsync(long circuitId, string additionalInfo = "",
                                                        bool removeNow = false, object destroy = null)
        {
            // Send destroy
            var reason = DestroyReasonOf(destroy);
            if (destroy != null && (reason != 0 || destroy is bool))
            {
                DestroyRelay(circuitId, reason);
            }

            if (!removeNow || Settings.RemoveTunnelDelay > 0)
            {
                await Task.Delay((int)(Settings.RemoveTunnelDelay * 1000)).ConfigureAwait(false);
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Removing relay {circuitId} {additionalInfo}");

            return RelayFromTo.TryGetValue(circuitId, out var relay) && RelayFromTo.Remove(circuitId)
                ? relay
                : null;
        }

        /// <summary>Remove an exit socket. Send a destroy message if necessary.</summary>
        public virtual void RemoveExitSocket(long circuitId, string additionalInfo = "", bool removeNow = false,
                                             object destroy = null)
        {
            RunAnonymousIgnoringErrors("remove_exit_socket",
                () => RemoveExitSocketAsync(circuitId, additionalInfo, removeNow, destroy));
        }

        private async Task<TunnelExitSocket> RemoveExitSocketAsync(long circuitId, string additionalInfo = "",
                                                                   bool removeNow = false, object destroy = null)
        {
            var exitSocketToDestroy = ExitSockets.TryGetValue(circuitId, out var found) ? found : null;
            var reason = DestroyReasonOf(destroy);
            if (exitSocketToDestroy != null && destroy != null && (reason != 0 || destroy is bool))
            {
                DestroyExitSocket(exitSocketToDestroy, reason);
            }

            if (!removeNow || Settings.RemoveTunnelDelay > 0)
            {
                await Task.Delay((int)(Settings.RemoveTunnelDelay * 1000)).ConfigureAwait(false);
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Removing exit socket {circuitId} {additionalInfo}");
            if (ExitSockets.TryGetValue(circuitId, out var exitSocket) && ExitSockets.Remove(circuitId))
            {
                // Close socket
                if (exitSocket.Enabled)
                {
                    await exitSocket.Close().ConfigureAwait(false);
                }
                else
                {
                    exitSocket.ShutdownTasks();
                }
                return exitSocket;
            }
            return null;
        }

        /// <summary>Interpret the py ``destroy`` argument (bool or int) as a destroy reason.</summary>
        private static int DestroyReasonOf(object destroy)
        {
            return destroy switch
            {
                null => 0,
                int i => i,
                bool b => b ? 1 : 0,
                long l => (int)l,
                _ => 0
            };
        }

        /// <summary>Send a destroy message over a circuit. Note that the circuit will still exist.</summary>
        public void DestroyCircuit(Circuit circuit, int reason = 0)
        {
            var sockAddr = circuit.Hop.Address;
            SendDestroy(sockAddr, circuit.CircuitId, reason);
            Log.TraceEvent(TraceEventType.Information, 0, $"destroy_circuit {circuit.CircuitId} {sockAddr}");
        }

        /// <summary>
        /// Destroy our relay circuit upon request and forward a destroy message.
        /// Note that the relay route will still exist.
        /// </summary>
        public void DestroyRelay(long circuitId, int reason = 0)
        {
            if (RelayFromTo.TryGetValue(circuitId, out var relay))
            {
                Log.TraceEvent(TraceEventType.Information, 0,
                    $"Send destroy for relay {circuitId} -> {relay.CircuitId} ({relay.Hop.Address})");
                SendDestroy(relay.Hop.Address, relay.CircuitId, reason);
            }
        }

        /// <summary>Destroy an exit socket. Note that the exit socket will still exist.</summary>
        public void DestroyExitSocket(TunnelExitSocket exitSocket, int reason = 0)
        {
            var sockAddr = exitSocket.Hop.Address;
            SendDestroy(sockAddr, exitSocket.CircuitId, reason);
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Destroy_exit_socket {exitSocket.CircuitId} {sockAddr}");
        }

        /// <summary>
        /// Send the given payload DIRECTLY to the given peer with the appropriate encryption rules.
        /// </summary>
        public void SendCell(Address targetAddr, CellablePayload payload)
        {
            var message = Util.SliceFrom(Serializer.PackSerializable(payload), 4);
            var cell = new CellPayload(payload.CircuitId,
                                       Util.Concat(new[] { (byte)payload.MsgNum }, message));
            cell.Plaintext = AnonymizationCells.IsNoCrypto(payload.MsgNum);
            CryptoEndpoint.SendCell(targetAddr, cell);
        }

        /// <summary>Pack the given binary data and forward it to the given peer.</summary>
        public void SendData(Address target, long circuitId, Address destAddress,
                             Address sourceAddress, byte[] data)
        {
            var payload = new DataPayload(circuitId, destAddress, sourceAddress, data);
            SendCell(target, payload);
        }

        /// <summary>Send raw data over the socket to a given peer and return the length of the sent data.</summary>
        public int SendPacket(Address target, byte[] packet)
        {
            Endpoint.Send(target, packet);
            return packet.Length;
        }

        /// <summary>Send a destroy message directly to the given peer.</summary>
        public void SendDestroy(Address target, long circuitId, int reason)
        {
            var packet = EzrPack(DestroyPayload.MsgId, new DestroyPayload(circuitId, reason));
            SendPacket(target, packet);
        }

        private void OursOnCreatedExtended(long circuitId, Payload payload)
        {
            var circuit = Circuits[circuitId];
            var hop = circuit.UnverifiedHop;

            if (hop == null || hop.DhSecret == null)
            {
                Log.TraceEvent(TraceEventType.Error, 0,
                    $"Can't extend circuit {circuitId} (no unverified hop)");
                return;
            }

            byte[] sharedSecret;
            byte[] payloadKey;
            byte[] payloadAuth;
            byte[] candidatesEnc;
            if (payload is CreatedPayload createdPayload)
            {
                payloadKey = createdPayload.Key;
                payloadAuth = createdPayload.Auth;
                candidatesEnc = createdPayload.CandidatesEnc;
            }
            else
            {
                var extendedPayload = (ExtendedPayload)payload;
                payloadKey = extendedPayload.Key;
                payloadAuth = extendedPayload.Auth;
                candidatesEnc = extendedPayload.CandidatesEnc;
            }
            try
            {
                sharedSecret = TunnelCrypto.VerifyAndGenerateSharedSecret(
                    hop.DhSecret, payloadKey, payloadAuth, hop.Peer.PublicKey.GetCryptPk());
            }
            catch (CryptoException)
            {
                RemoveCircuit(circuit.CircuitId, "error while verifying shared secret");
                return;
            }
            var sessionKeys = TunnelCrypto.GenerateSessionKeys(sharedSecret);
            hop.Keys = sessionKeys;

            circuit.UnverifiedHop = null;
            circuit.AddHop(hop);
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Added hop {circuit.Hops.Count} ({hop.Peer}) to circuit {circuit.CircuitId}");

            if (circuit.State == Tunnel.CircuitStateExtending)
            {
                var candidatesBin = sessionKeys.DecryptStr(candidatesEnc, Tunnel.Forward);
                var candidates = PexCommunity.UnpackVarlenHList(candidatesBin);

                var relayCandidates = candidates;
                var exitCandidates = new List<byte[]>();
                for (var i = 0; i < candidates.Count - 1; i++)
                {
                    if (Util.BytesEqual(candidates[i], candidates[i + 1]))
                    {
                        relayCandidates = candidates.GetRange(0, i);
                        exitCandidates = candidates.GetRange(i + 1, candidates.Count - (i + 1));
                        break;
                    }
                }

                var becomeExit = circuit.GoalHops - 1 == circuit.Hops.Count;
                // If there aren't enough relays, we'll extend to exits. We currently assume that exits also
                // allow relaying.
                var chosen = becomeExit
                    ? exitCandidates
                    : (relayCandidates.Count > 0 ? relayCandidates : exitCandidates);

                var cache = RequestCache.Pop(RetryRequestCache.Name, (int)circuit.CircuitId) as RetryRequestCache;
                SendExtend(circuit, chosen, cache?.MaxTries ?? 1);
            }
            else if (circuit.State == Tunnel.CircuitStateReady)
            {
                RequestCache.Pop(RetryRequestCache.Name, (int)circuit.CircuitId);
            }
        }

        /// <summary>Extend a circuit by choosing one of the given candidates.</summary>
        public void SendExtend(Circuit circuit, List<byte[]> candidates, int maxTries)
        {
            var becomeExit = circuit.GoalHops - 1 == circuit.Hops.Count;
            byte[] extendHopPublicBin;
            Address extendHopAddr;
            if (becomeExit && circuit.RequiredExit != null)
            {
                // Set the required exit according to the circuit setting (e.g. for linking e2e circuits)
                extendHopPublicBin = circuit.RequiredExit.PublicKey.KeyToBin();
                extendHopAddr = circuit.RequiredExit.Address;
            }
            else
            {
                // Chose the next candidate. Ensure we didn't use this candidate already, and its key is
                // compatible.
                var exclude = new List<byte[]>();
                foreach (var hop in circuit.Hops)
                {
                    exclude.Add(hop.PublicKeyBin);
                }
                exclude.Add(MyPeer.PublicKey.KeyToBin());
                if (circuit.RequiredExit != null)
                {
                    exclude.Add(circuit.RequiredExit.PublicKey.KeyToBin());
                }
                candidates = candidates.Where(c => !exclude.Any(e => Util.BytesEqual(e, c))
                                                   && Crypto.KeyFromPublicBin(c) != null).ToList();
                extendHopPublicBin = candidates.Count > 0 ? candidates[0] : Util.EmptyBytes;
                extendHopAddr = Address.Zero;

                if (extendHopPublicBin.Length == 0)
                {
                    // By default, nodes will give a number of candidates to which we can extend the circuit
                    // (i.e., peers that have already been punctured). However, it could be that there simply
                    // aren't enough candidates available. When this happens, we try to extend to exit nodes
                    // (which we assume are connectable).
                    var choices = GetCandidates(Tunnel.PeerFlagExitBt, Tunnel.PeerFlagRelay)
                        .Where(peer => !exclude.Any(e => Util.BytesEqual(e, peer.PublicKey.KeyToBin())))
                        .ToList();
                    if (choices.Count > 0)
                    {
                        var peer = choices[Random.Next(choices.Count)];
                        extendHopPublicBin = peer.PublicKey.KeyToBin();
                        extendHopAddr = peer.Address;
                        Log.TraceEvent(TraceEventType.Information, 0,
                            $"No candidates to extend to, trying exit node {peer} instead");
                    }
                }
            }

            if (extendHopPublicBin.Length > 0)
            {
                if (RequestCache.Has(RetryRequestCache.Name, (int)circuit.CircuitId))
                {
                    RequestCache.Pop(RetryRequestCache.Name, (int)circuit.CircuitId);
                    Log.TraceEvent(TraceEventType.Information, 0,
                        $"Retrying hop {circuit.Hops.Count + 1} for circuit {circuit.CircuitId}");
                }

                var extendHopPublicKey = Crypto.KeyFromPublicBin(extendHopPublicBin);
                _ = extendHopPublicKey;
                var hop = new Hop(new Peer(extendHopPublicBin),
                                  flags: _candidates.TryGetValue(new Peer(extendHopPublicBin),
                                                                 out var flags) ? flags : null);
                var (dhSecret, dhFirstPart) = Crypto.GenerateDiffieSecret();
                hop.DhSecret = dhSecret;
                hop.DhFirstPart = dhFirstPart;
                circuit.UnverifiedHop = hop;

                Log.TraceEvent(TraceEventType.Information, 0,
                    $"Extending circuit {circuit.CircuitId} with {Util.Hex(extendHopPublicBin)}");

                // Only retry if we are allowed to use another node
                List<byte[]> altCandidates;
                if (!becomeExit || circuit.RequiredExit == null)
                {
                    altCandidates = candidates.Where(c => !Util.BytesEqual(c, extendHopPublicBin)).ToList();
                }
                else
                {
                    altCandidates = new List<byte[]>();
                }

                var cache = new RetryRequestCache(this, circuit,
                                                  altCandidates.Cast<object>().ToList(), maxTries - 1,
                                                  (retryCircuit, retryCandidates, retryMaxTries)
                                                      => SendExtend(retryCircuit,
                                                                    retryCandidates.Cast<byte[]>().ToList(),
                                                                    retryMaxTries),
                                                  Settings.NextHopTimeout);
                RequestCache.Add(cache);

                SendCell(circuit.Hop.Address,
                         new ExtendPayload(circuit.CircuitId,
                                           cache.PacketIdentifier,
                                           circuit.UnverifiedHop.PublicKeyBin,
                                           circuit.UnverifiedHop.DhFirstPart,
                                           extendHopAddr));
            }
            else
            {
                RemoveCircuit(circuit.CircuitId, "no candidates to extend");
            }
        }

        /// <summary>Convert piggybacked introduction bytes to a list of peer flags.</summary>
        public List<int> ExtractPeerFlags(byte[] extraBytes)
        {
            if (extraBytes == null || extraBytes.Length == 0)
            {
                return new List<int>();
            }

            var payload = Serializer.UnpackSerializableAs<ExtraIntroductionPayload>(extraBytes, 0);
            return payload.Flags;
        }

        protected override void IntroductionRequestCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                            Payload payload)
        {
            // Try to extract piggybacked data from the introduction request.
            _candidates[peer] = ExtractPeerFlags(GetExtraBytes(payload));
        }

        protected override void IntroductionResponseCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                             Payload payload)
        {
            // Try to extract piggybacked data from the introduction response.
            _candidates[peer] = ExtractPeerFlags(GetExtraBytes(payload));
        }

        private static byte[] GetExtraBytes(Payload payload)
        {
            return payload switch
            {
                IntroductionRequestPayload p => p.ExtraBytes,
                NewIntroductionRequestPayload p => p.ExtraBytes,
                IntroductionResponsePayload p => p.ExtraBytes,
                NewIntroductionResponsePayload p => p.ExtraBytes,
                _ => Util.EmptyBytes
            };
        }

        public override byte[] CreateIntroductionRequest(Address socketAddress, byte[] extraBytes = null,
                                                         bool newStyle = false, byte[] prefix = null)
        {
            // Add peer flags to our introduction requests.
            var extraPayload = new ExtraIntroductionPayload(new List<int>(Settings.PeerFlags));
            extraBytes = Serializer.PackSerializable(extraPayload);
            return base.CreateIntroductionRequest(socketAddress, extraBytes, newStyle);
        }

        public override byte[] CreateIntroductionResponse(Address lanSocketAddress, Address socketAddress,
                                                          long identifier, Peer introduction = null,
                                                          byte[] extraBytes = null, byte[] prefix = null,
                                                          bool newStyle = false)
        {
            // Add peer flags to our introduction responses.
            var extraPayload = new ExtraIntroductionPayload(new List<int>(Settings.PeerFlags));
            extraBytes = Serializer.PackSerializable(extraPayload);
            return base.CreateIntroductionResponse(lanSocketAddress, socketAddress, identifier,
                                                   introduction, extraBytes, prefix, newStyle);
        }

        private Task OnCell(Address sourceAddress, byte[] data)
        {
            // Process an incoming cell, originating from a given address.
            var cell = CellPayload.FromBin(data);
            if (cell.Plaintext && !AnonymizationCells.IsNoCrypto(cell.Message[0]))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Got a cell with wrongfully set plaintext flag from circuit {cell.CircuitId}");
                return Task.CompletedTask;
            }

            OnPacketFromCircuit(sourceAddress, cell.Unwrap(GetPrefix()), cell.CircuitId);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Process incoming raw data, assumed to be an IPv8 packet, originating from a given address.
        /// </summary>
        public void OnPacketFromCircuit(Address sourceAddress, byte[] data, long circuitId)
        {
            var prefix = GetPrefix();
            if (!Util.StartsWith(data, prefix))
            {
                return;
            }
            var msgId = data[22];
            if (_decodeMapPrivate.TryGetValue(msgId, out var handler))
            {
                try
                {
                    handler(sourceAddress, data, circuitId);
                }
                catch (Exception e)
                {
                    Log.TraceEvent(TraceEventType.Error, 0,
                        "Exception occurred while handling packet: " + e);
                }
            }
        }

        /// <summary>Check whether we should join a circuit. Intended to be overwritten.</summary>
        public virtual bool ShouldJoinCircuit(CreatePayload createPayload, Address previousNodeAddress)
        {
            if (Settings.MaxJoinedCircuits <= RelayFromTo.Count + ExitSockets.Count)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Too many relays ({RelayFromTo.Count + ExitSockets.Count})");
                return false;
            }
            return true;
        }

        /// <summary>Actively join a circuit and send a created message back.</summary>
        public void JoinCircuit(CreatePayload createPayload, Address previousNodeAddress)
        {
            var circuitId = createPayload.CircuitId;

            Log.TraceEvent(TraceEventType.Information, 0,
                $"We joined circuit {circuitId} with neighbour {previousNodeAddress}");

            var (sharedSecret, key, auth) = Crypto.GenerateDiffieSharedSecret(createPayload.Key);
            var sessionKeys = TunnelCrypto.GenerateSessionKeys(sharedSecret);

            // In order to remain compatible with older peers, we ensure exits also have the RELAY flag set.
            var exitCandidates = GetCandidates(Tunnel.PeerFlagExitBt, Tunnel.PeerFlagRelay);
            var exitList = exitCandidates.GetRange(0, Math.Min(4, exitCandidates.Count));
            if (exitList.Count > 0)
            {
                // Separate relay-only nodes and exit nodes by listing the first exit twice.
                // Next time we make a breaking change in the protocol, this should be split into 2 lists.
                exitList.Insert(0, exitList[0]);
            }
            var relayOnly = GetCandidates(Tunnel.PeerFlagRelay)
                .Where(peer => !_candidates.TryGetValue(peer, out var flags) || flags == null
                               || !flags.Contains(Tunnel.PeerFlagExitBt))
                .Take(4)
                .ToList();
            var peersList = new List<Peer>(relayOnly);
            peersList.AddRange(exitList);
            var peersKeys = peersList.Select(peer => peer.PublicKey.KeyToBin()).ToList();
            var peersDict = new Dictionary<byte[], Peer>(ByteArrayEqualityComparer.Instance);
            foreach (var peer in peersList)
            {
                peersDict[peer.PublicKey.KeyToBin()] = peer;
            }

            var createdPeer = new Peer(createPayload.NodePublicKey, previousNodeAddress);
            RequestCache.Add(new CreatedRequestCache(this, circuitId, createdPeer, peersDict,
                                                     Settings.UnstableTimeout));

            var candidatesBin = PexCommunity.PackVarlenHList(peersKeys);
            var candidatesEnc = sessionKeys.EncryptStr(candidatesBin, Tunnel.Forward);
            ExitSockets[circuitId] = new TunnelExitSocket(circuitId, new Hop(createdPeer, sessionKeys), this);
            SendCell(previousNodeAddress,
                     new CreatedPayload(circuitId, createPayload.Identifier, key, auth, candidatesEnc));
        }

        /// <summary>Process a request to join someone's circuit.</summary>
        protected void OnCreate(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<CreatePayload>(data, 23);
            if (Settings.PeerFlags.Count == 0)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, $"Ignoring create for circuit {payload.CircuitId}");
                return;
            }
            if (RequestCache.Has(CreatedRequestCache.Name, (int)payload.CircuitId))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Already have a request for circuit {payload.CircuitId}");
                return;
            }

            var result = ShouldJoinCircuit(payload, sourceAddress);
            if (result)
            {
                JoinCircuit(payload, sourceAddress);
            }
            else
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"We're not joining circuit with ID {payload.CircuitId}");
            }
        }

        /// <summary>Callback for when another peer signals that they have joined our circuit.</summary>
        protected void OnCreated(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<CreatedPayload>(data, 23);
            var payloadCircuitId = payload.CircuitId;

            if (RequestCache.Has(CreateRequestCache.Name, (int)payload.Identifier))
            {
                var request = (CreateRequestCache)RequestCache.Pop(CreateRequestCache.Name,
                                                                   (int)payload.Identifier);

                Log.TraceEvent(TraceEventType.Information, 0,
                    "Got CREATED message forward as EXTENDED to origin.");

                if (!ExitSockets.TryGetValue(request.FromCircuitId, out var fromSocket))
                {
                    Log.TraceEvent(TraceEventType.Information, 0,
                        $"Created for unknown exit socket {request.FromCircuitId}");
                    return;
                }
                var sessionKeys = fromSocket.Hop.Keys;
                RemoveExitSocket(request.FromCircuitId, removeNow: true);

                var bwRelay = new RelayRoute(request.FromCircuitId,
                                             new Hop(request.Peer, sessionKeys), Tunnel.Backward);
                var fwRelay = new RelayRoute(request.ToCircuitId,
                                             new Hop(request.ToPeer, sessionKeys), Tunnel.Forward);

                RelayFromTo[request.ToCircuitId] = bwRelay;
                RelayFromTo[request.FromCircuitId] = fwRelay;

                SendCell(bwRelay.Hop.Address,
                         new ExtendedPayload(bwRelay.CircuitId, request.ExtendIdentifier,
                                             payload.Key, payload.Auth, payload.CandidatesEnc));
                return;
            }

            var cache = RequestCache.Get(RetryRequestCache.Name, (int)payloadCircuitId) as RetryRequestCache;

            // Check payload.identifier to ensure we're not accepting old created messages that have since
            // timed out.
            if (cache != null && cache.PacketIdentifier == payload.Identifier)
            {
                OursOnCreatedExtended(payloadCircuitId, payload);
            }
            else
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received unexpected created for circuit {payloadCircuitId}");
            }
        }

        /// <summary>Callback for when a peer asks us to extend for their circuit.</summary>
        protected void OnExtend(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<ExtendPayload>(data, 23);
            if (!Settings.PeerFlags.Contains(Tunnel.PeerFlagRelay))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, $"Ignoring create for circuit {payload.CircuitId}");
                return;
            }

            var payloadCircuitId = payload.CircuitId;
            // Leave the RequestCache in case the circuit owner wants to reuse the tunnel for a different
            // next-hop
            var request = RequestCache.Get(CreatedRequestCache.Name, (int)payloadCircuitId) as CreatedRequestCache;

            if (request == null)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received unexpected extend for circuit {payloadCircuitId}");
                return;
            }

            var zeroAddress = Address.Zero;
            var inCandidates = request.Candidates.TryGetValue(payload.NodePublicKey, out _);
            if (zeroAddress.Equals(payload.NodeAddr) && !inCandidates)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    "Node public key not in request candidates and no ip specified");
                return;
            }

            Peer extendCandidate;
            if (inCandidates)
            {
                extendCandidate = request.Candidates[payload.NodePublicKey];
            }
            else
            {
                var knownCandidate = Network.GetVerifiedByPublicKeyBin(payload.NodePublicKey);
                extendCandidate = knownCandidate ?? new Peer(payload.NodePublicKey, payload.NodeAddr);

                // Ensure that we are able to contact this peer
                if (extendCandidate.LastResponse + 57.5 < Util.NowEpoch())
                {
                    _ = DhtPeerLookup(extendCandidate.Mid, extendCandidate);
                }
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"On_extend send CREATE for circuit ({sourceAddress}, {payloadCircuitId}) to " +
                $"{extendCandidate.Address}");

            var toCircuitId = GenerateCircuitId();

            Peer candidate;
            if (Circuits.TryGetValue(payloadCircuitId, out var circuit))
            {
                candidate = circuit.Hop.Peer;
            }
            else if (ExitSockets.TryGetValue(payloadCircuitId, out var exitSocket))
            {
                candidate = exitSocket.Hop.Peer;
            }
            else if (RelayFromTo.TryGetValue(payloadCircuitId, out var relay))
            {
                candidate = relay.Hop.Peer;
            }
            else
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Got extend for unknown source circuit_id");
                return;
            }

            Log.TraceEvent(TraceEventType.Information, 0,
                $"Extending circuit, got candidate with IP {extendCandidate.Address} from " +
                $"{(inCandidates ? "cache" : "payload")}");

            var cache = new CreateRequestCache(this, (int)payload.Identifier, toCircuitId, payloadCircuitId,
                                               candidate, extendCandidate);
            RequestCache.Add(cache);

            SendCell(extendCandidate.Address,
                     new CreatePayload(toCircuitId, cache.Number, MyPeer.PublicKey.KeyToBin(), payload.Key));
        }

        /// <summary>Callback for when a peer signals that they have extended our circuit.</summary>
        protected void OnExtended(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<ExtendedPayload>(data, 23);
            var payloadCircuitId = payload.CircuitId;
            var cache = RequestCache.Get(RetryRequestCache.Name, (int)payloadCircuitId) as RetryRequestCache;
            if (cache == null || cache.PacketIdentifier != payload.Identifier)
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Received unexpected extended for circuit {payloadCircuitId}");
                return;
            }

            OursOnCreatedExtended(payloadCircuitId, payload);
        }

        /// <summary>
        /// Handle data, coming from a specific circuit and origin.
        /// This method is usually implemented in subclasses of this community.
        /// </summary>
        public virtual void OnRawData(Circuit circuit, Address origin, byte[] data)
        {
        }

        /// <summary>
        /// Callback for when we receive a DataPayload out of a circuit.
        /// Data is readable only if this handler is (a) an exit node or (b) the one that created the circuit.
        /// </summary>
        protected void OnData(Address sockAddr, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<DataPayload>(data, 23);

            // If it's our circuit, the messenger is the candidate assigned to that circuit and the DATA's
            // destination is set to the zero-address then the packet is from the outside world and addressed
            // to us from.
            var payloadCircuitId = payload.CircuitId;
            var destination = payload.DestAddress;
            var origin = payload.OrgAddress;
            var innerData = payload.Data;

            Log.TraceEvent(TraceEventType.Verbose, 0, $"Got data ({payloadCircuitId}) from {sockAddr}");

            var circuit = Circuits.TryGetValue(payloadCircuitId, out var found) ? found : null;
            if (circuit != null && !origin.Equals(Address.Zero) && sockAddr.Equals(circuit.Hop.Address))
            {
                circuit.BeatHeart();

                var e2eData = circuit.CType == Tunnel.CircuitTypeRpDownloader
                              || circuit.CType == Tunnel.CircuitTypeRpSeeder;
                if (DataChecker.CouldBeIpv8(innerData) && !e2eData)
                {
                    if (Util.StartsWith(innerData, GetPrefix()))
                    {
                        Log.TraceEvent(TraceEventType.Verbose, 0, "Incoming packet meant for us");
                        OnPacketFromCircuit(origin, innerData, payloadCircuitId);
                        return;
                    }

                    if (Endpoint is TunnelEndpoint tunnelEndpoint)
                    {
                        Log.TraceEvent(TraceEventType.Verbose, 0, "Incoming packet meant for other community");
                        tunnelEndpoint.NotifyListeners(new Packet(origin, innerData), fromTunnel: true);
                    }
                    else
                    {
                        Log.TraceEvent(TraceEventType.Verbose, 0,
                            "Incoming packet meant for other community, dropping");
                    }
                }
                else
                {
                    // We probably received raw data, handle it
                    OnRawData(circuit, origin, innerData);
                }
            }
            else
            {
                // It is not our circuit so we got it from a relay, we need to EXIT it!
                Log.TraceEvent(TraceEventType.Verbose, 0,
                    $"Data for circuit {payloadCircuitId} exiting tunnel ({destination})");
                if (!destination.Equals(Address.Zero))
                {
                    ExitData(payloadCircuitId, sockAddr, destination, innerData);
                }
                else
                {
                    Log.TraceEvent(TraceEventType.Warning, 0,
                        "Cannot exit data, destination is 0.0.0.0:0");
                }
            }
        }

        /// <summary>Callback for when we received a tunneled ping message.</summary>
        protected void OnPing(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<PingPayload>(data, 23);
            if (!Circuits.ContainsKey(payload.CircuitId)
                && !ExitSockets.ContainsKey(payload.CircuitId)
                && !RelayFromTo.ContainsKey(payload.CircuitId))
            {
                return;
            }

            if (ExitSockets.TryGetValue(payload.CircuitId, out var exitSocket))
            {
                exitSocket.BeatHeart();
            }

            SendCell(sourceAddress, new PongPayload(payload.CircuitId, payload.Identifier));
            Log.TraceEvent(TraceEventType.Verbose, 0, $"Got ping from {sourceAddress}");
        }

        /// <summary>Callback for when we received a tunneled pong (response) message.</summary>
        protected void OnPong(Address sourceAddress, byte[] data, long? circuitId)
        {
            var payload = Serializer.UnpackSerializableAs<PongPayload>(data, 23);
            if (!RequestCache.Has(PingRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid ping circuit_id");
                return;
            }

            RequestCache.Pop(PingRequestCache.Name, (int)payload.Identifier);
            Log.TraceEvent(TraceEventType.Verbose, 0, $"Got pong from {sourceAddress}");

            if (Circuits.TryGetValue(payload.CircuitId, out var circuit))
            {
                circuit.BeatHeart();
            }
        }

        /// <summary>Ping circuits. Pings are only sent to the first hop, subsequent hops will relay the ping.</summary>
        public virtual void DoPing(int[] exclude = null)
        {
            var excluded = new HashSet<long>();
            if (exclude != null)
            {
                foreach (var circuitId in exclude)
                {
                    excluded.Add(circuitId);
                }
            }
            foreach (var circuit in Circuits.Values.ToList())
            {
                if ((circuit.State == Tunnel.CircuitStateReady
                     || circuit.State == Tunnel.CircuitStateExtending)
                    && !excluded.Contains(circuit.CircuitId)
                    && circuit.Hops.Count > 0)
                {
                    var cache = new PingRequestCache(this);
                    RequestCache.Add(cache);
                    SendCell(circuit.Hop.Address, new PingPayload(circuit.CircuitId, cache.Number));
                }
            }
        }

        /// <summary>Raw destroy-message handler (py @lazy_wrapper(DestroyPayload)).</summary>
        protected Task OnDestroyRaw(Address sourceAddress, byte[] data)
        {
            // UNPACK (mimics py lazy_wrapper: auth + signature check + payload)
            var auth = Serializer.UnpackSerializableAs<BinMemberAuthenticationPayload>(data, 23);
            var (valid, remainder) = VerifySignature(auth, data);
            if (!valid)
            {
                throw new PacketDecodingError("Incoming packet DestroyPayload has an invalid signature");
            }
            var payload = Serializer.UnpackSerializableAs<DestroyPayload>(remainder, 23);

            var peer = Network.GetVerifiedByPublicKeyBin(auth.PublicKeyBin);
            if (peer != null)
            {
                peer.AddAddress(sourceAddress);
            }
            peer = peer ?? new Peer(auth.PublicKeyBin, sourceAddress);

            OnDestroy(peer, payload);
            return Task.CompletedTask;
        }

        /// <summary>Callback for when we received a destroy message.</summary>
        protected void OnDestroy(Peer peer, DestroyPayload payload)
        {
            var sourceAddress = peer.Address;
            var circuitId = payload.CircuitId;
            Log.TraceEvent(TraceEventType.Information, 0,
                $"Got destroy from {sourceAddress} for circuit {circuitId}");

            // Find the RelayRoute object for the other direction (if any).
            RelayRoute nextRelay = RelayFromTo.TryGetValue(circuitId, out var nr) ? nr : null;
            RelayRoute prevRelay = nextRelay != null && RelayFromTo.TryGetValue(nextRelay.CircuitId, out var pr)
                ? pr
                : null;
            if (prevRelay != null && peer.Equals(prevRelay.Hop.Peer))
            {
                RemoveRelay(circuitId, $"got destroy with reason {payload.Reason}", destroy: payload.Reason);
                RemoveRelay(nextRelay.CircuitId, $"got destroy with reason {payload.Reason}");
            }
            else if (ExitSockets.TryGetValue(circuitId, out var exitSocket)
                     && peer.Equals(exitSocket.Hop.Peer))
            {
                RemoveExitSocket(circuitId, $"got destroy with reason {payload.Reason}");
            }
            else if (Circuits.TryGetValue(circuitId, out var circuit)
                     && peer.Equals(circuit.Hop.Peer))
            {
                RemoveCircuit(circuitId, $"got destroy with reason {payload.Reason}");
            }
            else
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Invalid or unauthorized destroy");
            }
        }

        /// <summary>
        /// Exit data (to the destination) out of the exit socket associated with the given circuit id.
        /// </summary>
        public void ExitData(long circuitId, Address sockAddr, Address destination, byte[] data)
        {
            if (!ExitSockets.TryGetValue(circuitId, out var exitSocket))
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Dropping data packets with unknown circuit_id");
                return;
            }

            if (!exitSocket.Enabled)
            {
                // Check that we got the data from the correct IP.
                if (sockAddr.Host.Equals(exitSocket.Hop.Address.Host))
                {
                    exitSocket.Enable();
                }
                else
                {
                    Log.TraceEvent(TraceEventType.Error, 0,
                        $"Dropping outbound relayed packet: IP's are {sockAddr} != {exitSocket.Hop.Address}");
                    return;
                }
            }
            try
            {
                exitSocket.SendTo(data, destination);
            }
            catch (Exception)
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Dropping data packets while exiting");
            }
        }

        /// <summary>
        /// Perform a DHT lookup for a given SHA-1 hash of a public key.
        /// Note that connections (if any) will be performed in the background.
        /// </summary>
        public virtual async Task DhtPeerLookup(byte[] mid, Peer peer = null)
        {
            if (DhtProvider != null)
            {
                await DhtProvider.PeerLookupAsync(mid, peer).ConfigureAwait(false);
            }
            else
            {
                Log.TraceEvent(TraceEventType.Error, 0,
                    "Need a DHT provider to connect to a peer using the DHT");
            }
        }

        /// <summary>
        /// Send a speed test request and wait for a (data, RTT time in seconds) tuple to be recorded.
        /// </summary>
        public Task<(byte[] Data, double Rtt)> SendTestRequest(Circuit circuit,
                                                               int requestSize = 0,
                                                               int responseSize = 0)
        {
            var cache = new TestRequestCache(this, circuit);
            RequestCache.Add(cache);
            SendCell(circuit.Hop.Address,
                     new TestRequestPayload(circuit.CircuitId, cache.Number, responseSize,
                                            Util.RandomBytes(requestSize)));
            var result = new TaskCompletionSource<(byte[], double)>(TaskCreationOptions.RunContinuationsAsynchronously);
            cache.Future.Task.ContinueWith(t =>
            {
                if (t.IsFaulted)
                {
                    result.SetException(t.Exception?.InnerException ?? t.Exception);
                }
                else if (t.IsCanceled)
                {
                    result.SetCanceled();
                }
                else
                {
                    result.SetResult((ValueTuple<byte[], double>)t.Result);
                }
            }, TaskContinuationOptions.ExecuteSynchronously);
            return result.Task;
        }

        /// <summary>Callback for when we receive a speed test request.</summary>
        protected void OnTestRequest(Address sourceAddress, byte[] data, long? circuitId)
        {
            if (!Settings.PeerFlags.Contains(Tunnel.PeerFlagSpeedTest))
            {
                Log.TraceEvent(TraceEventType.Warning, 0,
                    $"Ignoring test-request from circuit {circuitId}");
                return;
            }

            if (circuitId == null)
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Dropping test-request without circuit_id");
                return;
            }

            var payload = Serializer.UnpackSerializableAs<TestRequestPayload>(data, 23);
            var hasExitSocket = ExitSockets.TryGetValue(circuitId.Value, out var exitSocket);
            var hasCircuit = Circuits.TryGetValue(circuitId.Value, out var circuit);
            if (!hasExitSocket
                && !(hasCircuit && (circuit.CType == Tunnel.CircuitTypeRpSeeder
                                    || circuit.CType == Tunnel.CircuitTypeRpDownloader)))
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Dropping test-request with unknown circuit_id");
                return;
            }

            Log.TraceEvent(TraceEventType.Verbose, 0,
                $"Got test-request ({circuitId}) from {sourceAddress}, replying with response");
            if (hasExitSocket)
            {
                exitSocket.BeatHeart();
            }
            SendCell(sourceAddress,
                     new TestResponsePayload(circuitId.Value, payload.Identifier,
                                             Util.RandomBytes(payload.ResponseSize)));
        }

        /// <summary>Callback for when we received a test response.</summary>
        protected void OnTestResponse(Address sourceAddress, byte[] data, long? circuitId)
        {
            if (circuitId == null)
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Dropping test-response without circuit_id");
                return;
            }

            var payload = Serializer.UnpackSerializableAs<TestResponsePayload>(data, 23);
            if (!Circuits.TryGetValue(circuitId.Value, out var circuit))
            {
                Log.TraceEvent(TraceEventType.Error, 0, "Dropping test-response with unknown circuit_id");
                return;
            }
            if (!RequestCache.Has(TestRequestCache.Name, (int)payload.Identifier))
            {
                Log.TraceEvent(TraceEventType.Warning, 0, "Dropping unexpected test-response");
                return;
            }

            Log.TraceEvent(TraceEventType.Verbose, 0,
                $"Got test-response ({circuitId}) from {sourceAddress}");
            var cache = (TestRequestCache)RequestCache.Pop(TestRequestCache.Name, (int)payload.Identifier);
            cache.Future.TrySetResult((object)(payload.Data, Util.NowEpoch() - cache.Ts));
        }

        public override void Unload()
        {
            // Remove all circuits/relays/exitsockets.
            foreach (var circuitId in Circuits.Keys.ToList())
            {
                RemoveCircuit(circuitId, "unload", removeNow: true, destroy: Tunnel.DestroyReasonShutdown);
            }
            foreach (var circuitId in RelayFromTo.Keys.ToList())
            {
                RemoveRelay(circuitId, "unload", removeNow: true, destroy: Tunnel.DestroyReasonShutdown);
            }
            foreach (var circuitId in ExitSockets.Keys.ToList())
            {
                RemoveExitSocket(circuitId, "unload", removeNow: true, destroy: Tunnel.DestroyReasonShutdown);
            }

            RequestCache.Shutdown();

            base.Unload();
        }
    }
}
