// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>Cell/data direction (tunnel.py: FORWARD = 0, BACKWARD = 1).</summary>
    public static class Tunnel
    {
        public const int Forward = 0;
        public const int Backward = 1;

        public const int PeerSourceUnknown = 0;
        public const int PeerSourceDht = 1;
        public const int PeerSourcePex = 2;

        public const int PeerFlagRelay = 1;
        public const int PeerFlagExitBt = 2;
        public const int PeerFlagExitIpv8 = 4;
        public const int PeerFlagSpeedTest = 8;

        /// <summary>Data circuits are general purpose circuits for exiting data.</summary>
        public const string CircuitTypeData = "DATA";

        /// <summary>
        /// The other circuits are supposed to end in a connectable node, not allowed to exit
        /// anything else than IPv8 messages, used for setting up end-to-end circuits.
        /// </summary>
        public const string CircuitTypeIpSeeder = "IP_SEEDER";
        public const string CircuitTypeIpDownloader = "IP_DOWNLOADER";
        public const string CircuitTypeRpSeeder = "RP_SEEDER";
        public const string CircuitTypeRpDownloader = "RP_DOWNLOADER";

        public const string CircuitStateReady = "READY";
        public const string CircuitStateExtending = "EXTENDING";
        public const string CircuitStateClosing = "CLOSING";

        public const int CircuitIdPort = 1024;
        public const double PingInterval = 7.5;

        /// <summary>Reasons for sending destroy messages. Code 0 must not be used for legacy reasons.</summary>
        public const int DestroyReasonUnknown = 1;
        public const int DestroyReasonShutdown = 2;
        public const int DestroyReasonUnneeded = 4;
    }

    /// <summary>
    /// Hop contains all information needed to add/remove a single layer of onion encryption
    /// and send it to the next target (tunnel.py::Hop).
    /// </summary>
    public sealed class Hop
    {
        public Peer Peer { get; }
        public SessionKeys Keys { get; set; }
        public List<int> Flags { get; set; }
        public byte[] DhFirstPart { get; set; }
        public PrivateKey DhSecret { get; set; }

        public Hop(Peer peer, SessionKeys keys = null, List<int> flags = null)
        {
            Peer = peer ?? throw new ArgumentNullException(nameof(peer));
            Keys = keys;
            Flags = flags;
        }

        public Address Address => Peer.Address;

        public PublicKey PublicKey => Peer.PublicKey;

        public byte[] PublicKeyBin => Peer.PublicKey.KeyToBin();

        public byte[] Mid => Peer.Mid;
    }

    /// <summary>
    /// Statistics for a tunnel to a peer over a circuit (base class for circuits, exit
    /// sockets, and relay routes) (tunnel.py::RoutingObject).
    /// </summary>
    public abstract class RoutingObject
    {
        public long CircuitId { get; }
        public double CreationTime { get; }
        public double LastActivity { get; set; }
        public long BytesUp { get; set; }
        public long BytesDown { get; set; }

        protected RoutingObject(long circuitId)
        {
            CircuitId = circuitId;
            CreationTime = Util.NowEpoch();
            LastActivity = CreationTime;
        }

        /// <summary>Notify this object that the tunnel was active.</summary>
        public void BeatHeart()
        {
            LastActivity = Util.NowEpoch();
        }
    }

    /// <summary>
    /// A peer-to-peer encrypted communication channel, consisting of 0 or more hops
    /// (intermediate peers) (tunnel.py::Circuit).
    /// </summary>
    public sealed class Circuit : RoutingObject
    {
        private readonly List<Hop> _hops = new List<Hop>();
        private bool _closing;
        private SessionKeys _hsSessionKeys;

        public int GoalHops { get; }
        public string CType { get; }
        public Peer RequiredExit { get; }
        public byte[] InfoHash { get; }

        /// <summary>Future that resolves to this circuit when it becomes READY (or null when closed).</summary>
        public TaskCompletionSource<Circuit> Ready { get; } = new TaskCompletionSource<Circuit>();

        public string ClosingInfo { get; private set; } = "";
        public Hop UnverifiedHop { get; set; }
        public bool E2e { get; set; }
        public int RelayEarlyCount { get; set; }
        public bool Dirty { get; set; }

        public Circuit(long circuitId, int goalHops = 0, string ctype = Tunnel.CircuitTypeData,
                       Peer requiredExit = null, byte[] infoHash = null)
            : base(circuitId)
        {
            GoalHops = goalHops;
            CType = ctype;
            RequiredExit = requiredExit;
            InfoHash = infoHash;
        }

        /// <summary>Adds a hop to the circuits hop collection.</summary>
        public void AddHop(Hop hop)
        {
            _hops.Add(hop);
            if (State == Tunnel.CircuitStateReady)
            {
                Ready.TrySetResult(this);
            }
            Dirty = true;
        }

        /// <summary>Get the session keys for hidden services (if any).</summary>
        public SessionKeys HsSessionKeys
        {
            get => _hsSessionKeys;
            set
            {
                _hsSessionKeys = value;
                Dirty = true;
            }
        }

        /// <summary>Return the first hop of the circuit (the unverified hop if not verified yet).</summary>
        public Hop Hop => _hops.Count > 0 ? _hops[0] : UnverifiedHop;

        /// <summary>Return a read only list of the hop-list of this circuit.</summary>
        public IReadOnlyList<Hop> Hops => _hops;

        /// <summary>Get the flags of the last hop in our circuit.</summary>
        public List<int> ExitFlags
        {
            get
            {
                if (_hops.Count > 0)
                {
                    return _hops[_hops.Count - 1].Flags;
                }
                return new List<int>();
            }
        }

        /// <summary>
        /// The circuit state: CLOSING, EXTENDING or READY.
        /// </summary>
        public string State
        {
            get
            {
                if (_closing)
                {
                    return Tunnel.CircuitStateClosing;
                }
                if (_hops.Count < GoalHops)
                {
                    return Tunnel.CircuitStateExtending;
                }
                return Tunnel.CircuitStateReady;
            }
        }

        /// <summary>
        /// Sets the state of the circuit to CIRCUIT_STATE_CLOSING. This ensures that this
        /// circuit will not be used to contact new peers.
        /// </summary>
        public void Close(string closingInfo = "")
        {
            ClosingInfo = closingInfo;
            _closing = true;
            Ready.TrySetResult(null);
        }
    }

    /// <summary>
    /// Relay object containing the destination circuit, socket address and whether it is
    /// online or not (tunnel.py::RelayRoute).
    /// </summary>
    public sealed class RelayRoute : RoutingObject
    {
        public Hop Hop { get; }
        public int Direction { get; }
        public bool RendezvousRelay { get; }

        public RelayRoute(long circuitId, Hop hop, int direction, bool rendezvousRelay = false)
            : base(circuitId)
        {
            Hop = hop;
            Direction = direction;
            RendezvousRelay = rendezvousRelay;
            // Since the creation of a RelayRoute object is triggered by an extend (which was
            // wrapped in a cell that had the early_relay flag set) we start the count at 1.
            RelayEarlyCount = 1;
        }

        public int RelayEarlyCount { get; set; }
    }

    /// <summary>Rendezvous for circuits to link up (tunnel.py::RendezvousPoint).</summary>
    public sealed class RendezvousPoint
    {
        public Circuit Circuit { get; }
        public byte[] Cookie { get; }

        /// <summary>
        /// The rendezvous address, set once the rendezvous is established. Unset is represented
        /// by the zero address (C# structs cannot hold py's None).
        /// </summary>
        public Address Address { get; set; }

        public TaskCompletionSource<RendezvousPoint> Ready { get; } = new TaskCompletionSource<RendezvousPoint>();

        public RendezvousPoint(Circuit circuit, byte[] cookie)
        {
            Circuit = circuit;
            Cookie = cookie;
            Address = Address.Zero;
        }
    }

    /// <summary>A point of introduction, available for linking up (tunnel.py::IntroductionPoint).</summary>
    public sealed class IntroductionPoint
    {
        public Peer Peer { get; }
        public byte[] SeederPk { get; }
        public int Source { get; }
        public double LastSeen { get; set; }

        public IntroductionPoint(Peer peer, byte[] seederPk, int source = Tunnel.PeerSourceUnknown,
                                 double? lastSeen = null)
        {
            Peer = peer;
            SeederPk = seederPk;
            Source = source;
            LastSeen = lastSeen ?? Util.NowEpoch();
        }

        public override bool Equals(object other)
            => other is IntroductionPoint point && Peer.Equals(point.Peer) && Util.BytesEqual(SeederPk, point.SeederPk);

        public override int GetHashCode()
            => Util.BytesHashCode(SeederPk) * 31 + Peer.GetHashCode();
    }

    /// <summary>
    /// A group of circuit exits that organizes around an SHA-1 (tunnel.py::Swarm).
    /// </summary>
    public sealed class Swarm
    {
        /// <summary>Attempt to find introduction points for the swarm (py Swarm.lookup_func).</summary>
        public delegate Task<List<IntroductionPoint>> LookupFunc(byte[] infoHash, IntroductionPoint target, int hops);

        public byte[] InfoHash { get; }
        public int Hops { get; }
        public LookupFunc LookupFuncDelegate { get; }
        public PrivateKey SeederSk { get; }
        public double MaxIpAge { get; }
        public double MinDhtLookupInterval { get; }
        public double MaxDhtLookupInterval { get; }

        public List<IntroductionPoint> IntroPoints { get; } = new List<IntroductionPoint>();

        /// <summary>RP circuit → the introduction point it connected through (py Swarm.connections).</summary>
        public Dictionary<long, ConnectionEntry> Connections { get; } = new Dictionary<long, ConnectionEntry>();

        public double LastLookup { get; set; }

        public double LastDhtResponse { get; set; }

        /// <summary>[bytes up, bytes down] accumulated from removed connections (py transfer_history).</summary>
        public long[] TransferHistory { get; } = new long[2];

        public Swarm(byte[] infoHash, int hops, LookupFunc lookupFunc, PrivateKey seederSk = null,
                     double maxIpAge = 180.0, double minDhtLookupInterval = 300.0,
                     double maxDhtLookupInterval = 120.0)
        {
            InfoHash = infoHash;
            Hops = hops;
            LookupFuncDelegate = lookupFunc ?? throw new ArgumentNullException(nameof(lookupFunc));
            SeederSk = seederSk;
            MaxIpAge = maxIpAge;
            MinDhtLookupInterval = minDhtLookupInterval;
            MaxDhtLookupInterval = maxDhtLookupInterval;
        }

        /// <summary>Whether we are seeding data in this swarm (py Swarm.seeding).</summary>
        public bool Seeding => SeederSk != null;

        /// <summary>The READY e2e circuits in this swarm (py Swarm._active_circuits).</summary>
        public List<Circuit> ActiveCircuits
        {
            get
            {
                var result = new List<Circuit>();
                foreach (var connection in Connections.Values)
                {
                    if (connection.Circuit.State == Tunnel.CircuitStateReady && connection.Circuit.E2e)
                    {
                        result.Add(connection.Circuit);
                    }
                }
                return result;
            }
        }

        /// <summary>Add a newly known circuit to this swarm (py Swarm.add_connection).</summary>
        public void AddConnection(Circuit rpCircuit, IntroductionPoint introPointUsed)
        {
            if (!Connections.ContainsKey(rpCircuit.CircuitId))
            {
                Connections[rpCircuit.CircuitId] = new ConnectionEntry(rpCircuit, introPointUsed);
            }
        }

        /// <summary>
        /// Remove the given circuit from this swarm, if we manage it. This does not close the
        /// circuit (py Swarm.remove_connection).
        /// </summary>
        public bool RemoveConnection(Circuit rpCircuit)
        {
            if (Connections.Remove(rpCircuit.CircuitId))
            {
                TransferHistory[0] += rpCircuit.BytesUp;
                TransferHistory[1] += rpCircuit.BytesDown;
                return true;
            }
            return false;
        }

        /// <summary>Check if the given public key is in the swarm (py Swarm.has_connection).</summary>
        public bool HasConnection(byte[] seederPk)
        {
            foreach (var connection in Connections.Values)
            {
                if (Util.BytesEqual(connection.IntroPoint.SeederPk, seederPk))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Get the number of circuits we have in this swarm (py Swarm.get_num_connections).</summary>
        public int GetNumConnections() => ActiveCircuits.Count;

        /// <summary>
        /// Get the number of circuits we don't have yet, but know of, in this swarm
        /// (py Swarm.get_num_connections_incomplete).
        /// </summary>
        public int GetNumConnectionsIncomplete() => Connections.Count - GetNumConnections();

        /// <summary>
        /// Add an available introduction point to this swarm. Returns the introduction point we
        /// should use (not necessarily the one we just added) (py Swarm.add_intro_point).
        /// </summary>
        public IntroductionPoint AddIntroPoint(IntroductionPoint ip)
        {
            IntroductionPoint oldIp = null;
            foreach (var existing in IntroPoints)
            {
                if (existing.Equals(ip))
                {
                    oldIp = existing;
                    break;
                }
            }

            if (oldIp != null)
            {
                oldIp.LastSeen = Util.NowEpoch();
            }
            else
            {
                IntroPoints.Add(ip);
            }

            return oldIp ?? ip;
        }

        /// <summary>Cleanup old introduction points (py Swarm.remove_old_intro_points).</summary>
        public void RemoveOldIntroPoints()
        {
            var now = Util.NowEpoch();
            var used = new List<IntroductionPoint>();
            foreach (var connection in Connections.Values)
            {
                if (connection.Circuit.State == Tunnel.CircuitStateReady && connection.Circuit.E2e)
                {
                    used.Add(connection.IntroPoint);
                }
            }
            IntroPoints.RemoveAll(ip => !(ip.LastSeen + MaxIpAge >= now || used.Contains(ip)));
        }

        /// <summary>Remove the given introduction point from this swarm (py Swarm.remove_intro_point).</summary>
        public void RemoveIntroPoint(IntroductionPoint ip) => IntroPoints.Remove(ip);

        /// <summary>
        /// Lookup introduction points, possibly those that match the given introduction point.
        /// Returns null when no lookup was performed (py Swarm.lookup).
        /// </summary>
        public async Task<List<IntroductionPoint>> Lookup(IntroductionPoint target = null)
        {
            // Are we doing a manual lookup?
            if (target != null)
            {
                return OnLookupSuccess(await LookupFuncDelegate(InfoHash, target, Hops));
            }

            var now = Util.NowEpoch();
            RemoveOldIntroPoints();
            LastLookup = now;
            if (now - LastDhtResponse > MinDhtLookupInterval
                || (IntroPoints.Count == 0 && now - LastDhtResponse > MaxDhtLookupInterval))
            {
                return OnLookupSuccess(await LookupFuncDelegate(InfoHash, null, Hops));
            }

            if (IntroPoints.Count > 0)
            {
                var results = new List<IntroductionPoint>();
                foreach (var ip in IntroPoints)
                {
                    // py gather(*tasks, return_exceptions=True): failures are ignored.
                    List<IntroductionPoint> part;
                    try
                    {
                        part = await LookupFuncDelegate(InfoHash, ip, Hops);
                    }
                    catch (Exception)
                    {
                        continue;
                    }
                    if (part != null)
                    {
                        results.AddRange(part);
                    }
                }
                return OnLookupSuccess(results);
            }
            return null;
        }

        private List<IntroductionPoint> OnLookupSuccess(List<IntroductionPoint> ips)
        {
            foreach (var ip in ips)
            {
                if (ip != null && ip.Source == Tunnel.PeerSourceDht)
                {
                    LastDhtResponse = Util.NowEpoch();
                    break;
                }
            }
            return ips;
        }

        /// <summary>Get the number of different seeder public keys in this swarm (py get_num_seeders).</summary>
        public int GetNumSeeders()
        {
            var seederPks = new List<byte[]>();
            foreach (var ip in IntroPoints)
            {
                seederPks.Add(ip.SeederPk);
            }
            foreach (var connection in Connections.Values)
            {
                seederPks.Add(connection.IntroPoint.SeederPk);
            }
            // Count DISTINCT keys (byte-exact comparison, mirroring the py set of bytes).
            var distinct = new List<byte[]>();
            foreach (var pk in seederPks)
            {
                var known = false;
                foreach (var seen in distinct)
                {
                    if (Util.BytesEqual(seen, pk))
                    {
                        known = true;
                        break;
                    }
                }
                if (!known)
                {
                    distinct.Add(pk);
                }
            }
            return distinct.Count;
        }

        /// <summary>Get the total number of bytes uploaded in this swarm (py get_total_up).</summary>
        public long GetTotalUp()
        {
            var total = TransferHistory[0];
            foreach (var circuit in ActiveCircuits)
            {
                total += circuit.BytesUp;
            }
            return total;
        }

        /// <summary>Get the total number of bytes downloaded from this swarm (py get_total_down).</summary>
        public long GetTotalDown()
        {
            var total = TransferHistory[1];
            foreach (var circuit in ActiveCircuits)
            {
                total += circuit.BytesDown;
            }
            return total;
        }
    }

    /// <summary>A Swarm.connections entry: the RP circuit and the introduction point it used.</summary>
    public sealed class ConnectionEntry
    {
        public Circuit Circuit { get; }
        public IntroductionPoint IntroPoint { get; }

        public ConnectionEntry(Circuit circuit, IntroductionPoint introPoint)
        {
            Circuit = circuit;
            IntroPoint = introPoint;
        }
    }
}
