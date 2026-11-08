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
                    return _hops[^1].Flags;
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
        public Address Address { get; set; }
        public TaskCompletionSource<RendezvousPoint> Ready { get; } = new TaskCompletionSource<RendezvousPoint>();

        public RendezvousPoint(Circuit circuit, byte[] cookie)
        {
            Circuit = circuit;
            Cookie = cookie;
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
}
