// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Messaging;

namespace IPv8.PeerDiscovery
{
    /// <summary>
    /// Strategy for discovering peers in the network (port of ipv8/peerdiscovery/discovery.py).
    /// </summary>
    public abstract class DiscoveryStrategy
    {
        protected DiscoveryStrategy(Overlay overlay)
        {
            Overlay = overlay;
            WalkLock = new object();
        }

        /// <summary>The overlay this strategy walks over (or null).</summary>
        public Overlay Overlay { get; }

        /// <summary>Lock guarding a walk step.</summary>
        protected readonly object WalkLock;

        /// <summary>Callback for when an IPv8 tick occurs (defaults to roughly every 0.5 seconds).</summary>
        public abstract void TakeStep();

        /// <summary>Determine the current number of peers.</summary>
        public int GetPeerCount() => Overlay == null ? 0 : Overlay.GetPeers().Count;
    }

    /// <summary>Walk randomly through the network (minimal port of py-ipv8 RandomWalk).</summary>
    public class RandomWalk : DiscoveryStrategy
    {
        private static readonly Random Rng = new Random();

        private readonly Dictionary<Address, double> _introTimeouts = new Dictionary<Address, double>();
        private readonly double _nodeTimeout;
        private readonly int _windowSize;
        private readonly int _resetChance;
        private readonly int _targetInterval;
        private double _lastStep;

        public RandomWalk(Overlay overlay, double timeout = 3.0, int windowSize = 5, int resetChance = 50,
                          int targetInterval = 0) : base(overlay)
        {
            _nodeTimeout = timeout;
            _windowSize = windowSize;
            _resetChance = resetChance;
            _targetInterval = targetInterval;
            _lastStep = 0;
        }

        /// <summary>Walk to a random walkable peer.</summary>
        public override void TakeStep()
        {
            lock (WalkLock)
            {
                // Sanitize unreachable nodes
                var now = Util.NowEpoch();
                var toRemove = _introTimeouts
                    .Where(pair => pair.Value + _nodeTimeout < now)
                    .Select(pair => pair.Key)
                    .ToList();
                foreach (var node in toRemove)
                {
                    _introTimeouts.Remove(node);
                    if (Overlay.Network.GetVerifiedByAddress(node) == null)
                    {
                        Overlay.Network.RemoveByAddress(node);
                    }
                }
                // Slow down the walk if a target_interval has been specified
                if (_targetInterval > 0 && _lastStep + _targetInterval >= now)
                {
                    return;
                }
                // If a valid window size (>0) is specified and we are waiting for (at least) this many
                // pings: return
                if (_windowSize > 0 && _windowSize <= _introTimeouts.Count)
                {
                    return;
                }
                // Take step
                var known = Overlay.GetWalkableAddresses();
                var inFlight = new HashSet<Address>(_introTimeouts.Keys);
                var available = known.Where(address => !inFlight.Contains(address)).ToList();

                // We can get stuck in an infinite loop of unreachable peers if we never contact the
                // tracker again
                if (available.Count > 0 && Rng.Next(256) >= _resetChance)
                {
                    var peer = available[Rng.Next(available.Count)];
                    Overlay.WalkTo(peer);
                    _introTimeouts[peer] = Util.NowEpoch();
                }
                else
                {
                    Overlay.GetNewIntroduction(null);
                }
                _lastStep = Util.NowEpoch();
            }
        }
    }

    /// <summary>
    /// Walk through the network by using edges (port of py-ipv8 EdgeWalk).
    ///
    /// This will perform a depth-first search in the network starting from your direct
    /// neighborhood. When a certain depth is reached, we teleport home and start again from our
    /// neighborhood.
    /// </summary>
    public class EdgeWalk : DiscoveryStrategy
    {
        private static readonly Random Rng = new Random();

        private List<Peer> _neighborhood = new List<Peer>();

        public readonly List<List<Peer>> CompleteEdges = new List<List<Peer>>();
        public readonly Dictionary<Peer, List<Peer>> UnderConstruction = new Dictionary<Peer, List<Peer>>();
        public readonly Dictionary<Peer, double> LastEdgeResponses = new Dictionary<Peer, double>();

        public readonly int EdgeLength;
        public readonly int NeighborhoodSize;
        public readonly double EdgeTimeout;

        public EdgeWalk(Overlay overlay, int edgeLength = 4, int neighborhoodSize = 6, double edgeTimeout = 3.0)
            : base(overlay)
        {
            EdgeLength = edgeLength;
            NeighborhoodSize = neighborhoodSize;
            EdgeTimeout = edgeTimeout;
        }

        /// <summary>Get a root which is not busy constructing an edge for us, if one exists.</summary>
        public Peer GetAvailableRoot()
        {
            var available = new List<Peer>(_neighborhood);
            available.RemoveAll(root => UnderConstruction.ContainsKey(root));
            return available.Count > 0 ? available[Rng.Next(available.Count)] : null;
        }

        /// <summary>Attempt to grow an edge.</summary>
        public override void TakeStep()
        {
            lock (WalkLock)
            {
                if (_neighborhood.Count == 0 || _neighborhood.Count < NeighborhoodSize)
                {
                    // Wait for our immediate neighborhood to be discovered
                    var peers = Overlay.GetPeers();
                    _neighborhood = peers.Take(NeighborhoodSize).ToList();
                    Overlay.Bootstrap();
                    foreach (var address in Overlay.GetWalkableAddresses().Take(NeighborhoodSize).ToList())
                    {
                        Overlay.WalkTo(address);
                    }
                }
                else
                {
                    var waitingRoot = GetAvailableRoot();
                    // Make sure we have as many outstanding/actively growing edges as roots
                    if (waitingRoot != null)
                    {
                        UnderConstruction[waitingRoot] = new List<Peer> { waitingRoot };
                        LastEdgeResponses[waitingRoot] = Util.NowEpoch();
                        Overlay.GetNewIntroduction(waitingRoot);
                    }
                    else
                    {
                        // Check if our introduced peer has answered yet
                        var completed = new List<Peer>();
                        foreach (var root in UnderConstruction.Keys.ToList())
                        {
                            var lastVerified = UnderConstruction[root][UnderConstruction[root].Count - 1];
                            var introductions = new List<Peer>();
                            foreach (var intro in Overlay.Network.GetIntroductionsFrom(lastVerified))
                            {
                                var verified = Overlay.Network.GetVerifiedByAddress(intro);
                                if (verified != null)
                                {
                                    introductions.Add(verified);
                                }
                                else
                                {
                                    Overlay.WalkTo(intro);
                                }
                            }
                            if (introductions.Count > 0)
                            {
                                // We got (multiple?) introductions from this peer, add it as verified
                                LastEdgeResponses[root] = Util.NowEpoch();
                                var nextInEdge = introductions[Rng.Next(introductions.Count)];
                                UnderConstruction[root].Add(nextInEdge);
                                if (UnderConstruction[root].Count == EdgeLength)
                                {
                                    // We have crawled the maximum depth, teleport home
                                    CompleteEdges.Add(UnderConstruction[root]);
                                    completed.Add(root);
                                }
                                else
                                {
                                    // Take this edge a step further
                                    Overlay.WalkTo(nextInEdge.Address);
                                }
                            }
                            else if (LastEdgeResponses[root] + EdgeTimeout < Util.NowEpoch())
                            {
                                // This edge isn't growing, mark it as complete
                                if (UnderConstruction[root].Count > 1)
                                {
                                    CompleteEdges.Add(UnderConstruction[root]);
                                }
                                completed.Add(root);
                            }
                        }
                        foreach (var root in completed)
                        {
                            UnderConstruction.Remove(root);
                        }
                    }
                }
            }
        }
    }
}
