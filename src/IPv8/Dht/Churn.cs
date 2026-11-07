// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/churn.py: strategy to maintain the data structures of the DHT community.

using System;
using System.Collections.Generic;
using IPv8.PeerDiscovery;

namespace IPv8.Dht
{
    /// <summary>
    /// Strategy to maintain the DHT community's data structures: removes bad nodes, re-registers
    /// routing-table nodes in the Network and pings nodes at the configured interval.
    /// </summary>
    public class PingChurn : DiscoveryStrategy
    {
        public double PingInterval;

        public PingChurn(Overlay overlay, double pingInterval = 25.0) : base(overlay)
        {
            PingInterval = pingInterval;
        }

        public override void TakeStep()
        {
            var overlay = (DhtCommunity)Overlay;
            lock (WalkLock)
            {
                // Nothing is happening yet, skip this step
                if (overlay.RoutingTables.Count == 0)
                {
                    return;
                }

                foreach (var routingTable in overlay.RoutingTables.Values)
                {
                    foreach (var node in routingTable.RemoveBadNodes())
                    {
                        overlay.Network.RemovePeer(node);
                    }
                }

                foreach (var peer in overlay.GetPeers())
                {
                    if (overlay.Network.Blacklist.Contains(peer.Address))
                    {
                        continue;
                    }

                    var node = new DhtNode(peer.Key, peer.Address);
                    var routingTable = overlay.GetRoutingTable(node);
                    if (!routingTable.Has(node.Id) && routingTable.Add(node) == null)
                    {
                        overlay.Network.RemovePeer(peer);
                    }
                }

                foreach (var routingTable in overlay.RoutingTables.Values)
                {
                    foreach (var bucket in routingTable.Trie.Values())
                    {
                        foreach (var node in bucket.Nodes.Values)
                        {
                            if (!ContainsPeer(overlay.GetPeers(), node))
                            {
                                var peer = new Peer(node.Key, node.Address);
                                overlay.Network.AddVerifiedPeer(peer);
                                overlay.Network.DiscoverServices(peer, new[] { overlay.CommunityId });
                            }
                        }
                    }
                }

                var now = Util.NowEpoch();
                foreach (var routingTable in overlay.RoutingTables.Values)
                {
                    foreach (var bucket in routingTable.Trie.Values())
                    {
                        foreach (var node in bucket.Nodes.Values)
                        {
                            if (node.LastPingSent + PingInterval <= now)
                            {
                                _ = overlay.Ping(node);
                            }
                        }
                    }
                }
            }
        }

        private static bool ContainsPeer(IReadOnlyList<Peer> peers, Peer node)
        {
            foreach (var peer in peers)
            {
                if (peer.Equals(node))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
