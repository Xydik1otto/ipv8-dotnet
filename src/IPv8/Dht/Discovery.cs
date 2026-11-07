// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/discovery.py: DHTDiscoveryCommunity — peer discovery behind NAT on top of the
// DHT (message ids 7-10: store-peer request/response and connect-peer request/response).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Messaging;

namespace IPv8.Dht
{
    /// <summary>Community for discovering peers that are behind NAT (py-ipv8 DHTDiscoveryCommunity).</summary>
    public class DhtDiscoveryCommunity : DhtCommunity
    {
        /// <summary>Known introduction points per key (py: defaultdict(list)).</summary>
        public readonly Dictionary<byte[], List<DhtNode>> Store
            = new Dictionary<byte[], List<DhtNode>>(ByteArrayEqualityComparer.Instance);

        /// <summary>Nodes that store us, per key (py: defaultdict(list)).</summary>
        public readonly Dictionary<byte[], List<DhtNode>> StoreForMe
            = new Dictionary<byte[], List<DhtNode>>(ByteArrayEqualityComparer.Instance);

        public DhtDiscoveryCommunity(CommunitySettings settings) : base(settings)
        {
            AddMessageHandler(typeof(StorePeerRequestPayload), OnStorePeerRequestPacket);
            AddMessageHandler(typeof(StorePeerResponsePayload), OnStorePeerResponsePacket);
            AddMessageHandler(typeof(ConnectPeerRequestPayload), OnConnectPeerRequestPacket);
            AddMessageHandler(typeof(ConnectPeerResponsePayload), OnConnectPeerResponsePacket);

            RegisterTask("store_peer", () => _ = StorePeerAsync(), interval: 30);
            RegisterTask("ping_all", PingAll, interval: 10);
        }

        /// <summary>When a ping comes in and we store it, update its metrics.</summary>
        protected override void OnPingRequest(Peer peer, PingRequestPayload payload, byte[] data)
        {
            base.OnPingRequest(peer, payload, data);
            var node = FindNodeInDict(peer.Key.KeyToBin(), Store);
            if (node != null)
            {
                node.AppendQuery(Util.NowEpoch());
            }
        }

        /// <summary>When a ping response comes in and we store it, update its metrics.</summary>
        protected override void OnPingResponse(Peer peer, PingResponsePayload payload, byte[] data)
        {
            base.OnPingResponse(peer, payload, data);
            var node = FindNodeInDict(peer.Key.KeyToBin(), StoreForMe);
            if (node != null)
            {
                node.LastResponse = Util.NowEpoch();
            }
        }

        /// <summary>Get the Node instance belonging to the public key in the given dictionary.</summary>
        protected static DhtNode FindNodeInDict(byte[] publicKeyBin, Dictionary<byte[], List<DhtNode>> nodeDict)
        {
            foreach (var nodes in nodeDict.Values)
            {
                foreach (var node in nodes)
                {
                    if (Util.BytesEqual(node.PublicKey.KeyToBin(), publicKeyBin))
                    {
                        return node;
                    }
                }
            }
            return null;
        }

        /// <summary>Store ourselves.</summary>
        public async Task<List<DhtNode>> StorePeerAsync()
        {
            var key = MyPeer.Mid;

            // Do we already have enough peers storing our address?
            if (ListFor(StoreForMe, key).Count >= TargetNodes / 2)
            {
                return new List<DhtNode>();
            }

            try
            {
                var nodes = await FindNodesAsync(key);
                return await SendStorePeerRequestAsync(key, nodes.Take(TargetNodes).ToList());
            }
            catch (DhtError)
            {
                return new List<DhtNode>();
            }
        }

        /// <summary>Send a request for storage to the given nodes.</summary>
        public async Task<List<DhtNode>> SendStorePeerRequestAsync(byte[] key, List<DhtNode> nodes)
        {
            // Create new objects to avoid problems with the nodes also being in the routing table.
            var myNodes = nodes
                .Where(node => !ContainsNode(ListFor(StoreForMe, key), node))
                .Select(node => new DhtNode(node.Key, node.Address))
                .ToList();

            if (myNodes.Count == 0)
            {
                throw new DhtError("No nodes found for storing peer");
            }

            var futures = new List<Task<object>>();
            foreach (var node in myNodes)
            {
                if (Tokens.TryGetValue(node.Id, out var tokenEntry))
                {
                    var cache = new DhtRequest(this, "store-peer", node, new object[] { key });
                    RequestCache.Add(cache);
                    futures.Add(cache.Future.Task);
                    EzSend(node, new StorePeerRequestPayload(cache.Number, tokenEntry.Token, key));
                }
                else
                {
                    Console.Error.WriteLine($"Not sending store-peer-request to {node} (no token available)");
                }
            }

            if (futures.Count == 0)
            {
                throw new DhtError("Peer was not stored");
            }
            return (await GatherWithoutErrors(futures)).OfType<DhtNode>().ToList();
        }

        /// <summary>Attempt to connect to a peer with the given mid, at first without a DHT lookup.</summary>
        public async Task<List<DhtNode>> ConnectPeerAsync(byte[] mid, Peer peer = null)
        {
            if (Store.TryGetValue(mid, out var stored))
            {
                return stored;
            }

            // If a peer is provided, we will first try to ping the peer (to see if it's
            // connectable). This could potentially save an expensive DHT lookup.
            if (peer != null)
            {
                var node = new DhtNode(peer.Key, peer.Address);
                try
                {
                    await Ping(node);
                }
                catch (DhtError)
                {
                    // Ignored: fall through to the DHT lookup.
                }
                return new List<DhtNode> { node };
            }

            var nodes = await FindNodesAsync(mid);
            var connected = await SendConnectPeerRequestAsync(mid, nodes.Take(TargetNodes).ToList());
            if (connected.Count == 0)
            {
                throw new DhtError("Failed to connect peer");
            }
            return connected;
        }

        /// <summary>Send a request for connection to the given nodes.</summary>
        public async Task<List<DhtNode>> SendConnectPeerRequestAsync(byte[] key, List<DhtNode> nodes)
        {
            // Create new objects to avoid problems with the nodes also being in the routing table.
            var myNodes = nodes.Select(node => new DhtNode(node.Key, node.Address)).ToList();

            if (myNodes.Count == 0)
            {
                throw new DhtError("No nodes found for connecting to peer");
            }

            var futures = new List<Task<object>>();
            foreach (var node in myNodes)
            {
                var cache = new DhtRequest(this, "connect-peer", node);
                RequestCache.Add(cache);
                futures.Add(cache.Future.Task);
                EzSend(node, new ConnectPeerRequestPayload(cache.Number, MyEstimatedLan, key));
            }

            var nodeLists = await GatherWithoutErrors(futures);
            var all = new List<DhtNode>();
            foreach (var nodeList in nodeLists)
            {
                if (nodeList is List<DhtNode> nodes2)
                {
                    all.AddRange(nodes2);
                }
            }
            // py: list(set(...)) — deduplicate while keeping Peer (public-key) semantics.
            return all.Distinct().ToList();
        }

        private Task? OnStorePeerRequestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<StorePeerRequestPayload>(sourceAddress, data);
            OnStorePeerRequest(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>When we receive a request to store a peer, attempt to add it.</summary>
        protected virtual void OnStorePeerRequest(Peer peer, StorePeerRequestPayload payload)
        {
            var node = new DhtNode(peer.Key, peer.Address);
            node.AppendQuery(Util.NowEpoch());

            if (!CheckToken(node, payload.Token))
            {
                Console.Error.WriteLine("Bad token, dropping packet.");
                return;
            }
            if (!Util.BytesEqual(payload.Target, peer.Mid))
            {
                Console.Error.WriteLine(
                    $"Not allowed to store under key {Serializer.Hexlify(payload.Target)}, dropping packet.");
                return;
            }

            var stored = ListFor(Store, payload.Target);
            if (!ContainsNode(stored, node))
            {
                stored.Add(node);
            }

            EzSend(node, new StorePeerResponsePayload(payload.Identifier));
        }

        private Task? OnStorePeerResponsePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<StorePeerResponsePayload>(sourceAddress, data);
            OnStorePeerResponse(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>When a peer signals storage is complete, pop it from our cache.</summary>
        protected virtual void OnStorePeerResponse(Peer peer, StorePeerResponsePayload payload)
        {
            if (!RequestCache.Has("store-peer", payload.Identifier))
            {
                Console.Error.WriteLine("Got store-peer-response with unknown identifier, dropping packet");
                return;
            }

            var cache = (DhtRequest)RequestCache.Pop("store-peer", payload.Identifier);

            var key = (byte[])cache.Params[0];
            var storedForMe = ListFor(StoreForMe, key);
            if (!ContainsNode(storedForMe, cache.Node))
            {
                storedForMe.Add(cache.Node);
            }

            cache.Future.TrySetResult(cache.Node);
        }

        private Task? OnConnectPeerRequestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<ConnectPeerRequestPayload>(sourceAddress, data);
            OnConnectPeerRequest(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>When a peer wants to connect to another peer, puncture the requested "other" peer.</summary>
        protected virtual void OnConnectPeerRequest(Peer peer, ConnectPeerRequestPayload payload)
        {
            var nodes = ListFor(Store, payload.Target).Take(MaxNodesInFind).ToList();
            foreach (var node in nodes)
            {
                var packet = CreatePunctureRequest(payload.LanAddress, peer.Address, payload.Identifier);
                Endpoint.Send(node.Address, packet);
            }

            EzSend(peer, new ConnectPeerResponsePayload(payload.Identifier, nodes));
        }

        private Task? OnConnectPeerResponsePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<ConnectPeerResponsePayload>(sourceAddress, data);
            OnConnectPeerResponse(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>Handle responses of peers that performed punctures for us.</summary>
        protected virtual void OnConnectPeerResponse(Peer peer, ConnectPeerResponsePayload payload)
        {
            if (!RequestCache.Has("connect-peer", payload.Identifier))
            {
                Console.Error.WriteLine("Got connect-peer-response with unknown identifier, dropping packet");
                return;
            }

            var cache = (DhtRequest)RequestCache.Pop("connect-peer", payload.Identifier);
            cache.Future.TrySetResult(payload.Nodes);
        }

        /// <summary>Send a ping to all known nodes.</summary>
        public void PingAll()
        {
            var now = Util.NowEpoch();
            foreach (var key in StoreForMe.Keys.ToList())
            {
                var nodes = StoreForMe[key];
                for (var index = nodes.Count - 1; index >= 0; index--)
                {
                    var node = nodes[index];
                    if (node.Status == DhtRouting.NodeStatusBad)
                    {
                        nodes.RemoveAt(index);
                    }
                    else if (node.LastPingSent + PingInterval <= now)
                    {
                        _ = Ping(node);
                    }
                }
            }

            foreach (var key in Store.Keys.ToList())
            {
                var nodes = Store[key];
                for (var index = nodes.Count - 1; index >= 0; index--)
                {
                    var node = nodes[index];
                    if (now > node.LastQuery + 60)
                    {
                        nodes.RemoveAt(index);
                    }
                }
            }
        }

        /// <summary>py-ipv8 defaultdict(list) access: get or create the list for the key.</summary>
        private static List<DhtNode> ListFor(Dictionary<byte[], List<DhtNode>> dict, byte[] key)
        {
            if (!dict.TryGetValue(key, out var list))
            {
                list = new List<DhtNode>();
                dict[key] = list;
            }
            return list;
        }

        private static bool ContainsNode(IEnumerable<DhtNode> nodes, DhtNode node)
            => nodes.Any(candidate => candidate.Equals(node));
    }
}
