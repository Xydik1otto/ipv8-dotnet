// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/community.py: DHTCommunity for storing/finding key-value pairs, its Request
// (RandomNumberCache) and the Crawl manager.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using IPv8.Messaging;
using IPv8.PeerDiscovery;

namespace IPv8.Dht
{
    /// <summary>The result of a find exchange: nodes and/or values (py-ipv8 uses a dict).</summary>
    public sealed class FindResult
    {
        public List<byte[]> Values;
        public List<DhtNode> Nodes;
    }

    /// <summary>
    /// This request cache keeps track of all outstanding requests within the DHTCommunity
    /// (py-ipv8 dht/community.py::Request).
    /// </summary>
    public class DhtRequest : RandomNumberCache
    {
        public readonly string MsgType;
        public readonly DhtNode Node;
        public readonly object[] Params;
        public readonly bool ConsumeErrors;
        public readonly double Timeout;
        public readonly double StartTime;
        public readonly TaskCompletionSource<object> Future
            = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);

        public DhtRequest(DhtCommunity community, string msgType, DhtNode node,
                          object[] parameters = null, bool consumeErrors = false, double timeout = 5.0)
            : base(community.RequestCache, msgType)
        {
            MsgType = msgType;
            Node = node;
            Params = parameters ?? Array.Empty<object>();
            ConsumeErrors = consumeErrors;
            Timeout = timeout;
            StartTime = Util.NowEpoch();
        }

        public override double TimeoutDelay => Timeout;

        /// <summary>Cancel our completion future, if it's not already done.</summary>
        public override void OnTimeout()
        {
            if (!Future.Task.IsCompleted)
            {
                Node.Failed += 1;
                if (!ConsumeErrors)
                {
                    Future.TrySetException(new DhtError($"Timeout for {MsgType} to {Node}"));
                }
                else
                {
                    Future.TrySetResult(null);
                }
            }
        }

        /// <summary>Update our associated node's success metrics.</summary>
        public void OnComplete()
        {
            Node.LastResponse = Util.NowEpoch();
            Node.Failed = 0;
            Node.Rtt = Util.NowEpoch() - StartTime;
        }
    }

    /// <summary>A node that still needs to be contacted (py-ipv8 Crawl.TodoNode).</summary>
    public sealed class CrawlTodoNode
    {
        public DhtNode NodeToContact;
        public DhtNode NodeToPuncture;
    }

    /// <summary>
    /// Class to manage crawls in the Community, in search of a specific target key
    /// (py-ipv8 dht/community.py::Crawl).
    /// </summary>
    public sealed class Crawl
    {
        public readonly byte[] Target;
        public readonly RoutingTable RoutingTable;
        public readonly bool ForceNodes;
        public readonly int Offset;

        public readonly List<CrawlTodoNode> NodesTodo = new List<CrawlTodoNode>();
        public readonly HashSet<DhtNode> NodesTried = new HashSet<DhtNode>();
        public readonly List<(DhtNode Sender, FindResult Response)> Responses
            = new List<(DhtNode, FindResult)>();

        public Crawl(byte[] target, RoutingTable routingTable, bool forceNodes = false, int offset = 0)
        {
            Target = target;
            RoutingTable = routingTable;
            ForceNodes = forceNodes;
            Offset = offset;

            var nodesClosest = routingTable.ClosestNodes(target, DhtCommunity.MaxCrawlNodes);
            if (nodesClosest.Count == 0)
            {
                throw new DhtError("No nodes found in the routing table");
            }

            // Keep a list of nodes that still need to be contacted.
            foreach (var node in nodesClosest)
            {
                NodesTodo.Add(new CrawlTodoNode { NodeToContact = node });
            }
        }

        /// <summary>Register a response by the given node.</summary>
        public void AddResponse(DhtNode sender, FindResult response)
        {
            Responses.Add((sender, response));

            var responseNodes = response.Nodes ?? new List<DhtNode>();
            for (var index = 0; index < responseNodes.Count; index++)
            {
                var node = responseNodes[index];
                if (NodesTried.Contains(node))
                {
                    continue;
                }

                // Only add nodes that are better than our current top-4
                if (NodesTodo.Count >= 4
                    && DhtRouting.CompareDistance(Target, node.Id, NodesTodo[3].NodeToContact.Id) > 0)
                {
                    continue;
                }

                var indexExisting = NodesTodo.FindIndex(t => t.NodeToContact.Equals(node));
                if (indexExisting >= 0)
                {
                    NodesTodo[indexExisting].NodeToPuncture = index == 0 ? null : sender;
                    continue;
                }

                NodesTodo.Add(new CrawlTodoNode { NodeToContact = node, NodeToPuncture = index == 0 ? null : sender });
                NodesTodo.Sort((a, b) => DhtRouting.CompareDistance(Target, a.NodeToContact.Id, b.NodeToContact.Id));
            }
        }

        /// <summary>Check if we exhausted our tries, or we have no nodes left to query.</summary>
        public bool Done => NodesTried.Count >= DhtCommunity.MaxCrawlRequests || NodesTodo.Count == 0;

        /// <summary>Return closest node to the target that did not respond with values.</summary>
        public DhtNode CacheCandidate
        {
            get
            {
                var nodesNoValues = new List<DhtNode>();
                foreach (var (sender, response) in Responses)
                {
                    if (response.Values == null)
                    {
                        nodesNoValues.Add(sender);
                    }
                }
                nodesNoValues.Sort((a, b) => DhtRouting.CompareDistance(Target, a.Id, b.Id));
                return nodesNoValues.Count > 0 ? nodesNoValues[0] : null;
            }
        }

        /// <summary>Get the currently known values for our crawl.</summary>
        public List<byte[]> Values
        {
            get
            {
                // Merge all values received into one sequence: first pick the first value from each
                // list, then the second, etc. (py zip_longest).
                var valueResponses = new List<List<byte[]>>();
                foreach (var (_, response) in Responses)
                {
                    if (response.Values != null)
                    {
                        valueResponses.Add(response.Values);
                    }
                }
                var maxLength = valueResponses.Count == 0 ? 0 : valueResponses.Max(r => r.Count);
                var values = new List<byte[]>();
                for (var i = 0; i < maxLength; i++)
                {
                    foreach (var response in valueResponses)
                    {
                        if (i < response.Count)
                        {
                            values.Add(response[i]);
                        }
                    }
                }

                // Filter out duplicates while preserving order.
                var seen = new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
                return values.Where(v => v != null && seen.Add(v)).ToList();
            }
        }

        /// <summary>Get the nodes we have already contacted to retrieve values.</summary>
        public List<DhtNode> NodesProposed
            => NodesTried.OrderBy(n => n, Comparer<DhtNode>.Create((a, b)
                           => DhtRouting.CompareDistance(Target, a.Id, b.Id))).ToList();
    }

    /// <summary>
    /// Community for storing/finding key-value pairs (port of ipv8/dht/community.py::DHTCommunity).
    /// </summary>
    public class DhtCommunity : Community
    {
        public const int PingInterval = 25;

        /// <summary>Maximum number of seconds a token can remain valid.</summary>
        public const double TokenExpirationTime = 600;

        public const int DhtEntryStr = 0;
        public const int DhtEntryStrSigned = 1;

        public const int MaxEntrySize = 170;
        public const int MaxEntryAge = 3600;

        /// <summary>Maximum number of nodes to start a crawl with.</summary>
        public const int MaxCrawlNodes = 8;

        /// <summary>Maximum number of find-requests a single crawl is allowed to make.</summary>
        public const int MaxCrawlRequests = 24;

        /// <summary>Maximum number of simultaneous outstanding find-requests per crawl.</summary>
        public const int MaxCrawlTasks = 4;

        public const int MaxValuesInStore = 8;
        public const int MaxValuesInFind = 8;
        public const int MaxNodesInFind = 8;

        /// <summary>Target number of nodes at which a key-value pair should be stored.</summary>
        public const int TargetNodes = 8;

        /// <summary>The fixed DHT community id (dht/community.py:255).</summary>
        public static readonly byte[] FixedCommunityId = Util.Unhex("8d0be1845d74d175f178197cad001591d04d73cc");

        public readonly Dictionary<AddressType, Storage> Storages = new Dictionary<AddressType, Storage>();
        public readonly Dictionary<AddressType, RoutingTable> RoutingTables
            = new Dictionary<AddressType, RoutingTable>();

        public RequestCache RequestCache { get; } = new RequestCache();

        /// <summary>Received tokens per node id: node_id -&gt; (timestamp, token).</summary>
        public readonly Dictionary<byte[], (double Timestamp, byte[] Token)> Tokens
            = new Dictionary<byte[], (double, byte[])>(ByteArrayEqualityComparer.Instance);

        /// <summary>Token secrets (py deque with maxlen=2: add trims the oldest).</summary>
        public readonly List<byte[]> TokenSecrets = new List<byte[]>();

        public DhtCommunity(CommunitySettings settings) : base(settings, FixedCommunityId)
        {
            // py-ipv8: self.network = Network() — the DHT community ignores the injected network.
            Network = new Network();
            Network.BlacklistMids.Add(MyPeer.Mid);
            // py-ipv8: self.network.blacklist.extend(self.network.blacklist) — a literal no-op quirk.

            // First call to token maintenance should happen immediately, in case we get requests
            // before it gets executed.
            TokenMaintenance();

            RegisterTask("token_maintenance", TokenMaintenance, interval: 300);
            RegisterTask("node_maintenance", () => _ = NodeMaintenanceAsync(), interval: 60);
            RegisterTask("value_maintenance", ValueMaintenance, interval: 3600);

            // Register messages
            AddMessageHandler(typeof(PingRequestPayload), OnPingRequestPacket);
            AddMessageHandler(typeof(PingResponsePayload), OnPingResponsePacket);
            AddMessageHandler(typeof(StoreRequestPayload), OnStoreRequestPacket);
            AddMessageHandler(typeof(StoreResponsePayload), OnStoreResponsePacket);
            AddMessageHandler(typeof(FindRequestPayload), OnFindRequestPacket);
            AddMessageHandler(typeof(FindResponsePayload), OnFindResponsePacket);
        }

        /// <summary>Extend our serializer with a node list packer (dht/community.py:294).</summary>
        protected override Serializer GetSerializer()
        {
            var serializer = base.GetSerializer();
            serializer.AddPacker("node-list", new ListOf(new NodePacker(serializer)));
            return serializer;
        }

        /// <summary>Extend our available strategies with our maintenance strategy.</summary>
        public Dictionary<string, Type> GetAvailableStrategies() => new Dictionary<string, Type>
        {
            { "PingChurn", typeof(PingChurn) },
        };

        public override void Unload()
        {
            RequestCache.Shutdown();
            base.Unload();
        }

        /// <summary>Get the class of the given node's address (py: the address tuple class).</summary>
        public AddressType GetAddressClass(Peer node) => node.Address.Type;

        /// <summary>Get the routing table that the given node belongs to.</summary>
        public RoutingTable GetRoutingTable(Peer node)
        {
            var addressClass = GetAddressClass(node);
            if (!RoutingTables.TryGetValue(addressClass, out var routingTable))
            {
                routingTable = new RoutingTable(GetMyNodeId(node));
                RoutingTables[addressClass] = routingTable;
            }
            return routingTable;
        }

        /// <summary>Get or create a Storage object for the given node.</summary>
        public Storage GetStorage(Peer node)
        {
            var addressClass = GetAddressClass(node);
            if (!Storages.TryGetValue(addressClass, out var storage))
            {
                storage = new Storage();
                Storages[addressClass] = storage;
            }
            return storage;
        }

        /// <summary>Get our own node id to share with the given node.</summary>
        public byte[] GetMyNodeId(Peer node)
        {
            var addressClass = GetAddressClass(node);
            var address = MyPeer.Addresses.TryGetValue(addressClass, out var ownAddress)
                ? ownAddress
                : MyEstimatedWan;
            return DhtRouting.CalcNodeId(address, MyPeer.Mid);
        }

        /// <summary>
        /// Add the given peer to the appropriate routing table and return it, or null if it is
        /// already blocked.
        /// </summary>
        protected DhtNode GetRequestingNode(Peer peer)
        {
            var routingTable = GetRoutingTable(peer);
            var node = new DhtNode(peer.Key, peer.Address);
            var existing = routingTable.Get(node.Id);
            if (existing != null && existing.Blocked)
            {
                return null;
            }

            node = routingTable.Add(node) ?? node;
            node.AppendQuery(Util.NowEpoch());
            return node;
        }

        /// <summary>Call our node discovery logic when an introduction request is received from it.</summary>
        protected override void IntroductionRequestCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                            Payload payload)
            => OnNodeDiscovered(peer.PublicKey.KeyToBin(), peer.Address);

        /// <summary>Call our node discovery logic when an introduction response is received from it.</summary>
        protected override void IntroductionResponseCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                             Payload payload)
            => OnNodeDiscovered(peer.PublicKey.KeyToBin(), peer.Address);

        /// <summary>Handler for potentially new nodes.</summary>
        public void OnNodeDiscovered(byte[] publicKeyBin, Address sourceAddress)
        {
            if (sourceAddress.Type == AddressType.Udpv6 && !MyPeer.Addresses.ContainsKey(AddressType.Udpv6))
            {
                return;
            }

            // We need to know our own node ID before we can start adding nodes to the routing table.
            if ((MyEstimatedWan.Host == "0.0.0.0" && MyEstimatedWan.Port == 0)
                || (MyEstimatedWan.Host == "::1" && MyEstimatedWan.Port == 0))
            {
                return;
            }

            // Filter out trackers
            if (!Network.Blacklist.Contains(sourceAddress))
            {
                var node = new DhtNode(publicKeyBin, sourceAddress);
                var routingTable = GetRoutingTable(node);
                var existed = routingTable.Has(node.Id);
                var rtNode = routingTable.Add(node);

                if (!existed && rtNode != null)
                {
                    // Ping the node in order to determine RTT
                    _ = Ping(rtNode);
                }
            }
        }

        /// <summary>Send a ping to the given node.</summary>
        public Task<object> Ping(DhtNode node)
        {
            var cache = new DhtRequest(this, "ping", node, consumeErrors: true);
            RequestCache.Add(cache);
            EzSend(node, new PingRequestPayload(cache.Number));
            node.LastPingSent = Util.NowEpoch();
            return cache.Future.Task;
        }

        private Task? OnPingRequestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<PingRequestPayload>(sourceAddress, data);
            OnPingRequest(decoded.Peer, decoded.Payload, data);
            return null;
        }

        /// <summary>When we receive a ping request through a valid node, send a response.</summary>
        protected virtual void OnPingRequest(Peer peer, PingRequestPayload payload, byte[] data)
        {
            var node = GetRequestingNode(peer);
            if (node == null)
            {
                return;
            }
            EzSend(peer, new PingResponsePayload(payload.Identifier));
        }

        private Task? OnPingResponsePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<PingResponsePayload>(sourceAddress, data);
            OnPingResponse(decoded.Peer, decoded.Payload, data);
            return null;
        }

        /// <summary>When we receive a response to our ping, update the node's metrics.</summary>
        protected virtual void OnPingResponse(Peer peer, PingResponsePayload payload, byte[] data)
        {
            if (!RequestCache.Has("ping", payload.Identifier))
            {
                Console.Error.WriteLine("Got ping-response with unknown identifier, dropping packet");
                return;
            }

            var cache = (DhtRequest)RequestCache.Pop("ping", payload.Identifier);
            cache.OnComplete();
            if (!cache.Future.Task.IsCompleted)
            {
                cache.Future.TrySetResult(cache.Node);
            }
        }

        /// <summary>Serialize the given bytes (DHT_ENTRY_STR / DHT_ENTRY_STR_SIGNED).</summary>
        public byte[] SerializeValue(byte[] data, bool sign = true)
        {
            if (sign)
            {
                var payload = new SignedStrPayload(data, (int)Util.NowEpoch(), MyPeer.PublicKey.KeyToBin());
                return EzPack(Util.EmptyBytes, DhtEntryStrSigned, new Payload[] { payload }, sig: true);
            }
            var strPayload = new StrPayload(data);
            return EzPack(Util.EmptyBytes, DhtEntryStr, new Payload[] { strPayload }, sig: false);
        }

        /// <summary>Unserialize data from the given serialized value.</summary>
        public (byte[] Data, byte[] PublicKey, int Version)? UnserializeValue(byte[] value)
        {
            if (value[0] == DhtEntryStr)
            {
                var strPayload = Serializer.UnpackSerializableAs<StrPayload>(value, 1);
                return (strPayload.Data, null, 0);
            }

            if (value[0] == DhtEntryStrSigned)
            {
                var payload = Serializer.UnpackSerializableAs<SignedStrPayload>(value, 1);
                var publicKey = Crypto.KeyFromPublicBin(payload.PublicKey);
                var sigLength = Crypto.GetSignatureLength(publicKey);
                var signature = Util.SliceFrom(value, value.Length - sigLength);
                if (Crypto.IsValidSignature(publicKey,
                                            Util.Slice(value, 0, value.Length - sigLength), signature))
                {
                    return (payload.Data, payload.PublicKey, payload.Version);
                }
            }

            return null;
        }

        /// <summary>Add a serialized value under the given key into a storage.</summary>
        public void AddValue(byte[] key, byte[] value, Storage storage, double maxAge = MaxEntryAge)
        {
            var unserialized = UnserializeValue(value);
            if (unserialized.HasValue)
            {
                var (_, publicKey, version) = unserialized.Value;
                var id = publicKey != null ? Util.Sha1(publicKey) : null;
                storage.Put(key, value, id: id, maxAge: maxAge, version: version);
            }
            else
            {
                Console.Error.WriteLine($"Failed to store value {Serializer.Hexlify(value)}");
            }
        }

        /// <summary>Attempt to store a value at the given key and return the nodes that store it.</summary>
        public async Task<List<DhtNode>> StoreValueAsync(byte[] key, byte[] data, bool sign = false)
        {
            var value = SerializeValue(data, sign: sign);
            return await StoreAsync(key, value);
        }

        /// <summary>Attempt to store a serialized value at the given key and return the storing nodes.</summary>
        public async Task<List<DhtNode>> StoreAsync(byte[] key, byte[] value)
        {
            if (value.Length > MaxEntrySize)
            {
                throw new DhtError("Maximum length exceeded");
            }

            var nodes = await FindNodesAsync(key);
            nodes = await StoreOnNodesAsync(key, new List<byte[]> { value }, nodes.Take(TargetNodes).ToList());
            if (nodes.Count < 1)
            {
                throw new DhtError("Failed to store value on DHT");
            }
            return nodes;
        }

        /// <summary>Store the given values under a given key on the given nodes.</summary>
        public async Task<List<DhtNode>> StoreOnNodesAsync(byte[] key, List<byte[]> values, List<DhtNode> nodes)
        {
            if (nodes.Count == 0)
            {
                throw new DhtError("No nodes found for storing the key-value pairs");
            }

            if (values.Count > MaxValuesInStore)
            {
                values = values.GetRange(0, MaxValuesInStore);
            }

            // Check if we also need to store this key-value pair
            var farthest = nodes[0];
            foreach (var node in nodes.Skip(1))
            {
                if (DhtRouting.CompareDistance(key, node.Id, farthest.Id) > 0)
                {
                    farthest = node;
                }
            }
            if (nodes.Count < TargetNodes || DhtRouting.CompareDistance(key, GetMyNodeId(nodes[0]), farthest.Id) < 0)
            {
                var storage = GetStorage(nodes[0]);
                foreach (var value in values.AsEnumerable().Reverse())
                {
                    AddValue(key, value, storage);
                }
            }

            var now = Util.NowEpoch();
            var futures = new List<Task<object>>();
            foreach (var node in nodes)
            {
                if (Tokens.TryGetValue(node.Id, out var tokenEntry)
                    && tokenEntry.Timestamp + TokenExpirationTime > now)
                {
                    var cache = new DhtRequest(this, "store", node);
                    RequestCache.Add(cache);
                    futures.Add(cache.Future.Task);
                    EzSend(node, new StoreRequestPayload(cache.Number, tokenEntry.Token, key, values));
                }
                else
                {
                    Console.Error.WriteLine($"Not sending store-request to {node} (no token available)");
                }
            }

            if (futures.Count == 0)
            {
                throw new DhtError("Value was not stored");
            }
            return (await GatherWithoutErrors(futures)).OfType<DhtNode>().ToList();
        }

        /// <summary>Gather only the successful results from the given futures.</summary>
        internal static async Task<List<T>> GatherWithoutErrors<T>(IEnumerable<Task<T>> tasks)
        {
            var results = new List<T>();
            foreach (var task in tasks)
            {
                try
                {
                    results.Add(await task);
                }
                catch (Exception)
                {
                    // py gather_without_errors: drop exceptions.
                }
            }
            return results;
        }

        private Task? OnStoreRequestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<StoreRequestPayload>(sourceAddress, data);
            OnStoreRequest(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>Store or forward the given requested value.</summary>
        protected virtual void OnStoreRequest(Peer peer, StoreRequestPayload payload)
        {
            var node = GetRequestingNode(peer);
            if (node == null)
            {
                return;
            }
            if (payload.Values.Any(value => value.Length > MaxEntrySize))
            {
                Console.Error.WriteLine("Maximum length of value exceeded, dropping packet.");
                return;
            }
            if (payload.Values.Count > MaxValuesInStore)
            {
                Console.Error.WriteLine("Too many values, dropping packet.");
                return;
            }
            // Note that even though we are preventing spoofing of source_address (by checking the
            // token), the value that is to be stored isn't checked. This should be done at a higher
            // level.
            if (!CheckToken(node, payload.Token))
            {
                Console.Error.WriteLine("Bad token, dropping packet.");
                return;
            }

            // How many nodes (that we know of) are closer to this value?
            var numCloser = 0;
            foreach (var closer in GetRoutingTable(node).ClosestNodes(payload.Target, 20))
            {
                if (DhtRouting.CompareDistance(payload.Target, closer.Id, GetMyNodeId(closer)) < 0)
                {
                    numCloser += 1;
                }
            }

            // To prevent over-caching, the expiration time of an entry depends on the number of
            // nodes that are closer than we are.
            var shift = Math.Max(0, numCloser - TargetNodes + 1);
            var maxAge = MaxEntryAge >> Math.Min(shift, 30);
            foreach (var value in payload.Values)
            {
                AddValue(payload.Target, value, GetStorage(node), maxAge);
            }

            EzSend(peer, new StoreResponsePayload(payload.Identifier));
        }

        private Task? OnStoreResponsePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<StoreResponsePayload>(sourceAddress, data);
            OnStoreResponse(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>We got confirmation of storage.</summary>
        protected virtual void OnStoreResponse(Peer peer, StoreResponsePayload payload)
        {
            if (!RequestCache.Has("store", payload.Identifier))
            {
                Console.Error.WriteLine("Got store-response with unknown identifier, dropping packet");
                return;
            }

            var cache = (DhtRequest)RequestCache.Pop("store", payload.Identifier);
            cache.OnComplete();
            if (!cache.Future.Task.IsCompleted)
            {
                cache.Future.TrySetResult(cache.Node);
            }
        }

        private TaskCompletionSource<object> SendFindRequest(DhtNode node, byte[] target, bool forceNodes,
                                                             int offset = 0)
        {
            var cache = new DhtRequest(this, "find", node, new object[] { forceNodes },
                                       consumeErrors: true, timeout: 2.0);
            RequestCache.Add(cache);
            EzSend(node, new FindRequestPayload(cache.Number, MyEstimatedLan, target, offset, forceNodes));
            return cache.Future;
        }

        private async Task<object> ContactNodeAsync(Crawl crawl, DhtNode node, DhtNode punctureNode)
        {
            if (punctureNode != null)
            {
                await SendFindRequest(punctureNode, node.Id, crawl.ForceNodes).Task;
            }
            var result = await SendFindRequest(node, crawl.Target, crawl.ForceNodes, crawl.Offset).Task;
            if (result != null)
            {
                crawl.RoutingTable.Add(node);
                crawl.AddResponse(node, (FindResult)result);
            }
            return null;
        }

        private async Task<object> FindCoreAsync(Crawl crawl, bool debug = false)
        {
            var tasks = new List<Task<object>>();
            while (true)
            {
                // Keep running tasks until work is done.
                while (!crawl.Done && tasks.Count < MaxCrawlTasks)
                {
                    var todo = crawl.NodesTodo[0];
                    crawl.NodesTodo.RemoveAt(0);
                    tasks.Add(ContactNodeAsync(crawl, todo.NodeToContact, todo.NodeToPuncture));
                    // Add to nodes_tried immediately to prevent sending multiple find-requests to
                    // the same node.
                    crawl.NodesTried.Add(todo.NodeToContact);
                }
                if (tasks.Count == 0)
                {
                    break;
                }
                var completed = await Task.WhenAny(tasks);
                tasks.Remove(completed);
            }

            if (crawl.ForceNodes)
            {
                return crawl.NodesProposed;
            }

            var cacheCandidate = crawl.CacheCandidate;
            var values = crawl.Values;

            if (cacheCandidate != null && values.Count > 0)
            {
                // Store the key-value pair on the most recently visited node that did not have it
                // (for caching purposes).
                await StoreOnNodesAsync(crawl.Target, values, new List<DhtNode> { cacheCandidate });
            }

            if (debug)
            {
                return (PostProcessValues(values), crawl);
            }
            return PostProcessValues(values);
        }

        /// <summary>Unpack signed and unsigned values and filter out duplicates.</summary>
        public List<(byte[] Data, byte[] PublicKey)> PostProcessValues(List<byte[]> values)
        {
            // Signed values grouped by (non-null) public key, in first-seen order; unsigned values
            // collected separately (py-ipv8's defaultdict keyed by the optional public key).
            var unpacked = new List<(byte[] PublicKey, List<(int Version, byte[] Data)> Entries)>();
            var unsignedEntries = new List<(int Version, byte[] Data)>();
            foreach (var value in values)
            {
                var unserialized = UnserializeValue(value);
                if (unserialized.HasValue)
                {
                    var (data, publicKey, version) = unserialized.Value;
                    if (publicKey != null)
                    {
                        var group = unpacked.FirstOrDefault(pair => Util.BytesEqual(pair.PublicKey, publicKey));
                        if (group.PublicKey == null)
                        {
                            group = (publicKey, new List<(int, byte[])>());
                            unpacked.Add(group);
                        }
                        group.Entries.Add((version, data));
                    }
                    else
                    {
                        unsignedEntries.Add((version, data));
                    }
                }
            }

            var results = new List<(byte[] Data, byte[] PublicKey)>();

            // Signed data: keep the highest version per public key.
            foreach (var (publicKey, entries) in unpacked)
            {
                var best = entries[0];
                foreach (var entry in entries.Skip(1))
                {
                    if (entry.Version > best.Version)
                    {
                        best = entry;
                    }
                }
                results.Add((best.Data, publicKey));
            }

            // Unsigned data
            foreach (var (_, data) in unsignedEntries)
            {
                results.Add((data, null));
            }
            return results;
        }

        public async Task<object> FindAsync(byte[] target, bool forceNodes, int offset, bool debug = false)
        {
            var futures = new List<Task<object>>();
            foreach (var routingTable in RoutingTables.Values)
            {
                var crawl = new Crawl(target, routingTable, forceNodes: forceNodes, offset: offset);
                futures.Add(FindCoreAsync(crawl, debug));
            }
            var results = await Task.WhenAll(futures);

            if (debug)
            {
                return results;
            }
            // Merge the results from all crawls into one flat list (py flattens a list of tuples);
            // the result is homogeneous per call since force_nodes applies to every crawl.
            if (forceNodes)
            {
                var mergedNodes = new List<DhtNode>();
                foreach (var result in results)
                {
                    if (result is List<DhtNode> nodes)
                    {
                        mergedNodes.AddRange(nodes);
                    }
                }
                return mergedNodes;
            }
            var mergedValues = new List<(byte[] Data, byte[] PublicKey)>();
            foreach (var result in results)
            {
                if (result is List<(byte[] Data, byte[] PublicKey)> values)
                {
                    foreach (var value in values)
                    {
                        mergedValues.Add(value);
                    }
                }
            }
            return mergedValues;
        }

        /// <summary>Find the values belonging to the target key.</summary>
        public async Task<List<(byte[] Data, byte[] PublicKey)>> FindValuesAsync(byte[] target,
                                                                                 int offset = 0,
                                                                                 bool debug = false)
            => (List<(byte[] Data, byte[] PublicKey)>)await FindAsync(target, false, offset, debug);

        /// <summary>Find the closest nodes for the target key.</summary>
        public async Task<List<DhtNode>> FindNodesAsync(byte[] target)
            => (List<DhtNode>)await FindAsync(target, true, 0);

        private Task? OnFindRequestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<FindRequestPayload>(sourceAddress, data);
            OnFindRequest(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>Try to perform a search for the requested target.</summary>
        protected virtual void OnFindRequest(Peer peer, FindRequestPayload payload)
        {
            var node = GetRequestingNode(peer);
            if (node == null)
            {
                return;
            }

            List<DhtNode> nodes;
            var storage = GetStorage(node);
            var values = payload.ForceNodes
                ? new List<byte[]>()
                : storage.Get(payload.Target, payload.Offset, MaxValuesInFind);

            if (payload.ForceNodes || values.Count == 0)
            {
                var routingTable = GetRoutingTable(node);
                nodes = routingTable.ClosestNodes(payload.Target, MaxNodesInFind, node);
                // Send puncture request to the closest node
                if (nodes.Count > 0)
                {
                    var packet = CreatePunctureRequest(payload.LanAddress, peer.Address, payload.Identifier);
                    Endpoint.Send(nodes[0].Address, packet);
                }
            }
            else
            {
                nodes = new List<DhtNode>();
            }

            EzSend(peer, new FindResponsePayload(payload.Identifier, GenerateToken(node), values, nodes));
        }

        private Task? OnFindResponsePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<FindResponsePayload>(sourceAddress, data);
            OnFindResponse(decoded.Peer, decoded.Payload);
            return null;
        }

        /// <summary>We got a response for our find requests.</summary>
        protected virtual void OnFindResponse(Peer peer, FindResponsePayload payload)
        {
            if (!RequestCache.Has("find", payload.Identifier))
            {
                Console.Error.WriteLine("Got find-response with unknown identifier, dropping packet");
                return;
            }

            var cache = (DhtRequest)RequestCache.Pop("find", payload.Identifier);
            cache.OnComplete();

            Tokens[cache.Node.Id] = (Util.NowEpoch(), payload.Token);

            if (cache.Future.Task.IsCompleted)
            {
                // The errback must already have been called (due to a timeout)
                return;
            }

            if ((bool)cache.Params[0])
            {
                cache.Future.TrySetResult(new FindResult { Nodes = payload.Nodes });
            }
            else
            {
                cache.Future.TrySetResult(payload.Values.Count > 0
                    ? new FindResult { Values = payload.Values }
                    : new FindResult { Nodes = payload.Nodes });
            }
        }

        /// <summary>Refresh old result values.</summary>
        public async Task NodeMaintenanceAsync()
        {
            // Determine which buckets to refresh
            var refreshTodo = new Dictionary<string, List<Bucket>>();
            var now = Util.NowEpoch();
            foreach (var routingTable in RoutingTables.Values)
            {
                foreach (var bucket in routingTable.Trie.Values())
                {
                    if (now - bucket.LastChanged > 15 * 60)
                    {
                        if (!refreshTodo.TryGetValue(bucket.PrefixId, out var buckets))
                        {
                            refreshTodo[bucket.PrefixId] = buckets = new List<Bucket>();
                        }
                        buckets.Add(bucket);
                    }
                }
            }

            // For every prefix perform a refresh. We only have to perform a single refresh for each
            // prefix because find_values will crawl both IPv4 and IPv6.
            foreach (var buckets in refreshTodo.Values)
            {
                try
                {
                    await FindValuesAsync(buckets[0].GenerateId());
                }
                catch (DhtError)
                {
                    // py: contextlib.suppress(DHTError)
                }

                foreach (var bucket in buckets)
                {
                    bucket.LastChanged = now;
                }
            }
        }

        /// <summary>Remove expired values from the storage objects.</summary>
        public void ValueMaintenance()
        {
            foreach (var storage in Storages.Values)
            {
                storage.Clean();
            }
        }

        /// <summary>Make sure tokens are periodically refreshed.</summary>
        public void TokenMaintenance()
        {
            using var rng = RandomNumberGenerator.Create();
            var secret = new byte[16];
            rng.GetBytes(secret);
            TokenSecrets.Add(secret);
            if (TokenSecrets.Count > 2)
            {
                TokenSecrets.RemoveAt(0);
            }

            // Cleanup old tokens
            var now = Util.NowEpoch();
            var expired = Tokens.Where(pair => now > pair.Value.Timestamp + TokenExpirationTime)
                .Select(pair => pair.Key)
                .ToList();
            foreach (var nodeId in expired)
            {
                Tokens.Remove(nodeId);
            }
        }

        /// <summary>Generate a token for the given node.</summary>
        public byte[] GenerateToken(DhtNode node)
            => Util.Sha1(Util.Concat(Util.Utf8(node.ToString()), TokenSecrets[TokenSecrets.Count - 1]));

        /// <summary>Check if the presented token is valid for the given node.</summary>
        public bool CheckToken(DhtNode node, byte[] token)
            => TokenSecrets.Any(secret
                => Util.BytesEqual(Util.Sha1(Util.Concat(Util.Utf8(node.ToString()), secret)), token));
    }
}
