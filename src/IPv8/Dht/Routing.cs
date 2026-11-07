// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/routing.py: node ids, XOR distances, Bucket and the RoutingTable (a trie of
// Buckets). Note: calc_node_id uses a PLAIN CRC32 (IEEE, like binascii.crc32) — the py-ipv8
// docstring claims crc32c but the code uses the plain variant.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPv8.Messaging;

namespace IPv8.Dht
{
    /// <summary>Plain CRC32 (IEEE), the binascii.crc32 / java.util.zip.CRC32 variant.</summary>
    public static class Crc32Ieee
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                var c = i;
                for (var k = 0; k < 8; k++)
                {
                    c = ((c & 1) != 0) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
                }
                table[i] = c;
            }
            return table;
        }

        public static uint Compute(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            foreach (var b in data)
            {
                crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFF;
        }
    }

    /// <summary>DHT routing constants (ipv8/dht/routing.py).</summary>
    public static class DhtRouting
    {
        public const int NodeLimitInterval = 5;
        public const int NodeLimitQueries = 10;

        public const int NodeStatusGood = 2;
        public const int NodeStatusUnknown = 1;
        public const int NodeStatusBad = 0;

        public const int MaxBucketSize = 8;

        /// <summary>Convert a node id to a 160-character binary string (id_to_binary_string).</summary>
        public static string IdToBinaryString(byte[] nodeId)
        {
            var sb = new StringBuilder(160);
            foreach (var b in nodeId)
            {
                sb.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
            }
            while (sb.Length < 160)
            {
                sb.Insert(0, '0');
            }
            return sb.ToString();
        }

        /// <summary>
        /// Get the XOR between two byte strings, encoded as a big-endian byte array (the 160-bit
        /// integer of py-ipv8's ``distance``, represented in 20 bytes — bytewise XOR is exactly the
        /// byte representation of the big-endian integer XOR).
        /// </summary>
        public static byte[] DistanceBytes(byte[] a, byte[] b)
        {
            var length = Math.Max(a.Length, b.Length);
            var result = new byte[length];
            for (var i = 0; i < length; i++)
            {
                var ab = i < a.Length ? a[a.Length - length + i] : 0;
                var bb = i < b.Length ? b[b.Length - length + i] : 0;
                result[i] = (byte)(ab ^ bb);
            }
            return result;
        }

        /// <summary>Unsigned lexicographic comparison of two equal-length byte strings.</summary>
        public static int CompareBytes(byte[] x, byte[] y)
        {
            var length = Math.Min(x.Length, y.Length);
            for (var i = 0; i < length; i++)
            {
                if (x[i] != y[i])
                {
                    return x[i] < y[i] ? -1 : 1;
                }
            }
            return x.Length.CompareTo(y.Length);
        }

        /// <summary>Compare distance(x, a) against distance(x, b).</summary>
        public static int CompareDistance(byte[] x, byte[] a, byte[] b)
            => CompareBytes(DistanceBytes(a, x), DistanceBytes(b, x));

        /// <summary>
        /// The node id for an address: first 3 bytes of crc32(IEEE) over the masked IP + the first
        /// 17 bytes of sha1(public_key) (calc_node_id). IPv6 masked over the first 8 address bytes
        /// with mask 01 03 07 0f 1f 3f 7f ff; IPv4 with mask 03 0f 3f ff.
        /// </summary>
        public static byte[] CalcNodeId(Address address, byte[] mid)
        {
            byte[] ipMasked;
            if (address.Type == AddressType.Udpv6)
            {
                var ipBin = System.Net.IPAddress.Parse(address.Host).GetAddressBytes();
                var ipMask = new byte[] { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };
                ipMasked = new byte[ipMask.Length];
                for (var i = 0; i < ipMask.Length; i++)
                {
                    ipMasked[i] = (byte)(ipBin[i] & ipMask[i]);
                }
            }
            else
            {
                var ipBin = Ipv4.InetAton(address.Host);
                var ipMask = new byte[] { 0x03, 0x0f, 0x3f, 0xff };
                ipMasked = new byte[ipMask.Length];
                for (var i = 0; i < ipMask.Length; i++)
                {
                    ipMasked[i] = (byte)(ipBin[i] & ipMask[i]);
                }
            }

            var crc32 = Crc32Ieee.Compute(ipMasked);
            var crc32Bin = new byte[4];
            Messaging.Be.WriteU64(crc32Bin, 0, crc32, 4);

            return Util.Concat(Util.Slice(crc32Bin, 0, 3), Util.Slice(mid, 0, 17));
        }
    }

    /// <summary>
    /// The Node class represents a peer within the DHT community (ipv8/dht/routing.py::Node).
    /// </summary>
    public class DhtNode : Peer
    {
        public Bucket Bucket;
        public double LastPingSent;
        public int Failed;
        public double Rtt;

        private readonly List<double> _lastQueries = new List<double>();

        public DhtNode(Keyvault.Key key, Address? address = null, bool intro = true)
            : base(key, address, intro)
        {
        }

        public DhtNode(byte[] publicKeyBin, Address? address = null, bool intro = true)
            : base(publicKeyBin, address, intro)
        {
        }

        /// <summary>The id of this node.</summary>
        public byte[] Id => DhtRouting.CalcNodeId(Address, Mid);

        /// <summary>Append a query timestamp (deque with a maximum of NODE_LIMIT_QUERIES entries).</summary>
        public void AppendQuery(double timestamp)
        {
            _lastQueries.Add(timestamp);
            if (_lastQueries.Count > DhtRouting.NodeLimitQueries)
            {
                _lastQueries.RemoveAt(0);
            }
        }

        /// <summary>The last timestamp (in seconds) that we queried this node.</summary>
        public double LastQuery => _lastQueries.Count > 0 ? _lastQueries[_lastQueries.Count - 1] : 0;

        /// <summary>The last timestamp (in seconds) that we interacted with this node.</summary>
        public double LastContact => Math.Max(LastResponse, LastQuery);

        /// <summary>Whether this node is blocked (query rate limiting).</summary>
        public bool Blocked
        {
            get
            {
                if (_lastQueries.Count < DhtRouting.NodeLimitQueries)
                {
                    return false;
                }
                return Util.NowEpoch() - _lastQueries[0] < DhtRouting.NodeLimitInterval;
            }
        }

        /// <summary>
        /// A good node has responded to one of our queries within the last 15 minutes, or has ever
        /// responded to one of our queries and has sent us a query within the last 15 minutes
        /// (BEP-5 logic).
        /// </summary>
        public int Status
        {
            get
            {
                var now = Util.NowEpoch();
                if (Failed >= 2)
                {
                    return DhtRouting.NodeStatusBad;
                }
                if ((now - LastResponse) < 15 * 60 || (LastResponse > 0 && (now - LastQuery) < 15 * 60))
                {
                    return DhtRouting.NodeStatusGood;
                }
                return DhtRouting.NodeStatusUnknown;
            }
        }

        /// <summary>The distance to another node (or node id).</summary>
        public byte[] DistanceTo(byte[] otherNodeId) => DhtRouting.DistanceBytes(Id, otherNodeId);
    }

    /// <summary>
    /// The Bucket class stores nodes that share a common prefix ID (ipv8/dht/routing.py::Bucket).
    /// </summary>
    public class Bucket
    {
        public readonly Dictionary<byte[], DhtNode> Nodes
            = new Dictionary<byte[], DhtNode>(ByteArrayEqualityComparer.Instance);
        public readonly string PrefixId;
        public readonly int MaxSize;
        public double LastChanged;

        public Bucket(string prefixId, int maxSize = DhtRouting.MaxBucketSize)
        {
            PrefixId = prefixId;
            MaxSize = maxSize;
        }

        private static readonly Random Rng = new Random();

        /// <summary>Generate a new (random) id within this bucket's prefix range.</summary>
        public byte[] GenerateId()
        {
            // py: random int in [0, 2^(160 - len(prefix))) rendered as a 160-bit binary string —
            // i.e., the first len(prefix) bits are zero and the rest is random.
            var bytes = new byte[20];
            Rng.NextBytes(bytes);
            var zeroBits = PrefixId.Length;
            for (var i = 0; i < zeroBits; i++)
            {
                bytes[i / 8] &= (byte)~(0x80 >> (i % 8));
            }
            return bytes;
        }

        /// <summary>Whether the given node id is in this bucket.</summary>
        public bool Owns(byte[] nodeId)
            => DhtRouting.IdToBinaryString(nodeId).StartsWith(PrefixId, StringComparison.Ordinal);

        /// <summary>Get the object belonging to the given node id.</summary>
        public DhtNode Get(byte[] nodeId) => Nodes.TryGetValue(nodeId, out var node) ? node : null;

        /// <summary>
        /// Attempt to add the given node to this bucket. Returns whether the addition was successful.
        /// </summary>
        public bool Add(DhtNode node)
        {
            // Is this node allowed to be in this bucket?
            if (!Owns(node.Id))
            {
                return false;
            }

            // Update existing node
            if (Nodes.TryGetValue(node.Id, out var currNode))
            {
                currNode.Address = node.Address;
                LastChanged = Util.NowEpoch();
                return true;
            }

            // Make room if needed
            if (Nodes.Count >= MaxSize)
            {
                foreach (var n in Nodes.Values.ToList())
                {
                    if (n.Status == DhtRouting.NodeStatusBad)
                    {
                        Nodes.Remove(n.Id);
                        break;
                    }
                }

                foreach (var n in Nodes.Values.ToList())
                {
                    if (node.Rtt > 0 && n.Rtt / node.Rtt >= 2.0)
                    {
                        Nodes.Remove(n.Id);
                        break;
                    }
                }
            }

            // Insert
            if (Nodes.Count < MaxSize)
            {
                Nodes[node.Id] = node;
                node.Bucket = this;
                LastChanged = Util.NowEpoch();
                return true;
            }

            return false;
        }

        /// <summary>Split this bucket in two. Returns null when the bucket is not full.</summary>
        public (Bucket, Bucket) Split()
        {
            if (Nodes.Count < MaxSize)
            {
                return default;
            }

            var b0 = new Bucket(PrefixId + "0", MaxSize);
            var b1 = new Bucket(PrefixId + "1", MaxSize);
            foreach (var node in Nodes.Values.ToList())
            {
                if (b0.Owns(node.Id))
                {
                    b0.Add(node);
                }
                else if (b1.Owns(node.Id))
                {
                    b1.Add(node);
                }
                else
                {
                    Console.Error.WriteLine("Failed to place node into bucket while splitting");
                }
            }
            return (b0, b1);
        }
    }

    /// <summary>
    /// The RoutingTable is a binary tree that keeps track of Nodes that we have a connection to
    /// (ipv8/dht/routing.py::RoutingTable).
    /// </summary>
    public class RoutingTable
    {
        private readonly object _lock = new object();
        public readonly byte[] MyNodeId;
        public readonly Trie<Bucket> Trie = new Trie<Bucket>("01");

        public RoutingTable(byte[] myNodeId)
        {
            MyNodeId = myNodeId;
            Trie[""] = new Bucket("");
        }

        /// <summary>Get the bucket that a given node id belongs to.</summary>
        public Bucket GetBucket(byte[] nodeId)
        {
            var nodeIdBinary = DhtRouting.IdToBinaryString(nodeId);
            return Trie.LongestPrefixValue(nodeIdBinary, null) ?? Trie[""];
        }

        /// <summary>Add the given node to the routing table. Returns the stored node or null.</summary>
        public DhtNode Add(DhtNode node)
        {
            lock (_lock)
            {
                var bucket = GetBucket(node.Id);

                // Add/update node
                if (!bucket.Add(node))
                {
                    // If adding the node failed, split the bucket.
                    // Splitting is only allowed if our own node_id falls within this bucket.
                    if (bucket.Owns(MyNodeId))
                    {
                        var split = bucket.Split();
                        if (split == default)
                        {
                            return null;
                        }
                        Trie[bucket.PrefixId + "0"] = split.Item1;
                        Trie[bucket.PrefixId + "1"] = split.Item2;
                        Trie.Remove(bucket.PrefixId);

                        // Retry
                        return Add(node);
                    }
                    return null;
                }
                return bucket.Get(node.Id);
            }
        }

        /// <summary>Remove nodes that have the BAD status. Returns the removed nodes.</summary>
        public List<DhtNode> RemoveBadNodes()
        {
            lock (_lock)
            {
                var removed = new List<DhtNode>();
                foreach (var bucket in Trie.Values())
                {
                    foreach (var pair in bucket.Nodes.ToList())
                    {
                        if (pair.Value.Status == DhtRouting.NodeStatusBad)
                        {
                            bucket.Nodes.Remove(pair.Key);
                            removed.Add(pair.Value);
                        }
                    }
                }
                return removed;
            }
        }

        /// <summary>Check if a node id is known.</summary>
        public bool Has(byte[] nodeId) => Get(nodeId) != null;

        /// <summary>Return a node belonging to an id, if it exists.</summary>
        public DhtNode Get(byte[] nodeId) => GetBucket(nodeId).Get(nodeId);

        /// <summary>Return the nodes closest to a node id.</summary>
        public List<DhtNode> ClosestNodes(byte[] nodeId, int maxNodes = 8, DhtNode excludeNode = null)
        {
            lock (_lock)
            {
                var hashBinary = DhtRouting.IdToBinaryString(nodeId);
                var prefix = Trie.LongestPrefix(hashBinary, "");

                var nodes = new HashSet<DhtNode>();
                for (var i = prefix.Length; i >= 0; i--)
                {
                    var stem = prefix.Substring(0, i);
                    foreach (var suffix in Trie.Suffixes(stem))
                    {
                        var bucket = Trie[stem + suffix];
                        foreach (var node in bucket.Nodes.Values)
                        {
                            if (node.Status != DhtRouting.NodeStatusBad
                                && (excludeNode == null || !Util.BytesEqual(node.Id, excludeNode.Id)))
                            {
                                nodes.Add(node);
                            }
                        }
                    }

                    // Limit number of nodes returned
                    if (nodes.Count > maxNodes)
                    {
                        break;
                    }
                }

                // Ensure nodes are sorted by distance (then status), like py's stable sorted().
                return nodes
                    .OrderBy(n => n, Comparer<DhtNode>.Create((a, b) =>
                    {
                        var byDistance = DhtRouting.CompareDistance(nodeId, a.Id, b.Id);
                        return byDistance != 0 ? byDistance : a.Status.CompareTo(b.Status);
                    }))
                    .Take(maxNodes)
                    .ToList();
            }
        }
    }
}
