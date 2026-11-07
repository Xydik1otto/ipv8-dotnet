// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A7: routing vectors (node ids v4+v6), XOR distance vectors, bucket insertion/eviction and
    /// closest_nodes ordering.
    /// </summary>
    public class RoutingTests
    {
        private static byte[] Hex(string hex) => Util.Unhex(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        private static DhtNode MakeNode(byte[] publicKeyBin, Address address)
            => new DhtNode(publicKeyBin, address);

        private static byte[] PubA => Hex(Vectors1b.MetaKey("alice_pub_bin_hex"));

        private static byte[] PubB => Hex(Vectors1b.MetaKey("bob_pub_bin_hex"));

        [Fact]
        public void Node_Id_Vector_V4_A_And_B()
        {
            var nodeA = MakeNode(PubA, Address.Udpv4("127.0.0.1", 7000));
            var nodeB = MakeNode(PubB, Address.Udpv4("127.0.0.1", 7001));
            Assert.Equal(Vectors1b.Routing("node_id_a_hex"), Hexlify(nodeA.Id));
            Assert.Equal(Vectors1b.Routing("node_id_b_hex"), Hexlify(nodeB.Id));
        }

        [Fact]
        public void Node_Id_Vector_V6_Localhost()
        {
            var nodeA = MakeNode(PubA, Address.Udpv6("::1", 7000));
            Assert.Equal(Vectors1b.Routing("node_id_v6_localhost_hex"), Hexlify(nodeA.Id));
        }

        [Fact]
        public void Xor_Distance_Is_Big_Endian_Integer_Xor()
        {
            var a = Hex(Vectors1b.Routing("node_id_a_hex"));
            var b = Hex(Vectors1b.Routing("node_id_b_hex"));

            // Reference computation: py-ipv8 distance = int(hexlify(a),16) ^ int(hexlify(b),16).
            var intA = BigInteger.Parse("0" + Hexlify(a), System.Globalization.NumberStyles.HexNumber);
            var intB = BigInteger.Parse("0" + Hexlify(b), System.Globalization.NumberStyles.HexNumber);
            var expectedXor = intA ^ intB;

            var distanceBytes = DhtRouting.DistanceBytes(a, b);
            var distanceInt = BigInteger.Parse("0" + Hexlify(distanceBytes),
                                               System.Globalization.NumberStyles.HexNumber);
            Assert.Equal(expectedXor, distanceInt);

            // Commutativity and self-distance (a XOR a = 0 over all 20 bytes).
            Assert.Equal(distanceBytes, DhtRouting.DistanceBytes(b, a));
            Assert.Equal(0, DhtRouting.CompareDistance(a, a, a));
            var selfDistance = DhtRouting.DistanceBytes(a, a);
            Assert.All(Enumerable.Range(0, 20), i => Assert.Equal(0, selfDistance[i]));
        }

        [Fact]
        public void CompareDistance_Orders_Nodes_By_Xor_Distance()
        {
            // All nodes on 127.0.0.1 share the crc32 prefix, so distances differ only in the mid part.
            var rng = new Random(1234);
            var nodes = new List<DhtNode>();
            for (var i = 0; i < 12; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                nodes.Add(new DhtNode(key, Address.Udpv4("127.0.0.1", 1000 + i)));
            }
            var target = Vectors1b.Target();

            var sorted = nodes.OrderBy(n => n, Comparer<DhtNode>.Create((x, y)
                => DhtRouting.CompareDistance(target, x.Id, y.Id))).ToList();

            for (var i = 1; i < sorted.Count; i++)
            {
                Assert.True(DhtRouting.CompareDistance(target, sorted[i - 1].Id, sorted[i].Id) <= 0,
                            "nodes must be sorted by increasing XOR distance");
            }
        }

        private static Bucket BucketWithNodes(params DhtNode[] nodes)
        {
            var bucket = new Bucket("");
            foreach (var node in nodes)
            {
                Assert.True(bucket.Add(node));
            }
            return bucket;
        }

        [Fact]
        public void Bucket_Owns_And_Update_Existing()
        {
            var nodeA = MakeNode(PubA, Address.Udpv4("127.0.0.1", 7000));
            var bucket = new Bucket("");
            Assert.True(bucket.Owns(nodeA.Id));
            Assert.True(bucket.Add(nodeA));
            Assert.Same(nodeA, bucket.Get(nodeA.Id));

            // Adding a node with the same id updates the existing node's address instead.
            var updated = MakeNode(PubA, Address.Udpv4("127.0.0.1", 9999));
            Assert.True(bucket.Add(updated));
            Assert.Single(bucket.Nodes);
            Assert.Equal(9999, bucket.Get(nodeA.Id).Address.Port);

            // A bucket with a restrictive prefix does not own the node (node id A starts with bit 0).
            var prefixed = new Bucket("1");
            Assert.False(prefixed.Owns(nodeA.Id));
            Assert.False(prefixed.Add(nodeA));
        }

        [Fact]
        public void Bucket_Rejects_When_Full_Of_Unknown_Nodes()
        {
            var nodes = new List<DhtNode>();
            for (var i = 0; i < DhtRouting.MaxBucketSize; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                nodes.Add(new DhtNode(key, Address.Udpv4("127.0.0.1", 2000 + i)));
            }
            var bucket = BucketWithNodes(nodes.ToArray());
            Assert.Equal(DhtRouting.MaxBucketSize, bucket.Nodes.Count);

            // A fresh UNKNOWN node cannot evict anything (no bad nodes, no rtt-based eviction).
            var extra = new DhtNode(ECCrypto.Default.GenerateKey("curve25519"), Address.Udpv4("127.0.0.1", 3000));
            Assert.False(bucket.Add(extra));
            Assert.Equal(DhtRouting.MaxBucketSize, bucket.Nodes.Count);
        }

        [Fact]
        public void Bucket_Evicts_Bad_Node()
        {
            var nodes = new List<DhtNode>();
            for (var i = 0; i < DhtRouting.MaxBucketSize; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                nodes.Add(new DhtNode(key, Address.Udpv4("127.0.0.1", 2000 + i)));
            }
            var bucket = BucketWithNodes(nodes.ToArray());

            // Mark the first node BAD (two failures).
            nodes[0].Failed = 2;

            var extra = new DhtNode(ECCrypto.Default.GenerateKey("curve25519"), Address.Udpv4("127.0.0.1", 3000));
            Assert.True(bucket.Add(extra));
            Assert.Equal(DhtRouting.MaxBucketSize, bucket.Nodes.Count);
            Assert.Null(bucket.Get(nodes[0].Id));
            Assert.NotNull(bucket.Get(extra.Id));
        }

        [Fact]
        public void Bucket_Evicts_Slow_Node_By_Rtt()
        {
            var nodes = new List<DhtNode>();
            for (var i = 0; i < DhtRouting.MaxBucketSize; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                nodes.Add(new DhtNode(key, Address.Udpv4("127.0.0.1", 2000 + i)));
            }
            var bucket = BucketWithNodes(nodes.ToArray());

            // The existing node measured a much larger RTT than the newcomer: it gets evicted.
            nodes[0].Rtt = 10.0;
            var fast = new DhtNode(ECCrypto.Default.GenerateKey("curve25519"), Address.Udpv4("127.0.0.1", 3000));
            fast.Rtt = 1.0; // n.rtt / node.rtt = 10 >= 2.0
            Assert.True(bucket.Add(fast));
            Assert.Null(bucket.Get(nodes[0].Id));
        }

        [Fact]
        public void RoutingTable_Splits_And_Adds()
        {
            // Our own node id shares the 24-bit 127.0.0.1 crc prefix with all nodes (like a real
            // node on the same subnet), so full buckets on the shared prefix can still split.
            var routingTable = new RoutingTable(Hex(Vectors1b.Routing("node_id_a_hex")));
            var added = new List<DhtNode>();
            for (var i = 0; i < DhtRouting.MaxBucketSize + 2; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                var node = new DhtNode(key, Address.Udpv4("127.0.0.1", 4000 + i));
                var stored = routingTable.Add(node);
                Assert.NotNull(stored);
                added.Add(stored);
            }

            // Adding the 9th node forces a split of the root bucket (the root owns our all-zero
            // my_node_id): the "" bucket is gone and every node is still reachable.
            var bucketIds = routingTable.Trie.Values().Select(b => b.PrefixId).ToList();
            Assert.DoesNotContain("", bucketIds);
            Assert.All(bucketIds, id => Assert.True(id.Length >= 1));
            Assert.Equal(DhtRouting.MaxBucketSize + 2,
                         routingTable.Trie.Values().Sum(b => b.Nodes.Count));

            // has/get find every node again.
            foreach (var node in added)
            {
                Assert.True(routingTable.Has(node.Id));
                Assert.Equal(node.Id, routingTable.Get(node.Id).Id);
            }
        }

        [Fact]
        public void Bucket_Split_Places_Every_Node_By_Prefix()
        {
            var nodes = new List<DhtNode>();
            for (var i = 0; i < DhtRouting.MaxBucketSize; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                nodes.Add(new DhtNode(key, Address.Udpv4("127.0.0.1", 2000 + i)));
            }
            var root = BucketWithNodes(nodes.ToArray());

            var (bucket0, bucket1) = root.Split();
            Assert.NotNull(bucket0);
            Assert.Equal("0", bucket0.PrefixId);
            Assert.Equal("1", bucket1.PrefixId);
            Assert.Equal(DhtRouting.MaxBucketSize, bucket0.Nodes.Count + bucket1.Nodes.Count);
            foreach (var node in nodes)
            {
                var placedIn0 = bucket0.Nodes.ContainsKey(node.Id);
                var placedIn1 = bucket1.Nodes.ContainsKey(node.Id);
                Assert.True(placedIn0 ^ placedIn1, "each node lands in exactly one half");
                Assert.Equal(placedIn0, DhtRouting.IdToBinaryString(node.Id).StartsWith("0"));
            }
        }

        [Fact]
        public void RoutingTable_ClosestNodes_Ordering_And_Exclusion()
        {
            var routingTable = new RoutingTable(Hex(Vectors1b.Routing("node_id_a_hex")));
            var nodes = new List<DhtNode>();
            for (var i = 0; i < 10; i++)
            {
                var key = ECCrypto.Default.GenerateKey("curve25519");
                var node = new DhtNode(key, Address.Udpv4("127.0.0.1", 5000 + i));
                Assert.NotNull(routingTable.Add(node));
                nodes.Add(node);
            }
            var target = Vectors1b.Target();

            var closest = routingTable.ClosestNodes(target, maxNodes: 8);
            Assert.Equal(8, closest.Count);
            // Sorted by increasing distance.
            for (var i = 1; i < closest.Count; i++)
            {
                Assert.True(DhtRouting.CompareDistance(target, closest[i - 1].Id, closest[i].Id) <= 0);
            }

            // Exclude one node.
            var excluded = closest[0];
            var without = routingTable.ClosestNodes(target, maxNodes: 8, excludeNode: excluded);
            Assert.DoesNotContain(excluded, without);
            Assert.Equal(8, without.Count);
        }

        [Fact]
        public void RoutingTable_Removes_Bad_Nodes()
        {
            var routingTable = new RoutingTable(new byte[20]);
            var good = new DhtNode(PubA, Address.Udpv4("127.0.0.1", 7000));
            var bad = new DhtNode(PubB, Address.Udpv4("127.0.0.1", 7001));
            bad.Failed = 3;
            Assert.NotNull(routingTable.Add(good));
            Assert.NotNull(routingTable.Add(bad));

            var removed = routingTable.RemoveBadNodes();
            Assert.Single(removed);
            Assert.Equal(bad.Id, removed[0].Id);
            Assert.False(routingTable.Has(bad.Id));
            Assert.True(routingTable.Has(good.Id));
        }

        [Fact]
        public void Trie_LongestPrefix_And_Suffixes()
        {
            var trie = new Trie<string>("01");
            trie[""] = "root";
            trie["01"] = "one";
            trie["011"] = "two";

            Assert.Equal("two", trie["011"]);
            Assert.Throws<KeyNotFoundException>(() => trie["10"]);
            Assert.Equal("two", trie.LongestPrefixValue("0111"));
            Assert.Equal("011", trie.LongestPrefix("0111"));
            Assert.Equal("", trie.LongestPrefix("1", ""));
            Assert.Equal(new List<string> { "", "1" }, trie.Suffixes("01"));

            trie.Remove("011");
            Assert.Throws<KeyNotFoundException>(() => trie["011"]);
            Assert.Equal("one", trie["01"]);
        }

        [Fact]
        public void Id_To_Binary_String_Has_160_Chars()
        {
            var nodeId = Hex(Vectors1b.Routing("node_id_a_hex"));
            var binary = DhtRouting.IdToBinaryString(nodeId);
            Assert.Equal(160, binary.Length);
            Assert.StartsWith("01000100", binary); // 0x44 = "01000100"
        }
    }
}
