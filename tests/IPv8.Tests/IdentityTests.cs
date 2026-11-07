// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Attestation;
using IPv8.Database;
using IPv8.Attestation.Identity;
using IPv8.Attestation.TokenTree;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;
using IdentityAttestation = IPv8.Attestation.Identity.Attestation;

namespace IPv8.Tests
{
    /// <summary>A17/A19: identity manager + tokentree + community advertise/attest flows.</summary>
    public class IdentityTests : IDisposable
    {
        private static readonly byte[] FakeHash = Enumerable.Repeat((byte)'a', 32).ToArray();

        private readonly List<TestNode> _nodes = new List<TestNode>();

        // ------------------------------------------------------------------
        // A17: manager semantics (py test/attestation/identity/test_manager.py)
        // ------------------------------------------------------------------

        [Fact]
        public void Manager_Create_Identity_Empty()
        {
            using var manager = new IdentityManager();
            var pseudonym = manager.GetPseudonym(PrivateKey());
            Assert.Empty(pseudonym.GetCredentials());
        }

        [Fact]
        public void Manager_Substantiate_Empty()
        {
            using var manager = new IdentityManager();
            var privateKey = PrivateKey();
            var (valid, pseudonym) = manager.Substantiate((PublicKey)privateKey.Pub(),
                Util.EmptyBytes, Util.EmptyBytes, Util.EmptyBytes, Util.EmptyBytes);
            Assert.True(valid);
            Assert.Empty(pseudonym.GetCredentials());
        }

        [Fact]
        public void Manager_Create_Credential()
        {
            using var manager = new IdentityManager();
            var pseudonym = manager.GetPseudonym(PrivateKey());
            pseudonym.CreateCredential(ThirtyTwoAbs(), JsonDict.Of(("some_key", "some_value")));

            Assert.Single(pseudonym.GetCredentials());
            Assert.Equal(0, pseudonym.GetCredentials()[0].Attestations.Count);
            Assert.Equal(new Dictionary<string, object> { ["some_key"] = "some_value" },
                         pseudonym.GetCredentials()[0].Metadata.ParseJsonDict());
        }

        [Fact]
        public void Manager_Substantiate_Credential_Update()
        {
            using var manager = new IdentityManager();
            var privateKey = PrivateKey();
            var pseudonym = manager.GetPseudonym(privateKey);
            pseudonym.CreateCredential(ThirtyTwoAbs(), JsonDict.Of(("some_key", "some_value")));
            var (metadata, tokens, attestations, authorities) =
                pseudonym.DiscloseCredentials(pseudonym.GetCredentials(), new HashSet<byte[]>());

            manager.ForgetIdentities();

            var (valid, publicPseudonym) = manager.Substantiate((PublicKey)privateKey.Pub(),
                metadata, tokens, attestations, authorities);
            Assert.True(valid);
            Assert.Single(publicPseudonym.GetCredentials());
            Assert.Equal(0, publicPseudonym.GetCredentials()[0].Attestations.Count);
            Assert.Equal(new Dictionary<string, object> { ["some_key"] = "some_value" },
                         publicPseudonym.GetCredentials()[0].Metadata.ParseJsonDict());
        }

        [Fact]
        public void Manager_Substantiate_Credential_No_Metadata()
        {
            using var manager = new IdentityManager();
            var privateKey = PrivateKey();
            var pseudonym = manager.GetPseudonym(privateKey);
            pseudonym.CreateCredential(ThirtyTwoAbs(), JsonDict.Of(("some_key", "some_value")));
            var (_, tokens, attestations, authorities) =
                pseudonym.DiscloseCredentials(pseudonym.GetCredentials(), new HashSet<byte[]>());

            manager.ForgetIdentities();

            var (valid, publicPseudonym) = manager.Substantiate((PublicKey)privateKey.Pub(),
                Util.EmptyBytes, tokens, attestations, authorities);
            Assert.True(valid);
            Assert.Empty(publicPseudonym.GetCredentials());
            Assert.Equal(1, publicPseudonym.Tree.Elements.Count);
        }

        [Fact]
        public void Manager_Substantiate_Credential_Full()
        {
            using var manager = new IdentityManager();
            var privateKey = PrivateKey();
            var authorityKey = PrivateKey();
            var pseudonym = manager.GetPseudonym(privateKey);
            pseudonym.CreateCredential(ThirtyTwoAbs(), JsonDict.Of(("some_key", "some_value")));

            var attestation = pseudonym.CreateAttestation(pseudonym.GetCredentials()[0].Metadata, authorityKey);
            pseudonym.AddAttestation((PublicKey)authorityKey.Pub(), attestation);

            var (metadata, tokens, attestations, authorities) = pseudonym.DiscloseCredentials(
                pseudonym.GetCredentials(), new HashSet<byte[]>(new[] { attestation.GetHash() }, ByteArrayEqualityComparer.Instance));

            manager.ForgetIdentities();

            var (valid, publicPseudonym) = manager.Substantiate((PublicKey)privateKey.Pub(),
                metadata, tokens, attestations, authorities);
            Assert.True(valid);
            Assert.Single(publicPseudonym.GetCredentials());
            Assert.Equal(1, publicPseudonym.GetCredentials()[0].Attestations.Count);
            Assert.Equal(new Dictionary<string, object> { ["some_key"] = "some_value" },
                         publicPseudonym.GetCredentials()[0].Metadata.ParseJsonDict());
        }

        [Fact]
        public void Manager_Substantiate_Credential_Partial()
        {
            using var manager = new IdentityManager();
            var privateKey = PrivateKey();
            var authorityKey = PrivateKey();
            var pseudonym = manager.GetPseudonym(privateKey);
            pseudonym.CreateCredential(ThirtyTwoAbs(), JsonDict.Of(("some_key", "some_value")));

            var attestation = pseudonym.CreateAttestation(pseudonym.GetCredentials()[0].Metadata, authorityKey);
            pseudonym.AddAttestation((PublicKey)authorityKey.Pub(), attestation);

            var attestation2 = pseudonym.CreateAttestation(pseudonym.GetCredentials()[0].Metadata, privateKey);
            pseudonym.AddAttestation((PublicKey)privateKey.Pub(), attestation2);

            // Only disclose the authority's attestation.
            var (metadata, tokens, attestations, authorities) = pseudonym.DiscloseCredentials(
                pseudonym.GetCredentials(), new HashSet<byte[]>(new[] { attestation.GetHash() }, ByteArrayEqualityComparer.Instance));

            manager.ForgetIdentities();

            var (valid, publicPseudonym) = manager.Substantiate((PublicKey)privateKey.Pub(),
                metadata, tokens, attestations, authorities);
            Assert.True(valid);
            Assert.Single(publicPseudonym.GetCredentials());
            Assert.Equal(1, publicPseudonym.GetCredentials()[0].Attestations.Count);
        }

        // ------------------------------------------------------------------
        // A19: community flows (py test/attestation/identity/test_identity.py)
        // ------------------------------------------------------------------

        [Fact]
        public async Task Community_Advertise_And_Attest_Over_Loopback()
        {
            var nodeA = CreateNode();
            var nodeB = CreateNode();
            await Introduce(nodeA, nodeB);

            nodeB.Community.AddKnownHash(FakeHash, "attribute", nodeA.MyPeer.PublicKey.KeyToBin());
            nodeA.Community.RequestAttestationAdvertisement(nodeA.Peer, FakeHash, "attribute");

            await WaitUntilAsync(() =>
                nodeA.Community.PseudonymManager.GetCredentials().Any(credential =>
                    credential.Attestations.Count > 0)
                && PseudonymOf(nodeB, nodeA).GetCredentials().Any(credential =>
                    credential.Attestations.Count > 0),
                "attestation to arrive on both nodes");

            // Node A (owner) has the attestation on its own credential.
            var own = nodeA.Community.PseudonymManager.GetCredentials();
            Assert.Single(own);
            Assert.Single(own[0].Attestations);

            // Node B loaded the disclosure through substantiate().
            var loaded = PseudonymOf(nodeB, nodeA);
            Assert.Single(loaded.GetCredentials());
            Assert.Single(loaded.GetCredentials()[0].Attestations);
        }

        [Fact]
        public async Task Community_Advertise_With_Metadata()
        {
            var nodeA = CreateNode();
            var nodeB = CreateNode();
            await Introduce(nodeA, nodeB);

            nodeB.Community.AddKnownHash(FakeHash, "attribute", nodeA.MyPeer.PublicKey.KeyToBin(),
                                         new Dictionary<string, string> { ["a"] = "b" });
            nodeA.Community.RequestAttestationAdvertisement(nodeA.Peer, FakeHash, "attribute", "id_metadata",
                                                            new Dictionary<string, string> { ["a"] = "b" });

            await WaitUntilAsync(() =>
                nodeA.Community.PseudonymManager.GetCredentials().Any(credential =>
                    credential.Attestations.Count > 0),
                "attestation with metadata to arrive");

            var own = nodeA.Community.PseudonymManager.GetCredentials();
            Assert.Single(own);
            Assert.Single(own[0].Attestations);
            var dict = own[0].Metadata.ParseJsonDict();
            Assert.Equal("b", dict["a"]);
        }

        // ------------------------------------------------------------------
        // A17 aux: tokentree chains (py test/attestation/tokentree/test_token.py)
        // ------------------------------------------------------------------

        [Fact]
        public void TokenTree_Chain_Serialize_Unserialize_Roundtrip()
        {
            var privateKey = PrivateKey();
            var tree = new TokenTree(privateKey: privateKey);
            var first = tree.Add(new byte[] { 1 });
            var second = tree.Add(new byte[] { 2 }, first);
            var third = tree.Add(new byte[] { 3 }, second);

            Assert.Equal(3, tree.Elements.Count);
            Assert.True(tree.Verify(third));
            // py get_root_path walks UP: [token, predecessor, ..., root].
            var path = tree.GetRootPath(third);
            Assert.Same(third, path[0]);
            Assert.Same(first, path[2]);

            var serialized = tree.SerializePublic();
            var otherTree = new TokenTree((PublicKey)privateKey.Pub());
            Assert.True(otherTree.UnserializePublic(serialized));
            Assert.Equal(3, otherTree.Elements.Count);
            Assert.True(otherTree.Verify(otherTree.Elements[third.GetHash()]));
        }

        [Fact]
        public void TokenTree_Unchained_Tokens_Wait_For_Predecessor()
        {
            var privateKey = PrivateKey();
            var tree = new TokenTree(privateKey: privateKey);
            var first = tree.Add(new byte[] { 1 });

            var otherTree = new TokenTree((PublicKey)privateKey.Pub());
            // A child arriving BEFORE its predecessor is delayed (unchained).
            var signedChild = new Token(first.GetHash(), new byte[] { 2 }, null, privateKey, null);
            Assert.Null(otherTree.GatherToken(signedChild));
            Assert.Equal(1, otherTree.Unchained.Count);
            Assert.Equal(new HashSet<byte[]>(new[] { first.GetHash() }), otherTree.GetMissing());

            // When the predecessor arrives, the unchained child chains in (chain reaction).
            Assert.NotNull(otherTree.GatherToken(first));
            Assert.Empty(otherTree.Unchained);
            Assert.Equal(2, otherTree.Elements.Count);
        }

        [Fact]
        public void Token_Receive_Content_Matches_Hash()
        {
            var privateKey = PrivateKey();
            var content = Util.Utf8("some content");
            var token = new Token(new byte[32], content, null, privateKey, null);
            Assert.True(token.ReceiveContent(content));
            Assert.False(token.ReceiveContent(Util.Utf8("other content")));
        }

        [Fact]
        public void Metadata_Unserialize_Rejects_Bad_Signature_Length()
        {
            var privateKey = PrivateKey();
            var publicKey = (PublicKey)privateKey.Pub();
            var token = new TokenTree(privateKey: privateKey).Add(new byte[] { 1 });
            var metadata = Metadata.Create(token, JsonDict.Of(("k", "v")), privateKey);

            var signed = metadata.GetPlaintextSigned();
            var restored = Metadata.Unserialize(signed, publicKey);
            Assert.True(restored.Verify(publicKey));
            Assert.True(Util.BytesEqual(metadata.GetPlaintextSigned(), restored.GetPlaintextSigned()));
        }

        [Fact]
        public void IdentityAttestation_Roundtrip_With_Padding()
        {
            var privateKey = PrivateKey();
            var publicKey = (PublicKey)privateKey.Pub();
            var token = new TokenTree(privateKey: privateKey).Add(new byte[] { 1 });
            var metadata = Metadata.Create(token, JsonDict.Of(("k", "v")), privateKey);
            var attestation = IdentityAttestation.Create(metadata, privateKey);

            var signed = attestation.GetPlaintextSigned();
            var restored = IdentityAttestation.Unserialize(signed, publicKey);
            Assert.True(restored.Verify(publicKey));
            Assert.False(restored.Verify((PublicKey)PrivateKey().Pub()));
        }

        // ------------------------------------------------------------------
        // Infrastructure
        // ------------------------------------------------------------------

        private static Keyvault.PrivateKey PrivateKey()
            => (Keyvault.PrivateKey)ECCrypto.Default.GenerateKey("curve25519");

        /// <summary>py: b"ab" * 16 (32 bytes).</summary>
        private static byte[] ThirtyTwoAbs()
        {
            var result = new byte[32];
            for (var i = 0; i < result.Length; i += 2)
            {
                result[i] = 0xab;
                result[i + 1] = 0xab;
            }
            return result;
        }

        private TestNode CreateNode()
        {
            var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(endpoint.Open());
            var address = endpoint.GetAddress();
            var settings = new IdentitySettings(IdentityCommunity.FixedCommunityId, myPeer, endpoint, new Network())
            {
                WorkingDirectory = ":memory:"
            };
            var community = new IdentityCommunity(settings);
            community.MyEstimatedLan = address;
            community.MyEstimatedWan = address;
            var node = new TestNode { Community = community, Endpoint = endpoint, MyPeer = myPeer };
            _nodes.Add(node);
            return node;
        }

        private static async Task Introduce(TestNode a, TestNode b)
        {
            a.Community.WalkTo(b.Address);
            b.Community.WalkTo(a.Address);
            await WaitUntilAsync(() => a.Community.GetPeers().Count > 0 && b.Community.GetPeers().Count > 0,
                                 "mutual introduction");
        }

        private static PseudonymManager PseudonymOf(TestNode holder, TestNode owner)
            => holder.Community.IdentityManager.GetPseudonym(owner.MyPeer.PublicKey);

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 5000)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(5);
            }
        }

        private sealed class TestNode : IDisposable
        {
            public IdentityCommunity Community;
            public UDPEndpoint Endpoint;
            public Peer MyPeer;

            public Address Address => Endpoint.GetAddress();

            /// <summary>The single known peer of this node's community (2-node tests).</summary>
            public Peer Peer => Community.GetPeers().FirstOrDefault()
                                ?? throw new InvalidOperationException("peer unknown");

            public void Dispose() => Endpoint.Close();
        }

        public void Dispose()
        {
            foreach (var node in _nodes)
            {
                node.Dispose();
            }
        }
    }

}
