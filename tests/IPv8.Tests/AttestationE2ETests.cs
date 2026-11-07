// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using IPv8.Wallet.Primitives;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A20: wallet/attestation E2E over real loopback UDP — node A gets an attribute attested by
    /// node B (bonehexact/id_metadata), then B verifies A's disclosure (challenges over the wire).
    /// Includes the tampered-disclosure rejection path.
    /// </summary>
    public class AttestationE2ETests
    {
        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        /// <summary>The golden id_metadata Boneh key (key_size 32) from vectors-phase2.json.</summary>
        private static BonehPrivateKey GoldenSecretKey()
            => BonehPrivateKey.Unserialize(Util.Unhex(Vectors2.BonehKey("serialize_hex")));

        private sealed class TestNode : IDisposable
        {
            public AttestationCommunity Community;
            public UDPEndpoint InnerEndpoint;
            private TamperingEndpoint _tamperWrapper;

            public static TestNode Create(byte[] bonehSecretKeySerialization = null, bool tamperDisclosure = false)
            {
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var inner = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(inner.Open());
                Endpoint endpoint = inner;
                if (tamperDisclosure)
                {
                    endpoint = new TamperingEndpoint(inner, (PrivateKey)myPeer.Key);
                }
                var community = new AttestationCommunity(new AttestationSettings(
                    AttestationCommunity.FixedCommunityId, myPeer, endpoint, new Network())
                {
                    WorkingDirectory = ":memory:"
                });
                community.MyEstimatedLan = inner.GetAddress();
                community.MyEstimatedWan = inner.GetAddress();
                return new TestNode
                {
                    Community = community,
                    InnerEndpoint = inner,
                    _tamperWrapper = endpoint as TamperingEndpoint
                };
            }

            public Address Address => InnerEndpoint.GetAddress();

            public void Dispose()
            {
                Community.Unload();
                InnerEndpoint.Close();
            }
        }

        /// <summary>
        /// Delegating endpoint that corrupts outgoing wallet msg-2 (attestation chunk) packets:
        /// the payload data is flipped and the packet is RE-SIGNED with the node's own key, so the
        /// tampered disclosure reaches the chunk assembly with a valid signature (exercising the
        /// sha1 blob integrity check, not merely the packet signature).
        /// </summary>
        private sealed class TamperingEndpoint : Endpoint
        {
            private readonly Endpoint _inner;
            private readonly PrivateKey _signingKey;
            private readonly ForwardingListener _forwarder;

            public TamperingEndpoint(Endpoint inner, PrivateKey signingKey) : base(22)
            {
                _inner = inner;
                _signingKey = signingKey;
                _forwarder = new ForwardingListener(this);
                inner.AddListener(_forwarder);
            }

            public override bool IsOpen => _inner.IsOpen;

            public override Address GetAddress() => _inner.GetAddress();

            public override bool Open() => _inner.Open();

            public override void Close() => _inner.Close();

            public override void ResetByteCounters() => _inner.ResetByteCounters();

            public override void Send(Address socketAddress, byte[] packet)
            {
                if (packet.Length > 23 && packet[22] == 2)
                {
                    packet = TamperChunk(packet);
                }
                _inner.Send(socketAddress, packet);
            }

            private byte[] TamperChunk(byte[] packet)
            {
                // The raw chunk data is the last field before the 64-byte signature: flip its
                // final byte and replace the signature trailer with a fresh valid one.
                var tampered = (byte[])packet.Clone();
                var dataEnd = tampered.Length - 64;
                tampered[dataEnd - 1] ^= 0xFF;
                var signedPortion = Util.Slice(tampered, 0, dataEnd);
                return Util.Concat(signedPortion, Crypto.CreateSignature(_signingKey, signedPortion));
            }

            private ECCrypto Crypto { get; } = ECCrypto.Default;

            private sealed class ForwardingListener : EndpointListener
            {
                private readonly TamperingEndpoint _owner;

                public ForwardingListener(TamperingEndpoint owner) : base(owner.Inner)
                {
                    _owner = owner;
                }

                public override void OnPacket(Packet packet) => _owner.NotifyListeners(packet);
            }

            private Endpoint Inner => _inner;
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 15000)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(10);
            }
        }

        private sealed class CompletionTracker
        {
            public readonly TaskCompletionSource<(string Name, byte[] Hash, string IdFormat, Peer From)>
                Done = new(TaskCreationOptions.RunContinuationsAsynchronously);

            public void OnComplete(Peer _, string name, byte[] hash, string idFormat, Peer fromPeer)
                => Done.TrySetResult((name, hash, idFormat, fromPeer));

            /// <summary>The completion with a watchdog so a broken flow fails instead of hanging.</summary>
            public async Task<(string Name, byte[] Hash, string IdFormat, Peer From)> WaitOrThrowAsync(
                int timeoutMs = 20000)
            {
                var done = await Task.WhenAny(Done.Task, Task.Delay(timeoutMs));
                if (done != Done.Task)
                {
                    throw new TimeoutException("attestation completion not reached");
                }
                return Done.Task.Result;
            }
        }

        private sealed class CertaintyTracker
        {
            public readonly TaskCompletionSource<(byte[] Hash, List<double> Certainties)> Done =
                new(TaskCreationOptions.RunContinuationsAsynchronously);

            public void OnComplete(byte[] hash, List<double> certainties) => Done.TrySetResult((hash, certainties));

            public async Task<(byte[] Hash, List<double> Certainties)> WaitOrThrowAsync(int timeoutMs = 20000)
            {
                var done = await Task.WhenAny(Done.Task, Task.Delay(timeoutMs));
                if (done != Done.Task)
                {
                    throw new TimeoutException("certainty completion not reached");
                }
                return Done.Task.Result;
            }
        }

        [Fact]
        public async Task Attest_Then_Verify_Loopback_Happy_Path()
        {
            using var nodeA = TestNode.Create();
            using var nodeB = TestNode.Create();
            var goldenKey = GoldenSecretKey();

            // Node B attests the value b"test" for node A's one-time Boneh key.
            // NOTE (py semantics): id_format/attribute/public_key are popped from the metadata
            // BEFORE the callback fires, so the callback only sees the extra metadata.
            nodeB.Community.SetAttestationRequestCallback((_, attributeName, _) =>
                Task.FromResult(attributeName == "my_attribute" ? Util.Utf8("test") : null));
            var attested = new CompletionTracker();
            nodeA.Community.SetAttestationRequestCompleteCallback(attested.OnComplete);

            var peerOfB = new Peer(nodeB.Community.MyPeer.PublicKey.KeyToBin(), nodeB.Address);
            nodeA.Community.RequestAttestation(peerOfB, "my_attribute", goldenKey,
                new Dictionary<string, string> { ["id_format"] = "id_metadata" });

            var (name, hash, idFormat, fromPeer) = await attested.WaitOrThrowAsync();
            Assert.Equal("my_attribute", name);
            Assert.Equal("id_metadata", idFormat);
            Assert.Equal(nodeB.Community.MyPeer.Mid, fromPeer.Mid);

            // The attestation is registered + persisted under its (public) hash.
            Assert.Contains(hash, nodeA.Community.AttestationKeys.Keys);
            Assert.NotEmpty(nodeA.Community.Database.GetAttestationByHash(hash));

            // Node B verifies the disclosure: challenges flow over the wire.
            // NOTE: b"tesX" is used as the wrong value because py-ipv8's relativity map has only
            // three buckets — b"tesw" coincidentally shares b"test"'s bucket distribution.
            var verified = new CertaintyTracker();
            nodeB.Community.VerifyAttestationValues(nodeA.Address, hash,
                new List<byte[]> { Util.Utf8("test"), Util.Utf8("tesX") },
                verified.OnComplete, "id_metadata");

            var (_, certainties) = await verified.WaitOrThrowAsync();
            Assert.Equal(2, certainties.Count);
            // The attested value verifies with near-certainty; a different value does not.
            Assert.True(certainties[0] > 0.99, $"certainty(test) = {certainties[0]}");
            Assert.True(certainties[1] < 0.5, $"certainty(tesX) = {certainties[1]}");
        }

        [Fact]
        public async Task Tampered_Disclosure_Is_Never_Accepted()
        {
            using var nodeA = TestNode.Create(tamperDisclosure: true);
            using var nodeB = TestNode.Create();
            var goldenKey = GoldenSecretKey();

            nodeB.Community.SetAttestationRequestCallback((_, _, _) => Task.FromResult(Util.Utf8("test")));
            var attested = new CompletionTracker();
            nodeA.Community.SetAttestationRequestCompleteCallback(attested.OnComplete);

            var peerOfB = new Peer(nodeB.Community.MyPeer.PublicKey.KeyToBin(), nodeB.Address);
            nodeA.Community.RequestAttestation(peerOfB, "my_attribute", goldenKey,
                new Dictionary<string, string> { ["id_format"] = "id_metadata" });

            // The INITIAL attestation transfer (B → A) is untouched: it completes.
            var (name, hash, idFormat, _) = await attested.WaitOrThrowAsync();
            Assert.Equal("my_attribute", name);

            // Node B requests the disclosure; node A's outgoing chunks are tampered (and
            // re-signed, so they pass the packet signature check).
            var verified = new CertaintyTracker();
            nodeB.Community.VerifyAttestationValues(nodeA.Address, hash,
                new List<byte[]> { Util.Utf8("test") }, verified.OnComplete, "id_metadata");

            // The assembled blob no longer matches the announced sha1: the attestation is
            // dropped, no certainty is ever reported.
            var completed = await Task.WhenAny(verified.Done.Task, Task.Delay(1500));
            Assert.NotEqual(verified.Done.Task, completed);

            // The verifier's caches are still waiting (nothing was accepted or completed).
            var verifyId = HashCache.IdFromHash("receive-verify-attestation", hash);
            Assert.True(nodeB.Community.RequestCache.Has(verifyId.Prefix, verifyId.Number));
            var provingId = HashCache.IdFromHash("proving-attestation", hash);
            Assert.True(nodeB.Community.RequestCache.Has(provingId.Prefix, provingId.Number));
        }
    }
}
