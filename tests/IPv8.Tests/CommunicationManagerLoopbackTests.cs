// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Attestation;
using IPv8.Attestation.Identity;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// D4: the communication_manager glue. The unit tests cover the pseudonym folder management
    /// and the channel bookkeeping; the E2E test wires a pseudonym per py load() (a tunnel
    /// community on the real socket + identity/attestation overlays on a TunnelEndpoint with
    /// anonymize=true) and routes an attestation transfer THROUGH the hidden tunnels:
    /// request → attest → verify over the tunnel circuits, certainty > 0.9.
    /// </summary>
    public class CommunicationManagerLoopbackTests
    {
        private static string TempFolder()
        {
            return Path.Combine(Path.GetTempPath(), "ipv8-dotnet-d4-" + Guid.NewGuid().ToString("N"));
        }

        [Fact]
        public void Pseudonym_Folder_Manager_Roundtrip()
        {
            var folder = TempFolder();
            try
            {
                var manager = new PseudonymFolderManager(folder);

                var first = manager.GetOrCreatePrivateKey("alice");
                Assert.True(File.Exists(Path.Combine(folder, "alice")));
                var second = manager.GetOrCreatePrivateKey("alice");
                Assert.True(Util.BytesEqual(first.KeyToBin(), second.KeyToBin()));

                manager.GetOrCreatePrivateKey("bob");
                Assert.Equal(new[] { "alice", "bob" }, manager.ListPseudonymFiles().OrderBy(n => n));

                manager.RemovePseudonymFile("alice");
                Assert.Equal(new[] { "bob" }, manager.ListPseudonymFiles());
            }
            finally
            {
                if (Directory.Exists(folder))
                {
                    Directory.Delete(folder, true);
                }
            }
        }

        [Fact]
        public async Task Communication_Channel_Bookkeeping()
        {
            var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(endpoint.Open());
            try
            {
                var identity = new IdentityCommunity(new IdentitySettings(
                    IdentityCommunity.FixedCommunityId, myPeer, endpoint, new Network())
                {
                    IdentityManager = new IdentityManager(":memory:"),
                    WorkingDirectory = ":memory:"
                });
                var attestation = new AttestationCommunity(new AttestationSettings(
                    AttestationCommunity.FixedCommunityId, myPeer, endpoint, identity.Network)
                {
                    WorkingDirectory = ":memory:"
                });
                var channel = new CommunicationChannel(attestation, identity);

                // The wallet calls the channel's request callback; the channel stores the request.
                var otherPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var future = channel.AttestationOverlay.AttestationRequestCallback(
                    otherPeer, "my_attribute", new Dictionary<string, string> { ["note"] = "x" });
                Assert.False(future.IsCompleted);
                Assert.True(channel.AttestationRequests.ContainsKey((otherPeer, "my_attribute")));
                Assert.Equal("{\"note\": \"x\"}",
                             channel.AttestationRequests[(otherPeer, "my_attribute")].MetadataJson);

                // The business logic attests: the outstanding future resolves with the value.
                channel.Attest(otherPeer, "my_attribute", Util.Utf8("test"));
                Assert.True(Util.BytesEqual(Util.Utf8("test"), await future));

                // An unknown verify hash falls back to the falsy "do not verify" answer (py succeed(None)).
                Assert.False(await channel.AttestationOverlay.VerifyRequestCallback(
                    otherPeer, new byte[32]));

                // py on_attestation_complete: for a foreign for_peer we record the known hash.
                var attributeHash = System.Text.Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
                channel.AttestationOverlay.AttestationRequestCompleteCallback(
                    otherPeer, "my_attribute", attributeHash, "id_metadata", myPeer);
                Assert.True(identity.KnownAttestationHashes.ContainsKey(attributeHash));
            }
            finally
            {
                endpoint.Close();
            }
        }

        private sealed class CountingIdentity : IdentityCommunity
        {
            public int Received;

            public CountingIdentity(IdentitySettings settings) : base(settings)
            {
            }

            public override void OnPacket(Packet packet)
            {
                System.Threading.Interlocked.Increment(ref Received);
                base.OnPacket(packet);
            }
        }

        private sealed class PseudonymNode : IDisposable
        {
            public UDPEndpoint BusinessSocket;
            public TunnelEndpoint BusinessEndpoint;
            public TunnelCommunity Tunnel;
            public IdentityCommunity Identity;
            public AttestationCommunity Attestation;
            public CommunicationChannel Channel;

            /// <summary>py load()/ipv8_service.py:126-127: when anonymized overlays exist the whole
            /// service endpoint becomes a TunnelEndpoint — the tunnel community, the identity overlay
            /// and the attestation overlay all share it. The tunnel's own cells stay un-anonymized
            /// (its prefix is not registered); only the business overlays' prefixes route through the
            /// circuits, and their tunnel-returning replies are handed back via notify_listeners.</summary>
            public static PseudonymNode Create(HashSet<int> peerFlags)
            {
                var businessSocket = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(businessSocket.Open());
                var address = businessSocket.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var sharedEndpoint = new TunnelEndpoint(businessSocket);

                var tunnel = new TunnelCommunity(new TunnelSettings
                {
                    MyPeer = myPeer,
                    Endpoint = sharedEndpoint,
                    Network = new Network(),
                    PeerFlags = peerFlags,
                    RemoveTunnelDelay = 0
                });
                tunnel.MyEstimatedLan = address;
                tunnel.MyEstimatedWan = address;

                var identity = new CountingIdentity(new IdentitySettings(
                    IdentityCommunity.FixedCommunityId, myPeer, sharedEndpoint, new Network(),
                    anonymize: true)
                {
                    IdentityManager = new IdentityManager(":memory:"),
                    WorkingDirectory = ":memory:"
                });
                identity.MyEstimatedLan = address;
                identity.MyEstimatedWan = address;

                var attestation = new AttestationCommunity(new AttestationSettings(
                    AttestationCommunity.FixedCommunityId, myPeer, sharedEndpoint, identity.Network,
                    anonymize: true)
                {
                    WorkingDirectory = TempFolder()
                });
                attestation.MyEstimatedLan = address;
                attestation.MyEstimatedWan = address;
                sharedEndpoint.SetTunnelCommunity(tunnel, 1);

                return new PseudonymNode
                {
                    BusinessSocket = businessSocket,
                    BusinessEndpoint = sharedEndpoint,
                    Tunnel = tunnel,
                    Identity = identity,
                    Attestation = attestation,
                    Channel = new CommunicationChannel(attestation, identity)
                };
            }

            public Address BusinessAddress => BusinessSocket.GetAddress();

            public Address TunnelAddress => BusinessAddress;

            public void Dispose()
            {
                Attestation.Unload();
                Identity.Unload();
                Tunnel.Unload();
                BusinessSocket.Close();
            }
        }

        private static readonly HashSet<int> RelayExitFlags =
            new HashSet<int>
            {
                Tunnel.PeerFlagRelay, Tunnel.PeerFlagExitBt, Tunnel.PeerFlagExitIpv8, Tunnel.PeerFlagSpeedTest
            };

        private static readonly HashSet<int> DownloaderFlags =
            new HashSet<int> { Tunnel.PeerFlagSpeedTest };

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 20000)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(10);
            }
        }

        [Fact]
        public async Task Attestation_Transfer_Through_Hidden_Tunnels()
        {
            // Node roles mirror py's pseudonym topology: the downloader and the seeder carry no
            // tunnel flags; the relays/exits (b, e) provide the EXIT_IPV8 circuits the
            // TunnelEndpoint routes through. Replies that come back to a tunnel hop are re-injected
            // into the tunnel by the exit socket and reach the anonymized overlays through
            // TunnelEndpoint.notify_listeners.
            using var a = PseudonymNode.Create(DownloaderFlags);
            using var b = PseudonymNode.Create(RelayExitFlags);
            using var s = PseudonymNode.Create(DownloaderFlags);
            using var e = PseudonymNode.Create(RelayExitFlags);
            var all = new[] { a, b, s, e };

            // Tunnel peers (all-pairs, both directions — the D3 pattern).
            for (var i = 0; i < all.Length; i++)
            {
                for (var j = i + 1; j < all.Length; j++)
                {
                    all[i].Tunnel.WalkTo(all[j].TunnelAddress);
                    all[j].Tunnel.WalkTo(all[i].TunnelAddress);
                }
            }
            await WaitUntilAsync(() =>
            {
                foreach (var node in all)
                {
                    if (node.Tunnel.GetPeers().Count() != all.Length - 1)
                    {
                        return false;
                    }
                }
                return true;
            }, "all tunnel peers verified");

            // The identity overlays walk THROUGH the tunnels (py: RandomWalk over the TunnelEndpoint).
            // The TunnelEndpoint queues packets until a 1-hop EXIT_IPV8 circuit is READY and flushes
            // on the next send, so — like py's RandomWalk — keep walking until the peers converge.
            var identityDeadline = System.Diagnostics.Stopwatch.StartNew();
            await WaitUntilAsync(() =>
            {
                var converged = true;
                foreach (var node in all)
                {
                    if (node.Identity.GetPeers().Count() != all.Length - 1)
                    {
                        converged = false;
                        foreach (var other in all)
                        {
                            if (!ReferenceEquals(other, node))
                            {
                                node.Identity.WalkTo(other.BusinessAddress);
                            }
                        }
                    }
                }
                return converged;
            }, "all identity peers verified through the tunnels");

            var sPeerForA = new Peer(s.Identity.MyPeer.PublicKey.KeyToBin(), s.BusinessAddress);
            var aPeerForS = new Peer(a.Identity.MyPeer.PublicKey.KeyToBin(), a.BusinessAddress);

            // 1. The downloader asks the seeder to attest "my_attribute" (the channel generates a
            //    fresh id_metadata secret key, like py request_attestation).
            a.Channel.RequestAttestation(sPeerForA, "my_attribute", "id_metadata",
                new Dictionary<string, string> { ["note"] = "d4" });

            // 2. The seeder's business logic sees the request (through the tunnels) and attests.
            await WaitUntilAsync(
                () => s.Channel.AttestationRequests.ContainsKey((aPeerForS, "my_attribute")),
                "the seeder received the attestation request through the hidden tunnels");
            s.Channel.Attest(aPeerForS, "my_attribute", Util.Utf8("test"));

            // 3. The attestation completes on the downloader (the blob flowed back through the
            //    tunnels) and the identity glue advertises it.
            await WaitUntilAsync(() => a.Channel.GetMyAttributes().Count == 1,
                                 "the attested attribute landed in the downloader's identity chain");
            var (attributeHash, (attributeName, _, _)) =
                a.Channel.GetMyAttributes().First();
            Assert.Equal("my_attribute", attributeName);

            // 4. The seeder verifies the attribute: challenges over the tunnel circuits, gated by
            //    the downloader's consent (the channel's verify-request callback).
            s.Channel.Verify(aPeerForS, attributeHash,
                new List<byte[]> { Util.Utf8("test"), Util.Utf8("tesX") }, "id_metadata");

            await WaitUntilAsync(
                () => a.Channel.VerifyRequests.ContainsKey((sPeerForA, "my_attribute")),
                "the downloader received the verify request through the hidden tunnels");
            a.Channel.AllowVerification(sPeerForA, "my_attribute");

            // 5. The seeder's verification output fills in the certainties (index-aligned).
            await WaitUntilAsync(
                () => s.Channel.VerificationOutput.TryGetValue(attributeHash, out var output)
                      && output.Count == 2 && output.All(p => p.Result != null),
                "the verification results reached the seeder's channel");
            var certainties = s.Channel.VerificationOutput[attributeHash]
                .Select(p => p.Result!.Value).ToList();
            Assert.True(certainties[0] > 0.9, $"certainty(test) = {certainties[0]}");
            Assert.True(certainties[1] < 0.5, $"certainty(tesX) = {certainties[1]}");
        }
    }
}
