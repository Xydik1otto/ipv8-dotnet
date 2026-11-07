// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPv8.Bootstrapping;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A14: IPv8 service assembly — two overlays on one endpoint, clean stop without leaked
    /// listeners, get_overlay/get_peers correctness, key loading, walker ticking.
    /// </summary>
    public class IPv8ServiceTests
    {
        /// <summary>A minimal community used as a service-registered overlay type.</summary>
        private sealed class FakeCommunity : Community
        {
            public bool Unloaded;
            public readonly byte[] OwnId;

            public FakeCommunity(CommunitySettings settings, byte[] communityId)
                : base(settings, communityId)
            {
                OwnId = communityId;
            }

            public override void Unload()
            {
                Unloaded = true;
                base.Unload();
            }
        }

        private static byte[] CommunityIdFor(string name)
            => Util.Sha1(Encoding.UTF8.GetBytes("ipv8-dotnet:" + name));

        private static async Task WaitUntilAsync(Func<bool> condition, string description,
                                                 int timeoutMs = 5000)
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

        /// <summary>A plain (non-Community) overlay: bootstrappers must be rejected for it.</summary>
        private sealed class FakePlainOverlay : Overlay
        {
            public FakePlainOverlay(OverlaySettings settings) : base(settings)
            {
            }

            public override void OnPacket(Packet packet)
            {
            }

            public override void WalkTo(Address address)
            {
            }

            public override void GetNewIntroduction(Peer fromPeer = null)
            {
            }

            public override IReadOnlyList<Peer> GetPeers() => Array.Empty<Peer>();

            public override IReadOnlyList<Address> GetWalkableAddresses() => Array.Empty<Address>();
        }

        private static Dictionary<string, Func<CommunitySettings, Overlay>> FakeRegistry()
        {
            var idA = CommunityIdFor("fake-a");
            var idB = CommunityIdFor("fake-b");
            return new Dictionary<string, Func<CommunitySettings, Overlay>>
            {
                ["FakeCommunityA"] = settings => new FakeCommunity(settings, idA),
                ["FakeCommunityB"] = settings => new FakeCommunity(settings, idB),
                ["FakePlainOverlay"] = settings => new FakePlainOverlay(settings)
            };
        }

        private static IPv8Configuration TwoOverlayConfiguration(string keyAlias)
        {
            return new IPv8Configuration
            {
                Keys = new List<IPv8KeyConfig>
                {
                    new IPv8KeyConfig { Alias = keyAlias, Generation = "curve25519" }
                },
                Overlays = new List<IPv8OverlayConfig>
                {
                    new IPv8OverlayConfig
                    {
                        Class = "FakeCommunityA",
                        Key = keyAlias,
                        Walkers = new List<IPv8WalkerConfig>
                        {
                            new IPv8WalkerConfig { Strategy = "RandomWalk", Peers = 5 }
                        }
                    },
                    new IPv8OverlayConfig
                    {
                        Class = "FakeCommunityB",
                        Key = keyAlias,
                        Walkers = new List<IPv8WalkerConfig>
                        {
                            new IPv8WalkerConfig { Strategy = "EdgeWalk", Peers = -1 }
                        }
                    }
                },
                WalkerInterval = 0.05
            };
        }

        [Fact]
        public async Task Service_Assembles_Two_Overlays_On_One_Endpoint_And_Stops_Cleanly()
        {
            var configuration = TwoOverlayConfiguration("peer key");
            var endpoint = new UDPEndpoint(0, "127.0.0.1");

            var extraCommunities = FakeRegistry();
            var service = new IPv8Service(configuration, endpoint,
                                           extraCommunities: extraCommunities);

            // The endpoint is only opened by start() (py-ipv8: await self.endpoint.open()).
            Assert.False(endpoint.IsOpen);
            Assert.Equal(2, service.Overlays.Count);
            Assert.Equal(2, service.StrategiesCount);

            // get_overlay/get_peers correctness.
            var overlayA = service.GetOverlay<FakeCommunity>();
            var overlayB = service.GetOverlays<FakeCommunity>().Skip(1).First();
            Assert.Equal(CommunityIdFor("fake-a"), overlayA.CommunityId);
            Assert.Equal(CommunityIdFor("fake-b"), overlayB.CommunityId);
            Assert.NotNull(service.GetOverlay(typeof(FakeCommunity)));
            Assert.Empty(overlayA.GetPeers());
            Assert.Empty(overlayB.GetPeers());

            // The overlays share one endpoint but have disjoint prefixes and listener dispatch
            // routes packets to the right overlay.
            Assert.Same(endpoint, overlayA.Endpoint);
            Assert.Same(endpoint, overlayB.Endpoint);

            // Start + clean stop: no leaked listeners, all overlays unloaded.
            service.Start();
            Assert.True(endpoint.IsOpen);
            Assert.True(service.Overlays.Count == 2);
            await service.StopAsync();

            Assert.False(endpoint.IsOpen);
            Assert.True(overlayA.Unloaded);
            Assert.True(overlayB.Unloaded);
            Assert.Empty(service.Overlays);
            Assert.Equal(0, service.StrategiesCount);
        }

        [Fact]
        public async Task Service_Ticker_Walks_Strategies()
        {
            var configuration = TwoOverlayConfiguration("walker key");
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            var extraCommunities = FakeRegistry();
            var service = new IPv8Service(configuration, endpoint,
                                           extraCommunities: extraCommunities);

            var overlayA = service.GetOverlay<FakeCommunity>();
            var overlayB = service.GetOverlays<FakeCommunity>().Skip(1).First();
            Assert.NotNull(overlayA);
            Assert.NotNull(overlayB);

            // An external seed node running the same community class as overlay A, on its own
            // endpoint (packets to a shared endpoint only ever reach the overlay whose prefix
            // matches — a walk to the shared address cannot reach overlay B).
            var seedId = CommunityIdFor("fake-a");
            var seedEndpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(seedEndpoint.Open());
            var seedPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
            var seedCommunity = new FakeCommunity(
                new CommunitySettings(seedId, seedPeer, seedEndpoint, new Network()), seedId);
            seedCommunity.MyEstimatedLan = seedEndpoint.GetAddress();
            seedCommunity.MyEstimatedWan = seedEndpoint.GetAddress();

            service.Start();
            try
            {
                var seedAddress = seedEndpoint.GetAddress();
                var seedAsPeer = new Peer(seedPeer.PublicKey.KeyToBin(), seedAddress);
                overlayA.Network.DiscoverAddress(seedAsPeer, seedAddress, overlayA.CommunityId);

                // The ticker walks overlay A's RandomWalk strategy to the seed; the seed
                // answers and both verify each other.
                await WaitUntilAsync(() => overlayA.GetPeers().Count > 0
                                           && seedCommunity.GetPeers().Count > 0,
                                     "service-driven walk produced peers");

                Assert.Equal(seedPeer.Mid, overlayA.GetPeers().Single().Mid);
                Assert.Null(overlayA.LastHandlerException);
                Assert.Null(overlayB.LastHandlerException);
            }
            finally
            {
                await service.StopAsync();
                seedEndpoint.Close();
            }
        }

        [Fact]
        public void Service_Loads_Key_From_Bin_And_Persists_Generated_Keys()
        {
            // A pre-generated key delivered by base64 "bin".
            var keyBytes = ECCrypto.Default.GenerateKey("curve25519").KeyToBin();
            var configuration = TwoOverlayConfiguration("shared key");
            configuration.Keys = new List<IPv8KeyConfig>
            {
                new IPv8KeyConfig
                {
                    Alias = "shared key",
                    Bin = Convert.ToBase64String(keyBytes)
                }
            };
            var service = new IPv8Service(configuration, new UDPEndpoint(0, "127.0.0.1"),
                                           extraCommunities: FakeRegistry());
            Assert.Equal(new Peer(ECCrypto.Default.KeyFromPrivateBin(keyBytes)).Mid,
                         service.Keys["shared key"].Mid);

            // A generated key gets persisted to the requested file.
            var keyFile = Path.Combine(Path.GetTempPath(), "ipv8-dotnet-test-key-" + Guid.NewGuid());
            try
            {
                var persistedConfig = TwoOverlayConfiguration("file key");
                persistedConfig.Keys = new List<IPv8KeyConfig>
                {
                    new IPv8KeyConfig { Alias = "file key", File = keyFile, Generation = "curve25519" }
                };
                var persistedService = new IPv8Service(persistedConfig, new UDPEndpoint(0, "127.0.0.1"),
                                                        extraCommunities: FakeRegistry());
                Assert.True(File.Exists(keyFile));
                var reloaded = new IPv8Service(persistedConfig, new UDPEndpoint(0, "127.0.0.1"),
                                                extraCommunities: FakeRegistry());
                Assert.Equal(persistedService.Keys["file key"].Mid, reloaded.Keys["file key"].Mid);
            }
            finally
            {
                if (File.Exists(keyFile))
                {
                    File.Delete(keyFile);
                }
            }
        }

        [Fact]
        public void Service_Wires_Dispersy_Bootstrappers_From_Config()
        {
            var configuration = TwoOverlayConfiguration("boot key");
            configuration.Overlays[0].Bootstrappers.Add(new IPv8BootstrapperConfig
            {
                Class = "DispersyBootstrapper",
                Init = new Dictionary<string, object>
                {
                    ["ip_addresses"] = new List<object> { new List<object> { "1.2.3.4", 6431 } },
                    ["dns_addresses"] = new List<object>(),
                    ["bootstrap_timeout"] = 10.0
                }
            });
            var service = new IPv8Service(configuration, new UDPEndpoint(0, "127.0.0.1"),
                                           extraCommunities: FakeRegistry());
            var overlayA = service.GetOverlay<FakeCommunity>();
            var bootstrapper = Assert.Single(overlayA.Bootstrappers);
            var dispersy = Assert.IsType<DispersyBootstrapper>(bootstrapper);
            Assert.Equal(Address.Udpv4("1.2.3.4", 6431), Assert.Single(dispersy.IpAddresses));
            Assert.Equal(10.0, dispersy.BootstrapTimeout);

            // A bootstrapper for a non-Community overlay crashes (py raises RuntimeError).
            var badConfiguration = TwoOverlayConfiguration("bad key");
            badConfiguration.Overlays[1].Class = "FakePlainOverlay";
            badConfiguration.Overlays[1].Bootstrappers.Add(new IPv8BootstrapperConfig
            {
                Class = "UDPBroadcastBootstrapper"
            });
            var endpointB = new UDPEndpoint(0, "127.0.0.1");
            Assert.Throws<ArgumentException>(() => new IPv8Service(badConfiguration, endpointB,
                extraCommunities: FakeRegistry()));
        }

        [Fact]
        public async Task Service_Add_Strategy_And_Unload_Overlay()
        {
            var configuration = TwoOverlayConfiguration("strategy key");
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            var service = new IPv8Service(configuration, endpoint,
                                           extraCommunities: FakeRegistry());
            var overlayA = service.GetOverlay<FakeCommunity>();
            var overlayB = service.GetOverlays<FakeCommunity>().Skip(1).First();

            // add_strategy registers the overlay too when it is missing.
            var extraOverlay = new FakeCommunity(
                new CommunitySettings(CommunityIdFor("fake-extra"), overlayA.MyPeer, endpoint,
                                      service.Network),
                CommunityIdFor("fake-extra"));
            var extraStrategy = new RandomWalk(extraOverlay);
            service.AddStrategy(extraOverlay, extraStrategy, -1);
            Assert.Contains(extraOverlay, service.Overlays);

            // unload_overlay drops the overlay and its strategies.
            await service.UnloadOverlay(extraOverlay);
            Assert.DoesNotContain(extraOverlay, service.Overlays);
            Assert.True(extraOverlay.Unloaded);
            Assert.DoesNotContain(service.Overlays, o => ReferenceEquals(o, extraOverlay));
            Assert.Empty(extraOverlay.GetPeers());
            // The other overlays remain.
            Assert.Contains(overlayA, service.Overlays);
            Assert.Contains(overlayB, service.Overlays);
        }

        [Fact]
        public void Service_Unknown_Community_Class_Raises()
        {
            var configuration = TwoOverlayConfiguration("x key");
            configuration.Overlays[0].Class = "NoSuchCommunity";
            Assert.Throws<ArgumentException>(() => new IPv8Service(configuration,
                new UDPEndpoint(0, "127.0.0.1"), extraCommunities: FakeRegistry()));
        }
    }
}
