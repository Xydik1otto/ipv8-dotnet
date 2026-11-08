// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IPv8;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using IPv8.Wallet.Primitives;

namespace IPv8.Tools.InteropCli;

/// <summary>
/// Headless IPv8 interop node (Phase 4 scope: LIVE cross-language interop, C1-C6).
///
/// Binds a real UDPEndpoint, prints "READY &lt;port&gt;" on stdout and then serves the
/// interop commands from stdin, one per line:
///
///   walk &lt;ip&gt; &lt;port&gt;                 - walk every overlay to that address (PEER lines
///                                       are printed for every newly verified peer)
///   store &lt;key_hex&gt; &lt;value_hex&gt;       - DHT store            → STORED
///   find &lt;key_hex&gt;                    - DHT find             → FOUND &lt;value_hex&gt; / NOTFOUND
///   circuit &lt;ip&gt; &lt;port&gt; &lt;ip2&gt; &lt;port2&gt; - 2-hop circuit        → CIRCUIT &lt;cid&gt; / CIRCUIT_FAIL
///   tunping &lt;cid&gt;                     - ping the circuit     → PONG
///   tunneldata &lt;cid&gt; &lt;ip&gt; &lt;port&gt; &lt;hex&gt;- tunnel to the exit   → TUNDATA &lt;hex&gt; (echoed back)
///   attest &lt;ip&gt; &lt;port&gt; &lt;name&gt;         - request attestation  → CERTAINTY &lt;float&gt;
///   quit                              - clean shutdown
///
/// stdout carries ONLY the machine-readable tokens above (plus READY/PEER); everything
/// else goes to stderr. All overlays share the endpoint and use the golden community ids
/// and the deterministic LibNaCLSK role keys.
/// </summary>
internal static class Program
{
    // Deterministic role keys (GoldenFixtures style, LibNaCLSK binary hex):
    // ALICE_SK = "LibNaCLSK:" + RFC 7748 §6.1 alice X25519 sk + RFC 8032 TEST 1 ed25519 seed.
    private const string AliceSkHex =
        "4c69624e61434c534b3a77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    // BOB_SK = "LibNaCLSK:" + RFC 7748 §6.1 bob X25519 sk + RFC 8032 TEST 2 ed25519 seed.
    private const string BobSkHex =
        "4c69624e61434c534b3a5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        + "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    // RELAY_SK = "LibNaCLSK:" + X25519 scalar 0xA0*32 + Ed25519 seed 0xC0*32.
    private const string RelaySkHex =
        "4c69624e61434c534b3a"
        + "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
        + "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

    // The golden Boneh secret key (vectors-phase2.json → boneh.key.serialize_hex): the
    // attestation requester key so cross-language runs stay deterministic.
    private const string GoldenBonehSkHex =
        "01091060f428c443ab410101090732849d8690333e1c0109102af5bb8d6f09a94f010909155b315f6c55c5d3"
        + "01090b950dcbc413696ff10108e8f11eb591fb4ab90104f432ed6b";

    // py-ipv8 peerdiscovery/community.py::DiscoveryCommunity.community_id (the base overlay
    // walk target; the DHT/tunnel/attestation ids come from the communities' golden constants).
    private static readonly byte[] DiscoveryCommunityId = Util.Unhex("7e313685c1912a141279f8248fc8db5899c5df5a");

    // The Phase 1a golden-fixture community id (ipv8-java GoldenFixtures.GOLDEN_COMMUNITY_ID):
    // the sibling interop node walks with both discovery ids, so we host both.
    private static readonly byte[] GoldenDiscoveryCommunityId = Util.Unhex("67f43dab165071e740b5856d46375d7416797f0b");

    private static readonly TimeSpan WalkPeerTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan CircuitTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan PongTimeout = TimeSpan.FromSeconds(15);

    private static readonly object PrintLock = new object();
    private static InteropNode _node;

    private static int Main(string[] args)
    {
        int port = 0;
        var ip = "127.0.0.1";
        var skHex = AliceSkHex;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--port" when i + 1 < args.Length:
                    port = int.Parse(args[++i], CultureInfo.InvariantCulture);
                    break;
                case "--ip" when i + 1 < args.Length:
                    ip = args[++i];
                    break;
                case "--sk" when i + 1 < args.Length:
                    skHex = ResolveSk(args[++i]);
                    break;
                case "--help" or "-h":
                    Console.Out.WriteLine("usage: InteropCli --port P [--ip 127.0.0.1] [--sk alice|bob|relay|<libnaclsk_hex>]");
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    return 2;
            }
        }

        try
        {
            _node = new InteropNode(ip, port, skHex);
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"Failed to start: {error}");
            return 1;
        }

        Console.Out.WriteLine($"READY {_node.Port}");
        Console.Out.Flush();

        using var cts = new CancellationTokenSource();
        var poller = Task.Run(() => _node.RunPeerPoller(cts.Token));

        string line;
        while ((line = Console.In.ReadLine()) != null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }
            if (trimmed == "quit")
            {
                break;
            }
            try
            {
                _node.DispatchAsync(trimmed).GetAwaiter().GetResult();
            }
            catch (Exception error)
            {
                Console.Error.WriteLine($"Command '{trimmed}' failed: {error.Message}");
            }
        }

        cts.Cancel();
        _node.Shutdown();
        return 0;
    }

    private static string ResolveSk(string value)
    {
        switch (value)
        {
            case "alice":
                return AliceSkHex;
            case "bob":
                return BobSkHex;
            case "relay":
                return RelaySkHex;
            default:
                var bytes = Util.Unhex(value);
                if (bytes.Length != 74 || Util.Utf8ToString(bytes, 0, 10) != "LibNaCLSK:")
                {
                    throw new ArgumentException("--sk expects alice|bob|relay or a 74-byte LibNaCLSK hex");
                }
                return value;
        }
    }

    private static void PrintLine(string line)
    {
        lock (PrintLock)
        {
            Console.Out.WriteLine(line);
            Console.Out.Flush();
        }
    }

    /// <summary>The concrete headless node: one endpoint, four golden overlays, command dispatch.</summary>
    private sealed class InteropNode
    {
        private readonly UDPEndpoint _endpoint;
        private readonly List<Community> _communities = new List<Community>();
        private readonly PlainCommunity _discovery;
        private readonly PlainCommunity _goldenDiscovery;
        private readonly DhtCommunity _dht;
        private readonly CliTunnelCommunity _tunnel;
        private readonly AttestationCommunity _attestation;
        private readonly HashSet<string> _printedMids = new HashSet<string>();

        public InteropNode(string ip, int port, string skHex)
        {
            _endpoint = new UDPEndpoint(port, ip);
            if (!_endpoint.Open())
            {
                throw new InvalidOperationException($"Could not bind UDP {ip}:{port}");
            }
            Port = _endpoint.GetAddress().Port;

            var myPeer = new Peer(ECCrypto.Default.KeyFromPrivateBin(Util.Unhex(skHex)));
            var address = _endpoint.GetAddress();

            _discovery = new PlainCommunity(
                new CommunitySettings(DiscoveryCommunityId, myPeer, _endpoint, new Network()),
                DiscoveryCommunityId);
            _goldenDiscovery = new PlainCommunity(
                new CommunitySettings(GoldenDiscoveryCommunityId, myPeer, _endpoint, new Network()),
                GoldenDiscoveryCommunityId);
            _dht = new DhtCommunity(
                new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, _endpoint, new Network()));
            _tunnel = new CliTunnelCommunity(new TunnelSettings
            {
                MyPeer = myPeer,
                Endpoint = _endpoint,
                Network = new Network(),
                PeerFlags = new HashSet<int>
                {
                    Tunnel.PeerFlagRelay, Tunnel.PeerFlagExitBt, Tunnel.PeerFlagSpeedTest
                }
            });
            _attestation = new AttestationCommunity(new AttestationSettings(
                AttestationCommunity.FixedCommunityId, myPeer, _endpoint, new Network())
            {
                WorkingDirectory = ":memory:"
            });

            _communities.AddRange(new Community[]
            {
                _discovery, _goldenDiscovery, _dht, _tunnel, _attestation
            });
            foreach (var community in _communities)
            {
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
            }

            // The interop attestation contract: attest "secret" for any attribute request and,
            // as the attester, verify the disclosure we just delivered (py-ipv8's
            // verify_attestation_values runs from the attester toward the attestation holder,
            // so this is the only node that can produce a CERTAINTY for the exchange).
            // NOTE: the attester's completion callback fires BEFORE the blob chunks hit the
            // wire, so the verify must be delayed until the holder actually holds the blob.
            _attestation.AttestationRequestCallback = (_, _, _) => Task.FromResult(Util.Utf8("secret"));
            _attestation.AttestationRequestCompleteCallback = (forPeer, _, attrHash, idFormat, fromPeer) =>
            {
                if (fromPeer != null)
                {
                    // We were the requester: the blob arrived, nothing to report here.
                    return;
                }
                var certaintySeen = 0;
                void OnCertainty(byte[] _, List<double> certainties)
                {
                    Interlocked.Exchange(ref certaintySeen, 1);
                    PrintLine($"CERTAINTY {certainties.Max().ToString("0.######", CultureInfo.InvariantCulture)}");
                }
                void AttemptVerify()
                {
                    if (Volatile.Read(ref certaintySeen) != 0)
                    {
                        return;
                    }
                    _attestation.VerifyAttestationValues(forPeer.Address, attrHash,
                        new List<byte[]> { Util.Utf8("secret") }, OnCertainty, idFormat);
                }
                // First attempt shortly after the blob should have arrived; one safety retry.
                var verifyTimer = Task.Run(async () =>
                {
                    try
                    {
                        await Task.Delay(750);
                        AttemptVerify();
                        await Task.Delay(2500);
                        AttemptVerify();
                    }
                    catch (Exception error)
                    {
                        Console.Error.WriteLine($"Attestation verify attempt failed: {error.Message}");
                    }
                });

            };
        }

        public int Port { get; }

        /// <summary>Print a PEER line for every newly verified peer on any overlay.</summary>
        public void RunPeerPoller(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    foreach (var community in _communities)
                    {
                        foreach (var peer in community.GetPeers())
                        {
                            var mid = Util.Hex(peer.Mid);
                            lock (_printedMids)
                            {
                                if (_printedMids.Add(mid))
                                {
                                    PrintLine($"PEER {mid}");
                                }
                            }
                        }
                    }
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine($"Peer poller error: {error.Message}");
                }
                Thread.Sleep(100);
            }
        }

        public async Task DispatchAsync(string line)
        {
            var tokens = line.Split(' ');
            switch (tokens[0])
            {
                case "walk":
                    Require(tokens, 3);
                    var address = ParseAddress(tokens[1], tokens[2]);
                    foreach (var community in _communities)
                    {
                        community.WalkTo(address);
                    }
                    break;

                case "store":
                    Require(tokens, 3);
                    await _dht.StoreValueAsync(Util.Unhex(tokens[1]), Util.Unhex(tokens[2]));
                    PrintLine("STORED");
                    break;

                case "find":
                    Require(tokens, 2);
                    var values = await _dht.FindValuesAsync(Util.Unhex(tokens[1]));
                    PrintLine(values.Count > 0 ? $"FOUND {Util.Hex(values[0].Data)}" : "NOTFOUND");
                    break;

                case "circuit":
                    Require(tokens, 5);
                    await HandleCircuitAsync(ParseAddress(tokens[1], tokens[2]),
                                             ParseAddress(tokens[3], tokens[4]));
                    break;

                case "tunping":
                    Require(tokens, 2);
                    await HandleTunpingAsync(long.Parse(tokens[1], CultureInfo.InvariantCulture));
                    break;

                case "tunneldata":
                    Require(tokens, 5);
                    HandleTunneldata(long.Parse(tokens[1], CultureInfo.InvariantCulture),
                                     ParseAddress(tokens[2], tokens[3]), Util.Unhex(tokens[4]));
                    break;

                case "attest":
                    Require(tokens, 4);
                    HandleAttest(ParseAddress(tokens[1], tokens[2]), tokens[3]);
                    break;

                case "debug":
                    foreach (var community in _communities)
                    {
                        Console.Error.WriteLine(
                            $"[debug] {community.GetType().Name}: peers={community.GetPeers().Count}");
                    }
                    if (_dht.RoutingTables.TryGetValue(AddressType.Udpv4, out var routingTable))
                    {
                        var nodeCount = 0;
                        foreach (var bucket in routingTable.Trie.Values())
                        {
                            nodeCount += bucket.Nodes.Count;
                        }
                        Console.Error.WriteLine($"[debug] dht routing v4: {nodeCount} nodes");
                    }
                    if (_dht.Storages.TryGetValue(AddressType.Udpv4, out var storage))
                    {
                        foreach (var pair in storage.Items)
                        {
                            Console.Error.WriteLine(
                                $"[debug] dht storage {Util.Hex(pair.Key)}: {pair.Value.Count} value(s)");
                        }
                    }
                    Console.Error.WriteLine($"[debug] tunnel circuits: {_tunnel.Circuits.Count}, "
                                            + $"relays: {_tunnel.RelayFromTo.Count}, exits: {_tunnel.ExitSockets.Count}, "
                                            + $"candidates: {_tunnel.Candidates.Count}");
                    break;

                default:
                    Console.Error.WriteLine($"Unknown command: {tokens[0]}");
                    break;
            }
        }

        private async Task HandleCircuitAsync(Address relayAddress, Address exitAddress)
        {
            var exitPeer = _tunnel.Candidates.Keys
                .FirstOrDefault(peer => AddressMatches(peer, exitAddress));
            if (exitPeer == null)
            {
                Console.Error.WriteLine($"No candidate for the exit at {exitAddress}");
                PrintLine("CIRCUIT_FAIL");
                return;
            }

            var circuit = _tunnel.CreateCircuit(2, requiredExit: exitPeer);
            if (circuit == null)
            {
                Console.Error.WriteLine("Could not create a 2-hop circuit (no first hop)");
                PrintLine("CIRCUIT_FAIL");
                return;
            }

            var deadline = DateTime.UtcNow + CircuitTimeout;
            while (circuit.State != Tunnel.CircuitStateReady)
            {
                if (DateTime.UtcNow > deadline)
                {
                    Console.Error.WriteLine($"Circuit {circuit.CircuitId} never became READY");
                    PrintLine("CIRCUIT_FAIL");
                    return;
                }
                await Task.Delay(20);
            }
            PrintLine($"CIRCUIT {circuit.CircuitId.ToString(CultureInfo.InvariantCulture)}");
        }

        private async Task HandleTunpingAsync(long circuitId)
        {
            if (!_tunnel.Circuits.TryGetValue(circuitId, out var circuit))
            {
                Console.Error.WriteLine($"Unknown circuit {circuitId}");
                return;
            }

            var activityBefore = circuit.LastActivity;
            _tunnel.DoPing();
            var deadline = DateTime.UtcNow + PongTimeout;
            while (circuit.LastActivity <= activityBefore)
            {
                if (DateTime.UtcNow > deadline)
                {
                    Console.Error.WriteLine($"No PONG for circuit {circuitId}");
                    return;
                }
                await Task.Delay(20);
            }
            PrintLine("PONG");
        }

        private void HandleTunneldata(long circuitId, Address destination, byte[] data)
        {
            if (!_tunnel.Circuits.TryGetValue(circuitId, out var circuit))
            {
                Console.Error.WriteLine($"Unknown circuit {circuitId}");
                return;
            }
            _tunnel.SendData(circuit.Hop.Address, circuitId, destination, Address.Zero, data);
        }

        private void HandleAttest(Address peerAddress, string attributeName)
        {
            var peer = _attestation.GetPeers().FirstOrDefault(candidate => AddressMatches(candidate, peerAddress));
            if (peer == null)
            {
                Console.Error.WriteLine($"No verified attestation peer at {peerAddress}");
                return;
            }
            var secretKey = BonehPrivateKey.Unserialize(Util.Unhex(GoldenBonehSkHex));
            _attestation.RequestAttestation(peer, attributeName, secretKey,
                new Dictionary<string, string> { ["id_format"] = "id_metadata" });
        }

        public void Shutdown()
        {
            foreach (var community in _communities)
            {
                try
                {
                    community.Unload();
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine($"Unload error: {error.Message}");
                }
            }
            _endpoint.Close();
        }

        private static void Require(string[] tokens, int count)
        {
            if (tokens.Length < count)
            {
                throw new ArgumentException($"Command '{tokens[0]}' expects {count - 1} argument(s)");
            }
        }

        private static Address ParseAddress(string host, string portText)
            => new Address(AddressType.Udpv4, host, int.Parse(portText, CultureInfo.InvariantCulture));

        private static bool AddressMatches(Peer peer, Address address)
            => peer.Address.Type == address.Type
               && string.Equals(peer.Address.Host, address.Host, StringComparison.OrdinalIgnoreCase)
               && peer.Address.Port == address.Port;
    }

    /// <summary>Minimal concrete Community (the py base overlay with the introduction machinery).</summary>
    private sealed class PlainCommunity : Community
    {
        public PlainCommunity(CommunitySettings settings, byte[] communityId) : base(settings, communityId)
        {
        }
    }

    /// <summary>TunnelCommunity that reports raw data returning through our own circuits.</summary>
    private sealed class CliTunnelCommunity : TunnelCommunity
    {
        public CliTunnelCommunity(TunnelSettings settings) : base(settings)
        {
        }

        public override void OnRawData(Circuit circuit, Address origin, byte[] data)
        {
            PrintLine($"TUNDATA {Util.Hex(data)}");
        }
    }
}
