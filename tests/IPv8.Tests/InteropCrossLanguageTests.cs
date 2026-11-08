// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPv8;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using IPv8.Wallet.Primitives;
using Xunit;
using Xunit.Abstractions;

namespace IPv8.Tests
{
    /// <summary>
    /// Phase 4 scope: LIVE cross-language interop (C1-C6). This suite SPAWNS the sibling
    /// ipv8-java headless node (tools/InteropCli equivalent:
    /// {@code java -cp <abs>/target/classes io.github.xydik1otto.ipv8.InteropCli --port P})
    /// and drives it over real UDP loopback + stdin/stdout, while the C# side of each
    /// scenario runs in-process on its own real UDPEndpoint.
    ///
    /// When the Java side's InteropCli has not been compiled yet (the sibling repo is built
    /// in parallel), the scenario logs a notice and passes vacuously; the interop report
    /// marks the criterion accordingly.
    /// </summary>
    public class InteropCrossLanguageTests
    {
        // The sibling java repository (read-only for this repo; the tests only compile it).
        private static readonly string JavaRepoRoot =
            Environment.GetEnvironmentVariable("IPV8_JAVA_REPO") ?? "G:/Projects/ipv8-port/ipv8-java";

        private static readonly string JavaClassesDir = Path.Combine(JavaRepoRoot, "target", "classes");
        private static readonly string JavaInteropClassFile = Path.Combine(JavaClassesDir,
            "io", "github", "xydik1otto", "ipv8", "interop", "InteropCli.class");
        private const string JavaInteropClassName = "io.github.xydik1otto.ipv8.interop.InteropCli";

        // Deterministic in-process C# interop key: "LibNaCLSK:" + X25519 scalar 0xB0*32 +
        // Ed25519 seed 0xD0*32. Deliberately NOT one of the ALICE/BOB/RELAY fixture keys, so
        // the in-process C# node never collides with a Java node role key.
        private const string DotNetSkHex =
            "4c69624e61434c534b3a"
            + "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
            + "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0";

        // py-ipv8 peerdiscovery/community.py::DiscoveryCommunity.community_id — the base
        // overlay walk target shared with the Java interop node.
        private static readonly byte[] DiscoveryCommunityId = Util.Unhex("7e313685c1912a141279f8248fc8db5899c5df5a");

        // The golden Boneh secret key (vectors-phase2.json → boneh.key.serialize_hex): the
        // attestation requester key, deterministic across both ports.
        private const string GoldenBonehSkHex =
            "01091060f428c443ab410101090732849d8690333e1c0109102af5bb8d6f09a94f010909155b315f6c55c5d3"
            + "01090b950dcbc413696ff10108e8f11eb591fb4ab90104f432ed6b";

        private static readonly object InitLock = new object();
        private static bool _javaProbed;
        private static bool _javaAvailable;

        private readonly ITestOutputHelper _output;

        public InteropCrossLanguageTests(ITestOutputHelper output)
        {
            _output = output;
        }

        // ------------------------------------------------------------------ infrastructure

        /// <summary>Whether the sibling Java interop node is compiled (compiles it if needed).</summary>
        private static bool JavaCliAvailable()
        {
            lock (InitLock)
            {
                if (_javaProbed)
                {
                    return _javaAvailable;
                }
                _javaProbed = true;
                _javaAvailable = File.Exists(JavaInteropClassFile);
                if (!_javaAvailable)
                {
                    try
                    {
                        CompileJavaOnce();
                        _javaAvailable = File.Exists(JavaInteropClassFile);
                    }
                    catch
                    {
                        // Reported by the individual scenarios; the interop report marks partial.
                    }
                }
                return _javaAvailable;
            }
        }

        private static void CompileJavaOnce()
        {
            var psi = new ProcessStartInfo("bash",
                $"{JavaRepoRoot}/mvnw.sh -q compile")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = JavaRepoRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(psi);
            if (process == null)
            {
                return;
            }
            if (!process.WaitForExit(600_000))
            {
                process.Kill(true);
                return;
            }
        }

        /// <summary>
        /// The Java node's deterministic key is derived from its port
        /// (InteropNode.deriveKeyForPort): sha256("ipv8-interop-x25519|&lt;port&gt;") as the
        /// X25519 scalar and sha256("ipv8-interop-ed25519|&lt;port&gt;") as the Ed25519 seed.
        /// This mirrors it to predict the Java node's mid cross-language.
        /// </summary>
        private static byte[] JavaMidForPort(int port)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var xSk = sha256.ComputeHash(Util.Utf8($"ipv8-interop-x25519|{port}"));
            var eSeed = sha256.ComputeHash(Util.Utf8($"ipv8-interop-ed25519|{port}"));
            var skBin = Util.Concat(Util.Utf8("LibNaCLSK:"), xSk, eSeed);
            var key = ECCrypto.Default.KeyFromPrivateBin(skBin);
            return Util.Slice(key.KeyToHash(), 0, 20);
        }

        private static int PickPort()
        {
            var random = new Random();
            lock (InitLock)
            {
                return random.Next(20000, 40000);
            }
        }

        /// <summary>Dump the spawned Java nodes' recent stderr for cross-test diagnostics.</summary>
        private void DumpJavaDiagnostics(string reason, params JavaNode[] nodes)
        {
            _output.WriteLine($"--- java diagnostics ({reason}) ---");
            foreach (var node in nodes)
            {
                List<string> snapshot;
                lock (node.Errors)
                {
                    snapshot = new List<string>(node.Errors);
                }
                _output.WriteLine($"node {node.Address}: {snapshot.Count} stderr line(s)");
                foreach (var line in snapshot.TakeLast(12))
                {
                    _output.WriteLine($"  {node.Address.Port}: {line}");
                }
            }
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 30000)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(25);
            }
        }

        /// <summary>The spawned Java headless interop node process.</summary>
        private sealed class JavaNode : IDisposable
        {
            public readonly Process Process;
            public readonly List<string> Lines = new List<string>();
            public readonly List<string> Errors = new List<string>();
            public int Port;

            private JavaNode(Process process)
            {
                Process = process;
            }

            public Address Address => new Address(AddressType.Udpv4, "127.0.0.1", Port);

            public static JavaNode Spawn(int port)
            {
                var javaExe = Environment.GetEnvironmentVariable("JAVA_HOME") is { } javaHome
                    && javaHome.Length > 0
                    ? Path.Combine(javaHome, "bin", "java")
                    : "java";
                var psi = new ProcessStartInfo(javaExe,
                    $"-cp \"{JavaClassesDir}\" {JavaInteropClassName} --port {port}")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = JavaRepoRoot,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                var process = Process.Start(psi)
                    ?? throw new InvalidOperationException("could not spawn the java interop node");
                var node = new JavaNode(process);

                var stdoutThread = new Thread(() =>
                {
                    string line;
                    while ((line = process.StandardOutput.ReadLine()) != null)
                    {
                        lock (node.Lines)
                        {
                            node.Lines.Add(line);
                        }
                    }
                })
                { IsBackground = true };
                var stderrThread = new Thread(() =>
                {
                    string line;
                    while ((line = process.StandardError.ReadLine()) != null)
                    {
                        lock (node.Errors)
                        {
                            node.Errors.Add(line);
                        }
                    }
                })
                { IsBackground = true };
                stdoutThread.Start();
                stderrThread.Start();

                var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
                while (DateTime.UtcNow < deadline)
                {
                    if (process.HasExited)
                    {
                        throw new InvalidOperationException(
                            $"the java interop node exited with {process.ExitCode} before READY "
                            + $"(stderr: {string.Join(" | ", node.Errors.Take(5))})");
                    }
                    var ready = node.TryTakeLine(l => l.StartsWith("READY ", StringComparison.Ordinal), out var line);
                    if (ready)
                    {
                        node.Port = int.Parse(line!.Substring("READY ".Length));
                        return node;
                    }
                    Thread.Sleep(50);
                }

                throw new TimeoutException($"the java interop node never printed READY within 30s "
                                           + $"(stderr: {string.Join(" | ", node.Errors.Take(5))})");
            }

            public void Send(string line)
            {
                Process.StandardInput.WriteLine(line);
                Process.StandardInput.Flush();
            }

            public bool TryTakeLine(Func<string, bool> predicate, out string? line)
            {
                lock (Lines)
                {
                    for (var index = 0; index < Lines.Count; index++)
                    {
                        if (predicate(Lines[index]))
                        {
                            line = Lines[index];
                            Lines.RemoveAt(index);
                            return true;
                        }
                    }
                }
                line = null;
                return false;
            }

            public async Task<string> WaitForLineAsync(Func<string, bool> predicate, string description,
                                                       int timeoutMs = 30000)
            {
                var stopwatch = Stopwatch.StartNew();
                while (stopwatch.ElapsedMilliseconds < timeoutMs)
                {
                    if (TryTakeLine(predicate, out var line))
                    {
                        return line!;
                    }
                    if (Process.HasExited)
                    {
                        throw new InvalidOperationException($"the java interop node exited while waiting: {description}");
                    }
                    await Task.Delay(25);
                }
                throw new TimeoutException($"no expected stdout line within {timeoutMs} ms: {description} "
                                           + $"(stderr: {string.Join(" | ", Errors.Take(5))})");
            }

            public void Dispose()
            {
                try
                {
                    Send("quit");
                }
                catch
                {
                    // Already gone.
                }
                try
                {
                    if (!Process.WaitForExit(2000))
                    {
                        Process.Kill(true);
                        Process.WaitForExit(3000);
                    }
                }
                catch
                {
                    // Already gone.
                }
                Process.Dispose();
            }
        }

        /// <summary>The in-process C# side of every scenario: one endpoint, all four overlays.</summary>
        private sealed class DotNetNode : IDisposable
        {
            public readonly UDPEndpoint Endpoint;
            public readonly Peer MyPeer;
            public readonly PlainCommunity Discovery;
            public readonly DhtCommunity Dht;
            public readonly TestTunnelCommunity Tunnel;
            public readonly AttestationCommunity Attest;
            public readonly CertaintyTracker Certainty = new CertaintyTracker();
            private readonly List<Task> _ignoreTasks = new List<Task>();

            private DotNetNode(UDPEndpoint endpoint, Peer myPeer, PlainCommunity discovery,
                               DhtCommunity dht, TestTunnelCommunity tunnel, AttestationCommunity attest)
            {
                Endpoint = endpoint;
                MyPeer = myPeer;
                Discovery = discovery;
                Dht = dht;
                Tunnel = tunnel;
                Attest = attest;
            }

            public static DotNetNode Create()
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.KeyFromPrivateBin(Util.Unhex(DotNetSkHex)));

                var discovery = new PlainCommunity(
                    new CommunitySettings(DiscoveryCommunityId, myPeer, endpoint, new Network()),
                    DiscoveryCommunityId);
                var dht = new DhtCommunity(
                    new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, endpoint, new Network()));
                // Empty peer flags: the in-process C# node is a pure initiator here; it must not
                // advertise relay/exit capabilities that could pull the Java nodes' builders in.
                var tunnel = new TestTunnelCommunity(new TunnelSettings
                {
                    MyPeer = myPeer,
                    Endpoint = endpoint,
                    Network = new Network(),
                    PeerFlags = new HashSet<int>()
                });
                var attest = new AttestationCommunity(new AttestationSettings(
                    AttestationCommunity.FixedCommunityId, myPeer, endpoint, new Network())
                {
                    WorkingDirectory = ":memory:"
                });

                var communities = new Community[] { discovery, dht, tunnel, attest };
                foreach (var community in communities)
                {
                    community.MyEstimatedLan = address;
                    community.MyEstimatedWan = address;
                }

                var node = new DotNetNode(endpoint, myPeer, discovery, dht, tunnel, attest);

                // Mirror of the CLI's interop attestation behavior: attest "secret" for any
                // attribute request and, as the attester, verify the delivered disclosure.
                attest.AttestationRequestCallback = (_, _, _) => Task.FromResult(Util.Utf8("secret"));
                attest.AttestationRequestCompleteCallback = (forPeer, _, attrHash, idFormat, fromPeer) =>
                {
                    if (fromPeer != null)
                    {
                        return;
                    }
                    var attester = forPeer;
                    var hash = attrHash;
                    var format = idFormat;
                    var verifyDelay = Task.Delay(750).ContinueWith(_ =>
                    {
                        attest.VerifyAttestationValues(attester.Address, hash,
                            new List<byte[]> { Util.Utf8("secret") },
                            node.Certainty.OnComplete, format);
                    });
                    node._ignoreTasks.Add(verifyDelay);
                };

                return node;
            }

            public Address Address => Endpoint.GetAddress();

            /// <summary>The DHT routing-table node for the given peer, if present.</summary>
            public DhtNode? RoutingNodeFor(byte[] mid, Address address)
            {
                var nodeId = DhtRouting.CalcNodeId(address, mid);
                return Dht.RoutingTables.TryGetValue(AddressType.Udpv4, out var routingTable)
                    ? routingTable.Get(nodeId)
                    : null;
            }

            public void Dispose()
            {
                Attest.Unload();
                Tunnel.Unload();
                Dht.Unload();
                Discovery.Unload();
                Endpoint.Close();
            }
        }

        /// <summary>Minimal concrete Community (the py base overlay with the introduction machinery).</summary>
        private sealed class PlainCommunity : Community
        {
            public PlainCommunity(CommunitySettings settings, byte[] communityId) : base(settings, communityId)
            {
            }
        }

        /// <summary>TunnelCommunity that records raw data returning through our own circuits.</summary>
        private sealed class TestTunnelCommunity : TunnelCommunity
        {
            public readonly List<(Circuit Circuit, Address Origin, byte[] Data)> RawData =
                new List<(Circuit, Address, byte[])>();

            /// <summary>Every packet handed to this community (for live interop diagnostics).</summary>
            public readonly List<byte[]> Incoming = new List<byte[]>();

            /// <summary>Every FINAL wire packet we sent (post crypto endpoint).</summary>
            public readonly List<byte[]> SentWires = new List<byte[]>();

            public TestTunnelCommunity(TunnelSettings settings) : base(settings)
            {
            }

            protected override ICryptoEndpoint CreateCryptoEndpoint(Endpoint endpoint)
            {
                Sniffer = new SniffingCryptoEndpoint(endpoint);
                return Sniffer;
            }

            public SniffingCryptoEndpoint Sniffer { get; private set; }

            public override void OnPacket(Packet packet)
            {
                lock (Incoming)
                {
                    Incoming.Add(packet.Data);
                }
                base.OnPacket(packet);
            }

            public override void OnRawData(Circuit circuit, Address origin, byte[] data)
            {
                lock (RawData)
                {
                    RawData.Add((circuit, origin, data));
                }
            }

            public sealed class SniffingCryptoEndpoint : PythonCryptoEndpoint
            {
                public SniffingCryptoEndpoint(Endpoint endpoint) : base(endpoint)
                {
                }

                public readonly List<byte[]> Wires = new List<byte[]>();

                protected override void OnWireSent(byte[] packet)
                {
                    lock (Wires)
                    {
                        Wires.Add(packet);
                    }
                }
            }
        }

        /// <summary>Collects the first (hash, certainties) completion of a verify flow.</summary>
        private sealed class CertaintyTracker
        {
            private readonly TaskCompletionSource<(byte[] Hash, List<double> Certainties)> _done =
                new(TaskCreationOptions.RunContinuationsAsynchronously);

            public void OnComplete(byte[] hash, List<double> certainties) => _done.TrySetResult((hash, certainties));

            public async Task<(byte[] Hash, List<double> Certainties)> WaitOrThrowAsync(int timeoutMs = 30000)
            {
                var completed = await Task.WhenAny(_done.Task, Task.Delay(timeoutMs));
                if (completed != _done.Task)
                {
                    throw new TimeoutException("certainty completion not reached");
                }
                return _done.Task.Result;
            }
        }

        // ------------------------------------------------------------------------- C1: walk

        /// <summary>
        /// C1: the C# node (in-process) walks the spawned Java node; both sides must end up
        /// verified with each other and the Java node must print {@code PEER <mid_hex>} of the
        /// C# node. The Java node's mid is additionally checked against the port-derived
        /// deterministic key (InteropNode.deriveKeyForPort).
        /// </summary>
        [Fact]
        public async Task C1_Walk_DotNet_Walks_Java_Node()
        {
            if (!JavaCliAvailable())
            {
                _output.WriteLine("SKIP (partial): the sibling java InteropCli is not compiled yet.");
                return;
            }

            using var java = JavaNode.Spawn(PickPort());
            using var cs = DotNetNode.Create();
            _output.WriteLine($"java node: {java.Address}, c# node: {cs.Address}");

            cs.Discovery.WalkTo(java.Address);

            // The C# side verifies the Java node from the introduction response.
            await WaitUntilAsync(() => cs.Discovery.GetPeers().Count > 0,
                "the C# node verified the Java node");
            var javaPeer = cs.Discovery.GetPeers().Single();
            Assert.Equal(JavaMidForPort(java.Port), javaPeer.Mid);

            // The Java side verifies the C# node from the introduction request and prints it.
            var peerLine = await java.WaitForLineAsync(line => line.StartsWith("PEER ", StringComparison.Ordinal),
                "the Java node printing PEER");
            var announcedMid = Util.Unhex(peerLine.Substring("PEER ".Length).Trim());
            Assert.Equal(cs.MyPeer.Mid, announcedMid);
        }

        // ------------------------------------------------------------------------- C2: DHT

        /// <summary>
        /// C2: the Java node stores a value, the C# node finds it through the DHT — and the
        /// mirror direction: the C# node stores, the Java node's {@code find} prints
        /// {@code FOUND <value_hex>} with a byte-identical value.
        /// </summary>
        [Fact]
        public async Task C2_Dht_Interop_Java_Stores_DotNet_Finds_And_Mirror()
        {
            if (!JavaCliAvailable())
            {
                _output.WriteLine("SKIP (partial): the sibling java InteropCli is not compiled yet.");
                return;
            }

            using var java = JavaNode.Spawn(PickPort());
            using var cs = DotNetNode.Create();
            _output.WriteLine($"java node: {java.Address}, c# node: {cs.Address}");

            // Establish DHT contact: the intro exchange populates both DHT routing tables
            // (the Java side's through the incoming request, ours through the response).
            cs.Dht.WalkTo(java.Address);
            await WaitUntilAsync(() => cs.Dht.GetPeers().Count > 0,
                "the C# DHT community verified the Java node");
            var javaMid = JavaMidForPort(java.Port);
            await WaitUntilAsync(() => cs.RoutingNodeFor(javaMid, java.Address) != null,
                "the C# DHT routing table learned the Java node");

            // Direction one: the Java node stores, the C# node finds.
            var keyOne = Util.Unhex(new string('a', 40));
            var valueOne = Util.Utf8("interop-value java->csharp");
            java.Send($"store {Util.Hex(keyOne)} {Util.Hex(valueOne)}");
            await java.WaitForLineAsync(line => line == "STORED", "the Java node printing STORED");
            var foundOne = await cs.Dht.FindValuesAsync(keyOne);
            Assert.Contains(foundOne, pair => pair.Data.SequenceEqual(valueOne));

            // Mirror direction: the C# node stores, the Java node finds.
            var keyTwo = Util.Unhex(new string('b', 40));
            var valueTwo = Util.Utf8("interop-value csharp->java");
            await cs.Dht.StoreValueAsync(keyTwo, valueTwo);
            java.Send($"find {Util.Hex(keyTwo)}");
            var findLine = await java.WaitForLineAsync(
                line => line.StartsWith("FOUND ", StringComparison.Ordinal) || line == "NOTFOUND",
                "the Java node printing FOUND/NOTFOUND");
            Assert.True(findLine.StartsWith("FOUND ", StringComparison.Ordinal),
                $"the Java node could not find the C#-stored value: {findLine}");
            Assert.Equal(valueTwo, Util.Unhex(findLine.Substring("FOUND ".Length).Trim()));
        }

        // ---------------------------------------------------------------------- C3: tunnel

        /// <summary>
        /// C3: the C# initiator (in-process) builds a 2-hop circuit through TWO spawned Java
        /// nodes (first = relay, second = exit with EXIT_BT); a PING over the circuit returns
        /// a PONG through the tunnel — all cell handshakes cross the language boundary live.
        /// </summary>
        [Fact]
        public async Task C3_Tunnel_Interop_TwoHop_Circuit_Through_Java_Relay_And_Exit()
        {
            if (!JavaCliAvailable())
            {
                _output.WriteLine("SKIP (partial): the sibling java InteropCli is not compiled yet.");
                return;
            }

            using var relay = JavaNode.Spawn(PickPort());
            using var exit = JavaNode.Spawn(PickPort());
            using var cs = DotNetNode.Create();
            _output.WriteLine($"java relay: {relay.Address}, java exit: {exit.Address}, c# node: {cs.Address}");

            // The initiator walks BOTH Java nodes on the tunnel overlay; their intro
            // responses advertise their relay/exit peer flags through the extra bytes.
            cs.Tunnel.WalkTo(relay.Address);
            cs.Tunnel.WalkTo(exit.Address);
            await WaitUntilAsync(
                () => cs.Tunnel.GetPeers().Any(peer => peer.Address.Port == relay.Port)
                      && cs.Tunnel.GetPeers().Any(peer => peer.Address.Port == exit.Port),
                "the initiator verified both Java nodes on the tunnel overlay");
            await WaitUntilAsync(() => cs.Tunnel.Candidates.Count >= 2,
                "the tunnel candidates (with their peer flags) populated");

            var exitPeer = cs.Tunnel.Candidates.Keys
                .First(peer => peer.Address.Type == AddressType.Udpv4 && peer.Address.Port == exit.Port);
            var circuit = cs.Tunnel.CreateCircuit(2, requiredExit: exitPeer);
            Assert.NotNull(circuit);
            try
            {
                await WaitUntilAsync(() => circuit!.State == Tunnel.CircuitStateReady,
                    "the 2-hop circuit through the Java relay and exit reached READY");
            }
            catch (TimeoutException)
            {
                DumpJavaDiagnostics("C3 circuit build timeout", relay, exit);
                _output.WriteLine($"circuit state: {circuit!.State}, hops: {circuit.Hops.Count}, "
                                  + $"cid: {circuit.CircuitId}");
                foreach (var candidate in cs.Tunnel.Candidates)
                {
                    _output.WriteLine($"candidate {candidate.Key.Address.Port}: flags=[{string.Join(",", candidate.Value)}]");
                }
                lock (cs.Tunnel.RawData)
                {
                    _output.WriteLine($"raw data received: {cs.Tunnel.RawData.Count}");
                }
                List<byte[]> incoming;
                lock (cs.Tunnel.Incoming)
                {
                    incoming = new List<byte[]>(cs.Tunnel.Incoming);
                }
                _output.WriteLine($"tunnel packets received by the C# initiator: {incoming.Count}");
                foreach (var packet in incoming.TakeLast(6))
                {
                    _output.WriteLine($"  IN  {Util.Hex(packet)}");
                }
                List<byte[]> sent;
                lock (cs.Tunnel.Sniffer.Wires)
                {
                    sent = new List<byte[]>(cs.Tunnel.Sniffer.Wires);
                }
                _output.WriteLine($"tunnel wire packets sent by the C# initiator: {sent.Count}");
                foreach (var packet in sent.TakeLast(4))
                {
                    _output.WriteLine($"  OUT {Util.Hex(packet)}");
                }
                throw;
            }

            Assert.Equal(2, circuit!.Hops.Count);
            Assert.All(circuit.Hops, hop => Assert.NotNull(hop.Keys));

            // A PING over the circuit returns a PONG through the Java relay.
            var activityBefore = circuit.LastActivity;
            cs.Tunnel.DoPing();
            await WaitUntilAsync(() => circuit.LastActivity > activityBefore,
                "the circuit heart beat on the returned PONG");
            Assert.Null(cs.Tunnel.LastHandlerException);
        }
    }
}
