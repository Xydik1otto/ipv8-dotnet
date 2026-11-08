// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// B3/B4: three in-process nodes on the UDP loopback; A builds a 2-hop circuit A→B→C;
    /// a PING over the circuit returns a PONG through the tunnel while wire sniffing shows
    /// encrypted cell bodies (B3); a datagram sent through the circuit exits at C to a
    /// loopback UDP echo server and the response returns through the tunnel (B4).
    /// </summary>
    public class TunnelLoopbackTests : IDisposable
    {
        /// <summary>Sniffs FINAL outgoing wire packets (post encryption/relay_early) for the wire-level assertions.</summary>
        public sealed class SniffingCryptoEndpoint : PythonCryptoEndpoint
        {
            public readonly List<byte[]> SentCellWires = new List<byte[]>();

            public SniffingCryptoEndpoint(Endpoint endpoint) : base(endpoint)
            {
            }

            protected override void OnWireSent(byte[] packet)
            {
                lock (SentCellWires)
                {
                    SentCellWires.Add(packet);
                }
            }
        }

        private sealed class Node : IDisposable
        {
            public UDPEndpoint Endpoint;
            public Peer MyPeer;
            public TestTunnelCommunity Community;

            public static Node Create(HashSet<int> peerFlags)
            {
                var endpoint = new UDPEndpoint(0, "127.0.0.1");
                Assert.True(endpoint.Open());
                var address = endpoint.GetAddress();
                var myPeer = new Peer(ECCrypto.Default.GenerateKey("curve25519"));
                var settings = new TunnelSettings
                {
                    MyPeer = myPeer,
                    Endpoint = endpoint,
                    Network = new Network(),
                    PeerFlags = peerFlags
                };
                var community = new TestTunnelCommunity(settings);
                community.MyEstimatedLan = address;
                community.MyEstimatedWan = address;
                return new Node { Endpoint = endpoint, MyPeer = myPeer, Community = community };
            }

            public Address Address => Endpoint.GetAddress();

            public void Dispose()
            {
                Community.Unload();
                Endpoint.Close();
            }
        }

        /// <summary>TunnelCommunity with a sniffing crypto endpoint and a raw-data recorder.</summary>
        private sealed class TestTunnelCommunity : TunnelCommunity
        {
            public SniffingCryptoEndpoint Sniffer { get; private set; }

            public readonly List<(Circuit Circuit, Address Origin, byte[] Data)> RawData =
                new List<(Circuit, Address, byte[])>();

            public TestTunnelCommunity(TunnelSettings settings) : base(settings)
            {
            }

            protected override ICryptoEndpoint CreateCryptoEndpoint(Endpoint endpoint)
            {
                Sniffer = new SniffingCryptoEndpoint(endpoint);
                return Sniffer;
            }

            public override void OnRawData(Circuit circuit, Address origin, byte[] data)
            {
                lock (RawData)
                {
                    RawData.Add((circuit, origin, data));
                }
            }
        }

        private readonly List<Node> _nodes = new List<Node>();

        private Node MakeNode(HashSet<int> peerFlags)
        {
            var node = Node.Create(peerFlags);
            _nodes.Add(node);
            return node;
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 10000)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(5);
            }
        }

        public void Dispose()
        {
            foreach (var node in _nodes)
            {
                node.Dispose();
            }
        }

        private static readonly HashSet<int> ExitFlags =
            new HashSet<int> { Tunnel.PeerFlagRelay, Tunnel.PeerFlagExitBt, Tunnel.PeerFlagSpeedTest };

        /// <summary>Decode a cell wire packet per py-ipv8 CellPayload.to_bin:
        /// [0..21] prefix, [22] msg_id(0), [23..26] circuit_id, [27] plaintext, [28] relay_early,
        /// [29..] inner message (leading byte = inner msg id).</summary>
        private static (long CircuitId, bool Plaintext, bool RelayEarly, byte[] Message) DecodeCell(byte[] wire)
        {
            var circuitId = ((long)wire[23] << 24) | ((long)wire[24] << 16) | ((long)wire[25] << 8) | wire[26];
            var plaintext = wire[27] != 0;
            var relayEarly = wire[28] != 0;
            var message = new byte[wire.Length - 29];
            Array.Copy(wire, 29, message, 0, message.Length);
            return (circuitId, plaintext, relayEarly, message);
        }

        [Fact]
        public async Task Loopback_Circuit_TwoHops_Ping_Pong_EncryptedOnWire()
        {
            var alice = MakeNode(new HashSet<int> { Tunnel.PeerFlagRelay, Tunnel.PeerFlagSpeedTest });
            var bob = MakeNode(ExitFlags);
            var carol = MakeNode(ExitFlags);

            // Wire the three nodes together through the usual (signed) introductions.
            // A 2-hop circuit needs a first hop that differs from the exit (py-ipv8 semantics),
            // so alice must know both relay-capable peers.
            alice.Community.WalkTo(bob.Address);
            alice.Community.WalkTo(carol.Address);
            bob.Community.WalkTo(carol.Address);
            await WaitUntilAsync(() => alice.Community.GetPeers().Any(p => p.Mid.SequenceEqual(bob.MyPeer.Mid))
                                       && bob.Community.GetPeers().Any(p => p.Mid.SequenceEqual(carol.MyPeer.Mid))
                                       && alice.Community.GetPeers().Any(p => p.Mid.SequenceEqual(carol.MyPeer.Mid)),
                                 "alice-bob, bob-carol and alice-carol verified each other");

            // The intro exchange populates the candidates (with their announced peer flags).
            await WaitUntilAsync(() => alice.Community.Candidates.Count >= 2
                                       && bob.Community.Candidates.Count >= 2,
                                 "candidates populated on alice and bob");

            // B3: A builds a 2-hop circuit A→B→C with a deterministic exit choice.
            var carolPeer = alice.Community.Candidates.Keys
                .First(p => p.Mid.SequenceEqual(carol.MyPeer.Mid));
            var circuit = alice.Community.CreateCircuit(2, requiredExit: carolPeer);
            Assert.NotNull(circuit);
            await WaitUntilAsync(() => circuit.State == Tunnel.CircuitStateReady,
                                 "2-hop circuit reached READY state");

            // Both hops got session keys and the hop list is filled.
            Assert.Equal(2, circuit.Hops.Count);
            Assert.All(circuit.Hops, hop => Assert.NotNull(hop.Keys));
            Assert.True(bob.Community.RelayFromTo.Count > 0, "bob ended up as the relay");
            Assert.True(carol.Community.ExitSockets.Count > 0, "carol ended up as the exit node");

            // A PING over the circuit returns a PONG through the tunnel.
            var activityBefore = circuit.LastActivity;
            alice.Community.DoPing();
            await WaitUntilAsync(() => circuit.LastActivity > activityBefore,
                                 "the circuit heart beat on the returned PONG");

            // No handler exceptions anywhere.
            Assert.Null(alice.Community.LastHandlerException);
            Assert.Null(bob.Community.LastHandlerException);
            Assert.Null(carol.Community.LastHandlerException);

            // Wire sniffing: the PING cell that left A must be ENCRYPTED (no plaintext flag,
            // no plaintext ping message id, the message starts with the session counter, and
            // it does not contain the plaintext ping payload).
            byte[] pingWire;
            lock (alice.Community.Sniffer.SentCellWires)
            {
                // The last encrypted cell A sent before the PONG returned is the PING cell.
                pingWire = alice.Community.Sniffer.SentCellWires.Last(w =>
                {
                    var decoded = DecodeCell(w);
                    return decoded.Message.Length >= 24 && !decoded.Plaintext;
                });
            }
            var (sentCircuitId, plaintext, relayEarly, message) = DecodeCell(pingWire);
            Assert.Equal(circuit.CircuitId, sentCircuitId);
            Assert.False(plaintext, "the PING cell must be encrypted (plaintext flag unset)");
            Assert.True(relayEarly, "the PING cell carries the relay_early flag");
            Assert.NotEqual(PingPayload.MsgId, message[0]);

            // The first 8 bytes of an encrypted message are the wire counter (BE). Counters
            // increment BEFORE use starting at 1, so the FIRST forward use (the EXTEND cell)
            // carries counter 2 and the PING — the second forward use on hop1's keys — carries 3.
            Assert.Equal(3L, ((long)message[0] << 56) | ((long)message[1] << 48) | ((long)message[2] << 40)
                             | ((long)message[3] << 32) | ((long)message[4] << 24) | ((long)message[5] << 16)
                             | ((long)message[6] << 8) | message[7]);

            // The PONG traveling back through B must be encrypted as well.
            byte[] pongWire;
            lock (bob.Community.Sniffer.SentCellWires)
            {
                pongWire = bob.Community.Sniffer.SentCellWires.Last(w =>
                {
                    var decoded = DecodeCell(w);
                    return decoded.Message.Length >= 24 && !decoded.Plaintext;
                });
            }
            var (_, pongPlaintext, _, pongMessage) = DecodeCell(pongWire);
            Assert.False(pongPlaintext, "the PONG cell must be encrypted (plaintext flag unset)");
            Assert.NotEqual(PongPayload.MsgId, pongMessage[0]);
        }

        [Fact]
        public async Task Exit_Socket_Datagram_Exits_And_Echo_Returns()
        {
            var alice = MakeNode(new HashSet<int> { Tunnel.PeerFlagRelay, Tunnel.PeerFlagSpeedTest });
            var bob = MakeNode(ExitFlags);
            var carol = MakeNode(ExitFlags);

            // Same topology as B3: alice knows both peers (first hop must differ from the exit).
            alice.Community.WalkTo(bob.Address);
            alice.Community.WalkTo(carol.Address);
            bob.Community.WalkTo(carol.Address);
            await WaitUntilAsync(() => alice.Community.GetPeers().Any(p => p.Mid.SequenceEqual(bob.MyPeer.Mid))
                                       && bob.Community.GetPeers().Any(p => p.Mid.SequenceEqual(carol.MyPeer.Mid))
                                       && alice.Community.GetPeers().Any(p => p.Mid.SequenceEqual(carol.MyPeer.Mid)),
                                 "the three nodes verified each other");
            await WaitUntilAsync(() => alice.Community.Candidates.Count >= 2
                                       && bob.Community.Candidates.Count >= 2,
                                 "candidates populated");

            var carolPeer = alice.Community.Candidates.Keys
                .First(p => p.Mid.SequenceEqual(carol.MyPeer.Mid));
            var circuit = alice.Community.CreateCircuit(2, requiredExit: carolPeer);
            Assert.NotNull(circuit);
            await WaitUntilAsync(() => circuit.State == Tunnel.CircuitStateReady,
                                 "2-hop circuit reached READY state");

            // Loopback UDP echo server (plain datagram echo, no IPv8).
            var echoEndpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(echoEndpoint.Open());
            var received = new List<byte[]>();
            echoEndpoint.AddListener(new EchoListener(echoEndpoint, received));
            try
            {
                // Send a payload through the tunnel: A→B→C, C exits to the echo server.
                // The payload is DHT-shaped (bencoded dictionary, DataChecker.CouldBeDht) so the
                // exit node's IsAllowed accepts it AND the returning echo takes the raw-data path
                // at alice (an IPv8-shaped payload would require a TunnelEndpoint listener).
                var payload = new byte[30];
                payload[0] = (byte)'d';
                payload[1] = 0x01;
                payload[29] = (byte)'e';
                alice.Community.SendData(circuit.Hop.Address, circuit.CircuitId,
                                         echoEndpoint.GetAddress(), Address.Zero, payload);

                // The echo server receives the (exited) datagram...
                await WaitUntilAsync(() =>
                {
                    lock (received)
                    {
                        return received.Count > 0;
                    }
                }, "echo server received the datagram");
                Assert.Equal(payload, received[0]);

                // ...and the response makes it back through the tunnel to A's on_raw_data.
                await WaitUntilAsync(() =>
                {
                    lock (alice.Community.RawData)
                    {
                        return alice.Community.RawData.Any(entry => entry.Data.SequenceEqual(payload));
                    }
                }, "the echoed response returned through the tunnel");

                Assert.Null(alice.Community.LastHandlerException);
                Assert.Null(bob.Community.LastHandlerException);
                Assert.Null(carol.Community.LastHandlerException);
            }
            finally
            {
                echoEndpoint.Close();
            }
        }

        private sealed class EchoListener : EndpointListener
        {
            private readonly UDPEndpoint _endpoint;
            private readonly List<byte[]> _received;

            public EchoListener(UDPEndpoint endpoint, List<byte[]> received) : base(endpoint)
            {
                _endpoint = endpoint;
                _received = received;
            }

            public override void OnPacket(Packet packet)
            {
                lock (_received)
                {
                    _received.Add(packet.Data);
                }
                // Echo the datagram straight back to the sender.
                _endpoint.Send(packet.SourceAddress, packet.Data);
            }
        }
    }
}
