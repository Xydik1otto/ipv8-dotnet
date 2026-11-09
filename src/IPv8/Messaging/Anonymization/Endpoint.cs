// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System.Collections.Generic;
using IPv8.Messaging.Interfaces;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// Endpoint implementation that routes all data through a TunnelCommunity
    /// (endpoint.py::TunnelEndpoint).
    /// </summary>
    public sealed class TunnelEndpoint : Endpoint
    {
        private static readonly System.Diagnostics.TraceSource Log =
            new System.Diagnostics.TraceSource("TunnelEndpoint");

        public Endpoint Endpoint { get; }
        public int Hops { get; private set; }
        public TunnelCommunity TunnelCommunity { get; private set; }
        private readonly Dictionary<byte[], bool> _settings = new Dictionary<byte[], bool>(ByteArrayEqualityComparer.Instance);
        private readonly Queue<(Address, byte[])> _sendQueue = new Queue<(Address, byte[])>();

        public TunnelEndpoint(Endpoint endpoint)
        {
            Endpoint = endpoint;
            Hops = 0;
            TunnelCommunity = null;
        }

        /// <summary>
        /// Configure this endpoint to create tunnels of a given number of hops over the given community.
        /// </summary>
        public void SetTunnelCommunity(TunnelCommunity tunnelCommunity, int hops = 1)
        {
            TunnelCommunity = tunnelCommunity;
            Hops = hops;
        }

        /// <summary>Enable or disable tunneling for the given community id.</summary>
        public void SetAnonymity(byte[] prefix, bool enable)
        {
            _settings[prefix] = enable;
        }

        public override bool IsOpen => Endpoint.IsOpen;

        public override Address GetAddress()
        {
            return Endpoint.GetAddress();
        }

        public override void Send(Address address, byte[] packet)
        {
            var prefix = Util.Slice(packet, 0, 22);
            var registered = _settings.TryGetValue(prefix, out var enabled) && enabled;
            if (!registered)
            {
                Endpoint.Send(address, packet);
                return;
            }

            var tunnelCommunity = TunnelCommunity;
            if (tunnelCommunity == null)
            {
                return;
            }
            var circuits = tunnelCommunity.FindCircuits(
                exitFlags: new[] { Tunnel.PeerFlagExitIpv8 }, hops: Hops, state: null);
            var circuit = circuits.Count > 0 ? circuits[0] : null;
            if (circuit == null || circuit.State != Tunnel.CircuitStateReady)
            {
                // Recreate tunnel when needed
                if (circuit == null)
                {
                    tunnelCommunity.CreateCircuit(Hops, exitFlags: new[] { Tunnel.PeerFlagExitIpv8 });
                }
                if (_sendQueue.Count >= 100)
                {
                    // py deque(maxlen=100): appending drops the OLDEST queued packet.
                    _sendQueue.Dequeue();
                }
                _sendQueue.Enqueue((address, packet));
                return;
            }

            var circuitId = circuit.CircuitId;
            tunnelCommunity.SendData(circuit.Hop.Address, circuitId, address, Address.Zero, packet);

            // Any packets still need sending?
            while (_sendQueue.Count > 0)
            {
                (var queuedAddress, var queuedPacket) = _sendQueue.Dequeue();
                tunnelCommunity.SendData(circuit.Hop.Address, circuitId, queuedAddress, Address.Zero, queuedPacket);
            }
        }

        /// <summary>
        /// Ensure packets are only delivered if they follow they are properly encrypted.
        /// </summary>
        public void NotifyListeners(Packet packet, bool fromTunnel = false)
        {
            foreach (var listener in Endpoint.Listeners)
            {
                // Anonymized communities should ignore traffic received from the socket
                // Non-anonymized communities should ignore traffic received from the TunnelCommunity
                if (listener.Anonymize != fromTunnel)
                {
                    continue;
                }
                Endpoint.DeliverLater(listener, packet);
            }
        }

        public override void AddListener(EndpointListener listener)
        {
            // Forward directly to the underlying endpoint.
            Endpoint.AddListener(listener);
        }

        public override void AddPrefixListener(EndpointListener listener, byte[] prefix)
        {
            // Forward directly to the underlying endpoint.
            Endpoint.AddPrefixListener(listener, prefix);
        }

        public new void AssertOpen()
        {
            // Forward directly to the underlying endpoint.
            Endpoint.AssertOpen();
        }

        public override bool Open()
        {
            // Forward directly to the underlying endpoint.
            return Endpoint.Open();
        }

        public override void Close()
        {
            // Forward directly to the underlying endpoint.
            Endpoint.Close();
        }

        public override void ResetByteCounters()
        {
            // Forward directly to the underlying endpoint.
            Endpoint.ResetByteCounters();
        }
    }
}
