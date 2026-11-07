// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using IPv8.Messaging;

namespace IPv8.Bootstrapping
{
    /// <summary>
    /// Endpoint that opens a broadcast socket
    /// (port of ipv8/bootstrapping/udpbroadcast/bootstrapper.py::BroadcastBootstrapEndpoint).
    /// </summary>
    public sealed class BroadcastBootstrapEndpoint : IDisposable
    {
        public static readonly byte[] ProtocolVersion = { 0x00, 0x00 };
        public static readonly byte[] Magic = { 0x49, 0x50, 0x76, 0x38 }; // "IPv8"

        /// <summary>PROTOCOL_VERSION + MAGIC + b"\x00" (7 bytes).</summary>
        public static readonly byte[] HdrAnnounce =
            Util.Concat(Util.Concat(ProtocolVersion, Magic), new byte[] { 0x00 });

        private readonly Community _overlay;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();

        private Socket _socket;
        private volatile bool _closed;

        public BroadcastBootstrapEndpoint(Community overlay)
        {
            _overlay = overlay ?? throw new ArgumentNullException(nameof(overlay));
        }

        /// <summary>The locally bound (host, port) of this socket, when open.</summary>
        public Address LocalAddress { get; private set; }

        /// <summary>Whether the last send attempt failed (broadcast denied by the OS).</summary>
        public bool LastSendFailed { get; private set; }

        /// <summary>Open the broadcast socket. Returns false when the OS denies it.</summary>
        public bool Open()
        {
            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                _socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                var bound = (IPEndPoint)_socket.LocalEndPoint;
                LocalAddress = Address.Udpv4(bound.Address.ToString(), bound.Port);
                _ = ReceiveLoopAsync();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Attempt to send data to the given socket address and silently fail.</summary>
        public void Send(Address socketAddress, byte[] data)
        {
            try
            {
                if (_socket != null)
                {
                    _socket.SendTo(data, data.Length, SocketFlags.None,
                        new IPEndPoint(IPAddress.Parse(socketAddress.Host), socketAddress.Port));
                }
            }
            catch (Exception)
            {
                // Windows doesn't really care, Ubuntu throws an exception on "illegal" ports
                LastSendFailed = true;
            }
        }

        private async Task ReceiveLoopAsync()
        {
            var buffer = new byte[65536];
            while (!_closed)
            {
                EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                try
                {
                    var received = await _socket.ReceiveFromAsync(
                        new ArraySegment<byte>(buffer), SocketFlags.None, remote);
                    remote = received.RemoteEndPoint;
                    var data = new byte[received.ReceivedBytes];
                    Array.Copy(buffer, data, data.Length);
                    var ipEndpoint = (IPEndPoint)remote;
                    OnDatagram(data, Address.Udpv4(ipEndpoint.Address.ToString(), ipEndpoint.Port));
                }
                catch (Exception)
                {
                    // Socket closed or receive failed: exit the loop.
                    return;
                }
            }
        }

        /// <summary>
        /// We received data on our broadcast socket.
        /// Note that we do not use the broadcast socket but the overlay socket to send a reply.
        /// </summary>
        public void OnDatagram(byte[] data, Address addr)
        {
            if (Util.StartsWith(data, HdrAnnounce))
            {
                var prefix = Util.SliceFrom(data, HdrAnnounce.Length);
                if (Util.BytesEqual(_overlay.GetPrefix(), prefix))
                {
                    Console.Error.WriteLine($"Received data from beacon {addr}: attempting walk!");
                    _overlay.WalkTo(addr);
                }
                // Otherwise: valid, but not for our overlay
            }
            else if (Util.StartsWith(data, _overlay.GetPrefix()))
            {
                Console.Error.WriteLine($"Walk success by {addr}: attempting handoff!");
                _overlay.OnPacket(new Packet(addr, data));
            }
            else
            {
                Console.Error.WriteLine($"Dropping garbage packet from {addr}");
            }
        }

        /// <summary>Close this endpoint.</summary>
        public void Close()
        {
            if (_closed)
            {
                return;
            }
            _closed = true;
            _cts.Cancel();
            try
            {
                _socket?.Close();
            }
            catch (Exception)
            {
                // Ignore.
            }
        }

        public void Dispose() => Close();
    }

    /// <summary>
    /// Bootstrapper that finds peers by iterating over ALL 65k ports of the local broadcast address
    /// (port of ipv8/bootstrapping/udpbroadcast/bootstrapper.py::UDPBroadcastBootstrapper).
    /// </summary>
    public class UdpBroadcastBootstrapper : Bootstrapper
    {
        public BroadcastBootstrapEndpoint Endpoint { get; private set; }

        public Community Overlay { get; private set; }

        public double BootstrapTimeout { get; }

        public double LastBootstrap { get; set; }

        public UdpBroadcastBootstrapper(double bootstrapTimeout = 30.0)
        {
            BootstrapTimeout = bootstrapTimeout;

            LastBootstrap = 0;
        }

        public override Task<bool> InitializeAsync(Community overlay)
        {
            if (Initialized)
            {
                return Task.FromResult(true);
            }
            Initialized = true;

            Overlay = overlay;

            // Open the socket
            var endpoint = new BroadcastBootstrapEndpoint(overlay);
            var success = endpoint.Open();
            if (!success)
            {
                return Task.FromResult(false);
            }
            Endpoint = endpoint;

            // Start sending
            Beacon(overlay.GetPrefix());

            return Task.FromResult(true);
        }

        /// <summary>Try to find a listener (fire and forget).</summary>
        public void Beacon(byte[] servicePrefix)
        {
            if (Endpoint != null)
            {
                for (var p = 0; p < 65535; p++)
                {
                    Endpoint.Send(Address.Udpv4("255.255.255.255", p),
                                  Util.Concat(BroadcastBootstrapEndpoint.HdrAnnounce, servicePrefix));
                }
            }
        }

        public override Task<IReadOnlyList<Address>> GetAddressesAsync(Community overlay, double timeout)
        {
            if (Util.NowEpoch() - LastBootstrap < BootstrapTimeout)
            {
                return Task.FromResult<IReadOnlyList<Address>>(new List<Address>());
            }
            Console.Error.WriteLine(
                $"Bootstrapping {overlay.GetType().Name}, current peers {overlay.GetPeers().Count}");
            LastBootstrap = Util.NowEpoch();
            Beacon(overlay.GetPrefix());
            return Task.FromResult<IReadOnlyList<Address>>(new List<Address>());
        }

        public override void KeepAlive(Community overlay)
        {
            // Send a "keep alive" message.
            Beacon(overlay.GetPrefix());
        }

        public override IReadOnlyList<Address> Blacklist() => new List<Address>();

        public override void Unload()
        {
            // Stop this bootstrapper.
            Endpoint?.Close();
        }
    }
}
