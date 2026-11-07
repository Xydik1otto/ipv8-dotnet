// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using IPv8.Messaging.Interfaces;

namespace IPv8.Messaging.Interfaces.Udp
{
    /// <summary>
    /// Endpoint that binds UDP over IPv4 (port of ipv8/messaging/interfaces/udp/endpoint.py::UDPEndpoint),
    /// implemented with an async receive loop instead of asyncio.
    /// </summary>
    public sealed class UDPEndpoint : Endpoint
    {
        private readonly string _ip;
        private int _port;
        private volatile bool _running;
        private Socket _socket;
        private Task _receiveTask = Task.CompletedTask;

        /// <summary>Bytes sent through this endpoint.</summary>
        public long BytesUp { get; private set; }

        /// <summary>Bytes received by this endpoint.</summary>
        public long BytesDown { get; private set; }

        /// <summary>The port this endpoint is (bound to be) listening on.</summary>
        public int Port => _port;

        public UDPEndpoint(int port = 0, string ip = "0.0.0.0") : base()
        {
            _port = port;
            _ip = ip;
        }

        public override bool IsOpen => _running && _socket != null;

        public override Address GetAddress()
        {
            var localEndPoint = (IPEndPoint)_socket?.LocalEndPoint;
            if (localEndPoint == null)
            {
                return Address.Zero;
            }
            return Address.Udpv4(localEndPoint.Address.ToString(), localEndPoint.Port);
        }

        /// <summary>
        /// Process incoming data: if the endpoint is still running, accept incoming packets,
        /// otherwise drop them.
        /// </summary>
        private void DatagramReceived(byte[] datagram, Address addr)
        {
            if (_running)
            {
                BytesDown += datagram.Length;
                NotifyListeners(new Packet(addr, datagram));
            }
        }

        public override void Send(Address socketAddress, byte[] packet)
        {
            AssertOpen();
            try
            {
                var ipAddress = IPAddress.Parse(socketAddress.Host);
                _socket.SendTo(packet, new IPEndPoint(ipAddress, socketAddress.Port));
                BytesUp += packet.Length;
            }
            catch (Exception exc) when (exc is FormatException
                                        || exc is ArgumentException
                                        || exc is SocketException
                                        || exc is ObjectDisposedException)
            {
                // py-ipv8 logs and drops packets with formatting errors.
                Console.Error.WriteLine($"Dropping packet due to message formatting error: {exc.Message}");
            }
        }

        public override bool Open()
        {
            if (_running)
            {
                return true;
            }
            Socket bound = null;
            for (var attempt = 0; attempt < 10000; attempt++)
            {
                try
                {
                    var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveBuffer, 870400);
                    s.Bind(new IPEndPoint(IPAddress.Parse(_ip), _port));
                    _port = ((IPEndPoint)s.LocalEndPoint).Port;
                    bound = s;
                    break;
                }
                catch (SocketException)
                {
                    // Listening failed at this port: attempt the next one (py-ipv8 semantics).
                    _port += 1;
                }
            }
            if (bound == null)
            {
                return false;
            }
            _socket = bound;
            _running = true;
            _receiveTask = ReceiveLoopAsync();
            return true;
        }

        private async Task ReceiveLoopAsync()
        {
            var buffer = new byte[65536];
            var anyEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var socket = _socket;
            while (_running && socket != null)
            {
                try
                {
                    var result = await socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None,
                                                               anyEndPoint).ConfigureAwait(false);
                    if (!_running)
                    {
                        break;
                    }
                    var remote = (IPEndPoint)result.RemoteEndPoint;
                    var data = new byte[result.ReceivedBytes];
                    Array.Copy(buffer, 0, data, 0, result.ReceivedBytes);
                    DatagramReceived(data, Address.Udpv4(remote.Address.ToString(), remote.Port));
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException)
                {
                    if (!_running)
                    {
                        break;
                    }
                    // Transient socket error: keep listening.
                }
            }
        }

        public override void Close()
        {
            _running = false;
            var socket = _socket;
            _socket = null;
            try
            {
                socket?.Close();
            }
            catch (Exception)
            {
                // Ignore shutdown races.
            }
        }

        public override void ResetByteCounters()
        {
            BytesUp = 0;
            BytesDown = 0;
        }
    }
}
