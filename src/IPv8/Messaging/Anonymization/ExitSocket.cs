// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// Class to verify that only IPv8-allowed traffic is being forwarded (exit_socket.py::DataChecker).
    /// </summary>
    public static class DataChecker
    {
        /// <summary>
        /// Check if this data could be uTP (see also https://www.bittorrent.org/beps/bep_0029.html).
        ///
        /// Packets should be 20 bytes or larger. The type should be 0..4, the version should be 1
        /// and the extension should be 0..3.
        /// </summary>
        public static bool CouldBeUtP(byte[] data)
        {
            if (data.Length < 20)
            {
                return false;
            }
            var byte1 = data[0];
            var byte2 = data[1];
            // Type and version
            if (!(0 <= (byte1 >> 4) && (byte1 >> 4) <= 4 && (byte1 & 15) == 1))
            {
                return false;
            }
            // Extension
            return 0 <= byte2 && byte2 <= 3;
        }

        /// <summary>Check if the data could be a UDP-based tracker.</summary>
        public static bool CouldBeUdpTracker(byte[] data)
        {
            // For the UDP tracker protocol the action field is either at position 0 or 8,
            // and should be 0..3
            return (data.Length >= 8 && 0 <= UnpackUInt32Be(data, 0) && UnpackUInt32Be(data, 0) <= 3)
                   || (data.Length >= 12 && 0 <= UnpackUInt32Be(data, 8) && UnpackUInt32Be(data, 8) <= 3);
        }

        private static long UnpackUInt32Be(byte[] data, int offset)
        {
            return ((long)data[offset] << 24) | ((long)data[offset + 1] << 16)
                   | ((long)data[offset + 2] << 8) | data[offset + 3];
        }

        /// <summary>Check if the data contain a bencoded dictionary.</summary>
        public static bool CouldBeDht(byte[] data)
        {
            return data.Length > 1 && data[0] == (byte)'d' && data[data.Length - 1] == (byte)'e';
        }

        /// <summary>Check if the data could be any BitTorrent traffic.</summary>
        public static bool CouldBeBt(byte[] data)
        {
            return CouldBeUtP(data) || CouldBeUdpTracker(data) || CouldBeDht(data);
        }

        /// <summary>Check if the data is likely IPv8 overlay traffic.</summary>
        public static bool CouldBeIpv8(byte[] data)
        {
            return data.Length >= 23 && data[0] == 0x00 && (data[1] == 0x01 || data[1] == 0x02);
        }
    }

    /// <summary>
    /// Socket for exit nodes that communicates with the outside world
    /// (exit_socket.py::TunnelExitSocket).
    /// </summary>
    public sealed class TunnelExitSocket : RoutingObject
    {
        private static readonly System.Diagnostics.TraceSource Log =
            new System.Diagnostics.TraceSource("TunnelExitSocket");

        private readonly TaskManager _taskManager = new TaskManager();

        public Hop Hop { get; }
        public TunnelCommunity Overlay { get; }
        public UdpClient TransportIpv4 { get; private set; }
        public UdpClient TransportIpv6 { get; private set; }
        public Queue<(byte[] Data, Address Destination)> Queue { get; } =
            new Queue<(byte[], Address)>();

        /// <summary>Set under the Queue lock once both transports exist (see SendTo's enqueue race note).</summary>
        private bool transportsReady;
        public bool Enabled { get; private set; }

        public TunnelExitSocket(long circuitId, Hop hop, TunnelCommunity overlay) : base(circuitId)
        {
            Hop = hop;
            Overlay = overlay;
        }

        /// <summary>Allow data to be sent (creates the datagram endpoints).</summary>
        public void Enable()
        {
            if (Enabled)
            {
                return;
            }
            Enabled = true;

            _taskManager.RegisterTask("create_transports", () =>
            {
                // py-ipv8 registers this as an async task whose failures are ignored
                // (they must never crash the process, e.g. during shutdown races).
                _ = Task.Run(async () =>
                {
                    try
                    {
                        TransportIpv4 = CreateTransport(AddressFamily.InterNetwork);
                        TransportIpv6 = CreateTransport(AddressFamily.InterNetworkV6);
                        _ = StartReceiveLoop(TransportIpv4, DatagramReceivedIpv4);
                        _ = StartReceiveLoop(TransportIpv6, DatagramReceivedIpv6);

                        // Publish readiness under the queue lock BEFORE draining, so a concurrent
                        // SendTo can never strand a packet between its null-check and its enqueue.
                        lock (Queue)
                        {
                            transportsReady = true;
                        }

                        // Send any packets that have been waiting while the transports were being created
                        while (true)
                        {
                            byte[] data;
                            Address destination;
                            lock (Queue)
                            {
                                if (Queue.Count == 0)
                                {
                                    break;
                                }
                                (data, destination) = Queue.Dequeue();
                            }
                            SendTo(data, destination);
                        }
                    }
                    catch (Exception e)
                    {
                        Log.TraceEvent(System.Diagnostics.TraceEventType.Error, 0,
                            "Exit transport creation failed: " + e.Message);
                    }
                });
            });
        }

        private static UdpClient CreateTransport(AddressFamily family)
        {
            // py-ipv8 binds an ephemeral datagram endpoint ("0.0.0.0", 0) / ("::", 0):
            // an unbound UdpClient cannot receive.
            var localEndPoint = family == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);
            var socket = new UdpClient(localEndPoint)
            {
                Client =
                {
                    ReceiveBufferSize = ushort.MaxValue,
                },
            };
            return socket;
        }

        private static async Task StartReceiveLoop(UdpClient transport,
                                                   Action<byte[], Address> callback)
        {
            // Continuous receive loop; exits when the transport is disposed.
            while (true)
            {
                UdpReceiveResult result;
                try
                {
                    result = await transport.ReceiveAsync().ConfigureAwait(false);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException)
                {
                    return;
                }
                catch (InvalidOperationException)
                {
                    // Socket closed/closing mid-loop (e.g. during shutdown).
                    return;
                }
                var remote = result.RemoteEndPoint;
                var address = remote.AddressFamily == AddressFamily.InterNetworkV6
                    ? Address.Udpv6(remote.Address.ToString(), remote.Port)
                    : Address.Udpv4(remote.Address.ToString(), remote.Port);
                try
                {
                    callback(result.Buffer, address);
                }
                catch (Exception e)
                {
                    Log.TraceEvent(System.Diagnostics.TraceEventType.Error, 0,
                        "Exception occurred while handling incoming exit node data: " + e);
                }
            }
        }

        /// <summary>Send a message over our datagram transporter.</summary>
        public void SendTo(byte[] data, Address destination)
        {
            if (!IsAllowed(data))
            {
                return;
            }

            // Since this call comes from the TunnelCommunity, we assume the destination
            // address is either UDPv4Address/UDPv6Address/DomainAddress
            if (destination.Type == AddressType.Domain)
            {
                var resolveTask = Resolve(destination);
                _taskManager.RegisterAnonymousTask($"resolving_{destination.Host}", () =>
                {
                    resolveTask.ContinueWith(t =>
                    {
                        if (t.IsFaulted)
                        {
                            Log.TraceEvent(System.Diagnostics.TraceEventType.Error, 0,
                                "Can't resolve ip address for " + destination.Host + ". Failure: " + t.Exception);
                            return;
                        }
                        SendTo(data, t.Result);
                    }, TaskScheduler.Default);
                });
                return;
            }

            var transport = destination.Type == AddressType.Udpv6 ? TransportIpv6 : TransportIpv4;

            if (transport == null)
            {
                // The transports may come up concurrently (Enable's create_transports task);
                // re-check under the queue lock so an enqueued packet can never be stranded
                // by a flush that ran before this enqueue (py is single-threaded, we are not).
                lock (Queue)
                {
                    if (!transportsReady)
                    {
                        if (Queue.Count >= 10)
                        {
                            Queue.Dequeue();
                        }
                        Queue.Enqueue((data, destination));
                        return;
                    }
                    transport = destination.Type == AddressType.Udpv6 ? TransportIpv6 : TransportIpv4;
                }
            }

            var ep = destination.IsUdpv4
                ? (IPEndPoint)new IPEndPoint(IPAddress.Parse(destination.Host), destination.Port)
                : new IPEndPoint(IPAddress.Parse(destination.Host), destination.Port);
            transport.Send(data, data.Length, ep);
            BytesUp += data.Length;
            BeatHeart();
        }

        /// <summary>
        /// Resolve a (domain, port) address to a UDPv4/UDPv6 address (preferring IPv4).
        /// </summary>
        public static async Task<Address> Resolve(Address address)
        {
            var ipList = await Dns.GetHostAddressesAsync(address.Host).ConfigureAwait(false);
            // For the time being we prefer dealing with IPv4 addresses.
            var sorted = ipList.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();
            if (sorted.Count == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }
            var ip = sorted[0];
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return Address.Udpv6(ip.ToString(), address.Port);
            }
            return Address.Udpv4(ip.ToString(), address.Port);
        }

        private void DatagramReceivedIpv4(byte[] data, Address source)
        {
            DatagramReceived(data, source);
        }

        private void DatagramReceivedIpv6(byte[] data, Address source)
        {
            if (source.Host.StartsWith("::ffff:", StringComparison.Ordinal))
            {
                // We're not processing mapped IPv4, we have a separate endpoint for that.
                return;
            }
            DatagramReceived(data, source);
        }

        private void DatagramReceived(byte[] data, Address source)
        {
            BytesDown += data.Length;
            if (IsAllowed(data))
            {
                TunnelData(source, data);
            }
            else
            {
                Log.TraceEvent(System.Diagnostics.TraceEventType.Warning, 0,
                    "Dropping forbidden packets to exit socket with circuit_id " + CircuitId);
            }
        }

        /// <summary>Check if the captured data is not malicious junk.</summary>
        public bool IsAllowed(byte[] data)
        {
            var isBt = DataChecker.CouldBeBt(data);
            var isIpv8 = DataChecker.CouldBeIpv8(data);

            if (!(isBt && Overlay.Settings.PeerFlags.Contains(Tunnel.PeerFlagExitBt))
                && !(isIpv8 && Overlay.Settings.PeerFlags.Contains(Tunnel.PeerFlagExitIpv8))
                && !(isIpv8 && Util.StartsWith(data, Overlay.GetPrefix())))
            {
                Log.TraceEvent(System.Diagnostics.TraceEventType.Warning, 0,
                    "Dropping data packets, refusing to be an exit node (BT=" + isBt + ", IPv8=" + isIpv8 + ")");
                return false;
            }
            return true;
        }

        /// <summary>Send data back over the tunnel that we are exiting for.</summary>
        public void TunnelData(Address source, byte[] data)
        {
            Overlay.SendData(Hop.Address, CircuitId, Address.Zero, source, data);
        }

        /// <summary>Closes the UDP socket if enabled and cancels all pending tasks.</summary>
        public async Task Close()
        {
            // The resolution tasks can't be cancelled, so we need to wait for them to finish.
            await ShutdownTasks().ConfigureAwait(false);
            TransportIpv4?.Dispose();
            TransportIpv4 = null;
            TransportIpv6?.Dispose();
            TransportIpv6 = null;
        }

        /// <summary>Cancel and wait for the pending TaskManager tasks (py shutdown_task_manager).</summary>
        public Task ShutdownTasks()
        {
            return Task.Run(() => _taskManager.ShutdownTaskManager());
        }
    }
}
