// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace IPv8.Messaging.Interfaces
{
    /// <summary>
    /// Raised when an EndpointListener instance was expected, but not supplied
    /// (py-ipv8 IllegalEndpointListenerError).
    /// </summary>
    public class IllegalEndpointListenerError : Exception
    {
        public IllegalEndpointListenerError(object other)
            : base($"{other?.GetType().Name ?? "null"} is not an instance of {nameof(EndpointListener)}")
        {
        }
    }

    /// <summary>Raised when an endpoint is expected to be open, but is closed.</summary>
    public class EndpointClosedException : Exception
    {
        public EndpointClosedException(Endpoint endpoint)
            : base($"{endpoint.GetType().Name} is unexpectedly closed")
        {
        }
    }

    /// <summary>
    /// Interface for sending messages over the Internet (port of
    /// ipv8/messaging/interfaces/endpoint.py::Endpoint), with prefix-multiplexed dispatch.
    /// </summary>
    public abstract class Endpoint
    {
        protected readonly List<EndpointListener> Listeners = new List<EndpointListener>();
        protected readonly Dictionary<byte[], List<EndpointListener>> PrefixMap
            = new Dictionary<byte[], List<EndpointListener>>(ByteArrayEqualityComparer.Instance);
        protected readonly int PrefixLen;
        private readonly object _listenerUpdateLock = new object();

        protected Endpoint(int prefixlen = 22)
        {
            PrefixLen = prefixlen;
        }

        /// <summary>Add an EndpointListener to our listeners.</summary>
        public void AddListener(EndpointListener listener)
        {
            if (listener == null)
            {
                throw new IllegalEndpointListenerError(listener);
            }
            lock (_listenerUpdateLock)
            {
                Listeners.Add(listener);
                foreach (var prefix in PrefixMap.Keys)
                {
                    PrefixMap[prefix].Add(listener);
                }
            }
        }

        /// <summary>
        /// Add an EndpointListener to our listeners, only triggers on packets with a specific prefix.
        /// </summary>
        public void AddPrefixListener(EndpointListener listener, byte[] prefix)
        {
            if (listener == null)
            {
                throw new IllegalEndpointListenerError(listener);
            }
            if (prefix.Length != PrefixLen)
            {
                throw new InvalidOperationException(
                    $"Tried to register a prefix of length {prefix.Length}, required to be of length {PrefixLen}!");
            }
            lock (_listenerUpdateLock)
            {
                PrefixMap.TryGetValue(prefix, out var existing);
                var list = existing != null ? new List<EndpointListener>(existing) : new List<EndpointListener>();
                // py-ipv8: self._prefix_map[prefix] = [*existing, listener, *self._listeners]
                list.Add(listener);
                list.AddRange(Listeners);
                PrefixMap[prefix] = list;
            }
        }

        /// <summary>Remove a listener from our listeners, if it is registered.</summary>
        public void RemoveListener(EndpointListener listener)
        {
            lock (_listenerUpdateLock)
            {
                Listeners.RemoveAll(l => ReferenceEquals(l, listener));
                var newPrefixMap = new Dictionary<byte[], List<EndpointListener>>(ByteArrayEqualityComparer.Instance);
                foreach (var pair in PrefixMap)
                {
                    var filtered = new List<EndpointListener>();
                    foreach (var l in pair.Value)
                    {
                        if (!ReferenceEquals(l, listener))
                        {
                            filtered.Add(l);
                        }
                    }
                    // py-ipv8 keeps the prefix entry only when it differs from the generic listeners.
                    if (!SameSet(filtered, Listeners))
                    {
                        newPrefixMap[pair.Key] = filtered;
                    }
                }
                foreach (var pair in newPrefixMap)
                {
                    PrefixMap[pair.Key] = pair.Value;
                }
            }
        }

        private static bool SameSet(List<EndpointListener> a, List<EndpointListener> b)
        {
            if (a.Count != b.Count)
            {
                return false;
            }
            var setA = new HashSet<EndpointListener>(a);
            var setB = new HashSet<EndpointListener>(b);
            return setA.SetEquals(setB);
        }

        /// <summary>Ensure that the listener is still loaded when delivering the packet later.</summary>
        protected void DeliverLater(EndpointListener listener, Packet packet)
        {
            var prefix = new byte[PrefixLen];
            Array.Copy(packet.Data, 0, prefix, 0, Math.Min(PrefixLen, packet.Data.Length));
            bool deliver;
            lock (_listenerUpdateLock)
            {
                deliver = IsOpen && (PrefixMap.ContainsKey(prefix) || Listeners.Contains(listener));
            }
            if (deliver)
            {
                listener.OnPacket(packet);
            }
        }

        /// <summary>Send data to all listeners.</summary>
        public void NotifyListeners(Packet packet)
        {
            var prefix = new byte[PrefixLen];
            Array.Copy(packet.Data, 0, prefix, 0, Math.Min(PrefixLen, packet.Data.Length));
            EndpointListener[] listeners;
            lock (_listenerUpdateLock)
            {
                listeners = (PrefixMap.TryGetValue(prefix, out var mapped) ? mapped : Listeners).ToArray();
            }
            foreach (var listener in listeners)
            {
                DeliverLater(listener, packet);
            }
        }

        /// <summary>Crash with an exception (explaining the situation) if this endpoint is not opened.</summary>
        public void AssertOpen()
        {
            if (!IsOpen)
            {
                throw new EndpointClosedException(this);
            }
        }

        /// <summary>Whether this endpoint is open.</summary>
        public abstract bool IsOpen { get; }

        /// <summary>Get the MOST LIKELY external address for this endpoint. This is often wrong!</summary>
        public abstract Address GetAddress();

        /// <summary>Try to send data to some address. No delivery guarantees.</summary>
        public abstract void Send(Address socketAddress, byte[] packet);

        /// <summary>Attempt to open this endpoint and return if this was successful.</summary>
        public abstract bool Open();

        /// <summary>Close this endpoint as quick as possible.</summary>
        public abstract void Close();

        /// <summary>Reset any internal byte counting mechanisms.</summary>
        public abstract void ResetByteCounters();
    }

    /// <summary>Handler for messages coming in through an Endpoint (py-ipv8 EndpointListener).</summary>
    public abstract class EndpointListener
    {
        protected EndpointListener(Endpoint endpoint, bool mainThread = true)
        {
            Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
            UseMainThread = mainThread;
            MyEstimatedLan = Address.Zero;
            MyEstimatedWan = Address.Zero;
        }

        public Endpoint Endpoint { get; }

        /// <summary>Does the callback of this listener need to be executed on the main thread.</summary>
        public bool UseMainThread { get; }

        private Address? _myEstimatedLan;

        /// <summary>Estimate our LAN address and port (defaults to 0.0.0.0:0 until estimated or set).</summary>
        public Address MyEstimatedLan
        {
            get
            {
                if (_myEstimatedLan == null && Endpoint.IsOpen)
                {
                    var endpointAddress = Endpoint.GetAddress();
                    _myEstimatedLan = new Address(AddressType.Udpv4, GuessLanHost(), endpointAddress.Port);
                }
                return _myEstimatedLan ?? Address.Zero;
            }
            set => _myEstimatedLan = value;
        }

        /// <summary>Our (estimated) WAN address.</summary>
        public Address MyEstimatedWan { get; set; }

        /// <summary>Callback for when data is received on this endpoint.</summary>
        public abstract void OnPacket(Packet packet);

        /// <summary>Whether the given host is an IPv6 address.</summary>
        protected static bool IsIpv6Address(string address)
        {
            return System.Net.IPAddress.TryParse(address, out var parsed)
                   && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        /// <summary>Minimal port of py-ipv8's lan-address discovery: local IPv4 interface addresses.</summary>
        protected static IList<string> GetLanAddresses()
        {
            var addresses = new List<string>();
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    {
                        continue;
                    }
                    foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (unicast.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            addresses.Add(unicast.Address.ToString());
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Best-effort address discovery.
            }
            return addresses;
        }

        /// <summary>Choose the most likely local interface address, falling back to "127.0.0.1".</summary>
        protected static string GuessLanHost()
        {
            foreach (var address in GetLanAddresses())
            {
                if (!IsIpv6Address(address))
                {
                    return address;
                }
            }
            return "127.0.0.1";
        }

        /// <summary>
        /// Checks whether a given IPv4 address (string) is in a given subnet (main address, netmask bits).
        /// </summary>
        protected static bool IsAddressInSubnet(string address, string subnetMain, int netmask)
        {
            if (!Ipv4.TryParseDottedQuad(address, out var addressBytes)
                || !Ipv4.TryParseDottedQuad(subnetMain, out var subnetBytes))
            {
                return false;
            }
            var iAddress = ((uint)addressBytes[0] << 24) | ((uint)addressBytes[1] << 16)
                           | ((uint)addressBytes[2] << 8) | addressBytes[3];
            var iSubnetMain = ((uint)subnetBytes[0] << 24) | ((uint)subnetBytes[1] << 16)
                              | ((uint)subnetBytes[2] << 8) | subnetBytes[3];
            var shift = 32 - netmask;
            return (iAddress >> shift) == (iSubnetMain >> shift);
        }

        /// <summary>Whether the given address exists in any common LAN subnet.</summary>
        public bool AddressInLanSubnets(string address)
        {
            return IsAddressInSubnet(address, "192.168.0.0", 16)
                   || IsAddressInSubnet(address, "172.16.0.0", 12)
                   || IsAddressInSubnet(address, "10.0.0.0", 8);
        }

        /// <summary>Whether the given address is one of our own LAN addresses.</summary>
        public bool AddressIsLan(string address)
        {
            foreach (var lanAddress in GetLanAddresses())
            {
                if (lanAddress == address)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
