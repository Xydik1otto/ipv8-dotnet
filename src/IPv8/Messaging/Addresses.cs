// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Globalization;

namespace IPv8.Messaging
{
    /// <summary>
    /// The address "classes" of py-ipv8 (UDPv4Address, UDPv4LANAddress, UDPv6Address, DomainAddress).
    /// py-ipv8 uses namedtuple subclasses; the exact type carries semantic meaning
    /// (e.g. UDPv4LANAddress marks peers discovered over the LAN), so we carry it explicitly.
    /// </summary>
    public enum AddressType
    {
        Udpv4 = 0,
        Udpv4Lan = 1,
        Udpv6 = 2,
        Domain = 3
    }

    /// <summary>
    /// An address ("host", port) combination with an explicit type, mirroring the py-ipv8 Address
    /// union type (tuple[str, int] | UDPv4Address | UDPv6Address | DomainAddress).
    /// </summary>
    public readonly struct Address : IEquatable<Address>
    {
        public static readonly Address Zero = new Address(AddressType.Udpv4, "0.0.0.0", 0);

        public AddressType Type { get; }
        public string Host { get; }
        public int Port { get; }

        public Address(AddressType type, string host, int port)
        {
            Type = type;
            Host = host ?? throw new ArgumentNullException(nameof(host));
            Port = port;
        }

        /// <summary>Whether this address was created as a UDPv4Address (not LAN-tagged).</summary>
        public bool IsUdpv4 => Type == AddressType.Udpv4;

        /// <summary>Whether this address is any IPv4 flavor (UDPv4Address or UDPv4LANAddress).</summary>
        public bool IsIpv4 => Type == AddressType.Udpv4 || Type == AddressType.Udpv4Lan;

        public bool Equals(Address other)
            => Type == other.Type && Port == other.Port && string.Equals(Host, other.Host, StringComparison.Ordinal);

        public override bool Equals(object obj) => obj is Address other && Equals(other);

        public override int GetHashCode()
        {
            unchecked
            {
                var hash = 17;
                hash = (hash * 31) + (int)Type;
                hash = (hash * 31) + (Host == null ? 0 : Util.BytesHashCode(Util.Utf8(Host)));
                hash = (hash * 31) + Port;
                return hash;
            }
        }

        public static bool operator ==(Address left, Address right) => left.Equals(right);

        public static bool operator !=(Address left, Address right) => !left.Equals(right);

        public override string ToString() => $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";

        /// <summary>
        /// Create a UDPv4Address, mirroring ``UDPv4Address(*args)`` in py-ipv8.
        /// </summary>
        public static Address Udpv4(string host, int port) => new Address(AddressType.Udpv4, host, port);

        /// <summary>Create a UDPv4LANAddress (LAN-tagged IPv4 address).</summary>
        public static Address Udpv4Lan(string host, int port) => new Address(AddressType.Udpv4Lan, host, port);

        /// <summary>Create a UDPv6Address.</summary>
        public static Address Udpv6(string host, int port) => new Address(AddressType.Udpv6, host, port);

        /// <summary>Create a DomainAddress.</summary>
        public static Address Domain(string host, int port) => new Address(AddressType.Domain, host, port);
    }

    /// <summary>A packet received on an endpoint: (source address, data), like py-ipv8's (Address, bytes) tuple.</summary>
    public readonly struct Packet
    {
        public readonly Address SourceAddress;
        public readonly byte[] Data;

        public Packet(Address sourceAddress, byte[] data)
        {
            SourceAddress = sourceAddress;
            Data = data;
        }
    }
}
