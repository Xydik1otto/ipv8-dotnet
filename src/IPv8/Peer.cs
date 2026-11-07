// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;
using IPv8.Messaging;

namespace IPv8
{
    /// <summary>
    /// A public key that has additional information attached to it (like an IP address, measured
    /// RTT, etc.) — port of ipv8/peer.py.
    /// </summary>
    public class Peer : IEquatable<Peer>
    {
        /// <summary>The py-ipv8 INTERFACE_ORDER: [UDPv6Address, UDPv4Address, tuple].</summary>
        private static readonly AddressType[] InterfaceOrder =
        {
            AddressType.Udpv6,
            AddressType.Udpv4,
            AddressType.Domain
        };

        private readonly Dictionary<AddressType, Address> _addresses = new Dictionary<AddressType, Address>();
        private Address? _address;
        private ulong _lamportTimestamp;

        /// <summary>Create a new Peer from key material (mostly public) and an optional address.</summary>
        public Peer(Key key, Address? address = null, bool intro = true)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Init(address, intro);
        }

        /// <summary>
        /// Create a new Peer from a public key in binary format.
        /// Private key material is rejected, exactly like py-ipv8.
        /// </summary>
        public Peer(byte[] publicKeyBin, Address? address = null, bool intro = true)
        {
            if (publicKeyBin == null)
            {
                throw new ArgumentNullException(nameof(publicKeyBin));
            }
            if (Util.StartsWith(publicKeyBin, Keyvault.LibNaclPrivateKey.Prefix))
            {
                throw new ArgumentException(
                    "You attempted to initialize a Peer with PRIVATE key material."
                    + " This is normally ONLY done for your own Peer instance and internally handled by IPv8."
                    + " If this is truly what you want to do, initialize Peer with a PrivateKey subclass.");
            }
            Key = ECCrypto.Default.KeyFromPublicBin(publicKeyBin);
            Init(address, intro);
        }

        private void Init(Address? address, bool intro)
        {
            PublicKey = Key.Pub();
            Mid = PublicKey.KeyToHash();
            if (address != null)
            {
                _addresses[address.Value.Type] = address.Value;
                _address = address;
            }
            CreationTime = Util.NowEpoch();
            LastResponse = intro ? 0 : Util.NowEpoch();
            NewStyleIntro = false;
            AddressFrozen = false;
        }

        /// <summary>The key material of this peer (private for our own peer).</summary>
        public Key Key { get; }

        /// <summary>The public key of this peer.</summary>
        public PublicKey PublicKey { get; private set; }

        /// <summary>The SHA-1 hash of the public key binary (20 bytes).</summary>
        public byte[] Mid { get; private set; }

        /// <summary>Retrieve the addresses belonging to this Peer.</summary>
        public IReadOnlyDictionary<AddressType, Address> Addresses => _addresses;

        /// <summary>Retrieve the preferred address for this Peer ("0.0.0.0", 0 when unknown).</summary>
        public Address Address
        {
            get => _address ?? Address.Zero;
            set => AddAddress(value);
        }

        /// <summary>
        /// Add a known address for this Peer. Only one address can be used per address type.
        /// </summary>
        public void AddAddress(Address value)
        {
            if (AddressFrozen)
            {
                return;
            }
            _addresses[value.Type] = value;
            UpdatePreferredAddress();
        }

        private void UpdatePreferredAddress()
        {
            foreach (var interfaceType in InterfaceOrder)
            {
                if (_addresses.TryGetValue(interfaceType, out var preferred))
                {
                    _address = preferred;
                    break;
                }
            }
        }

        /// <summary>Set this to True if you want to avoid this Peer's address being updated.</summary>
        public bool AddressFrozen { get; set; }

        /// <summary>The time at which this Peer was created (epoch seconds).</summary>
        public double CreationTime { get; private set; }

        /// <summary>The time of the last response received from this peer (epoch seconds).</summary>
        public double LastResponse { get; set; }

        /// <summary>Whether this peer announced support for new-style introductions.</summary>
        public bool NewStyleIntro { get; set; }

        /// <summary>
        /// Update the Lamport timestamp for this peer: the current timestamp becomes the maximum of
        /// the last known and the most recently delivered timestamp.
        /// </summary>
        public void UpdateClock(ulong timestamp)
        {
            if (timestamp > _lamportTimestamp)
            {
                _lamportTimestamp = timestamp;
            }
            LastResponse = Util.NowEpoch();
        }

        /// <summary>Get the Lamport timestamp of this peer.</summary>
        public ulong GetLamportTimestamp() => _lamportTimestamp;

        public bool Equals(Peer other)
            => other != null && Util.BytesEqual(PublicKey.KeyToBin(), other.PublicKey.KeyToBin());

        public override bool Equals(object obj) => obj is Peer other && Equals(other);

        public override int GetHashCode()
        {
            // py-ipv8: unpack(">Q", self.mid[:8]) — first 8 bytes of the mid, big-endian.
            var hash = 0;
            for (var i = 0; i < 8; i++)
            {
                hash = (hash << 8) | Mid[i];
            }
            return hash;
        }

        public override string ToString()
        {
            var mid64 = Convert.ToBase64String(Mid);
            return $"Peer<{Address.Host}:{Address.Port}, {mid64}>";
        }
    }
}
