// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Messaging;

namespace IPv8.PeerDiscovery
{
    /// <summary>A walkable address: (introduced_by, services, new_style) (py-ipv8 WalkableAddress).</summary>
    public readonly struct WalkableAddress
    {
        public readonly byte[] IntroducedBy;
        public readonly byte[] Services;
        public readonly bool NewStyle;

        public WalkableAddress(byte[] introducedBy, byte[] services, bool newStyle)
        {
            IntroducedBy = introducedBy ?? Util.EmptyBytes;
            Services = services;
            NewStyle = newStyle;
        }
    }

    /// <summary>
    /// An observer that gets called back when a peer is added or removed from the Network
    /// (py-ipv8 PeerObserver).
    /// </summary>
    public interface IPeerObserver
    {
        void OnPeerAdded(Peer peer);

        void OnPeerRemoved(Peer peer);
    }

    /// <summary>
    /// A class that stores Peer instances and their various states and interconnections
    /// (minimal port of ipv8/peerdiscovery/network.py).
    /// </summary>
    public class Network
    {
        private readonly Dictionary<Address, WalkableAddress> _allAddresses
            = new Dictionary<Address, WalkableAddress>();
        private readonly HashSet<Peer> _verifiedPeers = new HashSet<Peer>();
        private readonly Dictionary<byte[], Peer> _verifiedByPublicKeyBin
            = new Dictionary<byte[], Peer>(ByteArrayEqualityComparer.Instance);
        private readonly Dictionary<byte[], HashSet<byte[]>> _servicesPerPeer
            = new Dictionary<byte[], HashSet<byte[]>>(ByteArrayEqualityComparer.Instance);
        private readonly Dictionary<byte[], Overlay> _serviceOverlays
            = new Dictionary<byte[], Overlay>(ByteArrayEqualityComparer.Instance);
        private readonly Dictionary<Address, Peer> _reverseIpLookup = new Dictionary<Address, Peer>();
        private readonly Dictionary<Peer, List<Address>> _reverseIntroLookup
            = new Dictionary<Peer, List<Address>>();
        private readonly Dictionary<byte[], List<Peer>> _reverseServiceLookup
            = new Dictionary<byte[], List<Peer>>(ByteArrayEqualityComparer.Instance);
        private readonly List<IPeerObserver> _peerObservers = new List<IPeerObserver>();
        private readonly object _graphLock = new object();

        public Network()
        {
            ReverseIpCacheSize = 500;
            ReverseIntroCacheSize = 500;
            ReverseServiceCacheSize = 500;
        }

        public int ReverseIpCacheSize { get; set; }

        public int ReverseIntroCacheSize { get; set; }

        public int ReverseServiceCacheSize { get; set; }

        /// <summary>All known IP:port addresses, mapped to (introduction peer, services, new_style).</summary>
        public IReadOnlyDictionary<Address, WalkableAddress> AllAddresses => _allAddresses;

        /// <summary>All verified Peer objects (Peer.address must be in _all_addresses).</summary>
        public IReadOnlyCollection<Peer> VerifiedPeers => _verifiedPeers;

        /// <summary>Peers we should not add to the network (e.g., bootstrap peers), by address.</summary>
        public List<Address> Blacklist { get; } = new List<Address>();

        /// <summary>Peers we should not add to the network (e.g., bootstrap peers), by mid.</summary>
        public List<byte[]> BlacklistMids { get; } = new List<byte[]>();

        /// <summary>Check if an address supports new-style introduction requests and responses.</summary>
        public bool IsNewStyle(Address address)
        {
            lock (_graphLock)
            {
                return _allAddresses.TryGetValue(address, out var walkable) && walkable.NewStyle;
            }
        }

        /// <summary>A peer has introduced us to another IP address.</summary>
        public void DiscoverAddress(Peer peer, Address address, byte[] service = null, bool newStyle = false)
        {
            lock (_graphLock)
            {
                if (Blacklist.Contains(address))
                {
                    AddVerifiedPeer(peer);
                    return;
                }
                var knownParent = _allAddresses.TryGetValue(address, out var walkable)
                                  && _verifiedByPublicKeyBin.ContainsKey(walkable.IntroducedBy);
                if (!_allAddresses.ContainsKey(address) || !knownParent)
                {
                    // This is a new address, or our previous parent has been removed.
                    _allAddresses[address] = new WalkableAddress(peer.PublicKey.KeyToBin(), service, newStyle);
                    if (!_reverseIntroLookup.TryGetValue(peer, out var introCache))
                    {
                        _reverseIntroLookup[peer] = introCache = new List<Address>();
                        if (_reverseIntroLookup.Count > ReverseIntroCacheSize)
                        {
                            DropOldest(_reverseIntroLookup);
                        }
                    }
                    introCache.Add(address);
                }
                AddVerifiedPeer(peer);
            }
        }

        /// <summary>A peer has advertised some services he can use.</summary>
        public void DiscoverServices(Peer peer, IEnumerable<byte[]> services)
        {
            lock (_graphLock)
            {
                var keyMaterial = peer.PublicKey.KeyToBin();
                if (!_servicesPerPeer.TryGetValue(keyMaterial, out var known))
                {
                    _servicesPerPeer[keyMaterial] = new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
                    known = _servicesPerPeer[keyMaterial];
                }
                foreach (var service in services)
                {
                    known.Add(service);
                    // Maintain the reverse service cache, mirroring py-ipv8.
                    if (_reverseServiceLookup.TryGetValue(service, out var serviceCache))
                    {
                        serviceCache.RemoveAll(candidate => candidate.Equals(peer));
                        _verifiedByPublicKeyBin.TryGetValue(keyMaterial, out var verifiedPeer);
                        serviceCache.Add(verifiedPeer ?? peer);
                        if (_reverseServiceLookup.Count > ReverseServiceCacheSize)
                        {
                            DropOldest(_reverseServiceLookup);
                        }
                    }
                }
            }
        }

        /// <summary>The holepunching layer has a new peer for us.</summary>
        public void AddVerifiedPeer(Peer peer)
        {
            if (ContainsBytes(BlacklistMids, peer.Mid))
            {
                return;
            }
            lock (_graphLock)
            {
                // This may just be an address update
                if (_verifiedByPublicKeyBin.TryGetValue(peer.PublicKey.KeyToBin(), out var known))
                {
                    foreach (var pair in peer.Addresses)
                    {
                        // py-ipv8: known.addresses.update(peer.addresses) — then the preferred
                        // address is refreshed by adding the same addresses to the known peer.
                        if (!known.Addresses.ContainsKey(pair.Key)
                            || known.Addresses[pair.Key].Type != pair.Value.Type
                            || known.Addresses[pair.Key].Port != pair.Value.Port
                            || known.Addresses[pair.Key].Host != pair.Value.Host)
                        {
                            known.AddAddress(pair.Value);
                        }
                    }
                    return;
                }
                var anyKnown = peer.Addresses.Values.Any(address => _allAddresses.ContainsKey(address));
                if (anyKnown)
                {
                    if (!_verifiedPeers.Contains(peer))
                    {
                        _verifiedPeers.Add(peer);
                        _verifiedByPublicKeyBin[peer.PublicKey.KeyToBin()] = peer;
                        NotifyPeerAdded(peer);
                    }
                }
                else if (peer.Addresses.Values.All(address => !Blacklist.Contains(address)))
                {
                    foreach (var address in peer.Addresses.Values)
                    {
                        if (!_allAddresses.ContainsKey(address))
                        {
                            _allAddresses[address] = new WalkableAddress(Util.EmptyBytes, null, false);
                        }
                    }
                    if (!_verifiedPeers.Contains(peer))
                    {
                        _verifiedPeers.Add(peer);
                        _verifiedByPublicKeyBin[peer.PublicKey.KeyToBin()] = peer;
                        NotifyPeerAdded(peer);
                    }
                }
            }
        }

        /// <summary>Register an overlay to provide a certain service id.</summary>
        public void RegisterServiceProvider(byte[] serviceId, Overlay overlay)
        {
            lock (_graphLock)
            {
                _serviceOverlays[serviceId] = overlay;
            }
        }

        /// <summary>Get peers which support a certain service.</summary>
        public List<Peer> GetPeersForService(byte[] serviceId)
        {
            lock (_graphLock)
            {
                List<Peer> serviceCache;
                if (_reverseServiceLookup.TryGetValue(serviceId, out serviceCache))
                {
                    _reverseServiceLookup.Remove(serviceId);
                }
                else
                {
                    serviceCache = null;
                }
                var outPeers = new List<Peer>();
                if (serviceCache == null)
                {
                    foreach (var peer in _verifiedPeers)
                    {
                        var keyMaterial = peer.PublicKey.KeyToBin();
                        if (_servicesPerPeer.TryGetValue(keyMaterial, out var services)
                            && ContainsBytes(services.ToList(), serviceId))
                        {
                            outPeers.Add(peer);
                        }
                    }
                }
                else
                {
                    foreach (var peer in serviceCache)
                    {
                        var keyMaterial = peer.PublicKey.KeyToBin();
                        if (_verifiedPeers.Contains(peer)
                            && _servicesPerPeer.TryGetValue(keyMaterial, out var services)
                            && ContainsBytes(services.ToList(), serviceId))
                        {
                            outPeers.Add(peer);
                        }
                    }
                }
                _reverseServiceLookup[serviceId] = outPeers;
                if (_reverseServiceLookup.Count > ReverseServiceCacheSize)
                {
                    DropOldest(_reverseServiceLookup);
                }
                return outPeers;
            }
        }

        /// <summary>Get the known services supported by a peer.</summary>
        public HashSet<byte[]> GetServicesForPeer(Peer peer)
        {
            lock (_graphLock)
            {
                if (_servicesPerPeer.TryGetValue(peer.PublicKey.KeyToBin(), out var services))
                {
                    return services;
                }
                return new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
            }
        }

        /// <summary>Get all addresses ready to be walked to.</summary>
        public List<Address> GetWalkableAddresses(byte[] serviceId = null, bool oldStyle = false)
        {
            lock (_graphLock)
            {
                var verified = new List<Address>();
                if (serviceId != null)
                {
                    foreach (var peer in GetPeersForService(serviceId))
                    {
                        verified.AddRange(peer.Addresses.Values);
                    }
                }
                else
                {
                    foreach (var peer in _verifiedPeers)
                    {
                        verified.AddRange(peer.Addresses.Values);
                    }
                }
                var verifiedSet = new HashSet<Address>(verified);
                var outAddresses = _allAddresses.Keys.Where(address => !verifiedSet.Contains(address)).ToList();
                if (serviceId != null)
                {
                    var newOut = new List<Address>();
                    foreach (var address in outAddresses)
                    {
                        var walkable = _allAddresses[address];
                        if (oldStyle && walkable.NewStyle)
                        {
                            continue;
                        }
                        // py-ipv8 quirk: services_per_peer.get(intro_peer, set()) returns the STORED
                        // set, and adding the walkable service mutates it in place.
                        var services = _servicesPerPeer.TryGetValue(walkable.IntroducedBy, out var knownServices)
                            ? knownServices
                            : new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
                        if (walkable.Services != null)
                        {
                            services.Add(walkable.Services);
                        }
                        if (ContainsBytes(services.ToList(), serviceId))
                        {
                            newOut.Add(address);
                        }
                    }
                    outAddresses = newOut;
                }
                return outAddresses;
            }
        }

        /// <summary>Get a verified Peer by its IP address.</summary>
        public Peer GetVerifiedByAddress(Address address)
        {
            lock (_graphLock)
            {
                if (_reverseIpLookup.TryGetValue(address, out var cachedPeer) && cachedPeer != null)
                {
                    // Refresh the peer in the cache.
                    _reverseIpLookup.Remove(address);
                    _reverseIpLookup[address] = cachedPeer;
                    return cachedPeer;
                }
                foreach (var p in _verifiedPeers)
                {
                    if (p.Addresses.Values.Contains(address))
                    {
                        _reverseIpLookup[address] = p;
                        if (_reverseIpLookup.Count > ReverseIpCacheSize)
                        {
                            DropOldest(_reverseIpLookup);
                        }
                        return p;
                    }
                }
                return null;
            }
        }

        /// <summary>Get a verified Peer by its public key binary representation.</summary>
        public Peer GetVerifiedByPublicKeyBin(byte[] publicKeyBin)
        {
            lock (_graphLock)
            {
                return _verifiedByPublicKeyBin.TryGetValue(publicKeyBin, out var peer) ? peer : null;
            }
        }

        /// <summary>Get the addresses introduced to us by a certain peer.</summary>
        public List<Address> GetIntroductionsFrom(Peer peer)
        {
            lock (_graphLock)
            {
                if (_reverseIntroLookup.TryGetValue(peer, out var introductions))
                {
                    return introductions;
                }
                var publicKeyBin = peer.PublicKey.KeyToBin();
                introductions = _allAddresses
                    .Where(pair => Util.BytesEqual(pair.Value.IntroducedBy, publicKeyBin))
                    .Select(pair => pair.Key)
                    .ToList();
                _reverseIntroLookup[peer] = introductions;
                if (_reverseIntroLookup.Count > ReverseIntroCacheSize)
                {
                    DropOldest(_reverseIntroLookup);
                }
                return introductions;
            }
        }

        /// <summary>Remove all walkable addresses and verified peers using a certain IP address.</summary>
        public void RemoveByAddress(Address address)
        {
            lock (_graphLock)
            {
                _allAddresses.Remove(address);
                // py-ipv8: keep the peers that do NOT use this address; peers that DO use it are
                // removed, and (as a side effect of the lazy `or` in the set comprehension) their
                // services_per_peer entry is popped.
                var removedPeers = new List<Peer>();
                foreach (var peer in _verifiedPeers.ToList())
                {
                    if (peer.Addresses.Values.Contains(address))
                    {
                        _servicesPerPeer.Remove(peer.PublicKey.KeyToBin());
                        removedPeers.Add(peer);
                    }
                }
                foreach (var peer in removedPeers)
                {
                    _verifiedPeers.Remove(peer);
                    NotifyPeerRemoved(peer);
                }
            }
        }

        /// <summary>Remove a verified peer.</summary>
        public void RemovePeer(Peer peer)
        {
            lock (_graphLock)
            {
                foreach (var address in peer.Addresses.Values)
                {
                    _allAddresses.Remove(address);
                }
                if (_verifiedPeers.Remove(peer))
                {
                    NotifyPeerRemoved(peer);
                }
                _verifiedByPublicKeyBin.Remove(peer.PublicKey.KeyToBin());
                _servicesPerPeer.Remove(peer.PublicKey.KeyToBin());
            }
        }

        /// <summary>Add a peer observer to notify about peer addition and removal.</summary>
        public void AddPeerObserver(IPeerObserver observer)
        {
            lock (_graphLock)
            {
                _peerObservers.Add(observer);
            }
        }

        /// <summary>Remove a registered peer observer.</summary>
        public void RemovePeerObserver(IPeerObserver observer)
        {
            lock (_graphLock)
            {
                _peerObservers.Remove(observer);
            }
        }

        /// <summary>Get a snapshot of all verified peers (py-ipv8 Network.snapshot).</summary>
        public byte[] Snapshot()
        {
            lock (_graphLock)
            {
                var serializer = new Messaging.Serializer();
                var parts = new List<byte[]>();
                foreach (var peer in _verifiedPeers)
                {
                    if (!(peer.Address.Host == "0.0.0.0" && peer.Address.Port == 0))
                    {
                        parts.Add(serializer.Pack("address", peer.Address));
                    }
                }
                return Util.Concat(parts.ToArray());
            }
        }

        /// <summary>
        /// Load a snapshot into the walkable addresses. This method will prefer returning no peers
        /// over throwing an exception (py-ipv8 Network.load_snapshot).
        /// </summary>
        public void LoadSnapshot(byte[] snapshot)
        {
            snapshot ??= Util.EmptyBytes;
            var snaplen = snapshot.Length;
            var offset = 0;
            var serializer = new Messaging.Serializer();
            lock (_graphLock)
            {
                while (offset < snaplen)
                {
                    var previousOffset = offset;
                    Address address = default;
                    try
                    {
                        var (value, newOffset) = serializer.Unpack("address", snapshot, offset);
                        address = (Address)value;
                        offset = newOffset;
                        _allAddresses[address] = new WalkableAddress(Util.EmptyBytes, null, false);
                    }
                    catch (Exception)
                    {
                        if (offset <= previousOffset)
                        {
                            // We got stuck, or even went back in time.
                            Console.Error.WriteLine("Snapshot loading got stuck! Aborting snapshot load.");
                            break;
                        }
                        Console.Error.WriteLine($"Snapshot failed on entry, skipping {address}!");
                    }
                }
            }
        }

        private void NotifyPeerAdded(Peer peer)
        {
            foreach (var observer in _peerObservers)
            {
                observer.OnPeerAdded(peer);
            }
        }

        private void NotifyPeerRemoved(Peer peer)
        {
            foreach (var observer in _peerObservers)
            {
                observer.OnPeerRemoved(peer);
            }
        }

        private static void DropOldest<K, V>(Dictionary<K, V> dictionary)
        {
            K oldest = default;
            var found = false;
            foreach (var key in dictionary.Keys)
            {
                oldest = key;
                found = true;
                break;
            }
            if (found)
            {
                dictionary.Remove(oldest);
            }
        }

        private static bool ContainsBytes(IEnumerable<byte[]> haystack, byte[] needle)
        {
            foreach (var item in haystack)
            {
                if (Util.BytesEqual(item, needle))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
