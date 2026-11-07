// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/provider.py: wrapper around the DHTDiscoveryCommunity used to discover
// introduction points for hidden services. The full IntroductionPoint lives in the (much larger)
// tunnel module (out of Phase 1b scope); we port the provider-facing data class minimally.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IPv8.Messaging;

namespace IPv8.Dht
{
    /// <summary>Tunnel-module constants needed by the provider (py-ipv8 tunnel.py).</summary>
    public static class TunnelConstants
    {
        /// <summary>Introduction point source flag for the DHT (tunnel.py PEER_SOURCE_DHT).</summary>
        public const int PeerSourceDht = 1;
    }

    /// <summary>
    /// Minimal introduction point record carrying the fields the DHT provider uses (the tunnel
    /// module's IntroductionPoint, Phase 2 will port the full class).
    /// </summary>
    public class IntroductionPoint
    {
        public Peer Peer;
        public byte[] SeederPk;
        public int Source;
        public int LastSeen;

        public IntroductionPoint(Peer peer, byte[] seederPk, int source, int lastSeen)
        {
            Peer = peer;
            SeederPk = seederPk;
            Source = source;
            LastSeen = lastSeen;
        }
    }

    /// <summary>
    /// Payload to pack an introduction point's address, most recent time of response, public key
    /// and associated seeder public key (py-ipv8 DHTIntroPointPayload).
    /// </summary>
    public sealed class DhtIntroPointPayload : Payload
    {
        public Address Address;
        public int LastSeen;
        public byte[] IntroPk;
        public byte[] SeederPk;

        public DhtIntroPointPayload()
        {
        }

        public DhtIntroPointPayload(Address address, int lastSeen, byte[] introPk, byte[] seederPk)
        {
            Address = address;
            LastSeen = lastSeen;
            IntroPk = introPk;
            SeederPk = seederPk;
        }

        public override IReadOnlyList<object> FormatList
            => new object[] { "ip_address", "I", "varlenH", "varlenH" };

        public override IList<PackEntry> ToPackList()
            => new List<PackEntry>
            {
                new PackEntry("ip_address", Address),
                new PackEntry("I", LastSeen),
                new PackEntry("varlenH", IntroPk),
                new PackEntry("varlenH", SeederPk),
            };

        public override void FromUnpackList(object[] values)
        {
            Address = (Address)values[0];
            LastSeen = ToInt(values[1]);
            IntroPk = (byte[])values[2];
            SeederPk = (byte[])values[3];
        }
    }

    /// <summary>
    /// This class is a wrapper around the DHTDiscoveryCommunity and is used to discover introduction
    /// points for hidden services (py-ipv8 DHTCommunityProvider).
    /// </summary>
    public class DhtCommunityProvider
    {
        public readonly DhtDiscoveryCommunity DhtCommunity;
        public readonly int Port;

        public DhtCommunityProvider(DhtDiscoveryCommunity dhtCommunity, int port)
        {
            DhtCommunity = dhtCommunity;
            Port = port;
        }

        /// <summary>
        /// Attempt to find and connect to the given mid. If provided, the given peer will be pinged
        /// first to potentially avoid an expensive lookup.
        /// </summary>
        public async Task PeerLookupAsync(byte[] mid, Peer peer = null)
        {
            try
            {
                await DhtCommunity.ConnectPeerAsync(mid, peer);
            }
            catch (DhtError e)
            {
                Console.Error.WriteLine(
                    $"Failed to connect {Serializer.Hexlify(mid)} using the DHTCommunity (error: {e.Message})");
            }
        }

        /// <summary>
        /// Attempt to find introduction points for the given info hash (SHA-1 hash). Returns null
        /// when the lookup failed.
        /// </summary>
        public async Task<(byte[] InfoHash, List<IntroductionPoint> Results)> LookupAsync(byte[] infoHash)
        {
            object raw;
            try
            {
                raw = await DhtCommunity.FindValuesAsync(infoHash);
            }
            catch (DhtError e)
            {
                Console.Error.WriteLine(
                    $"Failed to lookup {Serializer.Hexlify(infoHash)} on the DHTCommunity (error: {e.Message})");
                return default;
            }

            var values = (List<(byte[] Data, byte[] PublicKey)>)raw;
            var results = new List<IntroductionPoint>();
            foreach (var (value, _) in values)
            {
                try
                {
                    var payload = DhtCommunity.Serializer.UnpackSerializableAs<DhtIntroPointPayload>(value);
                    var introPeer = new Peer(Util.Concat(Keyvault.LibNaclPublicKey.Prefix, payload.IntroPk),
                                             payload.Address);
                    results.Add(new IntroductionPoint(
                        introPeer,
                        Util.Concat(Keyvault.LibNaclPublicKey.Prefix, payload.SeederPk),
                        TunnelConstants.PeerSourceDht,
                        payload.LastSeen));
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(
                        $"Error during lookup {Serializer.Hexlify(infoHash)} on the DHTCommunity (error: {e.Message})");
                }
            }
            return (infoHash, results);
        }

        /// <summary>Announce the given introduction point to serve the given info hash (SHA-1).</summary>
        public async Task AnnounceAsync(byte[] infoHash, IntroductionPoint introPoint)
        {
            // We strip away the LibNaCLPK part of the public key to avoid going over the DHT size
            // limit.
            var value = DhtCommunity.Serializer.PackSerializable(new DhtIntroPointPayload(
                introPoint.Peer.Address,
                introPoint.LastSeen,
                Util.SliceFrom(introPoint.Peer.PublicKey.KeyToBin(), 10),
                Util.SliceFrom(introPoint.SeederPk, 10)));

            try
            {
                await DhtCommunity.StoreValueAsync(infoHash, value);
            }
            catch (DhtError e)
            {
                Console.Error.WriteLine(
                    $"Failed to announce {Serializer.Hexlify(infoHash)} to the DHTCommunity (error: {e.Message})");
            }
        }
    }
}
