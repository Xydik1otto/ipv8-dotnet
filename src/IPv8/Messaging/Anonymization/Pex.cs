// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>PEX protocol version (pex.py::PEX_VERSION).</summary>
    public static class PexConstants
    {
        public const int PexVersion = 1;
    }

    /// <summary>Settings for the PexCommunity (pex.py::PexSettings).</summary>
    public sealed class PexSettings : CommunitySettings
    {
        public byte[] InfoHash { get; set; }
    }

    /// <summary>
    /// New on-the-fly overlay for the PEX protocol (pex.py::PexCommunity).
    /// </summary>
    public sealed class PexCommunity : Community
    {
        public const int PexVersion = PexConstants.PexVersion;

        /// <summary>
        /// Introduction points, newest first (mirrors py deque(maxlen=20): index 0 is
        /// the left/most-recent end, the right end (last index) holds the oldest entry).
        /// </summary>
        private readonly List<IntroductionPoint> _introPoints = new List<IntroductionPoint>();

        public IReadOnlyList<IntroductionPoint> IntroPoints => _introPoints;

        private readonly List<byte[]> _introPointsFor = new List<byte[]>();

        public PexCommunity(PexSettings settings)
            : base(settings, ComputeCommunityId(settings.InfoHash))
        {
        }

        private static byte[] ComputeCommunityId(byte[] infoHash)
        {
            // int.from_bytes(infohash, "big") + PEX_VERSION, packed back as 20 bytes big-endian.
            // (BigInteger byte-array ctor is little-endian; pad a zero byte to stay unsigned.)
            var le = new byte[infoHash.Length + 1];
            for (var i = 0; i < infoHash.Length; i++)
            {
                le[i] = infoHash[infoHash.Length - 1 - i];
            }
            var asInt = new BigInteger(le) + PexVersion;

            var leBytes = asInt.ToByteArray(); // little-endian, sign byte included
            if (leBytes.Length > 1 && leBytes[leBytes.Length - 1] == 0)
            {
                Array.Resize(ref leBytes, leBytes.Length - 1); // drop the sign byte
            }
            var result = new byte[20];
            for (var i = 0; i < Math.Min(leBytes.Length, result.Length); i++)
            {
                result[result.Length - 1 - i] = leBytes[i];
            }
            return result;
        }

        /// <summary>
        /// Get a list of the most recent introduction points that were discovered using
        /// PexCommunity.
        /// </summary>
        public List<IntroductionPoint> GetIntroPoints()
        {
            // Remove old introduction points
            var now = Util.NowEpoch();
            while (_introPoints.Count > 0 && _introPoints[_introPoints.Count - 1].LastSeen + 300 < now)
            {
                _introPoints.RemoveAt(_introPoints.Count - 1);
            }

            var myPeer = new Peer(MyPeer.Key, MyEstimatedWan);
            var result = new List<IntroductionPoint>(_introPoints);
            foreach (var seederPk in _introPointsFor)
            {
                result.Add(new IntroductionPoint(myPeer, seederPk, Tunnel.PeerSourcePex));
            }
            return result;
        }

        /// <summary>Start announcing yourself as an introduction point for a certain seeder.</summary>
        public void StartAnnounce(byte[] seederPk)
        {
            foreach (var existing in _introPointsFor)
            {
                if (Util.BytesEqual(existing, seederPk))
                {
                    return;
                }
            }
            _introPointsFor.Add(seederPk);
        }

        /// <summary>Stop announcing yourself as an introduction point for a certain seeder.</summary>
        public void StopAnnounce(byte[] seederPk)
        {
            for (var i = 0; i < _introPointsFor.Count; i++)
            {
                if (Util.BytesEqual(_introPointsFor[i], seederPk))
                {
                    _introPointsFor.RemoveAt(i);
                    return;
                }
            }
        }

        /// <summary>Check if we have introduction points left.</summary>
        public bool IsDone => _introPointsFor.Count == 0;

        /// <summary>
        /// Unpack any introduction points piggybacked onto the introduction requests and
        /// responses.
        /// </summary>
        public void ProcessExtraBytes(Peer peer, byte[] extraBytes)
        {
            if (extraBytes == null || extraBytes.Length == 0)
            {
                return;
            }

            foreach (var seederPk in UnpackVarlenHList(extraBytes))
            {
                var ip = new IntroductionPoint(peer, seederPk, Tunnel.PeerSourcePex);
                var existingIndex = _introPoints.IndexOf(ip);
                if (existingIndex >= 0)
                {
                    // Remove first to put introduction point at front of the deque.
                    _introPoints.RemoveAt(existingIndex);
                }
                // Add new introduction point (with up-to-date last_seen)
                _introPoints.Insert(0, ip);
                if (_introPoints.Count > 20)
                {
                    _introPoints.RemoveAt(_introPoints.Count - 1);
                }
            }
        }

        protected override void IntroductionRequestCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                            Payload payload)
        {
            ProcessExtraBytes(peer, GetExtraBytes(payload));
        }

        protected override void IntroductionResponseCallback(Peer peer, GlobalTimeDistributionPayload dist,
                                                             Payload payload)
        {
            ProcessExtraBytes(peer, GetExtraBytes(payload));
        }

        private static byte[] GetExtraBytes(Payload payload)
        {
            return payload switch
            {
                IntroductionRequestPayload p => p.ExtraBytes,
                NewIntroductionRequestPayload p => p.ExtraBytes,
                IntroductionResponsePayload p => p.ExtraBytes,
                NewIntroductionResponsePayload p => p.ExtraBytes,
                _ => null
            };
        }

        public override byte[] CreateIntroductionRequest(Address socketAddress, byte[] extraBytes = null,
                                                    bool newStyle = false, byte[] prefix = null)
        {
            // Piggyback introduction points onto introduction requests.
            return base.CreateIntroductionRequest(socketAddress, GetSeederPks(), newStyle);
        }

        public override byte[] CreateIntroductionResponse(Address lanSocketAddress, Address socketAddress,
                                                     long identifier, Peer introduction = null,
                                                     byte[] extraBytes = null, byte[] prefix = null,
                                                     bool newStyle = false)
        {
            // Piggyback introduction points onto introduction responses.
            return base.CreateIntroductionResponse(lanSocketAddress, socketAddress, identifier,
                                                   introduction, GetSeederPks(), newStyle: newStyle);
        }

        /// <summary>Send a ping messages to a peer.</summary>
        public void SendPing(Peer peer)
        {
            SendIntroductionRequest(peer);
        }

        /// <summary>Pack the known seeder public keys (up to 10) as bytes.</summary>
        public byte[] GetSeederPks()
        {
            var all = new List<byte[]>(_introPointsFor);
            // random.sample equivalent: shuffle and take the first min(len, 10).
            var rng = new Random();
            for (var i = all.Count - 1; i > 0; i--)
            {
                var j = rng.Next(i + 1);
                (all[i], all[j]) = (all[j], all[i]);
            }
            var pks = all.GetRange(0, Math.Min(all.Count, 10));
            return PackVarlenHList(pks);
        }

        /// <summary>Pack a list of byte strings as varlenH-list ( '!H' length prefix per item ).</summary>
        internal static byte[] PackVarlenHList(IReadOnlyList<byte[]> items)
        {
            var size = 0;
            foreach (var item in items)
            {
                size += 2 + item.Length;
            }
            var result = new byte[size];
            var offset = 0;
            foreach (var item in items)
            {
                result[offset] = (byte)((item.Length >> 8) & 0xFF);
                result[offset + 1] = (byte)(item.Length & 0xFF);
                Array.Copy(item, 0, result, offset + 2, item.Length);
                offset += 2 + item.Length;
            }
            return result;
        }

        /// <summary>Unpack a varlenH-list byte string into its items.</summary>
        internal static List<byte[]> UnpackVarlenHList(byte[] data)
        {
            var result = new List<byte[]>();
            var offset = 0;
            while (offset + 2 <= data.Length)
            {
                var length = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                offset += 2;
                if (offset + length > data.Length)
                {
                    break;
                }
                var item = new byte[length];
                Array.Copy(data, offset, item, 0, length);
                offset += length;
                result.Add(item);
            }
            return result;
        }
    }
}
