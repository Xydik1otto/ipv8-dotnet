// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet
{
    /// <summary>A chunk of an attestation, keyed by its sequence number (py attestation_map entry).</summary>
    public sealed class AttestationChunk
    {
        public readonly int SequenceNumber;
        public readonly byte[] Data;

        public AttestationChunk(int sequenceNumber, byte[] data)
        {
            SequenceNumber = sequenceNumber;
            Data = data;
        }

        public override bool Equals(object obj)
            => obj is AttestationChunk other && SequenceNumber == other.SequenceNumber
                   && Util.BytesEqual(Data, other.Data);

        public override int GetHashCode()
            => Util.BytesHashCode(Data) * 31 + SequenceNumber;
    }

    /// <summary>
    /// Cache tied to a hash (port of ipv8/attestation/wallet/caches.py::HashCache).
    /// </summary>
    public abstract class HashCache : NumberCache
    {
        protected HashCache(RequestCache requestCache, string prefix, byte[] cacheHash, string idFormat)
            : base(requestCache, IdFromHash(prefix, cacheHash).Prefix, IdFromHash(prefix, cacheHash).Number)
        {
            IdFormat = idFormat;
        }

        /// <summary>Get a cache prefix and identifier from a hash (py id_from_hash).</summary>
        public static (string Prefix, int Number) IdFromHash(string prefix, byte[] cacheHash)
        {
            // DEVIATION (documented): py derives the cache number as the full big-endian integer
            // of the hash (arbitrary precision). The C# NumberCache carries a 32-bit number, so
            // the port keeps the full hash inside the (internal, non-wire) prefix instead.
            // Semantics are preserved: identical hashes map to identical cache identifiers and
            // distinct hashes collide only on a SHA-1-level collision.
            return (prefix + ":" + Util.Hex(cacheHash), 0);
        }

        public string IdFormat { get; }
    }

    /// <summary>
    /// Cache tied to a peer (mid) (port of ipv8/attestation/wallet/caches.py::PeerCache).
    /// </summary>
    public abstract class PeerCache : HashCache
    {
        protected PeerCache(RequestCache requestCache, string prefix, byte[] mid, string idFormat)
            : base(requestCache, prefix, mid, idFormat)
        {
        }

        /// <summary>Get a cache prefix and identifier from an mid (py id_from_address).</summary>
        public static (string Prefix, int Number) IdFromAddress(string prefix, byte[] mid)
            => HashCache.IdFromHash(prefix, mid);

        public override double TimeoutDelay => 120.0;
    }

    /// <summary>
    /// Pending attestation transfer, after request for attestation verification
    /// (port of ipv8/attestation/wallet/caches.py::ReceiveAttestationVerifyCache).
    /// </summary>
    public sealed class ReceiveAttestationVerifyCache : HashCache
    {
        public ReceiveAttestationVerifyCache(AttestationCommunity community, byte[] cacheHash,
                                             string idFormat)
            : base(community.RequestCache, "receive-verify-attestation", cacheHash, idFormat)
        {
            AttestationMap = new HashSet<AttestationChunk>();
        }

        /// <summary>The (sequence_number, data) chunks received so far.</summary>
        public ISet<AttestationChunk> AttestationMap { get; }

        public override void OnTimeout()
            => Console.Error.WriteLine("ReceiveAttestationVerify timed out!");

        public override double TimeoutDelay => 120.0;
    }

    /// <summary>
    /// Pending attestation transfer, after request for a new attestation. Stores the one-time
    /// key for this attribute attestation
    /// (port of ipv8/attestation/wallet/caches.py::ReceiveAttestationRequestCache).
    /// </summary>
    public sealed class ReceiveAttestationRequestCache : PeerCache
    {
        public ReceiveAttestationRequestCache(AttestationCommunity community, byte[] mid,
                                              BonehPrivateKey key, string name, string idFormat)
            : base(community.RequestCache, "receive-request-attestation", mid, idFormat)
        {
            AttestationMap = new HashSet<AttestationChunk>();
            Key = key;
            Name = name;
        }

        /// <summary>The (sequence_number, data) chunks received so far.</summary>
        public ISet<AttestationChunk> AttestationMap { get; }

        public BonehPrivateKey Key { get; }

        public string Name { get; }

        public override void OnTimeout()
            => Console.Error.WriteLine("ReceiveAttestation timed out!");
    }

    /// <summary>
    /// Pending attestation verification, stores expected relmap, hashed challenges and completion
    /// callback (port of ipv8/attestation/wallet/caches.py::ProvingAttestationCache).
    /// </summary>
    public sealed class ProvingAttestationCache : HashCache
    {
        public ProvingAttestationCache(AttestationCommunity community, byte[] cacheHash, string idFormat,
                                       object publicKey = null,
                                       Action<byte[], Dictionary<string, object>> onComplete = null)
            : base(community.RequestCache, "proving-attestation", cacheHash, idFormat)
        {
            Hash = cacheHash;
            PublicKey = publicKey;
            RelativityMap = new Dictionary<string, object>();
            HashedChallenges = new List<byte[]>();
            Challenges = new List<byte[]>();
            AttestationCallbacks = onComplete ?? ((_, _) => { });
        }

        public byte[] Hash { get; }

        public object PublicKey { get; set; }

        public Dictionary<string, object> RelativityMap { get; set; }

        public List<byte[]> HashedChallenges { get; set; }

        public List<byte[]> Challenges { get; set; }

        public Action<byte[], Dictionary<string, object>> AttestationCallbacks { get; }

        public override void OnTimeout()
            => Console.Error.WriteLine("ProvingAttestation timed out!");

        public override double TimeoutDelay => 120.0;
    }

    /// <summary>
    /// Single pending challenge for a ProvingAttestationCache
    /// (port of ipv8/attestation/wallet/caches.py::PendingChallengeCache).
    /// </summary>
    public sealed class PendingChallengeCache : HashCache
    {
        public PendingChallengeCache(AttestationCommunity community, byte[] cacheHash,
                                     ProvingAttestationCache provingCache, string idFormat,
                                     int honestyCheck = -1)
            : base(community.RequestCache, "proving-hash", cacheHash, idFormat)
        {
            ProvingCache = provingCache;
            HonestyCheck = honestyCheck;
        }

        public ProvingAttestationCache ProvingCache { get; }

        public int HonestyCheck { get; }

        public override void OnTimeout()
            => Console.Error.WriteLine("PendingChallenge timed out!");
    }
}
