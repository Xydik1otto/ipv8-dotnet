// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IPv8.Attestation.Schema;
using IPv8.Database;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;
using IPv8.PeerDiscovery;
using IPv8.Wallet.BonehExact;
using IPv8.Wallet.PengBaoOrange;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;
    using IdentityAlgorithm = IPv8.Wallet.Cryptography.IdentityAlgorithm;

    /// <summary>Settings for the Attestation community (py AttestationSettings).</summary>
    public class AttestationSettings : CommunitySettings
    {
        public AttestationSettings(byte[] communityId, Peer myPeer, Endpoint endpoint, Network network,
                                   bool anonymize = false)
            : base(communityId, myPeer, endpoint, network, anonymize: anonymize)
        {
        }

        public string WorkingDirectory { get; set; } = "";

        public string DbName { get; set; } = "attestations";
    }

    /// <summary>
    /// Community for sharing Attestations. Note that the logic for giving out Attestations is in
    /// the identity chain
    /// (port of ipv8/attestation/wallet/community.py::AttestationCommunity).
    /// </summary>
    public class AttestationCommunity : Community
    {
        public static readonly byte[] FixedCommunityId = Util.Unhex("b42c93d167a0fc4a0843f917d4bf1e9ebb340ec4");

        private readonly object _receiveBlockLock = new object();

        public readonly SchemaManager SchemaManager;

        /// <summary>
        /// Callback providing the value to attest: f(peer, attribute_name, metadata) → value bytes
        /// or null (no attestation). py returns a Future.
        /// </summary>
        public Func<Peer, string, Dictionary<string, string>, Task<byte[]>> AttestationRequestCallback;

        /// <summary>Called when an Attestation has been made for another peer.</summary>
        public Action<Peer, string, byte[], string, Peer> AttestationRequestCompleteCallback;

        /// <summary>Callback deciding whether we serve our attribute for verification.</summary>
        public Func<Peer, byte[], Task<bool>> VerifyRequestCallback;

        /// <summary>Map of attestation hash → (secret key, id_format).</summary>
        public readonly Dictionary<byte[], (object SecretKey, string IdFormat)> AttestationKeys =
            new Dictionary<byte[], (object, string)>(ByteArrayEqualityComparer.Instance);

        public readonly AttestationsDB Database;

        public readonly Dictionary<byte[], Attestation> CachedAttestationBlobs =
            new Dictionary<byte[], Attestation>(ByteArrayEqualityComparer.Instance);

        /// <summary>Map of mid → allowed global_time strings (py allowed_attestations).</summary>
        public readonly Dictionary<byte[], List<byte[]>> AllowedAttestations =
            new Dictionary<byte[], List<byte[]>>(ByteArrayEqualityComparer.Instance);

        public readonly RequestCache RequestCache = new RequestCache();

        public AttestationCommunity(AttestationSettings settings) : base(settings, FixedCommunityId)
        {
            SchemaManager = new SchemaManager();
            SchemaManager.RegisterDefaultSchemas();
            // py binds the algorithm classes lazily by import; the port registers them explicitly.
            SchemaManager.RegisterAlgorithm("bonehexact",
                (idFormat, formats) => new BonehExactAlgorithm(idFormat, formats));
            SchemaManager.RegisterAlgorithm("pengbaorange",
                (idFormat, formats) => new PengBaoRangeAlgorithm(idFormat, formats));

            AttestationRequestCallback = DefaultAttestationRequestCallback;
            AttestationRequestCompleteCallback = DefaultAttestationRequestCompleteCallback;
            VerifyRequestCallback = DefaultVerifyCallback;

            Database = new AttestationsDB(settings.WorkingDirectory, settings.DbName);
            foreach (var (attributeHash, _, key, idFormat) in Database.GetAll())
            {
                var idFormatString = Util.Utf8ToString(idFormat, 0, idFormat.Length);
                AttestationKeys[attributeHash] =
                    (GetIdAlgorithm(idFormatString).LoadSecretKey(key), idFormatString);
            }

            AddMessageHandler(typeof(VerifyAttestationRequestPayload), OnVerifyAttestationRequestPacket);
            AddMessageHandler(typeof(AttestationChunkPayload), OnAttestationChunkPacket);
            AddMessageHandler(typeof(ChallengePayload), OnChallengePacket);
            AddMessageHandler(typeof(ChallengeResponsePayload), OnChallengeResponsePacket);
            AddMessageHandler(typeof(RequestAttestationPayload), OnRequestAttestationPacket);
        }

        private static Task<byte[]> DefaultAttestationRequestCallback(Peer peer, string attributeName,
                                                                      Dictionary<string, string> metadata)
            => Task.FromResult<byte[]>(null);

        private static void DefaultAttestationRequestCompleteCallback(Peer forPeer, string attributeName,
                                                                      byte[] attrHash, string idFormat,
                                                                      Peer fromPeer)
        {
        }

        private static Task<bool> DefaultVerifyCallback(Peer peer, byte[] attrHash) => Task.FromResult(true);

        public override void Unload()
        {
            RequestCache.Shutdown();
            base.Unload();
            // Close the database after we stop accepting requests.
            Database.Close();
        }

        /// <summary>Resolve an algorithm from a name.</summary>
        public IdentityAlgorithm GetIdAlgorithm(string idFormat) => SchemaManager.GetAlgorithmInstance(idFormat);

        /// <summary>
        /// Set the callback to be called when someone requests an attestation from us. If it
        /// returns null, no attestation is made.
        /// </summary>
        public void SetAttestationRequestCallback(
            Func<Peer, string, Dictionary<string, string>, Task<byte[]>> callback)
            => AttestationRequestCallback = callback;

        /// <summary>Callback called when an Attestation has been completed for another peer.</summary>
        public void SetAttestationRequestCompleteCallback(
            Action<Peer, string, byte[], string, Peer> callback)
            => AttestationRequestCompleteCallback = callback;

        /// <summary>
        /// Set the callback to be called when someone wants to verify our attribute. If it returns
        /// true, the attribute will be verified.
        /// </summary>
        public void SetVerifyRequestCallback(Func<Peer, byte[], Task<bool>> callback)
            => VerifyRequestCallback = callback;

        /// <summary>
        /// Add an attribute directly (without the help of an IPv8 peer). Only for advanced use
        /// (py dump_blob; both stock algorithms reject imported blobs).
        /// </summary>
        public void DumpBlob(string attributeName, string idFormat, byte[] blob,
                             Dictionary<string, string> metadata = null)
        {
            metadata ??= new Dictionary<string, string>();
            var idAlgorithm = GetIdAlgorithm(idFormat);
            var (attestationBlob, key) = idAlgorithm.ImportBlob(blob);
            var attestation = idAlgorithm.GetAttestationClass()
                .UnserializePrivateKey(key, attestationBlob, idFormat);
            OnAttestationComplete(attestation, key, MyPeer, attributeName, attestation.GetHash(), idFormat);
        }

        /// <summary>Request attestation of one of our attributes (py request_attestation).</summary>
        public void RequestAttestation(Peer peer, string attributeName, BonehPrivateKey secretKey,
                                       Dictionary<string, string> metadata = null)
        {
            metadata ??= new Dictionary<string, string>();
            string idFormat;
            if (metadata.ContainsKey("id_format"))
            {
                idFormat = metadata["id_format"];
                metadata.Remove("id_format");
            }
            else
            {
                idFormat = "id_metadata";
            }

            // py insertion order: attribute, public_key, id_format, then the remaining metadata.
            var metaDict = new Dictionary<string, object>
            {
                ["attribute"] = attributeName,
                ["public_key"] = EncodeBytesMime(secretKey.PublicKey().Serialize()),
                ["id_format"] = idFormat
            };
            foreach (var pair in metadata)
            {
                metaDict[pair.Key] = pair.Value;
            }
            var bmetadata = Encoding.UTF8.GetBytes(MiniJson.PythonDumps(metaDict));

            var globalTime = ClaimGlobalTime();
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var payload = new RequestAttestationPayload(bmetadata);
            var dist = new GlobalTimeDistributionPayload(globalTime);

            var gtimeStr = Util.Utf8(globalTime.ToString());
            RequestCache.Add(new ReceiveAttestationRequestCache(this,
                Util.Concat(peer.Mid, gtimeStr), secretKey, attributeName, idFormat));
            if (!AllowedAttestations.TryGetValue(peer.Mid, out var allowed))
            {
                allowed = new List<byte[]>();
                AllowedAttestations[peer.Mid] = allowed;
            }
            allowed.Add(gtimeStr);

            var packet = EzPack(Prefix, 5, new Payload[] { auth, dist, payload });
            Endpoint.Send(peer.Address, packet);
        }

        private Task? OnRequestAttestationPacket(Address sourceAddress, byte[] data)
            => OnRequestAttestation(EzUnpackAuth<RequestAttestationPayload>(sourceAddress, data));

        private async Task OnRequestAttestation(DecodedPacket<RequestAttestationPayload> decoded)
        {
            var peer = decoded.Peer;
            var dist = decoded.Dist;
            var payload = decoded.Payload;
            // Someone wants us to attest their attribute.
            var metadata = MiniJson.Parse(Util.Utf8ToString(payload.Metadata, 0, payload.Metadata.Length))
                as Dictionary<string, object>;
            var attribute = (string)metadata["attribute"];
            metadata.Remove("attribute");
            var pubkeyB64 = Encoding.UTF8.GetBytes((string)metadata["public_key"]);
            metadata.Remove("public_key");
            var idFormat = (string)metadata["id_format"];
            metadata.Remove("id_format");
            var idAlgorithm = GetIdAlgorithm(idFormat);

            var stringMetadata = metadata.ToDictionary(pair => pair.Key, pair => (string)pair.Value);
            var value = await AttestationRequestCallback(peer, attribute, stringMetadata);
            if (value == null)
            {
                return;
            }

            var pk = (BonehPublicKey)idAlgorithm.LoadPublicKey(DecodeBytesMime(pubkeyB64));
            var attestationBlob = idAlgorithm.Attest(pk, value);
            var attestation = idAlgorithm.GetAttestationClass().Unserialize(attestationBlob, idFormat);

            AttestationRequestCompleteCallback(peer, attribute, attestation.GetHash(), idFormat, null);

            SendAttestation(peer.Address, attestationBlob, dist.GlobalTime);
        }

        /// <summary>We got an Attestation delivered to us (py on_attestation_complete).</summary>
        public void OnAttestationComplete(Attestation unserialized, object secretKey, Peer peer,
                                          string name, byte[] attestationHash, string idFormat)
        {
            AttestationKeys[attestationHash] = (secretKey, idFormat);
            Database.InsertAttestation(unserialized, attestationHash, (BonehPrivateKey)secretKey, idFormat);
            AttestationRequestCompleteCallback(MyPeer, name, attestationHash, idFormat, peer);
        }

        /// <summary>
        /// Ask the peer behind a socket address to deliver the Attestation with a certain hash
        /// (py verify_attestation_values).
        /// </summary>
        public void VerifyAttestationValues(Address socketAddress, byte[] attestationHash,
                                            List<byte[]> values,
                                            Action<byte[], List<double>> callback, string idFormat)
        {
            var algorithm = GetIdAlgorithm(idFormat);

            void OnComplete(byte[] attestHash, Dictionary<string, object> relativityMap)
            {
                callback(attestHash, values.Select(value => algorithm.Certainty(value, relativityMap))
                    .ToList());
            }

            RequestCache.Add(new ProvingAttestationCache(this, attestationHash, idFormat,
                onComplete: OnComplete));
            CreateVerifyAttestationRequest(socketAddress, attestationHash, idFormat);
        }

        /// <summary>
        /// Ask the peer behind a socket address to deliver the Attestation with a certain hash
        /// (py create_verify_attestation_request).
        /// </summary>
        public void CreateVerifyAttestationRequest(Address socketAddress, byte[] attestationHash,
                                                   string idFormat)
        {
            RequestCache.Add(new ReceiveAttestationVerifyCache(this, attestationHash, idFormat));

            var globalTime = ClaimGlobalTime();
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var payload = new VerifyAttestationRequestPayload(attestationHash);
            var dist = new GlobalTimeDistributionPayload(globalTime);

            var packet = EzPack(Prefix, 1, new Payload[] { auth, dist, payload });
            Endpoint.Send(socketAddress, packet);
        }

        private Task? OnVerifyAttestationRequestPacket(Address sourceAddress, byte[] data)
            => OnVerifyAttestationRequest(EzUnpackAuth<VerifyAttestationRequestPayload>(sourceAddress, data));

        private async Task OnVerifyAttestationRequest(DecodedPacket<VerifyAttestationRequestPayload> decoded)
        {
            var peer = decoded.Peer;
            var payload = decoded.Payload;
            // We received a request to verify one of our attestations. Send the requested
            // attestation back.
            var attestationBlobs = Database.GetAttestationByHash(payload.AttestationHash);
            if (attestationBlobs.Count == 0)
            {
                Console.Error.WriteLine("Dropping verification request of unknown hash!");
                return;
            }
            var attestationBlob = attestationBlobs[0];
            if (attestationBlob.Length == 0)
            {
                Console.Error.WriteLine("Attestation blob for verification is empty!");
                return;
            }

            var value = await VerifyRequestCallback(peer, payload.AttestationHash);
            if (!value)
            {
                return;
            }

            var (secretKey, idFormat) = AttestationKeys[payload.AttestationHash];
            var attestationClass = GetIdAlgorithm(idFormat).GetAttestationClass();
            var privateAttestation = attestationClass.UnserializePrivateKey(secretKey, attestationBlob,
                                                                            idFormat);
            var publicAttestationBlob = privateAttestation.Serialize();
            CachedAttestationBlobs[payload.AttestationHash] = privateAttestation;
            SendAttestation(peer.Address, publicAttestationBlob);
        }

        /// <summary>
        /// Send a serialized attestation (blob) to an address, split into chunks of 800 bytes
        /// (py send_attestation).
        /// </summary>
        public void SendAttestation(Address socketAddress, byte[] blob, ulong? globalTime = null)
        {
            var sequenceNumber = 0;
            for (var i = 0; i < blob.Length; i += 800)
            {
                var blobChunk = Util.Slice(blob, i, Math.Min(800, blob.Length - i));
                var currentGlobalTime = globalTime ?? ClaimGlobalTime();
                globalTime = currentGlobalTime;
                var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
                var payload = new AttestationChunkPayload(Util.Sha1(blob), sequenceNumber, blobChunk);
                var dist = new GlobalTimeDistributionPayload(currentGlobalTime);
                var packet = EzPack(Prefix, 2, new Payload[] { auth, dist, payload });
                Endpoint.Send(socketAddress, packet);
                sequenceNumber++;
            }
        }

        private Task? OnAttestationChunkPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<AttestationChunkPayload>(sourceAddress, data);
            OnAttestationChunk(decoded);
            return null;
        }

        /// <summary>We received a chunk of an Attestation (py on_attestation_chunk).</summary>
        private void OnAttestationChunk(DecodedPacket<AttestationChunkPayload> decoded)
        {
            var peer = decoded.Peer;
            var dist = decoded.Dist;
            var payload = decoded.Payload;
            var hashId = HashCache.IdFromHash("receive-verify-attestation", payload.AttestationHash);
            var distTimeString = Util.Utf8(dist.GlobalTime.ToString());
            var peerIds = AllowedAttestations.TryGetValue(peer.Mid, out var allowedGlobs)
                ? allowedGlobs.Where(glob => Util.BytesEqual(glob, distTimeString))
                    .Select(glob => PeerCache.IdFromAddress("receive-request-attestation",
                        Util.Concat(peer.Mid, glob)))
                    .ToList()
                : new List<(string Prefix, int Number)>();
            if (RequestCache.Has(hashId.Prefix, hashId.Number))
            {
                var rcache = (ReceiveAttestationVerifyCache)RequestCache.Get(hashId.Prefix, hashId.Number);
                rcache.AttestationMap.Add(new AttestationChunk(payload.SequenceNumber, payload.Data));

                var serialized = AssembleChunks(rcache.AttestationMap);

                var attestationClass = GetIdAlgorithm(rcache.IdFormat).GetAttestationClass();
                if (Util.BytesEqual(Util.Sha1(serialized), payload.AttestationHash))
                {
                    var unserialized = attestationClass.Unserialize(serialized, rcache.IdFormat);
                    RequestCache.Pop(hashId.Prefix, hashId.Number);
                    OnReceivedAttestation(peer, unserialized, payload.AttestationHash);
                }
            }
            else
            {
                var handled = false;
                foreach (var peerId in peerIds)
                {
                    if (!RequestCache.Has(peerId.Prefix, peerId.Number))
                    {
                        continue;
                    }
                    var cache = (ReceiveAttestationRequestCache)RequestCache.Get(peerId.Prefix, peerId.Number);
                    cache.AttestationMap.Add(new AttestationChunk(payload.SequenceNumber, payload.Data));

                    var serialized = AssembleChunks(cache.AttestationMap);

                    var attestationClass = GetIdAlgorithm(cache.IdFormat).GetAttestationClass();
                    if (Util.BytesEqual(Util.Sha1(serialized), payload.AttestationHash))
                    {
                        var unserialized = attestationClass.UnserializePrivateKey(cache.Key, serialized,
                                                                                 cache.IdFormat);
                        cache = (ReceiveAttestationRequestCache)RequestCache.Pop(peerId.Prefix, peerId.Number);
                        AllowedAttestations[peer.Mid] = AllowedAttestations[peer.Mid]
                            .Where(glob => !Util.BytesEqual(glob, distTimeString)).ToList();
                        if (AllowedAttestations[peer.Mid].Count == 0)
                        {
                            AllowedAttestations.Remove(peer.Mid);
                        }
                        OnAttestationComplete(unserialized, cache.Key, peer, cache.Name,
                                              unserialized.GetHash(), cache.IdFormat);
                    }

                    handled = true;
                    break;
                }
                if (!handled)
                {
                    Console.Error.WriteLine("Received Attestation chunk which we did not request!");
                }
            }
        }

        private static byte[] AssembleChunks(IEnumerable<AttestationChunk> chunks)
            => Util.Concat(chunks.OrderBy(chunk => chunk.SequenceNumber)
                .Select(chunk => chunk.Data).ToArray());

        /// <summary>
        /// Callback for when we got the entire attestation from a peer
        /// (py on_received_attestation).
        /// </summary>
        protected virtual void OnReceivedAttestation(Peer peer, Attestation attestation,
                                                     byte[] attestationHash)
        {
            if (attestation.IdFormat == null)
            {
                Console.Error.WriteLine($"Received {attestation} with None as its id_format: dropping!");
                return;
            }
            var algorithm = GetIdAlgorithm(attestation.IdFormat);

            var relativityMap = algorithm.CreateCertaintyAggregate(attestation);
            var hashedChallenges = new List<byte[]>();
            var cache = (ProvingAttestationCache)RequestCache.Get(
                HashCache.IdFromHash("proving-attestation", attestationHash).Prefix,
                HashCache.IdFromHash("proving-attestation", attestationHash).Number);
            cache.PublicKey = attestation.PK;
            var challenges = algorithm.CreateChallenges(attestation.PK, attestation);
            foreach (var challenge in challenges)
            {
                hashedChallenges.Add(Util.Sha1(challenge));
            }
            cache.RelativityMap = relativityMap;
            cache.HashedChallenges = hashedChallenges;
            cache.Challenges = challenges;
            var remaining = 10;
            foreach (var challenge in challenges)
            {
                if (remaining == 0)
                {
                    break;
                }
                var pendingId = HashCache.IdFromHash("proving-hash", Util.Sha1(challenge));
                if (RequestCache.Has(pendingId.Prefix, pendingId.Number))
                {
                    continue;
                }
                remaining--;
                RequestCache.Add(new PendingChallengeCache(this, Util.Sha1(challenge), cache,
                                                           cache.IdFormat));

                var globalTime = ClaimGlobalTime();
                var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
                var payload = new ChallengePayload(attestationHash, challenge);
                var dist = new GlobalTimeDistributionPayload(globalTime);

                var packet = EzPack(Prefix, 3, new Payload[] { auth, dist, payload });
                Endpoint.Send(peer.Address, packet);
            }
        }

        private Task? OnChallengePacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuth<ChallengePayload>(sourceAddress, data);
            OnChallenge(decoded);
            return null;
        }

        /// <summary>We received a challenge for an Attestation (py on_challenge).</summary>
        private void OnChallenge(DecodedPacket<ChallengePayload> decoded)
        {
            var peer = decoded.Peer;
            var payload = decoded.Payload;
            var (secretKey, idFormat) = AttestationKeys[payload.AttestationHash];
            var challengeHash = Util.Sha1(payload.Challenge);
            var algorithm = GetIdAlgorithm(idFormat);
            var attestation = CachedAttestationBlobs[payload.AttestationHash];

            var globalTime = ClaimGlobalTime();
            var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
            var rpayload = new ChallengeResponsePayload(challengeHash,
                algorithm.CreateChallengeResponse(secretKey, attestation, payload.Challenge));
            var dist = new GlobalTimeDistributionPayload(globalTime);

            var packet = EzPack(Prefix, 4, new Payload[] { auth, dist, rpayload });
            Endpoint.Send(peer.Address, packet);
        }

        private Task? OnChallengeResponsePacket(Address sourceAddress, byte[] data)
        {
            // py @synchronized: serialize handling of challenge responses.
            lock (_receiveBlockLock)
            {
                OnChallengeResponse(EzUnpackAuth<ChallengeResponsePayload>(sourceAddress, data));
            }
            return null;
        }

        /// <summary>We received a response to our challenge (py on_challenge_response).</summary>
        private void OnChallengeResponse(DecodedPacket<ChallengeResponsePayload> decoded)
        {
            var peer = decoded.Peer;
            var payload = decoded.Payload;
            var responseId = HashCache.IdFromHash("proving-hash", payload.ChallengeHash);
            var cache = RequestCache.Get(responseId.Prefix, responseId.Number) as PendingChallengeCache;
            if (cache != null)
            {
                RequestCache.Pop(responseId.Prefix, responseId.Number);
                var provingCache = cache.ProvingCache;
                var (pcachePrefix, pcacheId) =
                    HashCache.IdFromHash("proving-attestation", provingCache.Hash);
                byte[] challenge = null;
                var challengeIndex = provingCache.HashedChallenges
                    .FindIndex(hash => Util.BytesEqual(hash, payload.ChallengeHash));
                if (challengeIndex >= 0)
                {
                    provingCache.HashedChallenges.RemoveAt(challengeIndex);
                    var challengeListIndex = provingCache.Challenges
                        .FindIndex(c => Util.BytesEqual(Util.Sha1(c), payload.ChallengeHash));
                    if (challengeListIndex >= 0)
                    {
                        challenge = provingCache.Challenges[challengeListIndex];
                        provingCache.Challenges.RemoveAt(challengeListIndex);
                    }
                }
                var algorithm = GetIdAlgorithm(provingCache.IdFormat);
                if (cache.HonestyCheck < 0)
                {
                    algorithm.ProcessChallengeResponse(provingCache.RelativityMap, challenge,
                                                       payload.Response);
                }
                else if (!algorithm.ProcessHonestyChallenge(cache.HonestyCheck, payload.Response))
                {
                    Console.Error.WriteLine($"{peer.Address.Host} tried to cheat in the ZKP!");
                    // Liar, Completed
                    if (RequestCache.Has(pcachePrefix, pcacheId))
                    {
                        RequestCache.Pop(pcachePrefix, pcacheId);
                    }
                    provingCache.AttestationCallbacks(provingCache.Hash,
                        algorithm.CreateCertaintyAggregate(null));
                }
                if (provingCache.HashedChallenges.Count == 0)
                {
                    // Completed
                    if (RequestCache.Has(pcachePrefix, pcacheId))
                    {
                        RequestCache.Pop(pcachePrefix, pcacheId);
                    }
                    provingCache.AttestationCallbacks(provingCache.Hash, provingCache.RelativityMap);
                }
                else
                {
                    // Send another proving hash
                    var honestyCheck = algorithm.HonestyCheck && RandomByte() < 38;
                    var honestyCheckByte = honestyCheck ? ChoiceRng.Next(3) : -1;
                    byte[] nextChallenge = null;
                    if (honestyCheck)
                    {
                        while (nextChallenge == null || RequestCache.Has(
                                   HashCache.IdFromHash("proving-hash", Util.Sha1(nextChallenge)).Prefix,
                                   HashCache.IdFromHash("proving-hash", Util.Sha1(nextChallenge)).Number))
                        {
                            nextChallenge = algorithm.CreateHonestyChallenge(provingCache.PublicKey,
                                                                             honestyCheckByte);
                        }
                    }
                    var challengeIsPending = nextChallenge != null && RequestCache.Has(
                        HashCache.IdFromHash("proving-hash", Util.Sha1(nextChallenge)).Prefix,
                        HashCache.IdFromHash("proving-hash", Util.Sha1(nextChallenge)).Number);
                    if (!honestyCheck || (nextChallenge != null && challengeIsPending))
                    {
                        honestyCheckByte = -1;
                        nextChallenge = null;
                        foreach (var c in provingCache.Challenges)
                        {
                            var pendingId = HashCache.IdFromHash("proving-hash", Util.Sha1(c));
                            if (!RequestCache.Has(pendingId.Prefix, pendingId.Number))
                            {
                                nextChallenge = c;
                                break;
                            }
                        }
                        if (nextChallenge == null)
                        {
                            // No more bitpairs to challenge!
                            return;
                        }
                    }
                    RequestCache.Add(new PendingChallengeCache(this, Util.Sha1(nextChallenge),
                                                               provingCache, cache.IdFormat,
                                                               honestyCheckByte));

                    var globalTime = ClaimGlobalTime();
                    var auth = new BinMemberAuthenticationPayload(MyPeer.PublicKey.KeyToBin());
                    var rpayload = new ChallengePayload(provingCache.Hash, nextChallenge);
                    var dist = new GlobalTimeDistributionPayload(globalTime);

                    var packet = EzPack(Prefix, 3, new Payload[] { auth, dist, rpayload });
                    Endpoint.Send(peer.Address, packet);
                }
            }
        }

        private static readonly Random ChoiceRng = new Random();

        private static int RandomByte()
        {
            // py os.urandom(1)[0]
            var buffer = new byte[1];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
            return buffer[0];
        }

        /// <summary>py base64.encodebytes: MIME base64 with a newline every 76 characters.</summary>
        public static string EncodeBytesMime(byte[] data)
        {
            var base64 = Convert.ToBase64String(data);
            var builder = new StringBuilder();
            for (var i = 0; i < base64.Length; i += 76)
            {
                if (i > 0)
                {
                    builder.Append('\n');
                }
                var length = Math.Min(76, base64.Length - i);
                builder.Append(base64, i, length);
            }
            if (base64.Length > 0)
            {
                builder.Append('\n');
            }
            return builder.ToString();
        }

        /// <summary>py base64.decodebytes: lenient base64 decode (non-alphabet chars ignored).</summary>
        public static byte[] DecodeBytesMime(byte[] data)
        {
            var filtered = new StringBuilder();
            foreach (var c in data)
            {
                var ch = (char)c;
                var isBase64 = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                               || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=';
                if (isBase64)
                {
                    filtered.Append(ch);
                }
            }
            return Convert.FromBase64String(filtered.ToString());
        }
    }
}
