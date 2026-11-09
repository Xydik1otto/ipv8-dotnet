// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Attestation.Identity;
using IPv8.Attestation.TokenTree;
using IPv8.Keyvault;
using IPv8.Messaging.Anonymization;
using IPv8.PeerDiscovery;
using IPv8.Wallet;
using IPv8.Wallet.Primitives;

namespace IPv8.Attestation
{
    /// <summary>
    /// A communication channel for business and proving logic of a single pseudonym
    /// (port of ipv8/attestation/communication_manager.py::CommunicationChannel).
    /// </summary>
    public class CommunicationChannel
    {
        public readonly AttestationCommunity AttestationOverlay;

        public readonly IdentityCommunity IdentityOverlay;

        /// <summary>py: attestation_requests: dict[AttributePointer, tuple[asyncio.Future, str]].</summary>
        public readonly Dictionary<(Peer, string), (TaskCompletionSource<byte[]> Future, string MetadataJson)>
            AttestationRequests = new Dictionary<(Peer, string), (TaskCompletionSource<byte[]>, string)>();

        /// <summary>py: verify_requests: dict[AttributePointer, asyncio.Future].</summary>
        public readonly Dictionary<(Peer, string), TaskCompletionSource<bool>> VerifyRequests =
            new Dictionary<(Peer, string), TaskCompletionSource<bool>>();

        /// <summary>py: verification_output: dict[bytes, list[tuple[bytes, float | None]]].</summary>
        public readonly Dictionary<byte[], List<(byte[] Reference, double? Result)>> VerificationOutput =
            new Dictionary<byte[], List<(byte[], double?)>>(ByteArrayEqualityComparer.Instance);

        /// <summary>py: attestation_metadata: dict[AttributePointer, MetadataDict].</summary>
        public readonly Dictionary<(Peer, string), Dictionary<string, string>> AttestationMetadata =
            new Dictionary<(Peer, string), Dictionary<string, string>>();

        public CommunicationChannel(AttestationCommunity attestationCommunity, IdentityCommunity identityCommunity)
        {
            AttestationOverlay = attestationCommunity;
            IdentityOverlay = identityCommunity;

            AttestationOverlay.SetAttestationRequestCallback(OnRequestAttestation);
            AttestationOverlay.SetAttestationRequestCompleteCallback(OnAttestationComplete);
            AttestationOverlay.SetVerifyRequestCallback(OnVerifyRequest);
        }

        /// <summary>Get the public key of our pseudonym in bytes.</summary>
        public byte[] PublicKeyBin => IdentityOverlay.MyPeer.PublicKey.KeyToBin();

        /// <summary>List all the business logic peers for our pseudonym.</summary>
        public List<Peer> Peers => IdentityOverlay.GetPeers().ToList();

        /// <summary>List all the identity formats we support.</summary>
        public List<string> Schemas => AttestationOverlay.SchemaManager.Formats.Keys.ToList();

        /// <summary>py on_request_attestation: register an outstanding attestation request.</summary>
        private Task<byte[]> OnRequestAttestation(Peer peer, string attributeName,
                                                  Dictionary<string, string> metadata)
        {
            var future = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var json = Database.MiniJson.PythonDumps(
                metadata.ToDictionary(pair => pair.Key, pair => (object)pair.Value));
            AttestationRequests[(peer, attributeName)] = (future, json);
            AttestationMetadata[(peer, attributeName)] = new Dictionary<string, string>(metadata);
            return future.Task;
        }

        /// <summary>
        /// Callback for when an attestation has been completed for another peer. We can now sign for it.
        /// </summary>
        private void OnAttestationComplete(Peer forPeer, string attributeName, byte[] attributeHash,
                                           string idFormat, Peer fromPeer)
        {
            AttestationMetadata.TryGetValue((forPeer, attributeName), out var metadata);
            if (forPeer.Equals(IdentityOverlay.MyPeer))
            {
                if (fromPeer.Equals(IdentityOverlay.MyPeer))
                {
                    IdentityOverlay.SelfAdvertise(attributeHash, attributeName, idFormat, metadata);
                }
                else
                {
                    IdentityOverlay.RequestAttestationAdvertisement(fromPeer, attributeHash, attributeName,
                                                                    idFormat, metadata);
                }
            }
            else
            {
                IdentityOverlay.AddKnownHash(attributeHash, attributeName,
                                             forPeer.PublicKey.KeyToBin(), metadata);
            }
        }

        /// <summary>py on_verify_request: register an outstanding verification request.</summary>
        private Task<bool> OnVerifyRequest(Peer peer, byte[] attributeHash)
        {
            var metadata = IdentityOverlay.GetAttestationByHash(attributeHash);
            if (metadata == null)
            {
                // py: succeed(None) — a falsy answer, i.e. "do not verify".
                return Task.FromResult(false);
            }
            var name = (string)((Dictionary<string, object>)Database.MiniJson
                .Parse(System.Text.Encoding.UTF8.GetString(metadata.SerializedJsonDict)))["name"];
            var future = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            VerifyRequests[(peer, name)] = future;
            return future.Task;
        }

        /// <summary>Callback for when verification has concluded (index-aligned with the references).</summary>
        private void OnVerificationResults(byte[] attributeHash, List<double> values)
        {
            // The wallet's proving cache identifies the attestation by its plain (unpadded)
            // get_hash() key; map the results back to the hash the caller of Verify used.
            if (!VerificationOutput.ContainsKey(attributeHash)
                && attributeHash.Length == 20)
            {
                var padded = Util.Concat(Util.Utf8("SHA-1\0\0\0\0\0\0\0"), attributeHash);
                if (VerificationOutput.ContainsKey(padded))
                {
                    attributeHash = padded;
                }
            }
            var references = VerificationOutput[attributeHash];
            var merged = new List<(byte[], double?)>();
            for (var i = 0; i < references.Count; i++)
            {
                merged.Add((references[i].Reference, values[i]));
            }
            VerificationOutput[attributeHash] = merged;
        }

        /// <summary>
        /// Remove all metadata from the identity community (py _drop_identity_table_data).
        /// </summary>
        /// <returns>the list of attestation hashes which have been removed</returns>
        private List<byte[]> DropIdentityTableData()
        {
            return IdentityOverlay.IdentityManager.Database.DropAllFor(PublicKeyBin);
        }

        /// <summary>
        /// Remove all attestation data (claim based keys and ZKP blobs) by list of attestation hashes
        /// (py _drop_attestation_table_data).
        /// </summary>
        private void DropAttestationTableData(List<byte[]> attestationHashes)
        {
            if (attestationHashes.Count == 0)
            {
                return;
            }
            AttestationOverlay.Database.DeleteHashes(attestationHashes);
        }

        /// <summary>Remove this pseudonym from existence.</summary>
        public void Remove()
        {
            DropAttestationTableData(DropIdentityTableData());
            AttestationRequests.Clear();
        }

        /// <summary>Get the known attributes for our pseudonym.</summary>
        public Dictionary<byte[], (string Name, Dictionary<string, object> Metadata, List<byte[]> Attesters)>
            GetMyAttributes()
        {
            return GetAttributes(IdentityOverlay.MyPeer);
        }

        /// <summary>Get the known attributes of a given peer.</summary>
        public Dictionary<byte[], (string Name, Dictionary<string, object> Metadata, List<byte[]> Attesters)>
            GetAttributes(Peer peer)
        {
            var pseudonym = IdentityOverlay.IdentityManager.GetPseudonym(peer.PublicKey);
            var outMap = new Dictionary<byte[],
                (string, Dictionary<string, object>, List<byte[]>)>(ByteArrayEqualityComparer.Instance);
            foreach (var credential in pseudonym.GetCredentials())
            {
                var attestations = credential.Attestations.ToList();
                var attesters = attestations.Select(attestation =>
                    IdentityOverlay.IdentityManager.Database.GetAuthority(attestation)).ToList();
                var attributeHash = pseudonym.Tree.Elements[credential.Metadata.TokenPointer].ContentHash;
                var jsonMetadata = (Dictionary<string, object>)Database.MiniJson
                    .Parse(System.Text.Encoding.UTF8.GetString(credential.Metadata.SerializedJsonDict));
                outMap[attributeHash] = ((string)jsonMetadata["name"], jsonMetadata, attesters);
            }
            return outMap;
        }

        /// <summary>Request another peer to attest to our attribute.</summary>
        public void RequestAttestation(Peer peer, string attributeName, string idFormat,
                                       Dictionary<string, string> metadata)
        {
            var key = (BonehPrivateKey)AttestationOverlay.GetIdAlgorithm(idFormat).GenerateSecretKey();
            metadata["id_format"] = idFormat;
            AttestationMetadata[(IdentityOverlay.MyPeer, attributeName)] =
                new Dictionary<string, string>(metadata);
            AttestationOverlay.RequestAttestation(peer, attributeName, key, metadata);
        }

        /// <summary>Attest to another peer's attribute (if its value is what we expect).</summary>
        public void Attest(Peer peer, string attributeName, byte[] value)
        {
            var outstanding = AttestationRequests[(peer, attributeName)];
            AttestationRequests.Remove((peer, attributeName));
            outstanding.Future.SetResult(value);
        }

        /// <summary>Import an external proof as a raw blob (advanced use only!).</summary>
        public void ImportBlob(string attributeName, string idFormat, Dictionary<string, string> metadata,
                               byte[] value)
        {
            metadata["id_format"] = idFormat;
            AttestationOverlay.DumpBlob(attributeName, idFormat, value, metadata);
        }

        /// <summary>Consent to verification of an attribute by a peer.</summary>
        public void AllowVerification(Peer peer, string attributeName)
        {
            PopVerifyRequest(peer, attributeName).SetResult(true);
        }

        /// <summary>Do not consent to verification of an attribute by a peer.</summary>
        public void DisallowVerification(Peer peer, string attributeName)
        {
            PopVerifyRequest(peer, attributeName).SetResult(false);
        }

        private TaskCompletionSource<bool> PopVerifyRequest(Peer peer, string attributeName)
        {
            var outstanding = VerifyRequests[(peer, attributeName)];
            VerifyRequests.Remove((peer, attributeName));
            return outstanding;
        }

        /// <summary>Play out the Zero-Knowledge Proof of a given attribute hash for a peer.</summary>
        /// <remarks>
        /// py communication_manager.verify passes the identity-tree hash straight to the wallet.
        /// For the legacy SHA-1 identity formats (id_metadata/PengBao) that tree hash is the
        /// padded 32-byte "SHA-1" form (py identity/community.py self_advertise:249-250), while
        /// the wallet database keys attestations by the plain 20-byte get_hash() sha1
        /// (py wallet/community.py on_attestation_complete:265) — py's own legacy path would
        /// then miss in on_verify_attestation_request's database lookup. The port normalizes the
        /// attribute hash to the wallet's key form so the verify flow functions; the identity
        /// overlay still accepts both forms (py get_attestation_by_hash pads 20-byte hashes).
        /// </remarks>
        public void Verify(Peer peer, byte[] attributeHash, List<byte[]> referenceValues, string idFormat)
        {
            // The wallet's proving cache keys attestations by the plain get_hash() form; the
            // channel keeps the caller's hash for its own bookkeeping.
            var walletHash = attributeHash;
            if (walletHash.Length == 32 && Util.BytesEqual(
                    Util.Slice(walletHash, 0, 12), Util.Utf8("SHA-1\0\0\0\0\0\0\0")))
            {
                walletHash = Util.Slice(walletHash, 12, 20);
            }
            VerificationOutput[attributeHash] = referenceValues
                .Select(v => (v, (double?)null)).ToList();
            AttestationOverlay.VerifyAttestationValues(peer.Address, walletHash, referenceValues,
                                                       OnVerificationResults, idFormat);
        }
    }

    /// <summary>
    /// Perform file management of pseudonyms
    /// (port of ipv8/attestation/communication_manager.py::PseudonymFolderManager).
    /// </summary>
    public class PseudonymFolderManager
    {
        public readonly string PseudonymFolder;

        public PseudonymFolderManager(string directory)
        {
            PseudonymFolder = directory;
        }

        /// <summary>
        /// Get the private key for a pseudonym by either reading it or generating it.
        /// In the latter case, write to a file.
        /// </summary>
        public PrivateKey GetOrCreatePrivateKey(string name)
        {
            Directory.CreateDirectory(PseudonymFolder);
            var pseudonymFile = Path.Combine(PseudonymFolder, name);
            if (File.Exists(pseudonymFile))
            {
                return ECCrypto.Default.KeyFromPrivateBin(File.ReadAllBytes(pseudonymFile));
            }
            var privateKey = ECCrypto.Default.GenerateKey("curve25519");
            File.WriteAllBytes(pseudonymFile, privateKey.KeyToBin());
            return privateKey;
        }

        /// <summary>Remove a pseudonym file by its name.</summary>
        public void RemovePseudonymFile(string name)
        {
            var pseudonymFile = Path.Combine(PseudonymFolder, name);
            if (File.Exists(pseudonymFile))
            {
                File.Delete(pseudonymFile);
            }
        }

        /// <summary>List all the pseudonym files in our pseudonym directory.</summary>
        public List<string> ListPseudonymFiles()
        {
            if (!Directory.Exists(PseudonymFolder))
            {
                return new List<string>();
            }
            return Directory.GetFiles(PseudonymFolder).Select(Path.GetFileName).ToList();
        }
    }

    /// <summary>
    /// Manager of pseudonym managers, usually operated from the REST API by a user app
    /// (port of ipv8/attestation/communication_manager.py::CommunicationManager).
    /// </summary>
    public class CommunicationManager
    {
        private readonly IPv8Service _ipv8Instance;

        /// <summary>py: channels: dict[public_key_bin, CommunicationChannel].</summary>
        private readonly Dictionary<byte[], CommunicationChannel> _channels =
            new Dictionary<byte[], CommunicationChannel>(ByteArrayEqualityComparer.Instance);

        /// <summary>py: name_to_channel: dict[str, CommunicationChannel].</summary>
        private readonly Dictionary<string, CommunicationChannel> _nameToChannel =
            new Dictionary<string, CommunicationChannel>();

        private IdentityManager _identityManager;

        public readonly string WorkingDirectory;

        public readonly PseudonymFolderManager PseudonymFolderManager;

        public CommunicationManager(IPv8Service ipv8Instance, string pseudonymFolder = "pseudonyms",
                                    string workingDirectory = null)
        {
            _ipv8Instance = ipv8Instance;
            WorkingDirectory = workingDirectory ?? ".";
            PseudonymFolderManager = new PseudonymFolderManager(Path.Combine(WorkingDirectory, pseudonymFolder));
        }

        /// <summary>Lazy load the IdentityManager.</summary>
        public IdentityManager LazyIdentityManager()
        {
            if (_identityManager == null)
            {
                _identityManager = WorkingDirectory == ":memory:"
                    ? new IdentityManager(":memory:")
                    : new IdentityManager(Path.Combine(WorkingDirectory, "sqlite", "identity.db"));
            }
            return _identityManager;
        }

        /// <summary>
        /// py identity/community.py create_community: rendezvous tokens XOR the community id
        /// byte-for-byte up to the token length.
        /// </summary>
        public static byte[] RendezvousCommunityId(byte[] rendezvousToken)
        {
            var baseId = IdentityCommunity.FixedCommunityId;
            var rendezvousId = new byte[baseId.Length];
            for (var i = 0; i < baseId.Length; i++)
            {
                rendezvousId[i] = i < rendezvousToken.Length ? (byte)(baseId[i] ^ rendezvousToken[i]) : baseId[i];
            }
            return rendezvousId;
        }

        /// <summary>py ipv8_service.produce_anonymized_endpoint.</summary>
        private async Task<TunnelEndpoint> ProduceAnonymizedEndpointAsync()
        {
            var address = "0.0.0.0";
            foreach (var spec in _ipv8Instance.Configuration.Interfaces)
            {
                if (spec.Interface == "UDPIPv4")
                {
                    address = spec.Ip;
                }
            }
            var baseEndpoint = new Messaging.Interfaces.Udp.UDPEndpoint(0, address);
            baseEndpoint.Open();
            return new TunnelEndpoint(baseEndpoint);
        }

        /// <summary>Load a pseudonym.</summary>
        public async Task<CommunicationChannel> Load(string name, string rendezvousToken = null)
        {
            if (_nameToChannel.ContainsKey(name))
            {
                return _nameToChannel[name];
            }

            var privateKey = PseudonymFolderManager.GetOrCreatePrivateKey(name);

            var publicKey = privateKey.Pub().KeyToBin();
            if (!_channels.ContainsKey(publicKey))
            {
                var tunnelCommunity = _ipv8Instance.GetOverlay(typeof(HiddenTunnelCommunity))
                    as HiddenTunnelCommunity;
                var anonymize = tunnelCommunity != null;
                var decodedRendezvousToken = rendezvousToken == null
                    ? null
                    : Convert.FromBase64String(rendezvousToken);

                var endpoint = await ProduceAnonymizedEndpointAsync();
                var identityOverlay = new IdentityCommunity(new IdentitySettings(
                    decodedRendezvousToken == null
                        ? IdentityCommunity.FixedCommunityId
                        : RendezvousCommunityId(decodedRendezvousToken),
                    new Peer(privateKey), endpoint, new Network(), anonymize: anonymize)
                {
                    IdentityManager = LazyIdentityManager(),
                    WorkingDirectory = WorkingDirectory
                });
                _ipv8Instance.AddStrategy(identityOverlay, new RandomWalk(identityOverlay), -1);

                var attestationOverlay = new AttestationCommunity(new AttestationSettings(
                    AttestationCommunity.FixedCommunityId, identityOverlay.MyPeer, identityOverlay.Endpoint,
                    identityOverlay.Network, anonymize: anonymize)
                {
                    WorkingDirectory = WorkingDirectory
                });
                ((TunnelEndpoint)identityOverlay.Endpoint).SetTunnelCommunity(tunnelCommunity);
                var channel = new CommunicationChannel(attestationOverlay, identityOverlay);
                _channels[publicKey] = channel;
                _nameToChannel[name] = channel;
            }

            return _nameToChannel[name];
        }

        /// <summary>Unload a pseudonym.</summary>
        public async Task Unload(string name)
        {
            if (!_nameToChannel.TryGetValue(name, out var communicationChannel))
            {
                return;
            }
            _nameToChannel.Remove(name);
            _channels.Remove(communicationChannel.PublicKeyBin);
            await _ipv8Instance.UnloadOverlay(communicationChannel.IdentityOverlay);
            communicationChannel.AttestationOverlay.Unload();
            communicationChannel.IdentityOverlay.Endpoint.Close();
        }

        /// <summary>Remove a pseudonym from existence by name.</summary>
        public async Task Remove(string name)
        {
            if (_nameToChannel.TryGetValue(name, out var channel))
            {
                _nameToChannel.Remove(name);
                channel.Remove();
                await Unload(name);
                PseudonymFolderManager.RemovePseudonymFile(name);
            }
        }

        /// <summary>Close down all communication.</summary>
        public async Task Shutdown()
        {
            foreach (var name in _nameToChannel.Keys.ToList())
            {
                await Unload(name);
            }
        }

        /// <summary>List all known pseudonyms.</summary>
        public List<string> ListNames()
        {
            return PseudonymFolderManager.ListPseudonymFiles();
        }

        /// <summary>List all loaded pseudonyms by name.</summary>
        public List<string> ListLoaded()
        {
            return ListNames().Where(name => _nameToChannel.ContainsKey(name)).ToList();
        }
    }
}
