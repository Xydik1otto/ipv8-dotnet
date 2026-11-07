// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces;
using IPv8.PeerDiscovery;

namespace IPv8.Attestation.Identity
{
    /// <summary>Settings for the Identity community (py IdentitySettings).</summary>
    public class IdentitySettings : CommunitySettings
    {
        public IdentitySettings(byte[] communityId, Peer myPeer, Endpoint endpoint, Network network)
            : base(communityId, myPeer, endpoint, network)
        {
        }

        public IdentityManager IdentityManager { get; set; }

        public string WorkingDirectory { get; set; } = ".";
    }

    /// <summary>A known attestation hash entry (py: hash → (name, time, public_key, metadata)).</summary>
    public sealed class KnownAttestationHash
    {
        public string Name;
        public double Time;
        public byte[] PublicKey;
        public Dictionary<string, string> Metadata;
    }

    /// <summary>
    /// Community for business logic surrounding identities
    /// (port of ipv8/attestation/identity/community.py::IdentityCommunity).
    /// </summary>
    public class IdentityCommunity : Community
    {
        public static readonly byte[] FixedCommunityId = Util.Unhex("d5889074c1e4c50423cdb6e9307ee0ca5695ead7");

        public const int SafeUdpPacketLength = 1296;

        /// <summary>Dict of hash → (attribute_name, date, public_key, metadata).</summary>
        public readonly Dictionary<byte[], KnownAttestationHash> KnownAttestationHashes =
            new Dictionary<byte[], KnownAttestationHash>(ByteArrayEqualityComparer.Instance);

        public readonly IdentityManager IdentityManager;

        public readonly PseudonymManager PseudonymManager;

        public readonly List<TokenTree.Token> TokenChain = new List<TokenTree.Token>();

        public readonly List<Metadata> MetadataChain = new List<Metadata>();

        public readonly List<ISet<Attestation>> AttestationChain = new List<ISet<Attestation>>();

        /// <summary>Map of peer to the highest permitted index (py: permissions).</summary>
        public readonly Dictionary<Peer, int> Permissions = new Dictionary<Peer, int>();

        public IdentityCommunity(IdentitySettings settings) : base(settings, FixedCommunityId)
        {
            if (settings.IdentityManager == null)
            {
                var dbPath = settings.WorkingDirectory == ":memory:"
                    ? ":memory:"
                    : System.IO.Path.Combine(settings.WorkingDirectory, "sqlite", "identity.db");
                settings.IdentityManager = new IdentityManager(dbPath);
            }

            IdentityManager = settings.IdentityManager;
            PseudonymManager = settings.IdentityManager.GetPseudonym(settings.MyPeer.Key);

            // We assume other people try to cheat us with trees.
            // We don't attack ourselves though and just maintain a chain of attributes per pseudonym.
            foreach (var token in PseudonymManager.Tree.Elements.Values)
            {
                var chain = PseudonymManager.Tree.GetRootPath(token);
                if (chain.Count > TokenChain.Count)
                {
                    TokenChain.Clear();
                    TokenChain.AddRange(chain);
                }
            }
            foreach (var credential in PseudonymManager.GetCredentials())
            {
                foreach (var token in TokenChain)
                {
                    if (Util.BytesEqual(credential.Metadata.TokenPointer, token.GetHash()))
                    {
                        MetadataChain.Add(credential.Metadata);
                        AttestationChain.Add(credential.Attestations);
                        break;
                    }
                }
            }

            // Register messages
            AddMessageHandler(typeof(DisclosePayload), OnDisclosure);
            AddMessageHandler(typeof(AttestPayload), OnAttestPacket);
            AddMessageHandler(typeof(RequestMissingPayload), OnRequestMissing);
            AddMessageHandler(typeof(MissingResponsePayload), OnMissingResponse);
        }

        /// <summary>Pad an old-style SHA-1 hash into the new 32 byte SHA3-256 space.</summary>
        public byte[] PadHash(byte[] attributeHash)
            => Util.Concat(Util.Utf8("SHA-1" + "\0\0\0\0\0\0\0"), attributeHash);

        /// <summary>We know about this hash+peer combination, thus we can handle sign requests for it.</summary>
        public void AddKnownHash(byte[] attributeHash, string name, byte[] publicKey,
                                 Dictionary<string, string> metadata = null)
        {
            if (attributeHash.Length == 20)
            {
                attributeHash = PadHash(attributeHash);
            }
            KnownAttestationHashes[attributeHash] = new KnownAttestationHash
            {
                Name = name,
                Time = Util.NowEpoch(),
                PublicKey = publicKey,
                Metadata = metadata
            };
        }

        /// <summary>Get the Metadata object for a particular attribute hash, if it exists.</summary>
        public Metadata GetAttestationByHash(byte[] attributeHash)
        {
            if (attributeHash.Length == 20)
            {
                attributeHash = PadHash(attributeHash);
            }
            foreach (var credential in PseudonymManager.GetCredentials())
            {
                var token = PseudonymManager.Tree.Elements[credential.Metadata.TokenPointer];
                if (Util.BytesEqual(token.ContentHash, attributeHash))
                {
                    return credential.Metadata;
                }
            }
            return null;
        }

        /// <summary>Has the user asked us to sign for some metadata and is it still valid?</summary>
        public bool ShouldSign(PseudonymManager pseudonym, Metadata metadata)
        {
            var transaction = metadata.ParseJsonDict();
            if (!pseudonym.Tree.Elements.ContainsKey(metadata.TokenPointer))
            {
                return false;
            }
            var attributeHash = pseudonym.Tree.Elements[metadata.TokenPointer].ContentHash;
            if (!transaction.ContainsKey("name") || !transaction.ContainsKey("date")
                || !transaction.ContainsKey("schema"))
            {
                return false;
            }
            if (!KnownAttestationHashes.TryGetValue(attributeHash, out var known))
            {
                return false;
            }
            if (!Util.BytesEqual(pseudonym.PublicKey.KeyToBin(), known.PublicKey))
            {
                return false;
            }
            // Refuse to sign blocks older than 5 minutes
            if (Util.NowEpoch() > known.Time + 300)
            {
                return false;
            }
            if ((string)transaction["name"] != known.Name)
            {
                return false;
            }
            if (known.Metadata != null)
            {
                var extra = new Dictionary<string, object>();
                foreach (var pair in transaction)
                {
                    if (pair.Key != "name" && pair.Key != "date" && pair.Key != "schema")
                    {
                        extra[pair.Key] = pair.Value;
                    }
                }
                var knownDict = known.Metadata.ToDictionary(pair => pair.Key,
                                                            pair => (object)pair.Value);
                if (extra.Count != knownDict.Count || extra.Any(pair =>
                        !knownDict.TryGetValue(pair.Key, out var knownValue)
                        || !ValuesEqual(pair.Value, knownValue)))
                {
                    return false;
                }
            }
            foreach (var attestation in pseudonym.Database.GetAttestationsOver(metadata))
            {
                var authority = pseudonym.Database.GetAuthority(attestation);
                if (authority != null && Util.BytesEqual(authority, MyPeer.PublicKey.KeyToBin()))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool ValuesEqual(object a, object b)
            => string.Equals(Convert.ToString(a, System.Globalization.CultureInfo.InvariantCulture),
                             Convert.ToString(b, System.Globalization.CultureInfo.InvariantCulture),
                             StringComparison.Ordinal);

        /// <summary>Fit a disclosure (metadata, tokens, attestations and authorities) to a UDP packet.</summary>
        private (byte[] Metadata, byte[] Tokens, byte[] Attestations, byte[] Authorities) FitDisclosure(
            (byte[] Metadata, byte[] Tokens, byte[] Attestations, byte[] Authorities) disclosure)
        {
            var tokenSize = 64 + Crypto.GetSignatureLength((Keyvault.PublicKey)MyPeer.Key);
            var metadata = disclosure.Metadata;
            var tokens = disclosure.Tokens;
            var attestations = disclosure.Attestations;
            var authorities = disclosure.Authorities;
            var metaLen = metadata.Length + attestations.Length + authorities.Length;
            if (metaLen + tokens.Length > SafeUdpPacketLength)
            {
                var packetSpace = SafeUdpPacketLength - metaLen;
                packetSpace = Math.Max(0, packetSpace);
                var trimLen = packetSpace / tokenSize;
                tokens = Util.Slice(tokens,
                                    Math.Max(0, tokens.Length - trimLen * tokenSize),
                                    Math.Min(tokens.Length, trimLen * tokenSize));
            }
            return (metadata, tokens, attestations, authorities);
        }

        /// <summary>
        /// Attempt to insert a disclosure into our database and request more if we are still
        /// missing tokens.
        /// </summary>
        private void ReceivedDisclosureForAttest(Peer peer,
            (byte[] Metadata, byte[] Tokens, byte[] Attestations, byte[] Authorities) disclosure)
        {
            var solicited = KnownAttestationHashes.Values
                .Any(known => Util.BytesEqual(known.PublicKey, peer.PublicKey.KeyToBin()));
            if (solicited)
            {
                var (correct, pseudonym) = IdentityManager.Substantiate(peer.PublicKey,
                    disclosure.Metadata, disclosure.Tokens, disclosure.Attestations, disclosure.Authorities);
                var requiredAttributes = KnownAttestationHashes.Keys
                    .Where(attributeHash => Util.BytesEqual(
                        KnownAttestationHashes[attributeHash].PublicKey, peer.PublicKey.KeyToBin()))
                    .ToList();
                var knownAttributes = pseudonym.Tree.Elements.Values
                    .Select(token => token.ContentHash).ToList();
                if (correct && requiredAttributes.Any(h => knownAttributes.Any(k => Util.BytesEqual(k, h))))
                {
                    foreach (var credential in pseudonym.GetCredentials())
                    {
                        if (ShouldSign(pseudonym, credential.Metadata))
                        {
                            var attestation = pseudonym.CreateAttestation(credential.Metadata,
                                (Keyvault.PrivateKey)MyPeer.Key);
                            pseudonym.AddAttestation(MyPeer.PublicKey, attestation);
                            EzSend(peer, new AttestPayload(attestation.GetPlaintextSigned()));
                        }
                    }
                }
                foreach (var attributeHash in requiredAttributes)
                {
                    if (!knownAttributes.Any(k => Util.BytesEqual(k, attributeHash)))
                    {
                        EzSend(peer, new RequestMissingPayload(pseudonym.Tree.Elements.Count));
                    }
                }
            }
            else
            {
                Console.Error.WriteLine($"Received unsolicited disclosure from {peer}, dropping!");
            }
        }

        /// <summary>Request a peer to sign for our attestation advertisement.</summary>
        public void RequestAttestationAdvertisement(Peer peer, byte[] attributeHash, string name,
                                                    string blockType = "id_metadata",
                                                    Dictionary<string, string> metadata = null)
        {
            var credential = SelfAdvertise(attributeHash, name, blockType, metadata);
            if (credential == null)
            {
                throw new InvalidOperationException($"Failed to create credential {name}: aborting!");
            }
            Permissions[peer] = TokenChain.Count;
            var fitted = FitDisclosure(PseudonymManager.DiscloseCredentials(new[] { credential },
                new HashSet<byte[]>(ByteArrayEqualityComparer.Instance)));
            EzSend(peer, new DisclosePayload(fitted.Metadata, fitted.Tokens,
                                             fitted.Attestations, fitted.Authorities));
        }

        /// <summary>Self-sign an attribute; returns the created credential or null.</summary>
        public Credential SelfAdvertise(byte[] attributeHash, string name,
                                        string blockType = "id_metadata",
                                        Dictionary<string, string> metadata = null)
        {
            if (attributeHash.Length == 20)
            {
                attributeHash = PadHash(attributeHash);
            }

            // Construct metadata fields
            var extendedMetadata = new Dictionary<string, object>
            {
                ["name"] = name,
                ["schema"] = blockType,
                ["date"] = Util.NowEpoch()
            };
            if (metadata != null)
            {
                foreach (var pair in metadata)
                {
                    extendedMetadata[pair.Key] = pair.Value;
                }
            }

            // Create credential
            var credential = PseudonymManager.CreateCredential(attributeHash, extendedMetadata,
                MetadataChain.Count > 0 ? MetadataChain[MetadataChain.Count - 1] : null);
            if (credential == null)
            {
                return null;
            }

            // Construct chain data view
            AttestationChain.Add(credential.Attestations);
            MetadataChain.Add(credential.Metadata);
            TokenChain.Add(PseudonymManager.Tree.Elements[credential.Metadata.TokenPointer]);

            return credential;
        }

        /// <summary>Someone disclosed their attributes to us.</summary>
        private Task? OnDisclosure(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<DisclosePayload>(sourceAddress, data);
            ReceivedDisclosureForAttest(decoded.Peer,
                (decoded.Payload.Metadata, decoded.Payload.Tokens,
                 decoded.Payload.Attestations, decoded.Payload.Authorities));
            return null;
        }

        /// <summary>Someone made an attestation for us; try to insert it into our database.</summary>
        private Task? OnAttestPacket(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<AttestPayload>(sourceAddress, data);
            var attestation = Attestation.Unserialize(decoded.Payload.Attestation,
                                                      decoded.Peer.PublicKey);
            if (PseudonymManager.AddAttestation(decoded.Peer.PublicKey, attestation))
            {
                // Received attestation.
            }
            else
            {
                Console.Error.WriteLine($"Received invalid attestation from {decoded.Peer}!");
            }
            return null;
        }

        /// <summary>Someone requested tokens from us; send a permitted range.</summary>
        private Task? OnRequestMissing(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<RequestMissingPayload>(sourceAddress, data);
            var output = new List<byte[]>();
            var permitted = TokenChain.Take(Permissions.TryGetValue(decoded.Peer, out var value)
                ? value : 0).ToList();
            var size = 0;
            for (var index = 0; index < permitted.Count; index++)
            {
                if (index >= decoded.Payload.Known)
                {
                    var serialized = permitted[index].GetPlaintextSigned();
                    if (size + serialized.Length > SafeUdpPacketLength)
                    {
                        break;
                    }
                    output.Add(serialized);
                    size += serialized.Length;
                }
            }
            EzSend(decoded.Peer, new MissingResponsePayload(Util.Concat(output.ToArray())));
            return null;
        }

        /// <summary>We received tokens; insert them and check if we are still missing some.</summary>
        private Task? OnMissingResponse(Address sourceAddress, byte[] data)
        {
            var decoded = EzUnpackAuthNoDist<MissingResponsePayload>(sourceAddress, data);
            ReceivedDisclosureForAttest(decoded.Peer,
                (Util.EmptyBytes, decoded.Payload.Tokens, Util.EmptyBytes, Util.EmptyBytes));
            return null;
        }
    }
}
