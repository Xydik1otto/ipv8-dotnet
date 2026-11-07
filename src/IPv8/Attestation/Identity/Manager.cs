// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Keyvault;

namespace IPv8.Attestation.Identity
{
    /// <summary>
    /// Object to manage interactions with our own pseudonym or one belonging to someone else.
    /// Never create one yourself, use IdentityManager.GetPseudonym() instead
    /// (port of ipv8/attestation/identity/manager.py::PseudonymManager).
    /// </summary>
    public class PseudonymManager
    {
        public readonly IdentityDatabase Database;

        public readonly TokenTree.TokenTree Tree;

        public readonly List<Credential> Credentials = new List<Credential>();

        public PseudonymManager(IdentityDatabase database,
                                PublicKey publicKey = null,
                                PrivateKey privateKey = null)
        {
            Database = database;

            Tree = new TokenTree.TokenTree(publicKey, privateKey);

            foreach (var token in Database.GetTokensFor(PublicKey))
            {
                Tree.Elements[token.GetHash()] = token;
            }
            Credentials.AddRange(Database.GetCredentialsFor(PublicKey));
        }

        public PublicKey PublicKey => Tree.PublicKey;

        /// <summary>Add a credential to this pseudonym; returns the added credential on success.</summary>
        public Credential AddCredential(TokenTree.Token token, Metadata metadata,
                                        IEnumerable<(PublicKey AuthorityKey, Attestation Attestation)>
                                            attestations = null)
        {
            var attestationPairs = attestations ?? Enumerable.Empty<(PublicKey, Attestation)>();
            // If this token belongs to this chain, insert it.
            if (Tree.GatherToken(token) != null)
            {
                Database.InsertToken(PublicKey, token);

                // If the metadata belongs to this token and chain, insert it.
                if (metadata.Verify(PublicKey) && Util.BytesEqual(metadata.TokenPointer, token.GetHash()))
                {
                    Database.InsertMetadata(PublicKey, metadata);

                    // Insert all valid attestations to this metadata.
                    var validAttestations = new HashSet<Attestation>();
                    foreach (var (authorityKey, attestation) in attestationPairs)
                    {
                        if (AddAttestation(authorityKey, attestation))
                        {
                            validAttestations.Add(attestation);
                        }
                    }

                    var credential = new Credential(metadata, validAttestations);
                    Credentials.Add(credential);
                    return credential;
                }
            }
            return null;
        }

        /// <summary>Add an attestation to this pseudonym; true on success.</summary>
        public bool AddAttestation(PublicKey publicKey, Attestation attestation)
        {
            if (attestation.Verify(publicKey))
            {
                Database.InsertAttestation(PublicKey, publicKey, attestation);
                return true;
            }
            return false;
        }

        /// <summary>Add a metadata entry to this pseudonym; true on success.</summary>
        public bool AddMetadata(Metadata metadata)
        {
            if (metadata.Verify(PublicKey))
            {
                Database.InsertMetadata(PublicKey, metadata);
                return true;
            }
            return false;
        }

        /// <summary>Create an attestation for a metadata entry of this pseudonym.</summary>
        public Attestation CreateAttestation(Metadata metadata, PrivateKey privateKey)
            => Attestation.Create(metadata, privateKey);

        /// <summary>Create a credential and add it to this pseudonym.</summary>
        public Credential CreateCredential(byte[] attestationHash,
                                           Dictionary<string, object> metadataJson,
                                           Metadata after = null)
        {
            TokenTree.Token preceding = null;
            if (after != null)
            {
                Tree.Elements.TryGetValue(after.TokenPointer, out preceding);
            }
            var token = Tree.AddByHash(attestationHash, preceding);
            var metadata = new Metadata(token.GetHash(),
                                        Util.Utf8(IPv8.Database.MiniJson.PythonDumps(metadataJson)),
                                        Tree.PrivateKey, null);
            return AddCredential(token, metadata, Array.Empty<(PublicKey, Attestation)>());
        }

        /// <summary>Return the credential belonging to given metadata.</summary>
        public Credential GetCredential(Metadata metadata) => Database.GetCredentialOver(metadata);

        /// <summary>Get all credentials belonging to this pseudonym.</summary>
        public List<Credential> GetCredentials() => Database.GetCredentialsFor(PublicKey);

        /// <summary>Create a public disclosure for the given credentials.</summary>
        public (byte[] Metadata, byte[] Tokens, byte[] Attestations, byte[] Authorities)
            DiscloseCredentials(IEnumerable<Credential> credentials, ISet<byte[]> attestationSelector)
            => CreateDisclosure(new HashSet<Metadata>(credentials.Select(credential => credential.Metadata)),
                                attestationSelector);

        /// <summary>Create a public disclosure for the given set of metadata.</summary>
        public (byte[] Metadata, byte[] Tokens, byte[] Attestations, byte[] Authorities)
            CreateDisclosure(ISet<Metadata> metadata, ISet<byte[]> attestationSelector)
        {
            var sMetadata = new List<byte[]>();
            foreach (var md in metadata)
            {
                var serialized = md.GetPlaintextSigned();
                var lengthBytes = BitConverter.GetBytes(serialized.Length);
                Array.Reverse(lengthBytes); // >I big-endian
                sMetadata.Add(Util.Concat(lengthBytes, serialized));
            }

            var attestations = new List<byte[]>();
            var authorities = new List<byte[]>();
            foreach (var m in metadata)
            {
                foreach (var attestation in Database.GetAttestationsOver(m))
                {
                    if (attestationSelector.Contains(attestation.GetHash()))
                    {
                        attestations.Add(attestation.GetPlaintextSigned());
                        var authority = Database.GetAuthority(attestation);
                        var authorityLenBytes = BitConverter.GetBytes((ushort)authority.Length);
                        Array.Reverse(authorityLenBytes); // >H big-endian
                        authorities.Add(Util.Concat(authorityLenBytes, authority));
                    }
                }
            }

            var requiredTokenHashes = new HashSet<byte[]>(
                metadata.Select(m => m.TokenPointer), ByteArrayEqualityComparer.Instance);
            var tokens = new HashSet<TokenTree.Token>();
            foreach (var requiredTokenHash in requiredTokenHashes)
            {
                var rootToken = Tree.Elements[requiredTokenHash];
                if (!Tree.Verify(rootToken))
                {
                    throw new InvalidOperationException("Attempted to create disclosure for undisclosable Token!");
                }
                tokens.Add(rootToken);
                var currentToken = rootToken;
                while (!Util.BytesEqual(currentToken.PreviousTokenHash, Tree.GenesisHash))
                {
                    currentToken = Tree.Elements[currentToken.PreviousTokenHash];
                    tokens.Add(currentToken);
                }
            }

            var tokenParts = tokens.Select(token => token.GetPlaintextSigned()).ToArray();
            return (Util.Concat(sMetadata.ToArray()), Util.Concat(tokenParts),
                    Util.Concat(attestations.ToArray()), Util.Concat(authorities.ToArray()));
        }
    }

    /// <summary>
    /// Manager of our own pseudonyms and those of others
    /// (port of ipv8/attestation/identity/manager.py::IdentityManager).
    /// </summary>
    public class IdentityManager
    {
        public readonly IdentityDatabase Database;

        private readonly Dictionary<byte[], PseudonymManager> _pseudonyms =
            new Dictionary<byte[], PseudonymManager>(ByteArrayEqualityComparer.Instance);

        public readonly ECCrypto Crypto = ECCrypto.Default;

        public IdentityManager(string databasePath = ":memory:")
        {
            Database = new IdentityDatabase(databasePath);
            Database.Open();
        }

        /// <summary>Get the pseudonym belonging to a given public or private key.</summary>
        public PseudonymManager GetPseudonym(Key key)
        {
            var publicKeyMaterial = key.Pub().KeyToBin();
            if (!_pseudonyms.TryGetValue(publicKeyMaterial, out var pseudonym))
            {
                pseudonym = key is PrivateKey privateKey
                    ? new PseudonymManager(Database, privateKey: privateKey)
                    : new PseudonymManager(Database, publicKey: (PublicKey)key);
                _pseudonyms[publicKeyMaterial] = pseudonym;
            }
            return pseudonym;
        }

        /// <summary>
        /// Load the serialized form of a pseudonym for a given public key; returns whether this
        /// pseudonym is valid, together with the loaded pseudonym.
        /// </summary>
        public (bool Correct, PseudonymManager Pseudonym) Substantiate(PublicKey publicKey,
                                                                       byte[] serializedMetadata,
                                                                       byte[] serializedTokens,
                                                                       byte[] serializedAttestations,
                                                                       byte[] serializedAuthorities)
        {
            var pseudonym = GetPseudonym(publicKey);
            var correct = pseudonym.Tree.UnserializePublic(serializedTokens);

            var metadataOffset = 0;
            while (metadataOffset < serializedMetadata.Length)
            {
                var metadataLen = ReadU32(serializedMetadata, metadataOffset);
                var md = Metadata.Unserialize(
                    Util.Slice(serializedMetadata, metadataOffset + 4, (int)metadataLen), publicKey);
                pseudonym.AddMetadata(md);
                metadataOffset += 4 + (int)metadataLen;
            }

            var attestationOffset = 0;
            var authorityOffset = 0;
            while (authorityOffset < serializedAuthorities.Length)
            {
                var authorityLen = ReadU16(serializedAuthorities, authorityOffset);
                var authority = Crypto.KeyFromPublicBin(
                    Util.Slice(serializedAuthorities, authorityOffset + 2, (int)authorityLen));
                authorityOffset += 2 + (int)authorityLen;
                correct &= pseudonym.AddAttestation(authority,
                    Attestation.Unserialize(serializedAttestations, authority, attestationOffset));
                attestationOffset += 32 + authority.GetSignatureLength();
            }

            return (correct, pseudonym);
        }

        private static uint ReadU32(byte[] data, int offset)
            => ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16)
               | ((uint)data[offset + 2] << 8) | data[offset + 3];

        private static uint ReadU16(byte[] data, int offset)
            => (uint)((data[offset] << 8) | data[offset + 1]);
    }
}
