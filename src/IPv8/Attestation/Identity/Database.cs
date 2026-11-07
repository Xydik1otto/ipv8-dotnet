// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using IPv8.Database;
using IPv8.Keyvault;

namespace IPv8.Attestation.Identity
{
    /// <summary>Cache for Metadata ← [Attestation] mappings (py identity/database.py::Credential).</summary>
    public sealed class Credential
    {
        public Credential(Metadata metadata, ISet<Attestation> attestations)
        {
            Metadata = metadata;
            Attestations = attestations;
        }

        public Metadata Metadata { get; }

        public ISet<Attestation> Attestations { get; }
    }

    /// <summary>
    /// Database to store identity layer data
    /// (port of ipv8/attestation/identity/database.py::IdentityDatabase).
    ///
    /// DEVIATION: the py-ipv8 version runs SQL over native SQLite; this port stores the same
    /// rows/primary keys over the pure-managed JSON-persisted Database shim.
    /// </summary>
    public class IdentityDatabase : IPv8.Database.Database
    {
        public const int LatestDbVersion = 1;

        private const string TokensTable = "Tokens";
        private const string MetadataTable = "Metadata";
        private const string AttestationsTable = "Attestations";

        public IdentityDatabase(string databasePath) : base(databasePath)
        {
        }

        /// <summary>Inject a Token belonging to a certain public key into this database.</summary>
        public void InsertToken(PublicKey publicKey, TokenTree.Token token)
        {
            var (previousTokenHash, signature, contentHash, content) = token.ToDatabaseTuple();
            CreateTable(TokensTable, new[] { "public_key", "previous_token_hash", "content_hash" });
            var row = new DbRow
            {
                ["public_key"] = publicKey.KeyToBin(),
                ["previous_token_hash"] = previousTokenHash,
                ["signature"] = signature,
                ["content_hash"] = contentHash,
                ["content"] = content
            };
            Insert(TokensTable, row, orIgnore: true);
            Commit();
        }

        /// <summary>Inject Metadata belonging to a certain public key into this database.</summary>
        public void InsertMetadata(PublicKey publicKey, Metadata metadata)
        {
            var (tokenPointer, signature, serializedJsonDict) = metadata.ToDatabaseTuple();
            CreateTable(MetadataTable, new[] { "public_key", "token_pointer" });
            var row = new DbRow
            {
                ["public_key"] = publicKey.KeyToBin(),
                ["token_pointer"] = tokenPointer,
                ["signature"] = signature,
                ["serialized_json_dict"] = serializedJsonDict
            };
            Insert(MetadataTable, row, orIgnore: true);
            Commit();
        }

        /// <summary>Inject an Attestation made by some authority for a certain public key.</summary>
        public void InsertAttestation(PublicKey publicKey, PublicKey authorityKey, Attestation attestation)
        {
            var (metadataPointer, signature) = attestation.ToDatabaseTuple();
            CreateTable(AttestationsTable, new[] { "public_key", "metadata_pointer" });
            var row = new DbRow
            {
                ["public_key"] = publicKey.KeyToBin(),
                ["authority_key"] = authorityKey.KeyToBin(),
                ["metadata_pointer"] = metadataPointer,
                ["signature"] = signature
            };
            Insert(AttestationsTable, row, orIgnore: true);
            Commit();
        }

        /// <summary>Get all tokens in the tree of a certain public key.</summary>
        public ISet<TokenTree.Token> GetTokensFor(PublicKey publicKey)
        {
            var rows = Select(TokensTable, ("public_key", publicKey.KeyToBin()));
            var result = new HashSet<TokenTree.Token>();
            foreach (var row in rows)
            {
                result.Add(TokenTree.Token.FromDatabaseTuple(
                    row.GetBytes("previous_token_hash"), row.GetBytes("signature"),
                    row.GetBytes("content_hash"), row.GetBytes("content")));
            }
            return result;
        }

        /// <summary>Get all known metadata for a certain public key.</summary>
        public ISet<Metadata> GetMetadataFor(PublicKey publicKey)
        {
            var rows = Select(MetadataTable, ("public_key", publicKey.KeyToBin()));
            var result = new HashSet<Metadata>();
            foreach (var row in rows)
            {
                result.Add(Metadata.FromDatabaseTuple(
                    row.GetBytes("token_pointer"), row.GetBytes("signature"),
                    row.GetBytes("serialized_json_dict")));
            }
            return result;
        }

        /// <summary>Get all known attestations (made by others) for a certain public key.</summary>
        public ISet<Attestation> GetAttestationsFor(PublicKey publicKey)
        {
            var rows = Select(AttestationsTable, ("public_key", publicKey.KeyToBin()));
            return RowsToAttestations(rows);
        }

        /// <summary>Get all attestations made by a certain public key (for others).</summary>
        public ISet<Attestation> GetAttestationsBy(PublicKey publicKey)
        {
            var rows = Select(AttestationsTable, ("authority_key", publicKey.KeyToBin()));
            return RowsToAttestations(rows);
        }

        /// <summary>Get all known attestations for given metadata.</summary>
        public ISet<Attestation> GetAttestationsOver(Metadata metadata)
        {
            var rows = Select(AttestationsTable, ("metadata_pointer", metadata.GetHash()));
            return RowsToAttestations(rows);
        }

        private static ISet<Attestation> RowsToAttestations(IEnumerable<DbRow> rows)
        {
            var result = new HashSet<Attestation>();
            foreach (var row in rows)
            {
                result.Add(Attestation.FromDatabaseTuple(
                    row.GetBytes("metadata_pointer"), row.GetBytes("signature")));
            }
            return result;
        }

        /// <summary>Retrieve the authority that created a certain attestation.</summary>
        public byte[] GetAuthority(Attestation attestation)
        {
            var row = SelectFirst(AttestationsTable, ("signature", attestation.Signature));
            return row?.GetBytes("authority_key");
        }

        /// <summary>Collect all attestations for the given metadata, forming a credential.</summary>
        public Credential GetCredentialOver(Metadata metadata)
            => new Credential(metadata, GetAttestationsOver(metadata));

        /// <summary>Get all credentials for a given public key.</summary>
        public List<Credential> GetCredentialsFor(PublicKey publicKey)
        {
            return GetMetadataFor(publicKey)
                .Select(metadata => new Credential(metadata, GetAttestationsOver(metadata)))
                .ToList();
        }

        /// <summary>List the public keys of all known identity owners (py: SELECT public_key FROM Tokens).</summary>
        public List<byte[]> GetKnownIdentities()
        {
            // The reference queries ONLY the Tokens table here — do not add Metadata/Attestations.
            var result = new List<byte[]>();
            var seen = new HashSet<byte[]>(ByteArrayEqualityComparer.Instance);
            foreach (var row in Select(TokensTable))
            {
                var publicKey = row.GetBytes("public_key");
                if (publicKey != null && seen.Add(publicKey))
                {
                    result.Add(publicKey);
                }
            }
            return result;
        }

        protected override int CheckDatabase(byte[] databaseVersion)
        {
            // This is where an existing schema would be upgraded: no changes, nothing to upgrade.
            CreateTable(TokensTable, new[] { "public_key", "previous_token_hash", "content_hash" });
            CreateTable(MetadataTable, new[] { "public_key", "token_pointer" });
            CreateTable(AttestationsTable, new[] { "public_key", "metadata_pointer" });
            return LatestDbVersion;
        }
    }
}
