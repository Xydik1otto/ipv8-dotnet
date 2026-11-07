// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Database;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;

    /// <summary>
    /// Database to store attestations
    /// (port of ipv8/attestation/wallet/database.py::AttestationsDB).
    ///
    /// DEVIATION: the py-ipv8 version runs SQL over native SQLite; this port stores the same
    /// rows over the pure-managed JSON-persisted Database shim (contract Phase 2 step 2a).
    /// </summary>
    public class AttestationsDB : IPv8.Database.Database
    {
        public const int LatestDbVersion = 2;

        private readonly string _tableName;

        public AttestationsDB(string workingDirectory, string dbName)
            : base(workingDirectory == ":memory:"
                       ? ":memory:"
                       : System.IO.Path.Combine(workingDirectory, "sqlite", dbName + ".db"))
        {
            _tableName = dbName;
            Open();
        }

        /// <summary>Retrieve a serialized attestation by hash (py get_attestation_by_hash).</summary>
        public List<byte[]> GetAttestationByHash(byte[] attestationHash)
        {
            var row = SelectFirst(_tableName, ("hash", attestationHash));
            var blob = row?.GetBytes("blob");
            return blob == null ? new List<byte[]>() : new List<byte[]> { blob };
        }

        /// <summary>Get all serialized attestations we know of (py get_all).</summary>
        public List<(byte[] Hash, byte[] Blob, byte[] Key, byte[] IdFormat)> GetAll()
        {
            var result = new List<(byte[] Hash, byte[] Blob, byte[] Key, byte[] IdFormat)>();
            foreach (var row in Select(_tableName))
            {
                result.Add((row.GetBytes("hash"), row.GetBytes("blob"), row.GetBytes("key"),
                            row.GetBytes("id_format")));
            }
            return result;
        }

        /// <summary>Insert an attestation into the database.</summary>
        public void InsertAttestation(Attestation attestation, byte[] attestationHash,
                                      BonehPrivateKey secretKey, string idFormat)
        {
            var blob = attestation.SerializePrivateKey(secretKey.PublicKey());
            CreateTable(_tableName, new[] { "hash" });
            Insert(_tableName, new DbRow
            {
                ["hash"] = attestationHash,
                ["blob"] = blob,
                ["key"] = secretKey.Serialize(),
                ["id_format"] = Util.Utf8(idFormat)
            }, orIgnore: false);
            Commit();
        }

        protected override int CheckDatabase(byte[] databaseVersion)
        {
            CreateTable(_tableName, new[] { "hash" });
            return LatestDbVersion;
        }
    }
}
