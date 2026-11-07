// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.IO;
using IPv8.Attestation.Identity;
using IdentityAttestation = IPv8.Attestation.Identity.Attestation;
using IPv8.Attestation.TokenTree;
using IPv8.Database;
using IPv8.Keyvault;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>A16: database shim (no native SQLite) — JSON persistence, transactions, identity storage.</summary>
    public class DatabaseShimTests : IDisposable
    {
        private readonly List<string> _tempFiles = new List<string>();

        private string TempDbPath()
        {
            var path = Path.Combine(Path.GetTempPath(), $"ipv8test-{Guid.NewGuid():N}.json");
            _tempFiles.Add(path);
            return path;
        }

        public void Dispose()
        {
            foreach (var file in _tempFiles)
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }
        }

        // ------------------------------------------------------------------
        // MiniJson (json.dumps byte-compatibility)
        // ------------------------------------------------------------------

        [Fact]
        public void MiniJson_Dumps_Uses_Python_Separators()
        {
            // py: json.dumps({"a": 1, "b": "x"}) == '{"a": 1, "b": "x"}'
            var dumped = MiniJson.PythonDumps(JsonDict.Of(("a", 1L), ("b", "x")));
            Assert.Equal("{\"a\": 1, \"b\": \"x\"}", dumped);
        }

        [Fact]
        public void MiniJson_Dumps_Escapes_NonAscii_Like_EnsureAscii()
        {
            // py: json.dumps({"s": "тест"}, ensure_ascii=True)
            var dumped = MiniJson.PythonDumps(JsonDict.Of(("s", "тест")));
            Assert.Equal("{\"s\": \"\\u0442\\u0435\\u0441\\u0442\"}", dumped);
        }

        [Fact]
        public void MiniJson_Dumps_Floats_As_Python_Repr()
        {
            var dumped = MiniJson.PythonDumps(JsonDict.Of(("f", 1.5), ("g", 2.0)));
            Assert.Equal("{\"f\": 1.5, \"g\": 2.0}", dumped);
        }

        [Fact]
        public void MiniJson_Dumps_Nested_And_Bool_Null()
        {
            var dumped = MiniJson.PythonDumps(JsonDict.Of(
                ("list", new object[] { 1L, "two", false }),
                ("none", null),
                ("true", true)));
            Assert.Equal("{\"list\": [1, \"two\", false], \"none\": null, \"true\": true}", dumped);
        }

        [Fact]
        public void MiniJson_Bytes_Tag_Roundtrip()
        {
            var payload = new byte[] { 0x00, 0x01, 0xfe, 0xff };
            var dumped = MiniJson.PythonDumps(JsonDict.Of(("b", payload)));
            var parsed = (Dictionary<string, object>)MiniJson.Parse(dumped);
            var restored = MiniJson.DecodeBytesMarkers(parsed["b"]);
            Assert.IsType<byte[]>(restored);
            Assert.Equal(payload, (byte[])restored);
        }

        [Fact]
        public void MiniJson_Parse_Roundtrip_Types()
        {
            const string json = "{\"i\": 42, \"f\": 3.5, \"s\": \"ok\", \"t\": true, \"n\": null, "
                                + "\"l\": [1, 2]}";
            var parsed = (Dictionary<string, object>)MiniJson.Parse(json);
            Assert.Equal(42L, parsed["i"]);
            Assert.Equal(3.5, parsed["f"]);
            Assert.Equal("ok", parsed["s"]);
            Assert.Equal(true, parsed["t"]);
            Assert.Null(parsed["n"]);
            Assert.Equal(new object[] { 1L, 2L }, parsed["l"]);
        }

        [Fact]
        public void MiniJson_Parse_Rejects_Garbage()
        {
            // py json.loads raises a (JSON)DecodeError; the .NET analog is FormatException.
            Assert.Throws<FormatException>(() => MiniJson.Parse("{not json"));
        }

        // ------------------------------------------------------------------
        // Database shim mechanics
        // ------------------------------------------------------------------

        private sealed class TestDatabase : IPv8.Database.Database
        {
            public TestDatabase(string path) : base(path)
            {
            }

            public void Build()
            {
                CreateTable("kv", new[] { "k" });
            }

            public void Put(string key, object value, bool orIgnore = false)
            {
                var row = new DbRow();
                row["k"] = key;
                row["v"] = value;
                Insert("kv", row, orIgnore);
            }

            public List<DbRow> All() => Select("kv");

            public List<DbRow> Rows(params (string Column, object Value)[] where) => Select("kv", where);

            public new int Delete(string table, params (string Column, object Value)[] where)
                => base.Delete(table, where);

            protected override int CheckDatabase(byte[] databaseVersion) => 1;
        }

        [Fact]
        public void Database_Open_Twice_Throws()
        {
            var db = new TestDatabase(TempDbPath());
            Assert.True(db.Open());
            Assert.Throws<DatabaseException>(() => db.Open());
            Assert.True(db.Close());
        }

        [Fact]
        public void Database_Close_Without_Open_Throws()
        {
            var db = new TestDatabase(TempDbPath());
            Assert.Throws<DatabaseException>(() => db.Close());
        }

        [Fact]
        public void Database_Insert_Select_Delete_Roundtrip()
        {
            var db = new TestDatabase(TempDbPath());
            db.Open();
            db.Build();
            db.Put("a", "alpha");
            db.Put("b", 42L);
            db.Commit();
            Assert.Equal(2, db.All().Count);
            db.Delete("kv", ("k", "a"));
            Assert.Single(db.All());
            db.Close();
        }

        [Fact]
        public void Database_Insert_OrIgnore_Duplicates()
        {
            var db = new TestDatabase(TempDbPath());
            db.Open();
            db.Build();
            db.Put("a", "one");
            db.Put("a", "two", orIgnore: true);
            var rows = db.Rows(("k", "a"));
            Assert.Single(rows);
            Assert.Equal("one", rows[0].GetString("v"));
            db.Close();
        }

        [Fact]
        public void Database_Commit_Persists_To_File()
        {
            var path = TempDbPath();
            var db = new TestDatabase(path);
            db.Open();
            db.Build();
            db.Put("key", "value");
            db.Commit();
            db.Close();

            Assert.True(File.Exists(path));
            var db2 = new TestDatabase(path);
            db2.Open();
            db2.Build();
            var rows = db2.Rows(("k", "key"));
            Assert.Single(rows);
            Assert.Equal("value", rows[0].GetString("v"));
            db2.Close();
        }

        [Fact]
        public void Database_Transaction_Commits_And_IgnoreCommits_Drops()
        {
            var path = TempDbPath();
            var db = new TestDatabase(path);
            db.Open();
            db.Build();

            // Normal transaction: deferred commit is applied on exit.
            db.RunInTransaction(() =>
            {
                db.Put("kept", "yes");
                db.Commit();
            });
            Assert.Single(db.All());

            // IgnoreCommits (py ``with database:``): the reference never executes COMMIT, so the
            // inserted rows stay visible on the open connection but are never flushed to disk.
            db.RunInTransaction(() =>
            {
                db.Put("dropped", "no");
                db.Commit();
                throw new IgnoreCommits();
            });
            Assert.Equal(2, db.All().Count);

            // Closing without commit discards the open transaction: the file keeps only "kept".
            db.Close(commit: false);
            var db2 = new TestDatabase(path);
            db2.Open();
            db2.Build();
            Assert.Single(db2.All());
            Assert.Empty(db2.Rows(("k", "dropped")));
            db2.Close();
        }

        [Fact]
        public void Database_Other_Exceptions_Propagate()
        {
            var db = new TestDatabase(TempDbPath());
            db.Open();
            db.Build();
            Assert.Throws<InvalidOperationException>(() => db.RunInTransaction(() =>
            {
                db.Put("x", "y");
                throw new InvalidOperationException("boom");
            }));
            db.Close();
        }

        [Fact]
        public void Database_Memory_Backend_Needs_No_File()
        {
            var db = new TestDatabase(":memory:");
            Assert.True(db.Open());
            db.Build();
            db.Put("m", "mem");
            Assert.Single(db.All());
            db.Close();
            Assert.False(File.Exists(":memory:"));
        }

        // ------------------------------------------------------------------
        // IdentityDatabase (A16 acceptance: identity storage over the shim)
        // ------------------------------------------------------------------

        private static Keyvault.PrivateKey Gen()
            => (Keyvault.PrivateKey)ECCrypto.Default.GenerateKey("curve25519");

        [Fact]
        public void IdentityDatabase_Token_Metadata_Attestation_Roundtrip()
        {
            var db = new IdentityDatabase(TempDbPath());
            Assert.True(db.Open());
            Assert.Equal(IdentityDatabase.LatestDbVersion, db.DatabaseVersion);

            var subject = Gen();
            var authority = Gen();
            var publicKey = (Keyvault.PublicKey)subject.Pub();

            var genesis = new Token(new byte[32], new byte[] { 1, 2, 3 }, null, subject, null);
            var child = new Token(genesis.GetHash(), new byte[] { 4, 5, 6 }, null, subject, null);
            db.InsertToken(publicKey, genesis);
            db.InsertToken(publicKey, child);

            var metadata = new Metadata(child.GetHash(),
                                        Util.Utf8(MiniJson.PythonDumps(
                                            JsonDict.Of(("name", "my_field"), ("date", 12L)))),
                                        subject, null);
            db.InsertMetadata(publicKey, metadata);

            var attestation = IdentityAttestation.Create(metadata, authority);
            db.InsertAttestation(publicKey, (Keyvault.PublicKey)authority.Pub(), attestation);

            // Tokens for the subject are loaded back (both of them).
            var tokens = db.GetTokensFor(publicKey);
            Assert.Equal(2, tokens.Count);

            // Metadata roundtrips with identical bytes.
            var metadataSet = db.GetMetadataFor(publicKey);
            Assert.Single(metadataSet);
            var loadedMetadata = new List<Metadata>(metadataSet)[0];
            Assert.True(Util.BytesEqual(metadata.GetPlaintextSigned(),
                                        loadedMetadata.GetPlaintextSigned()));

            // Attestations over the metadata carry the authority key back.
            var over = db.GetAttestationsOver(loadedMetadata);
            Assert.Single(over);
            var loadedAttestation = new List<IdentityAttestation>(over)[0];
            Assert.True(Util.BytesEqual(loadedAttestation.GetPlaintextSigned(),
                                        attestation.GetPlaintextSigned()));
            Assert.True(Util.BytesEqual(authority.Pub().KeyToBin(), db.GetAuthority(loadedAttestation)));

            // Credential view.
            var credentials = db.GetCredentialsFor(publicKey);
            Assert.Single(credentials);
            Assert.True(Util.BytesEqual(metadata.GetHash(), credentials[0].Metadata.GetHash()));
            Assert.Equal(1, credentials[0].Attestations.Count);

            // Known identities lists exactly the subject.
            var known = db.GetKnownIdentities();
            Assert.Single(known);
            Assert.True(Util.BytesEqual(publicKey.KeyToBin(), known[0]));

            db.Close();
        }

        [Fact]
        public void IdentityDatabase_Empty_Getters()
        {
            var db = new IdentityDatabase(":memory:");
            db.Open();
            Assert.Empty(db.GetKnownIdentities());
            Assert.Empty(db.GetCredentialsFor((Keyvault.PublicKey)Gen().Pub()));
            db.Close();
        }
    }
}
