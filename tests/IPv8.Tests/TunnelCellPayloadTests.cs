// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Text.Json;
using IPv8.Messaging;
using IPv8.Messaging.Anonymization;
using IPv8.Messaging.Interfaces;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// B2: cell payload wire-exact golden cells from contract/vectors-phase3.json
    /// (pack + unpack + unwrap + negatives). The vectors were generated with py-ipv8's
    /// real anonymization payload classes.
    /// </summary>
    public class TunnelCellPayloadTests
    {
        private static readonly byte[] Prefix = Vectors3.Unhex(Vectors3.MetaKey("prefix_hex"));

        private static Address ParseAddress(JsonElement entry, string key)
        {
            var pair = entry.GetProperty(key);
            return Address.Udpv4(pair[0].GetString(), pair[1].GetInt32());
        }

        private static void AssertCellSection(string name, CellablePayload payload, JsonElement entry)
        {
            // 1. cell.message == msg_id(1B) + pack_serializable(payload)[4:]
            //    (circuit_id moved from the payload into the cell header, py send_cell).
            var serializer = new Serializer();
            var packed = serializer.PackSerializable(payload);
            var message = Util.Concat(new[] { (byte)payload.MsgNum }, Util.SliceFrom(packed, 4));
            Assert.Equal(Vectors3.HexString(entry, "message_hex"), Vectors3.Hex(message));

            // 2. to_bin == golden cell wire.
            var cell = new CellPayload(entry.GetProperty("circuit_id").GetInt64(), message,
                                       entry.GetProperty("plaintext").GetBoolean(),
                                       entry.GetProperty("relay_early").GetBoolean());
            var wire = cell.ToBin(Prefix);
            Assert.Equal(Vectors3.HexString(entry, "cell_wire_hex"), Vectors3.Hex(wire));

            // 3. from_bin roundtrip.
            var reparsed = CellPayload.FromBin(wire);
            Assert.Equal(cell.CircuitId, reparsed.CircuitId);
            Assert.Equal(cell.Plaintext, reparsed.Plaintext);
            Assert.Equal(cell.RelayEarly, reparsed.RelayEarly);
            Assert.Equal(Vectors3.Hex(message), Vectors3.Hex(reparsed.Message));

            // 4. unwrap == golden unwrapped packet, and the unwrapped packet unpacks at
            //    offset 23 (py-ipv8 unpack_cell) to the same field values.
            var unwrapped = cell.Unwrap(Prefix);
            Assert.Equal(Vectors3.HexString(entry, "unwrapped_hex"), Vectors3.Hex(unwrapped));
            var unpacked = serializer.UnpackSerializable(payload.GetType(), unwrapped, 23).Payload;
            Assert.Equal(Vectors3.Hex(serializer.PackSerializable(unpacked)),
                         Vectors3.Hex(packed));
        }

        [Fact]
        public void GoldenCell_Create()
        {
            var entry = Vectors3.Section("cells").GetProperty("create");
            var payload = new CreatePayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64(),
                Vectors3.Hex(entry, "node_public_key_hex"),
                Vectors3.Hex(entry, "key_hex"));
            Assert.Equal(2, CreatePayload.MsgId);
            AssertCellSection("create", payload, entry);
        }

        [Fact]
        public void GoldenCell_Created()
        {
            var entry = Vectors3.Section("cells").GetProperty("created");
            var payload = new CreatedPayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64(),
                Vectors3.Hex(entry, "key_hex"),
                Vectors3.Hex(entry, "auth_hex"),
                Vectors3.Hex(entry, "candidates_enc_hex"));
            Assert.Equal(3, CreatedPayload.MsgId);
            AssertCellSection("created", payload, entry);
        }

        [Fact]
        public void GoldenCell_Extend()
        {
            var entry = Vectors3.Section("cells").GetProperty("extend");
            var payload = new ExtendPayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64(),
                Vectors3.Hex(entry, "node_public_key_hex"),
                Vectors3.Hex(entry, "key_hex"),
                ParseAddress(entry, "node_addr"));
            Assert.Equal(4, ExtendPayload.MsgId);
            AssertCellSection("extend", payload, entry);
        }

        [Fact]
        public void GoldenCell_Extended()
        {
            var entry = Vectors3.Section("cells").GetProperty("extended");
            var payload = new ExtendedPayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64(),
                Vectors3.Hex(entry, "key_hex"),
                Vectors3.Hex(entry, "auth_hex"),
                Vectors3.Hex(entry, "candidates_enc_hex"));
            Assert.Equal(5, ExtendedPayload.MsgId);
            AssertCellSection("extended", payload, entry);
        }

        [Fact]
        public void GoldenCell_Ping()
        {
            var entry = Vectors3.Section("cells").GetProperty("ping");
            var payload = new PingPayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64());
            Assert.Equal(6, PingPayload.MsgId);
            AssertCellSection("ping", payload, entry);
        }

        [Fact]
        public void GoldenCell_Pong()
        {
            var entry = Vectors3.Section("cells").GetProperty("pong");
            var payload = new PongPayload(
                entry.GetProperty("circuit_id").GetInt64(),
                entry.GetProperty("identifier").GetInt64());
            Assert.Equal(7, PongPayload.MsgId);
            AssertCellSection("pong", payload, entry);
        }

        [Fact]
        public void EncryptedCells_WireExact()
        {
            var ping = Vectors3.Section("encrypted_cells").GetProperty("ping");
            var pingCell = new CellPayload(ping.GetProperty("circuit_id").GetInt64(),
                                           Vectors3.Hex(ping, "message_encrypted_hex"),
                                           ping.GetProperty("plaintext").GetBoolean(),
                                           ping.GetProperty("relay_early").GetBoolean());
            Assert.Equal(Vectors3.HexString(ping, "cell_wire_hex"), Vectors3.Hex(pingCell.ToBin(Prefix)));

            var data = Vectors3.Section("encrypted_cells").GetProperty("data");
            var dataCell = new CellPayload(data.GetProperty("circuit_id").GetInt64(),
                                           Vectors3.Hex(data, "message_encrypted_hex"),
                                           data.GetProperty("plaintext").GetBoolean(),
                                           data.GetProperty("relay_early").GetBoolean());
            Assert.Equal(Vectors3.HexString(data, "cell_wire_hex"), Vectors3.Hex(dataCell.ToBin(Prefix)));

            // The encrypted message decrypts back to the plaintext ping message (msg 6).
            var shared = Vectors3.Hex(Vectors3.Section("encrypted_cells"), "shared_secret_hex");
            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var decrypted = keys.DecryptStr(Vectors3.Hex(ping, "message_encrypted_hex"), TunnelDirection.Forward);
            Assert.Equal(Vectors3.HexString(Vectors3.Section("cells").GetProperty("ping"), "message_hex"),
                         Vectors3.Hex(decrypted));
        }

        [Fact]
        public void CreatedHandshake_CellWireExact()
        {
            var handshake = Vectors3.Section("created_handshake");
            var circuitId = Vectors3.RootElement.GetProperty("meta").GetProperty("circuit_id").GetInt64();
            var cell = new CellPayload(circuitId,
                                       Vectors3.Hex(handshake, "created_message_hex"),
                                       true, false);
            Assert.Equal(Vectors3.HexString(handshake, "created_cell_wire_hex"), Vectors3.Hex(cell.ToBin(Prefix)));

            // The created cell carries the created payload in plaintext (NO_CRYPTO_PACKETS).
            var reparsed = CellPayload.FromBin(cell.ToBin(Prefix));
            Assert.True(reparsed.Plaintext);
            Assert.False(reparsed.RelayEarly);
        }

        [Fact]
        public void DataPayload_RoundtripWithListPayloads()
        {
            // Extra coverage for the payload classes beyond the golden six: the peers
            // response with nested IntroductionInfo list and the rendezvous payloads.
            var serializer = new Serializer();
            var peers = new List<IntroductionInfo>
            {
                new(Address.Udpv4("127.0.0.1", 7000), Vectors3.Unhex(PubBinB), Vectors3.Unhex("aabb".PadLeft(40, '0')), 2),
            };
            var payload = new PeersResponsePayload(0x11223344, 0xCAFE,
                                                   Vectors3.Unhex(new string('1', 40)), peers);
            var packed = serializer.PackSerializable(payload);
            var unpacked = (PeersResponsePayload)serializer.UnpackSerializable(typeof(PeersResponsePayload),
                                                                               packed).Payload;
            Assert.Equal(payload.CircuitId, unpacked.CircuitId);
            Assert.Equal(payload.Identifier, unpacked.Identifier);
            Assert.Single(unpacked.Peers);
            Assert.Equal(Address.Udpv4("127.0.0.1", 7000), unpacked.Peers[0].Address);
            Assert.Equal(2, unpacked.Peers[0].Source);
            Assert.Equal(PubBinB, Vectors3.Hex(unpacked.Peers[0].Key));
        }

        [Fact]
        public void FlagsPacker_Roundtrip()
        {
            var packer = new FlagsPacker();

            var packed = packer.Pack(new object[] { new object[] { 1, 2, 4 } });
            Assert.Equal(new byte[] { 0x00, 0x07 }, packed);

            var unpackList = new List<object>();
            var consumed = packer.Unpack(packed, 0, unpackList, Array.Empty<object>());
            Assert.Equal(2, consumed);
            Assert.Equal(new List<object> { 1, 2, 4 }, unpackList[0]);

            // Empty flags pack to zero and unpack to an empty list.
            var empty = packer.Pack(new object[] { Array.Empty<object>() });
            Assert.Equal(new byte[] { 0x00, 0x00 }, empty);
            var emptyList = new List<object>();
            packer.Unpack(empty, 0, emptyList, Array.Empty<object>());
            Assert.Empty((List<object>)emptyList[0]);

            // OR-combination: 1 | 2 | 8 | 16 = 27.
            Assert.Equal(new byte[] { 0x00, 0x1B }, packer.Pack(new object[] { new object[] { 1, 2, 8, 16 } }));
        }

        [Fact]
        public void CellPayload_Negatives()
        {
            var entry = Vectors3.Section("cells").GetProperty("ping");
            var wire = Vectors3.Hex(entry, "cell_wire_hex");

            // Tampered circuit_id: from_bin must report the tampered value (no integrity
            // check at this layer — the AEAD tag covers the message, not the header).
            var tampered = (byte[])wire.Clone();
            tampered[26] ^= 0x01;
            var reparsed = CellPayload.FromBin(tampered);
            Assert.NotEqual(entry.GetProperty("circuit_id").GetInt64(), reparsed.CircuitId);

            // Truncated packet (shorter than the 29-byte cell header) must throw.
            Assert.ThrowsAny<Exception>(() => CellPayload.FromBin(new byte[28]));

            // Tampered message body of an encrypted cell must fail the AEAD open.
            var ping = Vectors3.Section("encrypted_cells").GetProperty("ping");
            var encCell = Vectors3.Hex(ping, "cell_wire_hex");
            var shared = Vectors3.Hex(Vectors3.Section("encrypted_cells"), "shared_secret_hex");
            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var fromBin = CellPayload.FromBin(encCell);
            var tamperedBody = (byte[])fromBin.Message.Clone();
            tamperedBody[tamperedBody.Length - 1] ^= 0x01;
            Assert.Throws<CryptoException>(() => keys.DecryptStr(tamperedBody, TunnelDirection.Forward));
        }

        private static string PubBinB => Vectors3.MetaKeys("bob_pub_bin_hex");
    }
}
