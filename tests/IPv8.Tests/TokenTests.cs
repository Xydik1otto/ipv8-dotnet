// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPv8.Dht;
using IPv8.Keyvault;
using IPv8.Messaging;
using IPv8.Messaging.Interfaces.Udp;
using IPv8.PeerDiscovery;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>A8: str(node) byte-format and token generate/check vectors.</summary>
    public class TokenTests : IDisposable
    {
        private readonly UDPEndpoint _endpoint = OpenEndpoint();
        private readonly List<DhtCommunity> _communities = new List<DhtCommunity>();

        private static UDPEndpoint OpenEndpoint()
        {
            var endpoint = new UDPEndpoint(0, "127.0.0.1");
            Assert.True(endpoint.Open());
            return endpoint;
        }

        private DhtCommunity BuildCommunity(Peer myPeer)
        {
            var community = new DhtCommunity(
                new CommunitySettings(DhtCommunity.FixedCommunityId, myPeer, _endpoint, new Network()));
            community.MyEstimatedLan = _endpoint.GetAddress();
            community.MyEstimatedWan = _endpoint.GetAddress();
            _communities.Add(community);
            return community;
        }

        private static byte[] Hex(string hex) => Util.Unhex(hex);

        private static DhtNode NodeA
            => new DhtNode(Hex(Vectors1b.MetaKey("alice_pub_bin_hex")), Address.Udpv4("127.0.0.1", 7000));

        public void Dispose()
        {
            foreach (var community in _communities)
            {
                community.Unload();
            }
            _endpoint.Close();
        }

        [Fact]
        public void Str_Node_Byte_Format_Matches_Vector()
        {
            Assert.Equal(Vectors1b.TokenStr, NodeA.ToString());
        }

        [Fact]
        public void Generate_Token_Matches_Vector()
        {
            var community = BuildCommunity(new Peer(ECCrypto.Default.GenerateKey("curve25519")));
            community.TokenSecrets.Clear();
            community.TokenSecrets.Add(Hex(Vectors1b.TokenSecretHex));

            Assert.Equal(Vectors1b.TokenHex, Convert.ToHexString(community.GenerateToken(NodeA)).ToLowerInvariant());
        }

        [Fact]
        public void Check_Token_Accepts_Current_Secrets_And_Rejects_Stale()
        {
            var community = BuildCommunity(new Peer(ECCrypto.Default.GenerateKey("curve25519")));
            var node = NodeA;
            var nodeString = node.ToString();

            var secret1 = Util.Sha1(Util.Utf8("secret-one"));
            var secret2 = Util.Sha1(Util.Utf8("secret-two"));
            var secret3 = Util.Sha1(Util.Utf8("secret-three"));

            // Both secrets in the (maxlen 2) list are accepted.
            community.TokenSecrets.Clear();
            community.TokenSecrets.Add(secret1);
            community.TokenSecrets.Add(secret2);
            Assert.True(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret1))));
            Assert.True(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret2))));
            Assert.False(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret3))));

            // One maintenance appends a fresh secret and drops the oldest (deque maxlen 2): secret1
            // is now rejected, secret2 still accepted.
            community.TokenMaintenance();
            Assert.Equal(2, community.TokenSecrets.Count);
            Assert.False(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret1))));
            Assert.True(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret2))));

            // Another maintenance: secret2 dropped from the list — now rejected too.
            community.TokenMaintenance();
            Assert.False(community.CheckToken(node, Util.Sha1(Util.Concat(Util.Utf8(nodeString), secret2))));
        }

        [Fact]
        public void Token_Maintenance_Cleans_Expired_Tokens()
        {
            var community = BuildCommunity(new Peer(ECCrypto.Default.GenerateKey("curve25519")));
            var node = NodeA;
            var nodeId = node.Id;
            community.Tokens[nodeId] = (Util.NowEpoch() - DhtCommunity.TokenExpirationTime - 1,
                                        Util.Sha1(Util.Utf8("expired")));
            community.TokenMaintenance();
            Assert.False(community.Tokens.ContainsKey(nodeId));
        }

        [Fact]
        public void Serialized_Values_Roundtrip_Through_Unserialize()
        {
            var community = BuildCommunity(new Peer(ECCrypto.Default.GenerateKey("curve25519")));
            var data = Encoding.UTF8.GetBytes("some dht value");

            // Unsigned values serialize as [0x00] + data and unserialize to (data, null, 0).
            var unsigned = community.SerializeValue(data, sign: false);
            Assert.Equal(new byte[] { 0x00 }, unsigned.Take(1).ToArray());
            Assert.Equal(Util.Concat(new byte[] { 0x00 }, data), unsigned);
            var unserialized = community.UnserializeValue(unsigned);
            Assert.True(unserialized.HasValue);
            Assert.Equal(data, unserialized.Value.Data);
            Assert.Null(unserialized.Value.PublicKey);
            Assert.Equal(0, unserialized.Value.Version);

            // Signed values serialize as [0x01] + payload + signature and verify on unserialize.
            var signed = community.SerializeValue(data, sign: true);
            Assert.Equal(0x01, signed[0]);
            var signedUnserialized = community.UnserializeValue(signed);
            Assert.True(signedUnserialized.HasValue);
            Assert.Equal(data, signedUnserialized.Value.Data);
            Assert.Equal(community.MyPeer.PublicKey.KeyToBin(), signedUnserialized.Value.PublicKey);
            Assert.True(signedUnserialized.Value.Version > 0);

            // A tampered signature must fail.
            var tampered = (byte[])signed.Clone();
            tampered[^1] ^= 0xFF;
            Assert.False(community.UnserializeValue(tampered).HasValue);
        }
    }
}
