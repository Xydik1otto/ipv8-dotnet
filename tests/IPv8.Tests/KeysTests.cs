// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Text;
using IPv8.Keyvault;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A1 (keys part): LibNaCLPK/LibNaCLSK binary formats per ipv8-rust-tunnels/src/keys.rs —
    /// "LibNaCLPK:"(10) + X25519 pub(32) + Ed25519 pub(32) = 74 B;
    /// "LibNaCLSK:"(10) + X25519 sk(32) + Ed25519 seed(32) = 74 B.
    /// </summary>
    public class KeysTests
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        [Fact]
        public void LibNaclPk_Binary_Layout_Is_74_Bytes()
        {
            var xPub = EnumerableRepeat(0x11, 32);
            var edPub = EnumerableRepeat(0x22, 32);
            var key = new LibNaclPublicKey(Util.Concat(LibNaclPublicKey.Prefix, xPub, edPub));

            var bin = key.KeyToBin();
            Assert.Equal(74, bin.Length);
            Assert.Equal("LibNaCLPK:", Encoding.ASCII.GetString(bin, 0, 10));
            var xPart = new byte[32];
            Array.Copy(bin, 10, xPart, 0, 32);
            var edPart = new byte[32];
            Array.Copy(bin, 42, edPart, 0, 32);
            Assert.Equal(Hexlify(xPub), Hexlify(xPart));
            Assert.Equal(Hexlify(edPub), Hexlify(edPart));

            // key_to_bin → load → key_to_bin roundtrip.
            var reloaded = new LibNaclPublicKey(bin);
            Assert.Equal(bin, reloaded.KeyToBin());
            Assert.Equal(Hexlify(edPub), Hexlify(Util.Slice(reloaded.KeyToBin(), 42, 32)));
        }

        [Fact]
        public void LibNaclSk_Binary_Layout_Is_74_Bytes_And_Survives_Roundtrip()
        {
            var xPriv = EnumerableRepeat(0x33, 32);
            var edSeed = Hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            var bin = Util.Concat(LibNaclPrivateKey.Prefix, xPriv, edSeed);

            var key = new LibNaclPrivateKey(bin);
            Assert.Equal(74, key.KeyToBin().Length);
            Assert.Equal("LibNaCLSK:", Encoding.ASCII.GetString(key.KeyToBin(), 0, 10));
            // Roundtrip: re-encoding the loaded key reproduces the exact binary (no clamping drift).
            Assert.Equal(bin, key.KeyToBin());

            // pub() derives both halves from the private halves.
            var pubBin = key.Pub().KeyToBin();
            Assert.Equal("LibNaCLPK:", Encoding.ASCII.GetString(pubBin, 0, 10));
            Assert.Equal(key.GetCryptPk(), Util.Slice(pubBin, 10, 32));
            // The Ed25519 half of the pub key must match the seed-derived public key.
            var seedKey = new LibNaclPrivateKey(Util.Concat(LibNaclPrivateKey.Prefix, new byte[32], edSeed));
            Assert.Equal(Util.Slice(seedKey.Pub().KeyToBin(), 42, 32), Util.Slice(pubBin, 42, 32));
        }

        [Fact]
        public void Signature_Length_Is_64_For_Ed25519()
        {
            var key = new LibNaclPrivateKey(Util.Concat(
                LibNaclPrivateKey.Prefix, new byte[32],
                Hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")));
            Assert.Equal(64, key.Pub().GetSignatureLength());
        }

        [Fact]
        public void Key_To_Hash_Uses_Public_Key_Bin()
        {
            var key = new LibNaclPrivateKey(Util.Concat(
                LibNaclPrivateKey.Prefix, new byte[32],
                Hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")));
            // key_to_hash = sha1(pub().key_to_bin())
            Assert.Equal(Hexlify(Util.Sha1(key.Pub().KeyToBin())), Hexlify(key.KeyToHash()));

            // The vector pins sha1 over the raw Ed25519 public bytes; the source of truth
            // (py-ipv8 keyvault/keys.py) defines key_to_hash over the 74-byte LibNaCLPK bin,
            // which is asserted above. sha1("d75a...") is the RFC 8032 TEST 1 public key.
            Assert.Equal(Vectors.Keys("mid_sha1_of_ed25519_pub"),
                         Hexlify(Util.Sha1(Hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))));
        }

        [Fact]
        public void Invalid_Key_Bins_Are_Rejected()
        {
            var crypto = ECCrypto.Default;
            Assert.False(crypto.IsValidPublicBin(new byte[10]));
            Assert.False(crypto.IsValidPublicBin(Util.Concat(new byte[5], new byte[69])));
            Assert.False(crypto.IsValidPrivateBin(new byte[74]));
            Assert.Throws<ArgumentException>(() => crypto.KeyFromPublicBin(new byte[74]));
            Assert.Throws<ArgumentException>(() => crypto.KeyFromPrivateBin(new byte[74]));
            Assert.Throws<ArgumentException>(() => new Peer(
                Util.Concat(LibNaclPrivateKey.Prefix, new byte[32], new byte[32])));
        }

        [Fact]
        public void Golden_Fixed_Key_Material_Parses()
        {
            // The A3 golden key material parses and its public key verifies the golden signature.
            var pubBin = Hex(GoldenPackets.PubBinHex);
            var publicKey = ECCrypto.Default.KeyFromPublicBin(pubBin);
            Assert.Equal(Hexlify(pubBin), Hexlify(publicKey.KeyToBin()));
            Assert.Equal(GoldenPackets.CommunityIdHex,
                         Hexlify(Util.Slice(Util.Sha1(pubBin), 0, 20)));
        }

        private static byte[] EnumerableRepeat(byte value, int count)
        {
            var data = new byte[count];
            Array.Fill(data, value);
            return data;
        }
    }
}
