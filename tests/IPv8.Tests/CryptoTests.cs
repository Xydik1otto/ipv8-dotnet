// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using IPv8.Keyvault;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>A1: crypto golden tests from vectors.json → crypto (RFC 8032 TEST 1/2, RFC 7748 §6.1).</summary>
    public class CryptoTests
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        private static byte[] MakePrivateKeyBin(byte[] x25519Priv, byte[] ed25519Seed)
            => Util.Concat(LibNaclPrivateKey.Prefix, x25519Priv, ed25519Seed);

        private static byte[] MakePublicKeyBin(byte[] x25519Pub, byte[] ed25519Pub)
            => Util.Concat(LibNaclPublicKey.Prefix, x25519Pub, ed25519Pub);

        [Fact]
        public void Ed25519_Rfc8032_Test1_DeriveSignVerify()
        {
            var seed = Hex(Vectors.CryptoField("ed25519_rfc8032_test1", "seed"));
            var key = new LibNaclPrivateKey(MakePrivateKeyBin(new byte[32], seed));

            // Public key derivation from the seed (vector: d75a9801...).
            var pubBin = key.Pub().KeyToBin();
            var edPub = new byte[32];
            Array.Copy(pubBin, 42, edPub, 0, 32);
            Assert.Equal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", Hexlify(edPub));

            // Sign the empty message: RFC 8032 TEST 1 signature.
            var msg = Array.Empty<byte>();
            var signature = key.Signature(msg);
            Assert.Equal(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                Hexlify(signature));

            // Verify with the RFC public key; must reject a signature over a different message.
            var publicKey = new LibNaclPublicKey(
                MakePublicKeyBin(new byte[32], Hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
            Assert.True(publicKey.Verify(signature, msg));
            Assert.False(publicKey.Verify(signature, new byte[] { 0x72 }));
        }

        [Fact]
        public void Ed25519_Rfc8032_Test2_DeriveSignVerify()
        {
            var seed = Hex(Vectors.CryptoField("ed25519_rfc8032_test2", "seed"));
            var key = new LibNaclPrivateKey(MakePrivateKeyBin(new byte[32], seed));

            var pubBin = key.Pub().KeyToBin();
            var edPub = new byte[32];
            Array.Copy(pubBin, 42, edPub, 0, 32);
            Assert.Equal("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", Hexlify(edPub));

            var msg = new byte[] { 0x72 };
            var signature = key.Signature(msg);
            Assert.Equal(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                Hexlify(signature));

            var publicKey = new LibNaclPublicKey(
                MakePublicKeyBin(new byte[32], Hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")));
            Assert.True(publicKey.Verify(signature, msg));
        }

        [Fact]
        public void X25519_Rfc7748_6_1_DiffieHellman()
        {
            // Raw X25519 through the LibNaCL key path: crypt key = alice, peer = bob (RFC 7748 §6.1).
            var alicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            var bobPriv = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            var alicePub = Hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
            var bobPub = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
            var expectedShared = Hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            var aliceKey = new LibNaclPrivateKey(MakePrivateKeyBin(alicePriv, new byte[32]));
            var bobKey = new LibNaclPrivateKey(MakePrivateKeyBin(bobPriv, new byte[32]));

            // Public key derivation (RFC 7748 §6.1).
            Assert.Equal(Hexlify(alicePub), Hexlify(aliceKey.GetCryptPk()));
            Assert.Equal(Hexlify(bobPub), Hexlify(bobKey.GetCryptPk()));

            // Diffie-Hellman both ways must produce the shared secret.
            var sharedAb = aliceKey.DiffieHellman(bobKey.GetCryptPk());
            var sharedBa = bobKey.DiffieHellman(aliceKey.GetCryptPk());
            Assert.Equal(32, sharedAb.Length);
            Assert.Equal(Hexlify(expectedShared), Hexlify(sharedAb));
            Assert.Equal(Hexlify(sharedAb), Hexlify(sharedBa));
        }

        [Fact]
        public void Mid_Is_Sha1_Of_PublicKeyBin()
        {
            // vectors.json → keys: mid_sha1_of_ed25519_pub == sha1(raw Ed25519 pub)[:20].
            var pub1 = Hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
            Assert.Equal(Vectors.Keys("mid_sha1_of_ed25519_pub"), Hexlify(Util.Sha1(pub1)));

            // Source of truth (py-ipv8 keyvault/keys.py): key_to_hash is sha1 over the full
            // 74-byte LibNaCLPK public bin — which is what the wire format actually carries.
            var key = new LibNaclPublicKey(MakePublicKeyBin(new byte[32], pub1));
            var mid = key.KeyToHash();
            Assert.Equal(20, mid.Length);
            Assert.Equal(Hexlify(Util.Sha1(key.KeyToBin())), Hexlify(mid));
        }

        [Fact]
        public void Generated_Curve25519_Keys_Are_Consistent()
        {
            var crypto = ECCrypto.Default;
            var privateKey = crypto.GenerateKey("curve25519");
            var publicKey = privateKey.Pub();

            var skBin = privateKey.KeyToBin();
            Assert.Equal(74, skBin.Length);
            Assert.Equal("LibNaCLSK:", System.Text.Encoding.ASCII.GetString(skBin, 0, 10));

            // sign/verify roundtrip through the ECCrypto layer (keys.rs-compatible formats).
            var msg = new byte[] { 1, 2, 3, 4, 5 };
            var signature = crypto.CreateSignature(privateKey, msg);
            Assert.Equal(64, crypto.GetSignatureLength(publicKey));
            Assert.Equal(64, signature.Length);
            Assert.True(crypto.IsValidSignature(publicKey, msg, signature));
            Assert.False(crypto.IsValidSignature(publicKey, new byte[] { 6 }, signature));

            // The pk bin embeds the derived X25519 public key at [10..42) and the Ed25519 key at [42..74).
            var pkBin = publicKey.KeyToBin();
            Assert.Equal(74, pkBin.Length);
            Assert.Equal("LibNaCLPK:", System.Text.Encoding.ASCII.GetString(pkBin, 0, 10));
            Assert.Equal(Hexlify(publicKey.GetCryptPk()), Hexlify(Util.Slice(pkBin, 10, 32)));
        }
    }
}
