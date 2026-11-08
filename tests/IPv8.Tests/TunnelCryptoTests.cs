// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Text.Json;
using IPv8.Messaging.Anonymization;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// B1: tunnel session crypto golden vectors — every primitive is checked against
    /// the SAME contract/vectors-phase3.json that the Java port consumes:
    /// - X25519: RFC 7748 section 6.1
    /// - HSalsa20: NaCl "Cryptography in NaCl" (2009) core1 vector (key = the RFC 7748
    ///   6.1 shared secret), implemented straight from ipv8-rust-tunnels/src/dh.rs
    /// - crypto_auth: HMAC-SHA512 truncated to 32 bytes (RFC 4231 TC1/TC2)
    /// - generate_session_keys: HKDF-SHA256 expand-only (RFC 5869 TC1-3 + the composed
    ///   info=b"key_generation" 72-byte split)
    /// - ChaCha20-Poly1305 cell seal: RFC 8439 section 2.8.2
    /// - beforenm composition + SessionKeys wire format (counter BE, increments BEFORE use)
    /// </summary>
    public class TunnelCryptoTests
    {
        private static byte[] X25519(byte[] privateKey32, byte[] publicKey32)
        {
            var agreement = new X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(privateKey32, 0));
            var result = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(publicKey32, 0), result, 0);
            return result;
        }

        [Fact]
        public void X25519_Rfc7748_61()
        {
            var section = Vectors3.Section("x25519");
            var shared = X25519(Vectors3.Hex(section, "alice_sk_hex"), Vectors3.Hex(section, "bob_pk_hex"));
            Assert.Equal(Vectors3.HexString(section, "shared_hex"), Vectors3.Hex(shared));

            var reverse = X25519(Vectors3.Hex(section, "bob_sk_hex"), Vectors3.Hex(section, "alice_pk_hex"));
            Assert.Equal(Vectors3.Hex(shared), Vectors3.Hex(reverse));
        }

        [Fact]
        public void Hsalsa20_NaClCore1()
        {
            var section = Vectors3.Section("hsalsa20");
            var result = TunnelSessionCrypto.Hsalsa20(Vectors3.Hex(section, "key_hex"));
            Assert.Equal(Vectors3.HexString(section, "out32_hex"), Vectors3.Hex(result));
        }

        [Fact]
        public void Hsalsa20_RejectsWrongLength()
        {
            Assert.Throws<ArgumentException>(() => TunnelSessionCrypto.Hsalsa20(new byte[31]));
            Assert.Throws<ArgumentException>(() => TunnelSessionCrypto.Hsalsa20(new byte[33]));
        }

        [Fact]
        public void BeforeNm_Composition()
        {
            foreach (var entry in Vectors3.Section("beforenm").EnumerateArray())
            {
                var result = TunnelSessionCrypto.CryptoBoxBeforeNm(
                    Vectors3.Hex(entry, "pk_hex"), Vectors3.Hex(entry, "sk_hex"));
                Assert.Equal(Vectors3.HexString(entry, "out32_hex"), Vectors3.Hex(result));
            }
        }

        [Fact]
        public void BeforeNm_LengthValidation()
        {
            Assert.Throws<ArgumentException>(() =>
                TunnelSessionCrypto.CryptoBoxBeforeNm(new byte[31], new byte[32]));
            Assert.Throws<ArgumentException>(() =>
                TunnelSessionCrypto.CryptoBoxBeforeNm(new byte[32], new byte[33]));
        }

        [Fact]
        public void CryptoAuth_Rfc4231_Truncated()
        {
            foreach (var entry in Vectors3.Section("hmac_sha512_32").EnumerateArray())
            {
                var mac = TunnelSessionCrypto.CryptoAuth(
                    Vectors3.Hex(entry, "key_hex"), Vectors3.Hex(entry, "msg_hex"));
                Assert.Equal(32, mac.Length);
                Assert.Equal(Vectors3.HexString(entry, "mac32_hex"), Vectors3.Hex(mac));
            }
        }

        [Fact]
        public void CryptoAuthVerify_PositiveAndNegative()
        {
            var entry = Vectors3.Section("hmac_sha512_32")[0];
            var key = Vectors3.Hex(entry, "key_hex");
            var msg = Vectors3.Hex(entry, "msg_hex");
            var tag = Vectors3.Hex(entry, "mac32_hex");

            Assert.True(TunnelSessionCrypto.CryptoAuthVerify(tag, key, msg));

            var tampered = (byte[])tag.Clone();
            tampered[0] ^= 0x01;
            Assert.False(TunnelSessionCrypto.CryptoAuthVerify(tampered, key, msg));
            Assert.False(TunnelSessionCrypto.CryptoAuthVerify(new byte[31], key, msg));
        }

        [Fact]
        public void HkdfExpandSha256_Rfc5869()
        {
            foreach (var entry in Vectors3.Section("hkdf_sha256").EnumerateArray())
            {
                var prk = Vectors3.Hex(entry, "prk_hex");
                var info = Vectors3.Hex(entry, "info_hex");
                var length = entry.GetProperty("l").GetInt32();
                var okm = TunnelSessionCrypto.HkdfExpandSha256(prk, info, length);
                Assert.Equal(Vectors3.HexString(entry, "okm_hex"), Vectors3.Hex(okm));
            }
        }

        [Fact]
        public void GenerateSessionKeys_72ByteSplit()
        {
            var section = Vectors3.Section("session_keys");
            var shared = Vectors3.Hex(section, "shared_secret_hex");
            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);

            Assert.Equal(Vectors3.HexString(section, "key_backward_hex"), Vectors3.Hex(keys.KeyBackward));
            Assert.Equal(Vectors3.HexString(section, "key_forward_hex"), Vectors3.Hex(keys.KeyForward));
            Assert.Equal(Vectors3.HexString(section, "salt_backward_hex"), Vectors3.Hex(keys.SaltBackward));
            Assert.Equal(Vectors3.HexString(section, "salt_forward_hex"), Vectors3.Hex(keys.SaltForward));
            // Counters start at 1 and are incremented BEFORE use: the first cell carries counter 2.
            Assert.Equal(1UL, keys.SaltExplicitForward);
            Assert.Equal(1UL, keys.SaltExplicitBackward);
        }

        [Fact]
        public void EncryptStr_FirstCellUsesCounter2()
        {
            var section = Vectors3.Section("session_keys");
            var shared = Vectors3.Hex(section, "shared_secret_hex");
            var content = Vectors3.Hex(section, "encrypt_forward", "content_hex");

            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var wire = keys.EncryptStr(content, TunnelDirection.Forward);

            Assert.Equal(Vectors3.HexString(section, "encrypt_forward", "wire_hex"), Vectors3.Hex(wire));
            Assert.Equal(2UL, keys.SaltExplicitForward);
            // The first 8 wire bytes are the counter, big endian, value 2.
            Assert.Equal(0x02, wire[7]);

            var backward = Vectors3.HexString(section, "encrypt_backward", "wire_hex");
            var keysB = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var wireB = keysB.EncryptStr(content, TunnelDirection.Backward);
            var wireBHex = Vectors3.Hex(wireB);
            Assert.Equal(backward, wireBHex);
            Assert.Equal(2UL, keysB.SaltExplicitBackward);
        }

        [Fact]
        public void EncryptDecrypt_Roundtrip_BothDirections()
        {
            var section = Vectors3.Section("session_keys");
            var shared = Vectors3.Hex(section, "shared_secret_hex");
            var content = Vectors3.Hex(section, "encrypt_forward", "content_hex");

            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var wire1 = keys.EncryptStr(content, TunnelDirection.Forward);
            var wire2 = keys.EncryptStr(content, TunnelDirection.Forward);
            Assert.Equal(3UL, keys.SaltExplicitForward);
            // Nonce reuse is impossible: distinct counters give distinct wire bytes.
            Assert.NotEqual(Vectors3.Hex(wire1), Vectors3.Hex(wire2));
            Assert.Equal(Vectors3.Hex(content), Vectors3.Hex(keys.DecryptStr(wire1, TunnelDirection.Forward)));
            Assert.Equal(Vectors3.Hex(content), Vectors3.Hex(keys.DecryptStr(wire2, TunnelDirection.Forward)));

            var back1 = keys.EncryptStr(content, TunnelDirection.Backward);
            Assert.Equal(2UL, keys.SaltExplicitBackward);
            Assert.Equal(Vectors3.Hex(content), Vectors3.Hex(keys.DecryptStr(back1, TunnelDirection.Backward)));
        }

        [Fact]
        public void DecryptStr_Negatives()
        {
            var section = Vectors3.Section("session_keys");
            var shared = Vectors3.Hex(section, "shared_secret_hex");
            var content = Vectors3.Hex(section, "encrypt_forward", "content_hex");
            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var wire = keys.EncryptStr(content, TunnelDirection.Forward);

            // Too short (< 24 bytes).
            Assert.Throws<CryptoException>(() => keys.DecryptStr(new byte[23], TunnelDirection.Forward));

            // Tampered tag.
            var tampered = (byte[])wire.Clone();
            tampered[^1] ^= 0x01;
            Assert.Throws<CryptoException>(() => keys.DecryptStr(tampered, TunnelDirection.Forward));

            // Tampered ciphertext.
            var tamperedBody = (byte[])wire.Clone();
            tamperedBody[8] ^= 0x01;
            Assert.Throws<CryptoException>(() => keys.DecryptStr(tamperedBody, TunnelDirection.Forward));

            // Wrong direction (different key stream).
            Assert.Throws<CryptoException>(() => keys.DecryptStr(wire, TunnelDirection.Backward));
        }

        [Fact]
        public void ChaCha20Poly1305_Rfc8439_Seal()
        {
            // Primitive-level check of the AEAD used by SessionKeys (RFC 8439 2.8.2, WITH
            // AAD — hence the direct AEAD call, since SessionKeys always uses an empty AAD).
            var section = Vectors3.Section("chacha20poly1305");
            var key = Vectors3.Hex(section, "key_hex");
            var nonce = Vectors3.Hex(section, "nonce_hex");
            var aad = Vectors3.Hex(section, "aad_hex");
            var plaintext = Vectors3.Hex(section, "plaintext_hex");

            var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
            var output = new byte[cipher.GetOutputSize(plaintext.Length)];
            var written = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, written);

            Assert.Equal(Vectors3.HexString(section, "ciphertext_hex") + Vectors3.HexString(section, "tag_hex"),
                Vectors3.Hex(output));
        }

        [Fact]
        public void SessionKeys_AeadHasNoAad()
        {
            // Cross-check the SessionKeys path: with the RFC 8439 key/nonce/plaintext but an
            // EMPTY AAD, the ciphertext must still match the RFC ciphertext (the AAD only
            // affects the tag) — pinning that SessionKeys really uses no AAD.
            var section = Vectors3.Section("chacha20poly1305");
            var nonce = Vectors3.Hex(section, "nonce_hex");
            var plaintext = Vectors3.Hex(section, "plaintext_hex");
            var key = Vectors3.Hex(section, "key_hex");

            ulong counter = 0;
            for (var i = 4; i < 12; i++)
            {
                counter = (counter << 8) | nonce[i];
            }
            // EncryptStr increments the counter BEFORE use, so pre-set it to (counter - 1)
            // to make the wire nonce equal the RFC 8439 2.8.2 nonce.
            var keys = new SessionKeys
            {
                KeyForward = key,
                SaltForward = Util.Slice(nonce, 0, 4),
                SaltExplicitForward = counter - 1,
            };

            var wire = keys.EncryptStr(plaintext, TunnelDirection.Forward);
            Assert.Equal(Vectors3.HexString(section, "ciphertext_hex"), Vectors3.Hex(Util.Slice(wire, 8, plaintext.Length)));
            // The tag must NOT be the RFC AAD-tag (empty AAD is a different Poly1305 input).
            Assert.NotEqual(Vectors3.HexString(section, "tag_hex"), Vectors3.Hex(Util.SliceFrom(wire, 8 + plaintext.Length)));
        }

        [Fact]
        public void Created_Handshake_Composition()
        {
            // The full create → created handshake crypto over the shared secret:
            // decrypt candidates_enc (FORWARD) back to the varlenH-list of candidate keys.
            var handshake = Vectors3.Section("created_handshake");
            var shared = Vectors3.Hex(handshake, "shared_secret_hex");
            var keys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            var candidatesEnc = Vectors3.Hex(handshake, "candidates_enc_hex");
            var candidates = keys.DecryptStr(candidatesEnc, TunnelDirection.Forward);
            Assert.Equal(Vectors3.HexString(handshake, "candidates_bin_hex"), Vectors3.Hex(candidates));

            // The auth tag verifies: crypto_auth(shared[:32], responder_tmp_pk).
            var auth = Vectors3.Hex(handshake, "auth_hex");
            var responderTmpPk = Vectors3.Hex(Vectors3.Section("meta").GetProperty("keys"),
                                              "dh_ephemeral_responder_pk_hex");
            Assert.True(TunnelSessionCrypto.CryptoAuthVerify(auth, Util.Slice(shared, 0, 32), responderTmpPk));
        }
    }
}
