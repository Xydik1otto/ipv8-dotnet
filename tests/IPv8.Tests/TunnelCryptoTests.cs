// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Text.Json;
using IPv8.Keyvault;
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

        // Correct beforenm-composition goldens printed by contract/tunnelcrypto_ref.py
        // (the JSON fixture's created_handshake uses raw X25519 halves — documented
        // deviation — so the rust-mandated composition goldens are pinned here instead).
        private const string RefSharedSecret =
            "921c10a75ecf05ac704373f59ff4ec283af50058b4bbe51f6ad93b6741df6471d0cc28d5abb3a95840563467d4345f42fb9e9e847813d1cd213526246851c968";
        private const string RefAuth =
            "328c01776c7194d16d0ddf8cfa10c087aa0174d85905c77f4cf9af3e0bb5235c";
        private const string RefKeyBackward =
            "b421808c33285e6b99340febde60866736f09c87597e1608327679ef2d945bcd";
        private const string RefKeyForward =
            "0e01137c3e07ac26b3382044a5690bc0a60ef6dbad8ca1844e92b8e26c8f1b21";
        private const string RefSaltBackward = "31bf74d2";
        private const string RefSaltForward = "32948896";
        private const string RefCandidatesEnc =
            "0000000000000002ac628282c73d41a5ce09e161b4500f43e2c5146a897d5c03dcdf285a063f92aa2d6628b009daa237305615a5b5679e6d182f284ec6cf6fd1745a6f1a711ad03f175a06228f3cfdaf054b7001fa79f48bfb68c8f55d8a3d90721b560b9d";

        [Fact]
        public void Created_Handshake_Beforenm_Composition()
        {
            // rust dh.rs composition (contract/tunnelcrypto_ref.py):
            //   shared = beforenm(eph_pk, resp_sk) || beforenm(eph_pk, bob_id_sk)
            //   auth   = crypto_auth(shared[:32], crypt_pk)
            var keysMeta = Vectors3.Section("meta").GetProperty("keys");
            var initSk = Vectors3.Hex(keysMeta, "dh_ephemeral_initiator_sk_hex");
            var respSk = Vectors3.Hex(keysMeta, "dh_ephemeral_responder_sk_hex");
            var bobIdSk = Vectors3.Hex(keysMeta, "bob_x_sk_hex");
            var initPk = Vectors3.Hex(keysMeta, "dh_ephemeral_initiator_pk_hex");
            var respPk = Vectors3.Hex(keysMeta, "dh_ephemeral_responder_pk_hex");
            var bobIdPk = Vectors3.Hex(Vectors3.Section("x25519"), "bob_pk_hex");

            // Responder side (generate_diffie_shared_secret).
            var shared = Util.Concat(
                TunnelSessionCrypto.CryptoBoxBeforeNm(initPk, respSk),
                TunnelSessionCrypto.CryptoBoxBeforeNm(initPk, bobIdSk));
            Assert.Equal(RefSharedSecret, Vectors3.Hex(shared));

            var auth = TunnelSessionCrypto.CryptoAuth(Util.Slice(shared, 0, 32), respPk);
            Assert.Equal(RefAuth, Vectors3.Hex(auth));

            // Initiator side (verify_and_generate_shared_secret) lands on the same secret.
            var sharedInit = Util.Concat(
                TunnelSessionCrypto.CryptoBoxBeforeNm(respPk, initSk),
                TunnelSessionCrypto.CryptoBoxBeforeNm(bobIdPk, initSk));
            Assert.Equal(RefSharedSecret, Vectors3.Hex(sharedInit));
            Assert.True(TunnelSessionCrypto.CryptoAuthVerify(auth, Util.Slice(sharedInit, 0, 32), respPk));

            // Session keys expand from the beforenm secret and open the candidates blob.
            var sessionKeys = TunnelSessionCrypto.GenerateSessionKeys(shared);
            Assert.Equal(RefKeyBackward, Vectors3.Hex(sessionKeys.KeyBackward));
            Assert.Equal(RefKeyForward, Vectors3.Hex(sessionKeys.KeyForward));
            Assert.Equal(RefSaltBackward, Vectors3.Hex(sessionKeys.SaltBackward));
            Assert.Equal(RefSaltForward, Vectors3.Hex(sessionKeys.SaltForward));

            var candidatesBin = sessionKeys.DecryptStr(Util.Unhex(RefCandidatesEnc), TunnelDirection.Forward);
            Assert.Equal(Vectors3.HexString(Vectors3.Section("created_handshake"), "candidates_bin_hex"),
                         Vectors3.Hex(candidatesBin));
        }

        /// <summary>
        /// The LIBRARY's handshake functions must implement the rust dh.rs beforenm
        /// composition symmetrically: the hop's generate_diffie_shared_secret and the
        /// initiator's verify_and_generate_shared_secret must agree (this is exactly the
        /// property the live cross-language handshake depends on).
        /// </summary>
        [Fact]
        public void Handshake_Functions_Agree_On_Beforenm_Composition()
        {
            var initiatorKey = (PrivateKey)ECCrypto.Default.KeyFromPrivateBin(Util.Unhex(
                "4c69624e61434c534b3a77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
                + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
            var hopKey = (PrivateKey)ECCrypto.Default.KeyFromPrivateBin(Util.Unhex(
                "4c69624e61434c534b3a5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
                + "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));

            // Hop side: the received DH part is the initiator's ephemeral crypt pk.
            var hopCrypto = new TunnelCrypto();
            hopCrypto.Initialize(hopKey);
            var (shared, cryptPk, auth) = hopCrypto.GenerateDiffieSharedSecret(initiatorKey.GetCryptPk());
            Assert.Equal(64, shared.Length);

            // Initiator side: verify against the hop's ephemeral pk + the hop's own crypt pk.
            var initShared = TunnelCrypto.VerifyAndGenerateSharedSecret(
                initiatorKey, cryptPk, auth, hopKey.GetCryptPk());
            Assert.Equal(shared, initShared);

            // Both sides expand identical session keys.
            var hopKeys = TunnelCrypto.GenerateSessionKeys(shared);
            var initKeys = TunnelCrypto.GenerateSessionKeys(initShared);
            Assert.Equal(hopKeys.KeyForward, initKeys.KeyForward);
            Assert.Equal(hopKeys.KeyBackward, initKeys.KeyBackward);
            Assert.Equal(hopKeys.SaltForward, initKeys.SaltForward);
            Assert.Equal(hopKeys.SaltBackward, initKeys.SaltBackward);
        }
    }
}
