// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace IPv8.Messaging.Anonymization
{
    /// <summary>
    /// The cell encryption direction (py-ipv8/ipv8/messaging/anonymization/tunnel.py:
    /// FORWARD = 0, BACKWARD = 1).
    /// </summary>
    public static class TunnelDirection
    {
        public const int Forward = 0;
        public const int Backward = 1;
    }

    /// <summary>
    /// Session key material and the cell encryption/decryption routines
    /// (port of the ``SessionKeys`` pyclass from ipv8-rust-tunnels/src/dh.rs, exposed to
    /// Python as ipv8/messaging/anonymization/crypto.py::SessionKeys).
    /// </summary>
    public sealed class SessionKeys
    {
        public byte[] KeyForward { get; set; }
        public byte[] KeyBackward { get; set; }
        public byte[] SaltForward { get; set; }
        public byte[] SaltBackward { get; set; }

        /// <summary>
        /// The explicit salt counters (u64). NOTE: these start at 1 and are incremented
        /// BEFORE use (the first encrypted cell carries counter 2) — mirrors the Rust source.
        /// </summary>
        public ulong SaltExplicitForward { get; set; } = 1;
        public ulong SaltExplicitBackward { get; set; } = 1;

        /// <summary>
        /// Encrypt the given content in the given direction.
        /// Wire format: counter (8 bytes, big endian) + ciphertext + tag (16 bytes).
        /// Nonce: salt (4 bytes) + counter (8 bytes, big endian); empty AAD.
        /// </summary>
        public byte[] EncryptStr(byte[] content, int direction)
        {
            ulong counter;
            byte[] key;
            byte[] salt;
            if (direction == TunnelDirection.Forward)
            {
                SaltExplicitForward += 1;
                counter = SaltExplicitForward;
                key = KeyForward;
                salt = SaltForward;
            }
            else
            {
                SaltExplicitBackward += 1;
                counter = SaltExplicitBackward;
                key = KeyBackward;
                salt = SaltBackward;
            }

            var counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            // Nonce = salt (4) + counter (8 BE) = 12 bytes.
            var nonce = new byte[12];
            Array.Copy(salt, 0, nonce, 0, 4);
            Array.Copy(counterBytes, 0, nonce, 4, 8);

            var ciphertextWithMac = AeadSeal(key, nonce, content);

            // Wire: 8 byte counter + ciphertext + 16 byte tag.
            var result = new byte[8 + ciphertextWithMac.Length];
            Array.Copy(counterBytes, 0, result, 0, 8);
            Array.Copy(ciphertextWithMac, 0, result, 8, ciphertextWithMac.Length);
            return result;
        }

        /// <summary>
        /// Decrypt the given content in the given direction. The counter is READ from the
        /// wire (not taken from the local counter). Raises <see cref="CryptoException"/>
        /// on truncated input or failed authentication.
        /// </summary>
        public byte[] DecryptStr(byte[] content, int direction)
        {
            if (content == null || content.Length < 24)
            {
                throw new CryptoException("Content too short");
            }

            byte[] key;
            byte[] salt;
            if (direction == TunnelDirection.Forward)
            {
                key = KeyForward;
                salt = SaltForward;
            }
            else
            {
                key = KeyBackward;
                salt = SaltBackward;
            }

            var counterBytes = new byte[8];
            Array.Copy(content, 0, counterBytes, 0, 8);

            var nonce = new byte[12];
            Array.Copy(salt, 0, nonce, 0, 4);
            Array.Copy(counterBytes, 0, nonce, 4, 8);

            var ciphertextWithMac = new byte[content.Length - 8];
            Array.Copy(content, 8, ciphertextWithMac, 0, ciphertextWithMac.Length);

            try
            {
                return AeadOpen(key, nonce, ciphertextWithMac);
            }
            catch (Exception e)
            {
                throw new CryptoException("Decryption failed", e);
            }
        }

        /// <summary>AEAD seal: returns ciphertext || 16-byte tag (empty AAD).</summary>
        private static byte[] AeadSeal(byte[] key, byte[] nonce, byte[] plaintext)
        {
            // BouncyCastle ChaCha20-Poly1305 (RFC 7539 ChaCha7539Engine + Poly1305):
            // identical behaviour on every TFM (netstandard2.0 has no BCL ChaCha20Poly1305).
            var cipher = new BcChaCha20Poly1305();
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, Array.Empty<byte>()));
            var output = new byte[cipher.GetOutputSize(plaintext.Length)];
            var written = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            written += cipher.DoFinal(output, written);
            if (written != output.Length)
            {
                throw new InvalidOperationException("ChaCha20-Poly1305 seal size mismatch");
            }
            return output;
        }

        /// <summary>AEAD open: input is ciphertext || 16-byte tag (empty AAD).</summary>
        private static byte[] AeadOpen(byte[] key, byte[] nonce, byte[] ciphertextWithMac)
        {
            var cipher = new BcChaCha20Poly1305();
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce, Array.Empty<byte>()));
            var output = new byte[cipher.GetOutputSize(ciphertextWithMac.Length)];
            var written = cipher.ProcessBytes(ciphertextWithMac, 0, ciphertextWithMac.Length, output, 0);
            written += cipher.DoFinal(output, written);
            if (written != output.Length)
            {
                throw new InvalidOperationException("ChaCha20-Poly1305 open size mismatch");
            }
            return output;
        }
    }

    /// <summary>
    /// The tunnel session crypto primitives, ported 1:1 from the Rust ground truth
    /// (ipv8-rust-tunnels/src/dh.rs + src/crypto.rs; exposed to Python as
    /// ipv8/messaging/anonymization/crypto.py).
    /// </summary>
    public static class TunnelSessionCrypto
    {
        private static readonly uint[] Sigma = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        /// <summary>
        /// Port of libnacl's crypto_box_beforenm (dh.rs::crypto_box_beforenm): clamp the
        /// secret key (nacl style), X25519-DH against the peer public key and compress the
        /// shared point with HSalsa20.
        /// </summary>
        public static byte[] CryptoBoxBeforeNm(byte[] pk, byte[] sk)
        {
            if (pk == null || pk.Length != 32)
            {
                throw new ArgumentException("Public key must be 32 bytes");
            }
            if (sk == null || sk.Length != 32)
            {
                throw new ArgumentException("Secret key must be 32 bytes");
            }

            // Clamp sk (same as libnacl's crypto_scalarmult_curve25519).
            var clampedSk = (byte[])sk.Clone();
            clampedSk[0] &= 248;
            clampedSk[31] &= 127;
            clampedSk[31] |= 64;

            // X25519 DH of the clamped sk key with the peer's pk.
            var shared = X25519(clampedSk, pk);

            // Perform hsalsa20 (same as libnacl's crypto_core_hsalsa20).
            return Hsalsa20(shared);
        }

        /// <summary>
        /// HSalsa20 core (dh.rs, 20 double rounds; constants 0x61707865/0x3320646e/
        /// 0x79622d32/0x6b206574; output order x0,x5,x10,x15,x6,x7,x8,x9 as LE u32s).
        /// </summary>
        public static byte[] Hsalsa20(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length != 32)
            {
                throw new ArgumentException("Shared secret must be 32 bytes");
            }

            uint x0 = Sigma[0];
            uint x5 = Sigma[1];
            uint x10 = Sigma[2];
            uint x15 = Sigma[3];
            uint x1 = Load32Le(sharedSecret, 0);
            uint x2 = Load32Le(sharedSecret, 4);
            uint x3 = Load32Le(sharedSecret, 8);
            uint x4 = Load32Le(sharedSecret, 12);
            uint x11 = Load32Le(sharedSecret, 16);
            uint x12 = Load32Le(sharedSecret, 20);
            uint x13 = Load32Le(sharedSecret, 24);
            uint x14 = Load32Le(sharedSecret, 28);
            uint x6 = 0;
            uint x7 = 0;
            uint x8 = 0;
            uint x9 = 0;

            for (var i = 0; i < 20; i += 2)
            {
                x4 ^= Rotl32(x0 + x12, 7);
                x8 ^= Rotl32(x4 + x0, 9);
                x12 ^= Rotl32(x8 + x4, 13);
                x0 ^= Rotl32(x12 + x8, 18);
                x9 ^= Rotl32(x5 + x1, 7);
                x13 ^= Rotl32(x9 + x5, 9);
                x1 ^= Rotl32(x13 + x9, 13);
                x5 ^= Rotl32(x1 + x13, 18);
                x14 ^= Rotl32(x10 + x6, 7);
                x2 ^= Rotl32(x14 + x10, 9);
                x6 ^= Rotl32(x2 + x14, 13);
                x10 ^= Rotl32(x6 + x2, 18);
                x3 ^= Rotl32(x15 + x11, 7);
                x7 ^= Rotl32(x3 + x15, 9);
                x11 ^= Rotl32(x7 + x3, 13);
                x15 ^= Rotl32(x11 + x7, 18);
                x1 ^= Rotl32(x0 + x3, 7);
                x2 ^= Rotl32(x1 + x0, 9);
                x3 ^= Rotl32(x2 + x1, 13);
                x0 ^= Rotl32(x3 + x2, 18);
                x6 ^= Rotl32(x5 + x4, 7);
                x7 ^= Rotl32(x6 + x5, 9);
                x4 ^= Rotl32(x7 + x6, 13);
                x5 ^= Rotl32(x4 + x7, 18);
                x11 ^= Rotl32(x10 + x9, 7);
                x8 ^= Rotl32(x11 + x10, 9);
                x9 ^= Rotl32(x8 + x11, 13);
                x10 ^= Rotl32(x9 + x8, 18);
                x12 ^= Rotl32(x15 + x14, 7);
                x13 ^= Rotl32(x12 + x15, 9);
                x14 ^= Rotl32(x13 + x12, 13);
                x15 ^= Rotl32(x14 + x13, 18);
            }

            var result = new byte[32];
            Store32Le(result, 0, x0);
            Store32Le(result, 4, x5);
            Store32Le(result, 8, x10);
            Store32Le(result, 12, x15);
            Store32Le(result, 16, x6);
            Store32Le(result, 20, x7);
            Store32Le(result, 24, x8);
            Store32Le(result, 28, x9);
            return result;
        }

        /// <summary>
        /// crypto_auth: the first 32 bytes of HMAC-SHA512 over the message with the given key
        /// (dh.rs::crypto_auth).
        /// </summary>
        public static byte[] CryptoAuth(byte[] key, byte[] message)
        {
            using var hmac = new HMACSHA512(key);
            var tag = hmac.ComputeHash(message ?? Array.Empty<byte>());
            var truncated = new byte[32];
            Array.Copy(tag, truncated, 32);
            return truncated;
        }

        /// <summary>
        /// crypto_auth_verify: recompute the tag and compare in constant time
        /// (dh.rs::crypto_auth_verify).
        /// </summary>
        public static bool CryptoAuthVerify(byte[] tag, byte[] key, byte[] message)
        {
            if (tag == null || tag.Length != 32)
            {
                return false;
            }
            var calculated = CryptoAuth(key, message);
            return FixedTimeEquals(calculated, tag);
        }

        /// <summary>Constant-time equality of two equally-sized byte arrays (32 bytes here).</summary>
        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var diff = 0;
            for (var i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }

        /// <summary>
        /// HKDF-SHA256 EXPAND-ONLY (RFC 5869 section 2.3): T(1) = HMAC(PRK, info || 0x01), ...
        /// (crypto.rs::generate_session_keys uses OpenSSL's HKDF EXPAND_ONLY mode).
        /// </summary>
        public static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
        {
            if (prk == null || prk.Length < 32)
            {
                throw new ArgumentException("PRK must be at least 32 bytes for HKDF-SHA256");
            }
            info ??= Array.Empty<byte>();

            using var hmac = new HMACSHA256(prk);
            var t = Array.Empty<byte>();
            var okm = new byte[length];
            var generated = 0;
            var counter = 1;
            while (generated < length)
            {
                var block = new byte[t.Length + info.Length + 1];
                Array.Copy(t, 0, block, 0, t.Length);
                Array.Copy(info, 0, block, t.Length, info.Length);
                block[block.Length - 1] = (byte)counter;
                t = hmac.ComputeHash(block);
                var toCopy = Math.Min(t.Length, length - generated);
                Array.Copy(t, 0, okm, generated, toCopy);
                generated += toCopy;
                counter += 1;
            }
            return okm;
        }

        /// <summary>
        /// Expand a shared secret into session keys using HKDF-SHA256 EXPAND-ONLY with
        /// info = b"key_generation", 72 output bytes (crypto.rs::generate_session_keys):
        /// key_backward = okm[0:32], key_forward = okm[32:64], salt_backward = okm[64:68],
        /// salt_forward = okm[68:72]; both salt-explicit counters start at 1.
        /// </summary>
        public static SessionKeys GenerateSessionKeys(byte[] sharedSecret)
        {
            if (sharedSecret == null)
            {
                throw new ArgumentNullException(nameof(sharedSecret));
            }

            var key = HkdfExpandSha256(sharedSecret, Util.Utf8("key_generation"), 72);

            var sessionKeys = new SessionKeys
            {
                KeyBackward = Util.Slice(key, 0, 32),
                KeyForward = Util.Slice(key, 32, 32),
                SaltBackward = Util.Slice(key, 64, 4),
                SaltForward = Util.Slice(key, 68, 4),
                SaltExplicitBackward = 1,
                SaltExplicitForward = 1
            };
            return sessionKeys;
        }

        /// <summary>X25519 scalar multiplication over the raw 32-byte keys (BouncyCastle).</summary>
        private static byte[] X25519(byte[] privateKey32, byte[] publicKey32)
        {
            var agreement = new Org.BouncyCastle.Crypto.Agreement.X25519Agreement();
            agreement.Init(new X25519PrivateKeyParameters(privateKey32, 0));
            var result = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(publicKey32, 0), result, 0);
            return result;
        }

        private static uint Load32Le(byte[] data, int offset)
        {
            return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)
                          | (data[offset + 3] << 24));
        }

        private static void Store32Le(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        private static uint Rotl32(uint value, int shift)
        {
            return (value << shift) | (value >> (32 - shift));
        }
    }

    /// <summary>
    /// Exception for when anything goes wrong with sessions, encoding, and decoding
    /// (crypto.py::CryptoException).
    /// </summary>
    public class CryptoException : Exception
    {
        public CryptoException()
        {
        }

        public CryptoException(string message) : base(message)
        {
        }

        public CryptoException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}
