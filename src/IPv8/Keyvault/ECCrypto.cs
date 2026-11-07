// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using IPv8.Keyvault;

namespace IPv8.Keyvault
{
    /// <summary>
    /// A crypto object which provides a layer between Dispersy and low level eccrypographic features
    /// (port of ipv8/keyvault/crypto.py, curve25519-only for Phase 1a).
    /// </summary>
    public sealed class ECCrypto
    {
        /// <summary>ECCrypto should be stateless: a global singleton for efficiency.</summary>
        public static readonly ECCrypto Default = new ECCrypto();

        private const string Curve25519 = "curve25519";

        /// <summary>
        /// Generate a new Elliptic Curve object with a new public / private key pair.
        /// Only "curve25519" (the dual LibNaCL key) is supported in Phase 1a.
        /// </summary>
        public PrivateKey GenerateKey(string securityLevel)
        {
            if (securityLevel == Curve25519)
            {
                return new LibNaclPrivateKey(new Org.BouncyCastle.Security.SecureRandom());
            }
            throw new ArgumentException($"Illegal curve for key generation: {securityLevel}", nameof(securityLevel));
        }

        /// <summary>Returns True if the input is a valid public/private keypair stored in a binary format.</summary>
        public bool IsValidPrivateBin(byte[] keystring)
        {
            try
            {
                KeyFromPrivateBin(keystring);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        /// <summary>Returns True if the input is a valid public key.</summary>
        public bool IsValidPublicBin(byte[] keystring)
        {
            try
            {
                KeyFromPublicBin(keystring);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        /// <summary>Get the EC from a public/private keypair stored in a binary format.</summary>
        public PrivateKey KeyFromPrivateBin(byte[] keystring)
        {
            if (keystring != null && Util.StartsWith(keystring, LibNaclPrivateKey.Prefix))
            {
                return new LibNaclPrivateKey(keystring);
            }
            throw new ArgumentException($"Public key is not a LibNaCLSK key");
        }

        /// <summary>Get the EC from a public key in binary format.</summary>
        public PublicKey KeyFromPublicBin(byte[] keystring)
        {
            if (keystring != null && Util.StartsWith(keystring, LibNaclPublicKey.Prefix))
            {
                return new LibNaclPublicKey(keystring);
            }
            throw new ArgumentException($"Public key is not a LibNaCLPK key");
        }

        /// <summary>Returns the length, in bytes, of each signature made using EC.</summary>
        public int GetSignatureLength(PublicKey key) => key.GetSignatureLength();

        /// <summary>Returns the signature of DIGEST made using EC.</summary>
        public byte[] CreateSignature(PrivateKey key, byte[] data) => key.Signature(data);

        /// <summary>Returns True when SIGNATURE matches the DIGEST made using EC.</summary>
        public bool IsValidSignature(PublicKey key, byte[] data, byte[] signature)
            => key.Verify(signature, data);
    }
}
