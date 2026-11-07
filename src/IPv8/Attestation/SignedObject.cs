// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using Org.BouncyCastle.Crypto.Digests;

namespace IPv8.Attestation
{
    /// <summary>SHA3-256 helper (BouncyCastle; .NET has no portable SHA3 for netstandard2.0).</summary>
    public static class Sha3
    {
        public static byte[] Sha3_256(byte[] data)
        {
            var digest = new Sha3Digest(256);
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
    }

    /// <summary>
    /// To reach immutability different objects will have to be signed to reach non-repudiation.
    /// Examples are Tokens, Metadata and Attestation objects
    /// (port of ipv8/attestation/signed_object.py::AbstractSignedObject).
    /// </summary>
    public abstract class AbstractSignedObject
    {
        private byte[] _hash = Util.EmptyBytes;

        protected AbstractSignedObject()
        {
            Crypto = Keyvault.ECCrypto.Default;
        }

        public Keyvault.ECCrypto Crypto { get; }

        public byte[] Signature { get; private set; }

        /// <summary>Return the hash of this object itself.</summary>
        public byte[] GetHash() => _hash;

        /// <summary>Verify if a public key belongs to this object.</summary>
        public bool Verify(Keyvault.PublicKey publicKey)
            => Crypto.IsValidSignature(publicKey, GetPlaintext(), Signature);

        /// <summary>
        /// Add a signature to this data: supply either the private key or an existing signature.
        /// MUST be called at the END of the derived constructor, once GetPlaintext() is complete
        /// (py: super().__init__(private_key, signature) is the last statement of __init__).
        /// </summary>
        protected void Sign(Keyvault.PrivateKey privateKey, byte[] signature)
        {
            if (privateKey != null && signature == null)
            {
                Signature = privateKey.Signature(GetPlaintext());
            }
            else if (privateKey == null && signature != null)
            {
                Signature = signature;
            }
            else
            {
                throw new InvalidOperationException("Specify either private_key or signature!");
            }
            _hash = Sha3.Sha3_256(GetPlaintextSigned());
        }

        /// <summary>Retrieve the content that needs to be signed, in serialized form.</summary>
        public abstract byte[] GetPlaintext();

        /// <summary>Concatenate the signature to the plaintext.</summary>
        public byte[] GetPlaintextSigned() => Util.Concat(GetPlaintext(), Signature);

        public override bool Equals(object other)
        {
            if (other == null || GetType() != other.GetType())
            {
                return false;
            }
            return Util.BytesEqual(GetPlaintextSigned(), ((AbstractSignedObject)other).GetPlaintextSigned());
        }

        public override int GetHashCode() => Util.BytesHashCode(Util.Slice(_hash, 0, 8));
    }
}
