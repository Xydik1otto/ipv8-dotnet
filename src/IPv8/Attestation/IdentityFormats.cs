// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Keyvault;

namespace IPv8.Wallet.Cryptography
{
    /// <summary>
    /// An attestation for a public key of a value. Requires an ``IdFormat`` field in subclasses
    /// (port of ipv8/attestation/identity_formats.py::Attestation).
    /// </summary>
    public abstract class Attestation
    {
        public string IdFormat;

        /// <summary>The public key used by this attestation (algorithm dependent type).</summary>
        public object PK;

        /// <summary>Serialize this Attestation to a string (public part only).</summary>
        public abstract byte[] Serialize();

        /// <summary>Serialize this Attestation to a string, including shared secrets (not to be published!).</summary>
        public abstract byte[] SerializePrivateKey(object privateKey);

        /// <summary>
        /// Unserialize the public form (py: ``get_attestation_class().unserialize``; the C# port
        /// dispatches through a prototype instance returned by IdentityAlgorithm.GetAttestationClass).
        /// </summary>
        public abstract Attestation Unserialize(byte[] serialized, string idFormat);

        /// <summary>
        /// Unserialize the private form, containing shared secrets not to be published
        /// (py: ``get_attestation_class().unserialize_private``).
        /// </summary>
        public abstract Attestation UnserializePrivateKey(object secretKey, byte[] serialized, string idFormat);

        /// <summary>The hash over the public part of this Attestation (py: sha1(serialize())).</summary>
        public byte[] GetHash() => Util.Sha1(Serialize());
    }

    /// <summary>
    /// Interface for IPv8-compatible identity/credential algorithms
    /// (port of ipv8/attestation/identity_formats.py::IdentityAlgorithm).
    /// </summary>
    public abstract class IdentityAlgorithm
    {
        /// <summary>Register a new algorithm of a certain format identifier and given format info.</summary>
        protected IdentityAlgorithm(string idFormat, Dictionary<string, Dictionary<string, object>> formats)
        {
            IdFormat = idFormat;
            HonestyCheck = false;

            if (!formats.ContainsKey(idFormat))
            {
                throw new InvalidOperationException("Tried to initialize with illegal identity format");
            }
        }

        public string IdFormat { get; }

        public bool HonestyCheck { get; set; }

        /// <summary>Generate a secret key.</summary>
        public abstract object GenerateSecretKey();

        /// <summary>Unserialize a secret key from the key material.</summary>
        public abstract object LoadSecretKey(byte[] serialized);

        /// <summary>Unserialize a public key from the key material.</summary>
        public abstract object LoadPublicKey(byte[] serialized);

        /// <summary>Return the Attestation (sub)class for serialization.</summary>
        public abstract Attestation GetAttestationClass();

        /// <summary>Attest to a value for a certain public key; returns the attestation string.</summary>
        public abstract byte[] Attest(object publicKey, byte[] value);

        /// <summary>The current certainty of the aggregate object representing a certain value [0.0-1.0].</summary>
        public abstract double Certainty(byte[] value, Dictionary<string, object> aggregate);

        /// <summary>Create challenges for a certain counterparty.</summary>
        public abstract List<byte[]> CreateChallenges(object publicKey, Attestation attestation);

        /// <summary>Create an honest response to a challenge of our value.</summary>
        public abstract byte[] CreateChallengeResponse(object secretKey, Attestation attestation,
                                                       byte[] challenge);

        /// <summary>Create an empty aggregate object, for matching to values.</summary>
        public abstract Dictionary<string, object> CreateCertaintyAggregate(Attestation attestation);

        /// <summary>Use a known value to check for honesty; returns the challenge to send.</summary>
        public abstract byte[] CreateHonestyChallenge(object publicKey, int value);

        /// <summary>Given a response, check if it matches the expected value.</summary>
        public abstract bool ProcessHonestyChallenge(int value, byte[] response);

        /// <summary>Given a response, update the current aggregate.</summary>
        public abstract Dictionary<string, object> ProcessChallengeResponse(
            Dictionary<string, object> aggregate, byte[] challenge, byte[] response);

        /// <summary>Directly import a raw serialized form (returns the id_format and secret key).</summary>
        public abstract (byte[] IdFormatBytes, object SecretKey) ImportBlob(byte[] blob);
    }
}
