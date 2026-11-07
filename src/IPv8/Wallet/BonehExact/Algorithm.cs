// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Cryptography;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.BonehExact
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;

    /// <summary>
    /// IPv8 wrapper around ZKP using the Boneh partially-homomorphic crypto scheme
    /// (port of ipv8/attestation/wallet/bonehexact/algorithm.py::BonehExactAlgorithm).
    /// </summary>
    public class BonehExactAlgorithm : IdentityAlgorithm
    {
        private readonly int _keySize;

        private delegate BonehAttestation AttestFunction(BonehPublicKey pk, byte[] value);

        private delegate Dictionary<string, object> AggregateReference(byte[] value);

        private readonly AttestFunction _attestFunction;
        private readonly AggregateReference _aggregateReference;

        public BonehExactAlgorithm(string idFormat, Dictionary<string, Dictionary<string, object>> formats)
            : base(idFormat, formats)
        {
            HonestyCheck = true;

            // Check algorithm match
            if ((string)formats[idFormat]["algorithm"] != "bonehexact")
            {
                throw new InvalidOperationException("Identity format linked to wrong algorithm");
            }

            // Check key size match
            _keySize = (int)(long)formats[idFormat]["key_size"];
            if (_keySize < 32 || _keySize > 512)
            {
                throw new InvalidOperationException("Illegal key size specified");
            }

            // Check hash mode match
            var hashMode = (string)formats[idFormat]["hash"];
            switch (hashMode)
            {
                case "sha256":
                    _attestFunction = BonehExactAttestation.AttestSha256;
                    _aggregateReference = BonehExactAttestation.BinaryRelativitySha256;
                    break;
                case "sha256_4":
                    _attestFunction = BonehExactAttestation.AttestSha256_4;
                    _aggregateReference = BonehExactAttestation.BinaryRelativitySha256_4;
                    break;
                case "sha512":
                    _attestFunction = BonehExactAttestation.AttestSha512;
                    _aggregateReference = BonehExactAttestation.BinaryRelativitySha512;
                    break;
                default:
                    throw new InvalidOperationException("Unknown hashing mode");
            }
        }

        /// <summary>Generate a secret key.</summary>
        public override object GenerateSecretKey() => Boneh.GenerateKeypair(_keySize).PrivateKey;

        public override object LoadSecretKey(byte[] serialized) => BonehPrivateKey.Unserialize(serialized);

        public override object LoadPublicKey(byte[] serialized) => BonehPublicKey.Unserialize(serialized);

        public override Attestation GetAttestationClass() => new BonehAttestation();

        /// <summary>Attest to a value for a certain public key.</summary>
        public override byte[] Attest(object publicKey, byte[] value)
            => _attestFunction((BonehPublicKey)publicKey, value).Serialize();

        /// <summary>The current certainty of the aggregate object representing a certain value.</summary>
        public override double Certainty(byte[] value, Dictionary<string, object> aggregate)
            => BonehExactAttestation.BinaryRelativityCertainty(_aggregateReference(value), aggregate);

        /// <summary>Create challenges for a certain counterparty.</summary>
        public override List<byte[]> CreateChallenges(object publicKey, Attestation attestation)
        {
            var pk = (BonehPublicKey)publicKey;
            var challenges = new List<byte[]>();
            foreach (var bitPair in ((BonehAttestation)attestation).BitPairs)
            {
                var challenge = BonehExactAttestation.CreateChallenge(pk, bitPair);
                challenges.Add(IPack.PackPair(challenge.A, challenge.B));
            }
            return challenges;
        }

        /// <summary>Create an honest response to a challenge of our value.</summary>
        public override byte[] CreateChallengeResponse(object secretKey, Attestation attestation,
                                                       byte[] challenge)
        {
            var sk = (BonehPrivateKey)secretKey;
            var (a, b, _) = IPack.UnpackPair(challenge);
            var response = BonehExactAttestation.CreateChallengeResponseFromPair(sk, a, b);
            return new[] { (byte)response };
        }

        /// <summary>Create an empty aggregate object, for matching to values.</summary>
        public override Dictionary<string, object> CreateCertaintyAggregate(Attestation attestation)
            => BonehExactAttestation.CreateEmptyRelativityMap();

        /// <summary>Use a known value to check for honesty.</summary>
        public override byte[] CreateHonestyChallenge(object publicKey, int value)
        {
            var rawChallenge = BonehExactAttestation.CreateHonestyCheck((BonehPublicKey)publicKey, value);
            return IPack.PackPair(rawChallenge.A, rawChallenge.B);
        }

        /// <summary>Given a response, check if it matches the expected value.</summary>
        public override bool ProcessHonestyChallenge(int value, byte[] response) => value == response[0];

        /// <summary>Given a response, update the current aggregate.</summary>
        public override Dictionary<string, object> ProcessChallengeResponse(
            Dictionary<string, object> aggregate, byte[] challenge, byte[] response)
        {
            BonehExactAttestation.ProcessChallengeResponse(aggregate, response[0]);
            return aggregate;
        }

        public override (byte[] IdFormatBytes, object SecretKey) ImportBlob(byte[] blob)
            => throw new NotImplementedException();
    }
}
