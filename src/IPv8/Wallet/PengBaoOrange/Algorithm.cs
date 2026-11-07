// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Cryptography;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.PengBaoOrange
{
    // Alias: the bare name Attestation would collide with the IPv8.Attestation namespace.
    using Attestation = IPv8.Wallet.Cryptography.Attestation;

    /// <summary>
    /// IPv8 wrapper around Peng and Bao's efficient range proof scheme
    /// (port of ipv8/attestation/wallet/pengbaorange/algorithm.py::PengBaoRangeAlgorithm).
    /// </summary>
    public class PengBaoRangeAlgorithm : IdentityAlgorithm
    {
        public const int LargeInteger = 32765;

        private readonly int _keySize;
        private readonly BigInteger _a;
        private readonly BigInteger _b;

        public PengBaoRangeAlgorithm(string idFormat, Dictionary<string, Dictionary<string, object>> formats)
            : base(idFormat, formats)
        {
            // Check algorithm match
            if ((string)formats[idFormat]["algorithm"] != "pengbaorange")
            {
                throw new InvalidOperationException("Identity format linked to wrong algorithm");
            }

            // Check key size match
            _keySize = (int)(long)formats[idFormat]["key_size"];
            if (_keySize < 32 || _keySize > 512)
            {
                throw new InvalidOperationException("Illegal key size specified");
            }

            _a = (long)formats[idFormat]["min"];
            _b = (long)formats[idFormat]["max"];
        }

        /// <summary>Generate a secret key.</summary>
        public override object GenerateSecretKey() => Boneh.GenerateKeypair(_keySize).PrivateKey;

        public override object LoadSecretKey(byte[] serialized) => BonehPrivateKey.Unserialize(serialized);

        public override object LoadPublicKey(byte[] serialized) => BonehPublicKey.Unserialize(serialized);

        public override Attestation GetAttestationClass() => new PengBaoAttestation();

        public override byte[] Attest(object publicKey, byte[] value)
        {
            var ivalue = BigMath.FromBigEndianUnsigned(value);
            return PengBaoAttestationFactory.CreateAttestPair((BonehPublicKey)publicKey, ivalue, _a, _b,
                _keySize).SerializePrivateKey((BonehPublicKey)publicKey);
        }

        /// <summary>
        /// The current certainty of the aggregate object representing a certain value:
        /// 1 is in range, 0 is out of range.
        /// </summary>
        public override double Certainty(byte[] value, Dictionary<string, object> aggregate)
        {
            var inRange = aggregate.Count > 1;
            foreach (var pair in aggregate)
            {
                if (pair.Key != "attestation")
                {
                    inRange &= (bool)pair.Value;
                }
            }
            var match = inRange ? 1.0 : 0.0;
            // py: struct.unpack(">?", value)[0] — the value is a single packed bool byte.
            return value.Length > 0 && value[0] != 0 ? match : 1.0 - match;
        }

        /// <summary>Create challenges for a certain counterparty.</summary>
        public override List<byte[]> CreateChallenges(object publicKey, Attestation attestation)
        {
            var pk = (BonehPublicKey)publicKey;
            var mod = pk.G.Mod - 1;
            return new List<byte[]>
            {
                IPack.PackPair(SafeRndInt(_keySize, mod), SafeRndInt(_keySize, mod))
            };
        }

        private static BigInteger SafeRndInt(int keySize, BigInteger mod)
        {
            // py: int(hexlify(urandom(key_size // 8)), 16) % mod, retried while < LARGE_INTEGER.
            BigInteger rnd;
            do
            {
                var bytes = new byte[keySize / 8];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(bytes);
                }
                rnd = BigMath.FromBigEndianUnsigned(bytes) % mod;
            } while (rnd < LargeInteger);
            return rnd;
        }

        /// <summary>Create an honest response to a challenge of our value.</summary>
        public override byte[] CreateChallengeResponse(object secretKey, Attestation attestation,
                                                       byte[] challenge)
        {
            var sk = (BonehPrivateKey)secretKey;
            var (s, t, _) = IPack.UnpackPair(challenge);
            // If someone is trying to cheat us by selecting an s or t which is too small, we
            // return random garbage.
            if (s < LargeInteger || t < LargeInteger)
            {
                return Util.Concat(
                    IPack.PackPair(SafeRndInt(_keySize, sk.G.Mod), SafeRndInt(_keySize, sk.G.Mod)),
                    IPack.PackPair(SafeRndInt(_keySize, sk.G.Mod), SafeRndInt(_keySize, sk.G.Mod)));
            }
            var (x, y, u, v) = ((PengBaoAttestation)attestation).PrivateData.GenerateResponse(s, t);
            return Util.Concat(IPack.PackPair(x, y), IPack.PackPair(u, v));
        }

        /// <summary>Create an empty aggregate object, for matching to values.</summary>
        public override Dictionary<string, object> CreateCertaintyAggregate(Attestation attestation)
            => new Dictionary<string, object> { ["attestation"] = attestation };

        public override byte[] CreateHonestyChallenge(object publicKey, int value)
            => throw new NotImplementedException();

        public override bool ProcessHonestyChallenge(int value, byte[] response)
            => throw new NotImplementedException();

        /// <summary>Given a response, update the current aggregate.</summary>
        public override Dictionary<string, object> ProcessChallengeResponse(
            Dictionary<string, object> aggregate, byte[] challenge, byte[] response)
        {
            var (x, y, remainder) = IPack.UnpackPair(response);
            var (u, v, _) = IPack.UnpackPair(remainder);
            var (s, t, _) = IPack.UnpackPair(challenge);
            var attestation = (PengBaoAttestation)aggregate["attestation"];
            // NOTE (py-internal key): challenge bytes are keyed by their hex form (C# dictionary
            // keys must be strings; py keys by the raw bytes object).
            aggregate[Util.Hex(challenge)] = attestation.PublicData.Check(_a, _b, s, t, x, y, u, v);
            return aggregate;
        }

        public override (byte[] IdFormatBytes, object SecretKey) ImportBlob(byte[] blob)
            => throw new NotImplementedException();
    }
}
