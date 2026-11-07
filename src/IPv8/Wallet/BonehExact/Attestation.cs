// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Numerics;
using IPv8.Wallet.Primitives;

namespace IPv8.Wallet.BonehExact
{
    /// <summary>
    /// Attestation and challenge machinery for the exact Boneh scheme
    /// (port of ipv8/attestation/wallet/bonehexact/attestation.py).
    /// </summary>
    public static class BonehExactAttestation
    {
        /// <summary>
        /// Generate a group of size n which is its own modular additive inverse modulo p + 1.
        /// </summary>
        public static List<BigInteger> GenerateModularAdditiveInverse(BigInteger p, int n)
        {
            var r = new List<BigInteger>();
            for (var i = 0; i < n - 1; i++)
            {
                r.Add(RandInt(1, p - 1));
            }
            BigInteger sum = 0;
            foreach (var value in r)
            {
                sum += value;
            }
            r.Add(p - FP2Value.PyMod(sum, p + 1) + 1);
            Shuffle(r);
            return r;
        }

        private static readonly Random Rng = new Random();

        private static BigInteger RandInt(BigInteger min, BigInteger max)
        {
            var range = max - min + 1;
            var bytes = new byte[(BigMath.ToBitLength(range) + 7) / 8];
            BigInteger candidate;
            do
            {
                lock (Rng)
                {
                    Rng.NextBytes(bytes);
                }
                candidate = BigMath.FromBigEndianUnsigned(bytes) % range;
            } while (false);
            return min + candidate;
        }

        private static void Shuffle<T>(IList<T> list)
        {
            for (var i = list.Count - 1; i > 0; i--)
            {
                int j;
                lock (Rng)
                {
                    j = Rng.Next(i + 1);
                }
                (list[i], list[j]) = (list[j], list[i]);
            }
        }

        /// <summary>Create an attestation for a public key's value lying within a certain bitspace.</summary>
        public static BonehAttestation Attest(BonehPublicKey pk, BigInteger value, int bitspace)
        {
            // py: A = [int(c) for c in str(bin(value))[2:]] — binary digits, most-significant first.
            var a = BinaryDigitsMsbFirst(value);
            while (a.Count < bitspace)
            {
                a.Insert(0, 0);
            }
            var r = GenerateModularAdditiveInverse(pk.P, bitspace);
            var tOutPublicV = new List<FP2Value>();
            for (var i = 0; i < a.Count; i++)
            {
                tOutPublicV.Add(Boneh.Encode(pk, a[i] + r[i]));
            }
            var tOutPrivate = new List<(int I, FP2Value E)>();
            for (var i = 0; i < a.Count - 1; i += 2)
            {
                // py: encode(PK, PK.p - ((R[i] + R[i + 1]) % (PK.p + 1)) + 1)
                var inner = FP2Value.PyMod(r[i] + r[i + 1], pk.P + 1);
                tOutPrivate.Add((i, Boneh.Encode(pk, pk.P - inner + 1)));
            }
            // Shuffle:
            var tOutPublic = new List<(int I, FP2Value V1, FP2Value V2)>();
            for (var i = 0; i < tOutPublicV.Count; i += 2)
            {
                tOutPublic.Add((i, tOutPublicV[i], tOutPublicV[i + 1]));
            }
            Shuffle(tOutPublic);
            var outPublic = new List<FP2Value>();
            var outPrivate = new List<(int I, FP2Value E)>();
            var shuffleMap = new Dictionary<int, int>();
            foreach (var (i, v1, v2) in tOutPublic)
            {
                shuffleMap[i] = outPublic.Count;
                outPublic.Add(v1);
                outPublic.Add(v2);
            }
            foreach (var (i, e) in tOutPrivate)
            {
                outPrivate.Add((shuffleMap[i], e));
            }
            Shuffle(outPrivate);
            // Formalize
            var bitPairs = new List<BitPairAttestation>();
            foreach (var (i, e) in outPrivate)
            {
                bitPairs.Add(new BitPairAttestation(outPublic[i], outPublic[i + 1], e));
            }
            return new BonehAttestation(pk, bitPairs);
        }



        /// <summary>Create an attestation for a value using a SHA512 hash.</summary>
        public static BonehAttestation AttestSha512(BonehPublicKey pk, byte[] value)
            => Attest(pk, AttestationHash.Sha512AsInt(value), 512);

        /// <summary>Create the inter-bitpair relativity map of a value using the SHA512 hash.</summary>
        public static Dictionary<string, object> BinaryRelativitySha512(byte[] value)
            => BinaryRelativity(AttestationHash.Sha512AsInt(value), 512);

        /// <summary>Create an attestation for a value using a SHA256 hash.</summary>
        public static BonehAttestation AttestSha256(BonehPublicKey pk, byte[] value)
            => Attest(pk, AttestationHash.Sha256AsInt(value), 256);

        /// <summary>Create the inter-bitpair relativity map of a value using the SHA256 hash.</summary>
        public static Dictionary<string, object> BinaryRelativitySha256(byte[] value)
            => BinaryRelativity(AttestationHash.Sha256AsInt(value), 256);

        /// <summary>Create an attestation for a value using a SHA256 4-byte hash.</summary>
        public static BonehAttestation AttestSha256_4(BonehPublicKey pk, byte[] value)
            => Attest(pk, AttestationHash.Sha256_4AsInt(value), 32);

        /// <summary>Create the inter-bitpair relativity map of a value using the SHA256 4-byte hash.</summary>
        public static Dictionary<string, object> BinaryRelativitySha256_4(byte[] value)
            => BinaryRelativity(AttestationHash.Sha256_4AsInt(value), 32);

        /// <summary>Construct a map of possible challenge responses (py create_empty_relativity_map).</summary>
        public static Dictionary<string, object> CreateEmptyRelativityMap()
            => new Dictionary<string, object> { ["0"] = 0, ["1"] = 0, ["2"] = 0, ["3"] = 0 };

        /// <summary>Create the inter-bitpair relativity map of a value.</summary>
        public static Dictionary<string, object> BinaryRelativity(BigInteger value, int bitspace)
        {
            // NOTE: the port keys relativity maps by DECIMAL STRING (py keys by int); the golden
            // vectors store them the same way ({str(k): v}).
            var @out = new Dictionary<string, object> { ["0"] = 0, ["1"] = 0, ["2"] = 0 };
            var a = BinaryDigitsMsbFirst(value);
            while (a.Count < bitspace)
            {
                a.Insert(0, 0);
            }
            for (var i = 0; i < bitspace - 1; i += 2)
            {
                var key = (a[i] + a[i + 1]).ToString();
                @out[key] = (int)@out[key] + 1;
            }
            @out["3"] = 0;
            return @out;
        }

        /// <summary>
        /// Get the matching percentage between relativity maps. Mismatches result in 0.0.
        /// </summary>
        public static double BinaryRelativityMatch(Dictionary<string, object> expected,
                                                   Dictionary<string, object> value)
        {
            var match = 1.0;
            foreach (var pair in expected)
            {
                var expectedCount = (int)pair.Value;
                var valueCount = (int)value[pair.Key];
                if (expectedCount < valueCount)
                {
                    return 0.0;
                }
                if (expectedCount == 0 || valueCount == 0)
                {
                    continue;
                }
                match *= valueCount / (double)expectedCount;
            }
            return match;
        }

        /// <summary>Give the chance of a current relativity map being the expected one.</summary>
        public static double BinaryRelativityCertainty(Dictionary<string, object> expected,
                                                       Dictionary<string, object> value)
        {
            BigInteger sum = 0;
            foreach (var v in value.Values)
            {
                sum += (int)v;
            }
            // py: 1 - 0.5 ** (sum(value.values())) — float exponentiation.
            var cert = 1 - Math.Pow(0.5, (double)sum);
            return BinaryRelativityMatch(expected, value) * cert;
        }

        /// <summary>Create a challenge for a bitpair attestation of a certain public key.</summary>
        public static FP2Value CreateChallenge(BonehPublicKey pk, BitPairAttestation bitPair)
            => bitPair.Compress() * Boneh.Encode(pk, 0);

        /// <summary>Create a honesty check challenge.</summary>
        public static FP2Value CreateHonestyCheck(BonehPublicKey pk, BigInteger value)
            => Boneh.Encode(pk, value);

        /// <summary>Respond to a bitpair challenge (py create_challenge_response_from_pair).</summary>
        public static int CreateChallengeResponseFromPair(BonehPrivateKey sk, BigInteger first,
                                                          BigInteger second)
            => CreateChallengeResponse(sk, new FP2Value(sk.P, first, second));

        /// <summary>Respond to a bitpair challenge (py create_challenge_response).</summary>
        public static int CreateChallengeResponse(BonehPrivateKey sk, FP2Value challenge)
        {
            var decoded = Boneh.Decode(sk, new[] { BigInteger.Zero, BigInteger.One, new BigInteger(2) },
                                       challenge);
            return decoded == null ? 3 : (int)decoded.Value;
        }

        /// <summary>Process a challenge response in a relativity map.</summary>
        public static void ProcessChallengeResponse(Dictionary<string, object> relativityMap, int response)
        {
            var key = response.ToString();
            relativityMap[key] = (int)relativityMap[key] + 1;
        }

        /// <summary>py: [int(c) for c in str(bin(value))[2:]] — most-significant first, no leading zeros.</summary>
        public static List<int> BinaryDigitsMsbFirst(BigInteger value)
        {
            var digits = new List<int>();
            if (value.IsZero)
            {
                digits.Add(0);
                return digits;
            }
            var work = value;
            while (work > 0)
            {
                digits.Add(work.IsEven ? 0 : 1);
                work >>= 1;
            }
            digits.Reverse();
            return digits;
        }
    }
}
