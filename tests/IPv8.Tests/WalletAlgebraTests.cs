// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using IPv8.Attestation.Schema;
using IPv8.Wallet.BonehExact;
using IPv8.Wallet.PengBaoOrange;
using IPv8.Wallet.Primitives;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A18: boneh/pengbaorange algebra golden vectors (vectors-phase2.json → boneh / pengbao),
    /// BigInteger-exact.
    /// </summary>
    public class WalletAlgebraTests
    {
        private static BonehPrivateKey GoldenBonehSecretKey()
            => BonehPrivateKey.Unserialize(Util.Unhex(Vectors2.BonehKey("serialize_hex")));

        private static BonehPrivateKey GoldenPengBaoSecretKey()
            => BonehPrivateKey.Unserialize(Util.Unhex(Vectors2.PengBao.GetProperty("key")
                .GetProperty("serialize_hex").GetString()));

        [Fact]
        public void Boneh_Key_Golden_Vector()
        {
            var sk = GoldenBonehSecretKey();
            Assert.Equal(Vectors2.BonehKey("p"), sk.P.ToString());
            Assert.Equal(Vectors2.BonehKey("n"), sk.N.ToString());
            Assert.Equal(Vectors2.BonehKey("t1"), sk.T1.ToString());
            // Serialization roundtrips byte-exactly.
            Assert.Equal(Vectors2.BonehKey("serialize_hex"), Util.Hex(sk.Serialize()));
            Assert.Equal(Vectors2.BonehKey("public_serialize_hex"), Util.Hex(sk.PublicKey().Serialize()));
            var pk = BonehPublicKey.Unserialize(Util.Unhex(Vectors2.BonehKey("public_serialize_hex")));
            Assert.Equal(Vectors2.BonehKey("public_serialize_hex"), Util.Hex(pk.Serialize()));
        }

        [Fact]
        public void Boneh_Keygen_Roundtrip()
        {
            var (pk, sk) = Boneh.GenerateKeypair(32);
            // p = l*n - 1 prime, p mod 3 = 2, n = t1*t2 with t1, t2 safe primes.
            var t2 = sk.N / sk.T1;
            Assert.Equal(sk.T1 * t2, sk.N);
            Assert.Equal(2, FP2Value.PyMod(pk.P, 3));
            Assert.True(BigMath.IsPrime(pk.P));
            Assert.True(BigMath.IsPrime(sk.T1));
            Assert.True(BigMath.IsPrime((sk.T1 - 1) / 2));
            Assert.True(BigMath.IsPrime(t2));
            Assert.True(BigMath.IsPrime((t2 - 1) / 2));
            // Roundtrip through the wire format.
            var sk2 = BonehPrivateKey.Unserialize(sk.Serialize());
            Assert.Equal(Util.Hex(sk.Serialize()), Util.Hex(sk2.Serialize()));
            Assert.Equal(Util.Hex(pk.Serialize()), Util.Hex(BonehPublicKey.Unserialize(pk.Serialize()).Serialize()));
            // Encode/decode roundtrip over the full message space.
            var msgspace = Enumerable.Range(0, 256).Select(i => new BigInteger(i)).ToArray();
            foreach (var m in new[] { 0, 1, 2, 3, 17, 128, 255 })
            {
                var cipher = Boneh.Encode(pk, m);
                Assert.Equal((BigInteger?)m, Boneh.Decode(sk, msgspace, cipher));
            }
        }

        [Fact]
        public void Boneh_Encode_Decode_Golden_Vectors()
        {
            var sk = GoldenBonehSecretKey();
            var msgspace = Enumerable.Range(0, 256).Select(i => new BigInteger(i)).ToArray();
            foreach (var (m, cipherA, cipherB) in Vectors2.BonehEncodeDecode())
            {
                // The golden ciphertext (compressed) must decode back to m with the golden SK.
                var cipher = new FP2Value(sk.P, BigInteger.Parse(cipherA), BigInteger.Parse(cipherB));
                Assert.Equal((BigInteger?)m, Boneh.Decode(sk, msgspace, cipher));
            }
        }

        [Fact]
        public void Boneh_Attestation_Golden_Vector()
        {
            var sk = GoldenBonehSecretKey();
            var vector = Vectors2.BonehAttestation;
            Assert.Equal("sha256_4", vector.GetProperty("hash_mode").GetString());
            Assert.Equal(32, vector.GetProperty("bitspace").GetInt32());

            var attestation = new BonehAttestation().Unserialize(Util.Unhex(
                vector.GetProperty("serialized_hex").GetString()), "id_metadata") as BonehAttestation;
            Assert.Equal(vector.GetProperty("bitpair_count").GetInt32(), attestation.BitPairs.Count);
            // The public serialization is stable (roundtrip byte-exact).
            Assert.Equal(vector.GetProperty("serialized_hex").GetString(), Util.Hex(attestation.Serialize()));

            // The inter-bitpair relativity map of the value is deterministic.
            var value = Util.Unhex(vector.GetProperty("value_hex").GetString());
            var expectedRelativity = BonehExactAttestation.BinaryRelativitySha256_4(value);
            var vectorRelativity = vector.GetProperty("relativity_map");
            foreach (var property in vectorRelativity.EnumerateObject())
            {
                Assert.Equal(vectorRelativity.GetProperty(property.Name).GetInt32(),
                             (int)expectedRelativity[property.Name]);
            }

            // Challenges: responses are deterministic given the golden challenges + SK.
            var aggregate = BonehExactAttestation.CreateEmptyRelativityMap();
            var challenges = vector.GetProperty("challenges");
            foreach (var challengeVector in challenges.EnumerateArray())
            {
                var challenge = Util.Unhex(challengeVector.GetProperty("challenge_hex").GetString());
                var (a, b, _) = IPack.UnpackPair(challenge);
                var response = BonehExactAttestation.CreateChallengeResponseFromPair(sk, a, b);
                Assert.InRange(response, 0, 3);
                Assert.Equal(challengeVector.GetProperty("response_int").GetInt32(), response);
                var packed = new[] { (byte)response };
                Assert.Equal(challengeVector.GetProperty("response_packed_hex").GetString(), Util.Hex(packed));
                BonehExactAttestation.ProcessChallengeResponse(aggregate, response);
            }
            var vectorAggregate = vector.GetProperty("aggregate_after_challenges");
            foreach (var property in vectorAggregate.EnumerateObject())
            {
                Assert.Equal(vectorAggregate.GetProperty(property.Name).GetInt32(), (int)aggregate[property.Name]);
            }

            // Certainty of the correct value ~ 1.0, wrong value 0.0.
            var certCorrect = BonehExactAttestation.BinaryRelativityCertainty(
                BonehExactAttestation.BinaryRelativitySha256_4(value), aggregate);
            Assert.True(certCorrect > 0.99, $"certainty_correct {certCorrect}");
            var certWrong = BonehExactAttestation.BinaryRelativityCertainty(
                BonehExactAttestation.BinaryRelativitySha256_4(Util.Utf8("tesw")),
                BonehExactAttestation.CreateEmptyRelativityMap());
            Assert.Equal(0.0, certWrong);

            // Honesty check: challenge = pack_pair(encode(PK, value)); honest response decodes to value.
            var honestyChallenge = Util.Unhex(vector.GetProperty("honesty_challenge_hex").GetString());
            var (ha, hb, _) = IPack.UnpackPair(honestyChallenge);
            var honestyResponse = new[] { (byte)BonehExactAttestation.CreateChallengeResponseFromPair(sk, ha, hb) };
            Assert.Equal(vector.GetProperty("honesty_response_packed_hex").GetString(), Util.Hex(honestyResponse));
            Assert.True(new BonehExactAlgorithm("id_metadata", DefaultIdentityFormats.Formats.ToDictionary(
                            pair => pair.Key, pair => pair.Value)).ProcessHonestyChallenge(2, honestyResponse));
        }

        [Fact]
        public void Boneh_Attestation_Big_Golden_Vector()
        {
            var vector = Vectors2.BonehAttestationBig;
            Assert.Equal("sha256", vector.GetProperty("hash_mode").GetString());
            Assert.Equal(256, vector.GetProperty("bitspace").GetInt32());
            var attestation = new BonehAttestation().Unserialize(Util.Unhex(
                vector.GetProperty("serialized_hex").GetString()), "id_metadata_big") as BonehAttestation;
            Assert.Equal(vector.GetProperty("bitpair_count").GetInt32(), attestation.BitPairs.Count);
            Assert.Equal(vector.GetProperty("serialized_hex").GetString(), Util.Hex(attestation.Serialize()));
        }

        [Fact]
        public void PengBao_Golden_Vector()
        {
            var vector = Vectors2.PengBao;
            var sk = GoldenPengBaoSecretKey();
            var keyVector = vector.GetProperty("key");
            Assert.Equal(keyVector.GetProperty("p").GetString(), sk.P.ToString());
            Assert.Equal(keyVector.GetProperty("n").GetString(), sk.N.ToString());
            Assert.Equal(keyVector.GetProperty("t1").GetString(), sk.T1.ToString());
            Assert.Equal(keyVector.GetProperty("serialize_hex").GetString(), Util.Hex(sk.Serialize()));
            Assert.Equal(keyVector.GetProperty("public_serialize_hex").GetString(),
                         Util.Hex(sk.PublicKey().Serialize()));

            var a = vector.GetProperty("a").GetInt32();
            var b = vector.GetProperty("b").GetInt32();
            Assert.Equal(18, a);
            Assert.Equal(200, b);
            Assert.Equal(vector.GetProperty("value_int").GetInt32(), 30);

            // Public data: unserialize → check with the golden challenge response.
            var publicSerialized = Util.Unhex(vector.GetProperty("public_serialized_hex").GetString());
            var (publicData, rest) = PengBaoPublicData.Unserialize(publicSerialized);
            Assert.Empty(rest);

            var challengeVector = vector.GetProperty("challenge");
            var challenge = Util.Unhex(challengeVector.GetProperty("challenge_hex").GetString());
            var (s, t, _) = IPack.UnpackPair(challenge);
            Assert.Equal(challengeVector.GetProperty("s").GetInt64(), (long)s);
            Assert.Equal(challengeVector.GetProperty("t").GetInt64(), (long)t);
            Assert.True(s >= 32765 && t >= 32765, "LARGE_INTEGER bound");

            var x = BigInteger.Parse(challengeVector.GetProperty("x").GetString());
            var y = BigInteger.Parse(challengeVector.GetProperty("y").GetString());
            var u = BigInteger.Parse(challengeVector.GetProperty("u").GetString());
            var v = BigInteger.Parse(challengeVector.GetProperty("v").GetString());
            Assert.True(publicData.Check(a, b, s, t, x, y, u, v), "check_ok");
            // Tampered response must fail.
            Assert.False(publicData.Check(a, b, s, t, x + 1, y, u, v), "check_tampered");
            // Wire response roundtrip.
            var responseWire = Util.Unhex(challengeVector.GetProperty("response_wire_hex").GetString());
            var (rx, ry, rem) = IPack.UnpackPair(responseWire);
            var (ru, rv, _) = IPack.UnpackPair(rem);
            Assert.True(publicData.Check(a, b, s, t, rx, ry, ru, rv), "check_wire_response");
            // Relay: serialize → unserialize → check again.
            var relayed = PengBaoPublicData.Unserialize(publicData.Serialize()).PublicData;
            Assert.True(relayed.Check(a, b, s, t, x, y, u, v), "relay_ok");

            // Private data: decode with the golden SK and regenerate the response.
            var privateSerialized = Util.Unhex(vector.GetProperty("private_serialized_hex").GetString());
            var privateAttestation = new PengBaoAttestation()
                .UnserializePrivateKey(sk, privateSerialized, "id_metadata_range_18plus") as PengBaoAttestation;
            Assert.NotNull(privateAttestation.PrivateData);
            var (px, py, pu, pv) = privateAttestation.PrivateData.GenerateResponse(s, t);
            Assert.Equal(x, px);
            Assert.Equal(y, py);
            Assert.Equal(u, pu);
            Assert.Equal(v, pv);
            // The private serialization roundtrips STRUCTURALLY (the encoded per-byte encodings
            // embed a random blinding r, so byte equality does not hold across re-serializations).
            var redecoded = new PengBaoAttestation()
                .UnserializePrivateKey(sk, privateAttestation.SerializePrivateKey(sk.PublicKey()),
                                       "id_metadata_range_18plus") as PengBaoAttestation;
            Assert.Equal(privateAttestation.PrivateData.M1, redecoded.PrivateData.M1);
            Assert.Equal(privateAttestation.PrivateData.M2, redecoded.PrivateData.M2);
            Assert.Equal(privateAttestation.PrivateData.M3, redecoded.PrivateData.M3);
            Assert.Equal(privateAttestation.PrivateData.R1, redecoded.PrivateData.R1);
            Assert.Equal(privateAttestation.PrivateData.R2, redecoded.PrivateData.R2);
            Assert.Equal(privateAttestation.PrivateData.R3, redecoded.PrivateData.R3);
        }

        [Fact]
        public void PengBao_Algorithm_Aggregate_And_Certainty()
        {
            var vector = Vectors2.PengBao;
            var algorithm = new PengBaoRangeAlgorithm("id_metadata_range_18plus",
                DefaultIdentityFormats.Formats.ToDictionary(pair => pair.Key, pair => pair.Value));

            var publicSerialized = Util.Unhex(vector.GetProperty("public_serialized_hex").GetString());
            var attestation = new PengBaoAttestation().Unserialize(publicSerialized, "id_metadata_range_18plus")
                as PengBaoAttestation;

            var challenge = Util.Unhex(vector.GetProperty("challenge").GetProperty("challenge_hex").GetString());
            var responseWire = Util.Unhex(vector.GetProperty("challenge").GetProperty("response_wire_hex").GetString());

            var aggregate = algorithm.CreateCertaintyAggregate(attestation);
            algorithm.ProcessChallengeResponse(aggregate, challenge, responseWire);
            // The single challenge passed: the aggregate only holds the attestation + one True.
            Assert.Equal(2, aggregate.Count);
            Assert.Equal(true, aggregate[Util.Hex(challenge)]);
            // value b"\x01" packs as a true bool byte → in-range → 1.0.
            Assert.Equal(1.0, algorithm.Certainty(new byte[] { 1 }, aggregate));
            // value b"\x00" → 0.0.
            Assert.Equal(0.0, algorithm.Certainty(new byte[] { 0 }, aggregate));
        }
    }
}
