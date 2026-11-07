// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.IO;
using System.Text.Json;
using IPv8.PeerDiscovery;

namespace IPv8.Tests
{
    /// <summary>
    /// Loader for the golden vectors (contract/vectors.json, copied next to the test assembly).
    /// </summary>
    public static class Vectors
    {
        private static readonly Lazy<JsonElement> Root = new Lazy<JsonElement>(LoadRoot);

        private static JsonElement LoadRoot()
        {
            var assemblyLocation = AppContext.BaseDirectory;
            var path = Path.Combine(assemblyLocation, "vectors.json");
            var json = File.ReadAllText(path);
            return JsonDocument.Parse(json).RootElement.Clone();
        }

        /// <summary>The JSON object under vectors["crypto"][key] (has seed/pub/msg/sig subfields).</summary>
        public static JsonElement CryptoObject(string key) => Root.Value.GetProperty("crypto").GetProperty(key);

        /// <summary>Hex subfield of a vectors["crypto"][key] object.</summary>
        public static string CryptoField(string key, string field) => CryptoObject(key).GetProperty(field).GetString();

        /// <summary>Hex string under vectors["keys"].</summary>
        public static string Keys(string key) => Root.Value.GetProperty("keys").GetProperty(key).GetString();

        /// <summary>Hex string under vectors["serializer"].</summary>
        public static string SerializerVector(string key)
            => Root.Value.GetProperty("serializer").GetProperty(key).GetString();
    }

    /// <summary>
    /// Fixed key material and golden full-packet hex vectors for the full-packet roundtrip (A3),
    /// generated against the py-ipv8 packet algorithm (prefix + msg_num + auth + dist + payload +
    /// Ed25519 signature) with RFC-fixed keys (RFC 8032 TEST 1 seed, RFC 7748 §6.1 alice private key).
    /// </summary>
    public static class GoldenPackets
    {
        public const string EdSeedHex =
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        public const string XPrivHex =
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        public const string PubBinHex =
            "4c69624e61434c504b3a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
            + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        public const string CommunityIdHex =
            "4c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348";
        public const string PrefixHex =
            "00024c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348";

        public const ulong GlobalTime = 43;

        public const string IntroRequestHex =
            "00024c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348f6004a4c69624e61434c504b3a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6ad75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000002b0102030413880a00000103e85555555507d001002bdeadbeefa01e4643da3c18705fbb75de36b51d4eea3f6fa175aeff861218cb352f92e1ec739a09268fe08ae337dc0ac671502ea7b197bb33329ee1c566784de00a217004";

        public const string IntroResponseHex =
            "00024c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348f5004a4c69624e61434c504b3a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6ad75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000002b3701020323290a00000207d25555555507d200000000000000000000000010002bfde8df78b4d1c513e2c8c9001059867d52a61d69ddde991b8bd0ddf299ab6cd7ad0ce9f45f71ebaeec6a1c564d7cc2fd43423161e1786c48efdf6093d005f201";

        public const string NewIntroRequestHex =
            "00024c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348ea004a4c69624e61434c504b3a8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6ad75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a000000000000002b01010203041388010a00000103e8015555555507d0002b001c4d026ca81e3354c8bfbb33a2d07e33a17bf7c50c2a4436faab09f2af9e485c6984493d0025abc54f5e36598711d2abf071b5f1966e8aec9c990eb819152800";

        public const string NewPunctureRequestHex =
            "00024c1bbe1a9fa74f89f9e461dd996ab41e8f4b5348e8000000000000002b010a00000103e8015555555507d0002b";
    }
}
