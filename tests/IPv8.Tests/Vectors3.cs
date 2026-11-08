// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.IO;
using System.Text.Json;

namespace IPv8.Tests
{
    /// <summary>
    /// Loader for the Phase 3 tunnel golden vectors
    /// (contract/vectors-phase3.json, copied next to the test assembly).
    /// </summary>
    public static class Vectors3
    {
        private static readonly Lazy<JsonElement> Root = new Lazy<JsonElement>(LoadRoot);

        private static JsonElement LoadRoot()
        {
            var assemblyLocation = AppContext.BaseDirectory;
            var path = Path.Combine(assemblyLocation, "vectors-phase3.json");
            var json = File.ReadAllText(path);
            return JsonDocument.Parse(json).RootElement.Clone();
        }

        public static JsonElement RootElement => Root.Value;

        public static JsonElement Section(string name) => Root.Value.GetProperty(name);

        public static string MetaKey(string key) => Root.Value.GetProperty("meta").GetProperty(key).GetString();

        public static string MetaKeys(string key)
            => Root.Value.GetProperty("meta").GetProperty("keys").GetProperty(key).GetString();

        public static string HexString(JsonElement parent, string key) => parent.GetProperty(key).GetString();

        public static byte[] Hex(JsonElement parent, string key) => Util.Unhex(parent.GetProperty(key).GetString());

        /// <summary>Hex string under parent[child][key].</summary>
        public static string HexString(JsonElement parent, string child, string key)
            => parent.GetProperty(child).GetProperty(key).GetString();

        /// <summary>Hex bytes under parent[child][key].</summary>
        public static byte[] Hex(JsonElement parent, string child, string key)
            => Util.Unhex(parent.GetProperty(child).GetProperty(key).GetString());

        public static byte[] Unhex(string hex) => Util.Unhex(hex);

        public static string Hex(byte[] data) => Util.Hex(data);
    }
}
