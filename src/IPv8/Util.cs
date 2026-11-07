// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Text;

namespace IPv8
{
    /// <summary>Small byte/string helpers shared across the port.</summary>
    public static class Util
    {
        private static readonly Encoding Utf8Strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false,
                                                                        throwOnInvalidBytes: true);

        /// <summary>Strict UTF-8 encoding (no BOM, throws on invalid sequences — like Python's .decode()).</summary>
        public static Encoding Utf8Encoding => Utf8Strict;

        public static byte[] Utf8(string s) => Utf8Strict.GetBytes(s);

        public static string Utf8ToString(byte[] data, int offset, int length)
            => Utf8Strict.GetString(data, offset, length);

        public static byte[] Sha1(byte[] data)
        {
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            return sha1.ComputeHash(data);
        }

        public static bool StartsWith(byte[] data, byte[] prefix)
        {
            if (data.Length < prefix.Length)
            {
                return false;
            }
            for (var i = 0; i < prefix.Length; i++)
            {
                if (data[i] != prefix[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static byte[] Slice(byte[] data, int start, int length)
        {
            if (start < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(start));
            }
            if (start >= data.Length)
            {
                return Array.Empty<byte>();
            }
            if (length < 0)
            {
                // Python slicing semantics: an empty (or reversed) slice is empty.
                return Array.Empty<byte>();
            }
            if (start + length > data.Length)
            {
                length = data.Length - start;
            }
            var result = new byte[length];
            Array.Copy(data, start, result, 0, length);
            return result;
        }

        public static byte[] SliceFrom(byte[] data, int start)
            => Slice(data, start, data.Length > start ? data.Length - start : 0);

        public static byte[] Concat(params byte[][] parts)
        {
            var total = 0;
            foreach (var part in parts)
            {
                total += part.Length;
            }
            var result = new byte[total];
            var offset = 0;
            foreach (var part in parts)
            {
                Array.Copy(part, 0, result, offset, part.Length);
                offset += part.Length;
            }
            return result;
        }

        public static byte[] CopyOf(byte[] data)
        {
            var result = new byte[data.Length];
            Array.Copy(data, result, data.Length);
            return result;
        }

        public static byte[] EmptyBytes = Array.Empty<byte>();

        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            for (var i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }

        public static int BytesHashCode(byte[] data)
        {
            unchecked
            {
                var hash = 17;
                foreach (var b in data)
                {
                    hash = (hash * 31) + b;
                }
                return hash;
            }
        }

        /// <summary>Seconds since the epoch (float), like Python's time.time().</summary>
        public static double NowEpoch()
            => (DateTimeOffset.UtcNow - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds;
    }

    /// <summary>Content-based equality comparer for byte arrays (for dictionary keys).</summary>
    public sealed class ByteArrayEqualityComparer : System.Collections.Generic.IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayEqualityComparer Instance = new ByteArrayEqualityComparer();

        public bool Equals(byte[] x, byte[] y) => Util.BytesEqual(x, y);

        public int GetHashCode(byte[] obj)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(nameof(obj));
            }
            // Cheap stable hash over the first bytes (keys here are small and fixed-size).
            unchecked
            {
                var hash = 17;
                var n = obj.Length < 8 ? obj.Length : 8;
                for (var i = 0; i < n; i++)
                {
                    hash = (hash * 31) + obj[i];
                }
                hash = (hash * 31) + obj.Length;
                return hash;
            }
        }
    }
}
