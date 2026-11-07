// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace IPv8.Database
{
    /// <summary>
    /// Minimal JSON reader/writer for the pure-managed database shim and metadata blobs.
    ///
    /// Deviation from py-ipv8 (documented in the port notes): the reference implementation
    /// persists its databases through native SQLite. Native SQLite is forbidden by the port's
    /// purity rules, so persistence goes through this JSON codec instead.
    /// The "python style" serializer mimics ``json.dumps`` defaults (", " and ": " separators,
    /// ensure_ascii escaping, repr-style floats) so signed metadata JSON stays byte-compatible
    /// with packets produced by py-ipv8.
    /// </summary>
    public static class MiniJson
    {
        private static readonly byte[] BytesTag = Util.Utf8("__bytes_b64");

        // ------------------------------------------------------------------
        // Parsing
        // ------------------------------------------------------------------

        public static object Parse(string json)
        {
            var index = 0;
            var value = ParseValue(json, ref index);
            SkipWhitespace(json, ref index);
            if (index != json.Length)
            {
                throw new FormatException($"Trailing JSON data at position {index}");
            }
            return value;
        }

        private static void SkipWhitespace(string json, ref int index)
        {
            while (index < json.Length && (json[index] == ' ' || json[index] == '\t'
                                                    || json[index] == '\n' || json[index] == '\r'))
            {
                index++;
            }
        }

        private static object ParseValue(string json, ref int index)
        {
            SkipWhitespace(json, ref index);
            if (index >= json.Length)
            {
                throw new FormatException("Unexpected end of JSON");
            }
            switch (json[index])
            {
                case '{': return ParseObject(json, ref index);
                case '[': return ParseArray(json, ref index);
                case '"': return ParseString(json, ref index);
                case 't':
                    Expect(json, ref index, "true");
                    return true;
                case 'f':
                    Expect(json, ref index, "false");
                    return false;
                case 'n':
                    Expect(json, ref index, "null");
                    return null;
                default: return ParseNumber(json, ref index);
            }
        }

        private static void Expect(string json, ref int index, string literal)
        {
            if (index + literal.Length > json.Length
                || string.CompareOrdinal(json, index, literal, 0, literal.Length) != 0)
            {
                throw new FormatException($"Invalid JSON literal at position {index}");
            }
            index += literal.Length;
        }

        private static Dictionary<string, object> ParseObject(string json, ref int index)
        {
            var result = new Dictionary<string, object>();
            index++; // {
            SkipWhitespace(json, ref index);
            if (index < json.Length && json[index] == '}')
            {
                index++;
                return result;
            }
            while (true)
            {
                SkipWhitespace(json, ref index);
                var key = ParseString(json, ref index);
                SkipWhitespace(json, ref index);
                if (json[index] != ':')
                {
                    throw new FormatException($"Expected ':' at position {index}");
                }
                index++;
                result[key] = ParseValue(json, ref index);
                SkipWhitespace(json, ref index);
                if (json[index] == ',')
                {
                    index++;
                    continue;
                }
                if (json[index] == '}')
                {
                    index++;
                    return result;
                }
                throw new FormatException($"Expected ',' or '}}' at position {index}");
            }
        }

        private static List<object> ParseArray(string json, ref int index)
        {
            var result = new List<object>();
            index++; // [
            SkipWhitespace(json, ref index);
            if (index < json.Length && json[index] == ']')
            {
                index++;
                return result;
            }
            while (true)
            {
                result.Add(ParseValue(json, ref index));
                SkipWhitespace(json, ref index);
                if (json[index] == ',')
                {
                    index++;
                    continue;
                }
                if (json[index] == ']')
                {
                    index++;
                    return result;
                }
                throw new FormatException($"Expected ',' or ']' at position {index}");
            }
        }

        private static string ParseString(string json, ref int index)
        {
            var sb = new StringBuilder();
            index++; // "
            while (index < json.Length && json[index] != '"')
            {
                var c = json[index];
                if (c == '\\')
                {
                    index++;
                    if (index >= json.Length)
                    {
                        throw new FormatException("Unterminated escape sequence");
                    }
                    switch (json[index])
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (index + 4 >= json.Length)
                            {
                                throw new FormatException("Invalid unicode escape");
                            }
                            sb.Append((char)Convert.ToInt32(json.Substring(index + 1, 4), 16));
                            index += 4;
                            break;
                        default:
                            throw new FormatException($"Invalid escape '\\{json[index]}'");
                    }
                    index++;
                }
                else
                {
                    sb.Append(c);
                    index++;
                }
            }
            if (index >= json.Length)
            {
                throw new FormatException("Unterminated JSON string");
            }
            index++; // closing quote
            return sb.ToString();
        }

        private static object ParseNumber(string json, ref int index)
        {
            var start = index;
            while (index < json.Length && (char.IsDigit(json[index]) || json[index] == '-'
                                                                || json[index] == '+' || json[index] == '.'
                                                                || json[index] == 'e' || json[index] == 'E'))
            {
                index++;
            }
            var literal = json.Substring(start, index - start);
            if (literal.Length == 0)
            {
                throw new FormatException($"Invalid JSON number at position {start}");
            }
            if (literal.IndexOfAny(new[] { '.', 'e', 'E' }) >= 0)
            {
                return double.Parse(literal, CultureInfo.InvariantCulture);
            }
            return long.Parse(literal, CultureInfo.InvariantCulture);
        }

        // ------------------------------------------------------------------
        // Serialization (compact, for the persistence file)
        // ------------------------------------------------------------------

        public static string Serialize(object value) => SerializeValue(value, new StringBuilder()).ToString();

        private static StringBuilder SerializeValue(object value, StringBuilder sb)
        {
            switch (value)
            {
                case null:
                    sb.Append("null");
                    break;
                case bool b:
                    sb.Append(b ? "true" : "false");
                    break;
                case string s:
                    SerializeString(s, sb);
                    break;
                case byte[] bytes:
                    sb.Append("{\"__bytes_b64\":\"").Append(Convert.ToBase64String(bytes)).Append("\"}");
                    break;
                case int i:
                    sb.Append(i.ToString(CultureInfo.InvariantCulture));
                    break;
                case long l:
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;
                case ulong ul:
                    sb.Append(ul.ToString(CultureInfo.InvariantCulture));
                    break;
                case double d:
                    sb.Append(FormatDouble(d));
                    break;
                case float f:
                    sb.Append(FormatDouble(f));
                    break;
                case IEnumerable<KeyValuePair<string, object>> dict:
                    SerializeDict(dict, sb);
                    break;
                case IEnumerable<object> list:
                    sb.Append('[');
                    var first = true;
                    foreach (var item in list)
                    {
                        if (!first)
                        {
                            sb.Append(',');
                        }
                        first = false;
                        SerializeValue(item, sb);
                    }
                    sb.Append(']');
                    break;
                default:
                    throw new ArgumentException($"Cannot serialize type {value.GetType().Name}");
            }
            return sb;
        }

        private static void SerializeDict(IEnumerable<KeyValuePair<string, object>> dict, StringBuilder sb)
        {
            sb.Append('{');
            var first = true;
            foreach (var pair in dict)
            {
                if (!first)
                {
                    sb.Append(',');
                }
                first = false;
                SerializeString(pair.Key, sb);
                sb.Append(':');
                SerializeValue(pair.Value, sb);
            }
            sb.Append('}');
        }

        private static void SerializeString(string s, StringBuilder sb)
        {
            sb.Append('"');
            foreach (var c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        // py json.dumps(ensure_ascii=True): everything outside printable ASCII
                        // (0x20..0x7E) is escaped as \\uXXXX; the named short escapes were
                        // already handled above.
                        if (c < ' ' || c > '~')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }

        /// <summary>
        /// Shortest round-trip double formatting with a Python-repr shape (always a '.' or an
        /// exponent, lowercase 'e', two-digit minimum exponent).
        /// </summary>
        public static string FormatDouble(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                throw new ArgumentException("Cannot serialize non-finite float");
            }
            var text = value.ToString("R", CultureInfo.InvariantCulture);
            if (text.IndexOfAny(new[] { '.', 'e', 'E' }) < 0)
            {
                text += ".0";
            }
            var eIndex = text.IndexOfAny(new[] { 'e', 'E' });
            if (eIndex >= 0)
            {
                var mantissa = text.Substring(0, eIndex);
                if (mantissa.IndexOf('.') < 0)
                {
                    mantissa += ".0";
                }
                var exponentPart = text.Substring(eIndex + 1);
                var negative = exponentPart.StartsWith("-", StringComparison.Ordinal);
                var digits = negative ? exponentPart.Substring(1) : exponentPart;
                if (digits.Length < 2)
                {
                    digits = digits.PadLeft(2, '0');
                }
                text = mantissa + "e" + (negative ? "-" : "+") + digits;
            }
            return text;
        }

        /// <summary>Decode the byte-array marker objects back into byte arrays (in-place style).</summary>
        public static object DecodeBytesMarkers(object value)
        {
            switch (value)
            {
                case Dictionary<string, object> dict:
                    if (dict.Count == 1 && dict.ContainsKey("__bytes_b64"))
                    {
                        return Convert.FromBase64String((string)dict["__bytes_b64"]);
                    }
                    foreach (var key in new List<string>(dict.Keys))
                    {
                        dict[key] = DecodeBytesMarkers(dict[key]);
                    }
                    return dict;
                case List<object> list:
                    for (var i = 0; i < list.Count; i++)
                    {
                        list[i] = DecodeBytesMarkers(list[i]);
                    }
                    return list;
                default:
                    return value;
            }
        }

        // ------------------------------------------------------------------
        // Python json.dumps-style serialization (for signed metadata)
        // ------------------------------------------------------------------

        /// <summary>
        /// Serialize like Python's ``json.dumps`` with default arguments: ``", "`` item
        /// separators, ``": "`` key separators and ensure_ascii=True escaping.
        /// </summary>
        public static string PythonDumps(object value)
        {
            var sb = new StringBuilder();
            PythonSerialize(value, sb);
            return sb.ToString();
        }

        private static void PythonSerialize(object value, StringBuilder sb)
        {
            switch (value)
            {
                case null:
                    sb.Append("null");
                    break;
                case bool b:
                    sb.Append(b ? "true" : "false");
                    break;
                case string s:
                    SerializeString(s, sb);
                    break;
                case byte[] bytes:
                    // Bytes are not native JSON in py either; the port tags them base64 so that
                    // round-trips through the JSON persistence layer keep the original bytes.
                    sb.Append("{\"__bytes_b64\": \"").Append(Convert.ToBase64String(bytes)).Append("\"}");
                    break;
                case int i:
                    sb.Append(i.ToString(CultureInfo.InvariantCulture));
                    break;
                case long l:
                    sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    break;
                case ulong ul:
                    sb.Append(ul.ToString(CultureInfo.InvariantCulture));
                    break;
                case double d:
                    sb.Append(FormatDouble(d));
                    break;
                case float f:
                    sb.Append(FormatDouble(f));
                    break;
                case IEnumerable<KeyValuePair<string, object>> dict:
                    sb.Append('{');
                    var first = true;
                    foreach (var pair in dict)
                    {
                        if (!first)
                        {
                            sb.Append(", ");
                        }
                        first = false;
                        SerializeString(pair.Key, sb);
                        sb.Append(": ");
                        PythonSerialize(pair.Value, sb);
                    }
                    sb.Append('}');
                    break;
                case IEnumerable<object> list:
                    sb.Append('[');
                    var listFirst = true;
                    foreach (var item in list)
                    {
                        if (!listFirst)
                        {
                            sb.Append(", ");
                        }
                        listFirst = false;
                        PythonSerialize(item, sb);
                    }
                    sb.Append(']');
                    break;
                default:
                    throw new ArgumentException($"Cannot serialize type {value.GetType().Name} python-style");
            }
        }
    }

    /// <summary>Insertion-ordered string-keyed map used for JSON objects and metadata dicts.</summary>
    public static class JsonDict
    {
        public static Dictionary<string, object> Of(params (string Key, object Value)[] entries)
        {
            var result = new Dictionary<string, object>();
            foreach (var (key, value) in entries)
            {
                result[key] = value;
            }
            return result;
        }
    }
}
