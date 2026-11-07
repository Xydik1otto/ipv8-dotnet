// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Byte-exact port of ipv8/messaging/serialization.py: the packers (DefaultStruct, Bits, Raw, VarLen,
// VarLenUtf8, IPv4, Address, ListOf, DefaultArray, NestedPayload) and the Serializer itself.
// All integers are packed big-endian (Python ">X" struct formats). The DefaultArray packers use
// little-endian item encoding: py-ipv8 delegates to CPython's ``array`` module, which emits
// machine (little-endian) byte order.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace IPv8.Messaging
{
    /// <summary>A given message format could not be packed to bytes or unpacked from bytes.</summary>
    public class PackError : Exception
    {
        public PackError(string message) : base(message)
        {
        }
    }

    /// <summary>
    /// One ("format", *args) entry of a Serializable pack list (a Python tuple in py-ipv8).
    /// </summary>
    public readonly struct PackEntry
    {
        public readonly string Format;
        public readonly object[] Args;

        public PackEntry(string format, params object[] args)
        {
            Format = format ?? throw new ArgumentNullException(nameof(format));
            Args = args ?? Array.Empty<object>();
        }

        public override string ToString()
        {
            var argsText = string.Join(", ", Args);
            return $"(\"{Format}\", {argsText})";
        }
    }

    /// <summary>Interface for packers: pack and unpack objects to and from bytes.</summary>
    public interface IPacker
    {
        /// <summary>Pack the given data.</summary>
        byte[] Pack(object[] args);

        /// <summary>
        /// Unpack an object from the given data buffer and return the new offset in the data buffer.
        /// </summary>
        int Unpack(byte[] data, int offset, List<object> unpackList, object[] args);
    }

    /// <summary>
    /// Interface for serializable objects (port of ipv8/messaging/serialization.py::Serializable).
    /// Subclasses expose their py-ipv8 ``format_list`` through <see cref="FormatList"/>; entries are
    /// packer name strings, <see cref="Type"/> references (nested "payload") or lists thereof
    /// ("payload-list"). The py-ipv8 ``from_unpack_list`` classmethod is mirrored by
    /// <see cref="FromUnpackList"/> on a parameterless-constructed instance.
    /// </summary>
    public abstract class Serializable
    {
        /// <summary>The py-ipv8 ``format_list`` for this serializable.</summary>
        public abstract IReadOnlyList<object> FormatList { get; }

        /// <summary>
        /// Serialize this object to a Serializer pack list, e.g. ``[("H", x), ("raw", y), ..]``.
        /// </summary>
        public abstract IList<PackEntry> ToPackList();

        /// <summary>Create a new Serializable object from a list of unpacked variables.</summary>
        public abstract void FromUnpackList(object[] values);
    }

    /// <summary>A serializable that has extra printing functionality (py-ipv8 Payload).</summary>
    public abstract class Payload : Serializable
    {
        /// <summary>
        /// The message number of this payload (py-ipv8 class attribute ``msg_id``); -1 for payloads
        /// that are never sent as a message on their own (e.g. the header payloads). Subclasses
        /// define a static readonly ``MsgId`` field and forward it here.
        /// </summary>
        public virtual int MsgNum => -1;

        public override string ToString()
        {
            var outText = GetType().Name;
            foreach (var field in GetType().GetFields())
            {
                if (field.Name.StartsWith("_", StringComparison.Ordinal) || field.Name == "FormatList")
                {
                    continue;
                }
                var value = field.GetValue(this);
                var text = value is byte[] bytes ? "0x" + Hexlify(bytes) : value?.ToString() ?? "None";
                outText += $"\n| {field.Name}: {text}";
            }
            return outText;
        }

        protected static int ToInt(object value)
        {
            switch (value)
            {
                case int i: return i;
                case bool b: return b ? 1 : 0;
                case uint u: return (int)u;
                case long l: return (int)l;
                case ulong ul: return (int)ul;
                default:
                    throw new PackError($"Expected a number, got {value?.GetType().Name ?? "null"}");
            }
        }

        protected static long ToLong(object value)
        {
            switch (value)
            {
                case long l: return l;
                case int i: return i;
                case bool b: return b ? 1 : 0;
                case uint u: return u;
                case ulong ul: return (long)ul;
                default:
                    throw new PackError($"Expected a number, got {value?.GetType().Name ?? "null"}");
            }
        }

        private static string Hexlify(byte[] data) => Serializer.Hexlify(data);
    }

    /// <summary>Packer for a known struct format string, like "I", "20s", etc.</summary>
    public sealed class DefaultStruct : IPacker
    {
        private readonly struct Token
        {
            public readonly char Kind;
            public readonly int Count;
            public readonly int Size;

            public Token(char kind, int count)
            {
                Kind = kind;
                Count = count;
                Size = kind switch
                {
                    '?' => 1,
                    'B' => 1,
                    'H' => 2,
                    'I' => 4,
                    'L' => 4,
                    'Q' => 8,
                    'q' => 8,
                    'l' => 4,
                    'f' => 4,
                    'd' => 8,
                    'c' => 1,
                    's' => count,
                    _ => throw new PackError($"Unknown struct character '{kind}' in format")
                };
            }
        }

        private static int CharSize(char kind)
        {
            return kind switch
            {
                '?' => 1,
                'B' => 1,
                'H' => 2,
                'I' => 4,
                'L' => 4,
                'Q' => 8,
                'q' => 8,
                'l' => 4,
                'f' => 4,
                'd' => 8,
                'c' => 1,
                's' => 0, // counted separately
                _ => throw new PackError($"Unknown struct character '{kind}' in format")
            };
        }

        private readonly Token[] _tokens;
        public readonly int Size;

        public DefaultStruct(string formatStr)
        {
            FormatStr = formatStr ?? throw new ArgumentNullException(nameof(formatStr));
            var tokens = new List<Token>();
            var size = 0;
            var i = 0;
            // Python struct: a leading byte-order character selects the byte order; py-ipv8 always
            // uses ">" (big-endian, no padding). Accept (and require) only that one.
            if (i < formatStr.Length && formatStr[i] == '>')
            {
                i++;
            }
            else if (i < formatStr.Length && "@=<>!".IndexOf(formatStr[i]) >= 0)
            {
                throw new PackError($"Only '>' (big-endian) struct formats are supported, got '{formatStr}'");
            }
            while (i < formatStr.Length)
            {
                var c = formatStr[i];
                if (char.IsDigit(c))
                {
                    // A count directly in front of an 's' (e.g. "20s").
                    var start = i;
                    while (i < formatStr.Length && char.IsDigit(formatStr[i]))
                    {
                        i++;
                    }
                    var count = int.Parse(formatStr.Substring(start, i - start), CultureInfo.InvariantCulture);
                    if (i >= formatStr.Length || formatStr[i] != 's')
                    {
                        throw new PackError($"Unsupported repeat count in struct format '{formatStr}'");
                    }
                    tokens.Add(new Token('s', count));
                    size += count;
                    i++;
                    continue;
                }
                if (c == 's')
                {
                    throw new PackError($"Struct format '{formatStr}' requires a count for 's'");
                }
                var tokenSize = CharSize(c);
                if (tokenSize < 0)
                {
                    throw new PackError($"Unknown struct character '{c}' in format '{formatStr}'");
                }
                tokens.Add(new Token(c, 1));
                size += tokenSize;
                i++;
            }
            _tokens = tokens.ToArray();
            Size = size;
        }

        public string FormatStr { get; }

        public byte[] Pack(object[] args)
        {
            if (args.Length < _tokens.Length)
            {
                throw new PackError($"Struct format '{FormatStr}' requires {_tokens.Length} args, got {args.Length}");
            }
            var result = new byte[Size];
            var offset = 0;
            for (var t = 0; t < _tokens.Length; t++)
            {
                var token = _tokens[t];
                var value = args[t];
                switch (token.Kind)
                {
                    case '?':
                        result[offset] = Truthy(value) ? (byte)1 : (byte)0;
                        offset += 1;
                        break;
                    case 'B':
                        Be.WriteU64(result, offset, ToUnsigned(value, token.Kind, 255), 1);
                        offset += 1;
                        break;
                    case 'H':
                        Be.WriteU64(result, offset, ToUnsigned(value, token.Kind, 65535), 2);
                        offset += 2;
                        break;
                    case 'I':
                    case 'L':
                        Be.WriteU64(result, offset, ToUnsigned(value, token.Kind, 0xFFFFFFFFUL), 4);
                        offset += 4;
                        break;
                    case 'Q':
                        Be.WriteU64(result, offset, ToUnsigned(value, token.Kind, ulong.MaxValue), 8);
                        offset += 8;
                        break;
                    case 'q':
                        Be.WriteI64(result, offset, ToSigned(value, token.Kind, long.MinValue, long.MaxValue), 8);
                        offset += 8;
                        break;
                    case 'l':
                        Be.WriteI64(result, offset, ToSigned(value, token.Kind, int.MinValue, int.MaxValue), 4);
                        offset += 4;
                        break;
                    case 'f':
                        Be.WriteF32(result, offset, ToFloat(value));
                        offset += 4;
                        break;
                    case 'd':
                        Be.WriteF64(result, offset, ToDouble(value));
                        offset += 8;
                        break;
                    case 'c':
                    {
                        var bytes = ToBytes(value);
                        if (bytes.Length != 1)
                        {
                            throw new PackError($"'c' format requires exactly one byte, got {bytes.Length}");
                        }
                        result[offset] = bytes[0];
                        offset += 1;
                        break;
                    }
                    case 's':
                    {
                        var bytes = ToBytes(value);
                        // struct 's': truncate to N bytes, pad with NULs when shorter.
                        for (var k = 0; k < token.Count; k++)
                        {
                            result[offset + k] = k < bytes.Length ? bytes[k] : (byte)0;
                        }
                        offset += token.Count;
                        break;
                    }
                }
            }
            return result;
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            if (offset + Size > data.Length)
            {
                throw new PackError(
                    $"Unpack buffer too small for '{FormatStr}': need {Size} bytes at offset {offset}, have {data.Length}");
            }
            var values = new object[_tokens.Length];
            var cursor = offset;
            for (var t = 0; t < _tokens.Length; t++)
            {
                var token = _tokens[t];
                switch (token.Kind)
                {
                    case '?':
                        values[t] = data[cursor] != 0;
                        cursor += 1;
                        break;
                    case 'B':
                        values[t] = (int)Be.ReadU64(data, cursor, 1);
                        cursor += 1;
                        break;
                    case 'H':
                        values[t] = (int)Be.ReadU64(data, cursor, 2);
                        cursor += 2;
                        break;
                    case 'I':
                    case 'L':
                        values[t] = (uint)Be.ReadU64(data, cursor, 4);
                        cursor += 4;
                        break;
                    case 'Q':
                        values[t] = Be.ReadU64(data, cursor, 8);
                        cursor += 8;
                        break;
                    case 'q':
                        values[t] = Be.ReadI64(data, cursor, 8);
                        cursor += 8;
                        break;
                    case 'l':
                        values[t] = (int)Be.ReadU64(data, cursor, 4);
                        cursor += 4;
                        break;
                    case 'f':
                        values[t] = Be.ReadF32(data, cursor);
                        cursor += 4;
                        break;
                    case 'd':
                        values[t] = Be.ReadF64(data, cursor);
                        cursor += 8;
                        break;
                    case 'c':
                        values[t] = new[] { data[cursor] };
                        cursor += 1;
                        break;
                    case 's':
                        values[t] = Util.Slice(data, cursor, token.Count);
                        cursor += token.Count;
                        break;
                }
            }
            // py-ipv8: result if len(result) > 1 else result[0]
            unpackList.Add(values.Length > 1 ? values : values[0]);
            return offset + Size;
        }

        internal static bool Truthy(object value)
        {
            switch (value)
            {
                case null: return false;
                case bool b: return b;
                case int i: return i != 0;
                case uint u: return u != 0;
                case long l: return l != 0;
                case ulong ul: return ul != 0;
                case byte[] bytes: return bytes.Length > 0;
                case string s: return s.Length > 0;
                default: return true;
            }
        }

        internal static ulong ToUnsigned(object value, char kind, ulong max)
        {
            ulong raw;
            switch (value)
            {
                case bool b: raw = b ? 1UL : 0UL; break;
                case int i:
                    if (i < 0)
                    {
                        throw new PackError($"'{kind}' format requires a non-negative value, got {i}");
                    }
                    raw = (ulong)i;
                    break;
                case uint u: raw = u; break;
                case long l:
                    if (l < 0)
                    {
                        throw new PackError($"'{kind}' format requires a non-negative value, got {l}");
                    }
                    raw = (ulong)l;
                    break;
                case ulong ul: raw = ul; break;
                case float f: raw = (ulong)f; break;
                case double d: raw = (ulong)d; break;
                default:
                    throw new PackError($"'{kind}' format requires a number, got {value?.GetType().Name ?? "null"}");
            }
            if (raw > max)
            {
                throw new PackError($"'{kind}' format requires -max <= value <= {max}, got {raw}");
            }
            return raw;
        }

        internal static long ToSigned(object value, char kind, long min, long max)
        {
            long raw;
            switch (value)
            {
                case bool b: raw = b ? 1L : 0L; break;
                case int i: raw = i; break;
                case uint u: raw = u; break;
                case long l: raw = l; break;
                case ulong ul:
                    if (ul > (ulong)long.MaxValue)
                    {
                        throw new PackError($"'{kind}' format requires {min} <= value <= {max}, got {ul}");
                    }
                    raw = (long)ul;
                    break;
                case float f: raw = (long)f; break;
                case double d: raw = (long)d; break;
                default:
                    throw new PackError($"'{kind}' format requires a number, got {value?.GetType().Name ?? "null"}");
            }
            if (raw < min || raw > max)
            {
                throw new PackError($"'{kind}' format requires {min} <= value <= {max}, got {raw}");
            }
            return raw;
        }

        internal static float ToFloat(object value)
        {
            switch (value)
            {
                case float f: return f;
                case double d: return (float)d;
                case int i: return i;
                case long l: return l;
                case ulong ul: return ul;
                default:
                    throw new PackError($"'f' format requires a number, got {value?.GetType().Name ?? "null"}");
            }
        }

        internal static double ToDouble(object value)
        {
            switch (value)
            {
                case double d: return d;
                case float f: return f;
                case int i: return i;
                case long l: return l;
                case ulong ul: return ul;
                default:
                    throw new PackError($"'d' format requires a number, got {value?.GetType().Name ?? "null"}");
            }
        }

        internal static byte[] ToBytes(object value)
        {
            if (value is byte[] bytes)
            {
                return bytes;
            }
            throw new PackError($"Expected bytes, got {value?.GetType().Name ?? "null"}");
        }
    }

    /// <summary>Packer for bits into a single byte (py-ipv8 Bits).</summary>
    public sealed class Bits : IPacker
    {
        public byte[] Pack(object[] args)
        {
            if (args.Length < 8)
            {
                throw new PackError($"'bits' format requires 8 args, got {args.Length}");
            }
            var byteValue = 0;
            byteValue |= DefaultStruct.Truthy(args[0]) ? 0x80 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[1]) ? 0x40 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[2]) ? 0x20 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[3]) ? 0x10 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[4]) ? 0x08 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[5]) ? 0x04 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[6]) ? 0x02 : 0x00;
            byteValue |= DefaultStruct.Truthy(args[7]) ? 0x01 : 0x00;
            return new[] { (byte)byteValue };
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            if (offset + 1 > data.Length)
            {
                throw new PackError($"Unpack buffer too small for 'bits' at offset {offset}");
            }
            var byteValue = data[offset];
            unpackList.Add((0x80 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x40 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x20 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x10 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x08 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x04 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x02 & byteValue) != 0 ? 1 : 0);
            unpackList.Add((0x01 & byteValue) != 0 ? 1 : 0);
            return offset + 1;
        }
    }

    /// <summary>Paste/unpack the remaining input without (un)packing (py-ipv8 Raw).</summary>
    public sealed class Raw : IPacker
    {
        public byte[] Pack(object[] args)
        {
            if (args.Length < 1)
            {
                throw new PackError("'raw' format requires 1 arg");
            }
            return DefaultStruct.ToBytes(args[0]);
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            // Match everything remaining in the data as a bytes string.
            unpackList.Add(Util.SliceFrom(data, offset));
            return data.Length;
        }
    }

    /// <summary>Pack/unpack from an encoded length + data string (py-ipv8 VarLen).</summary>
    public class VarLen : IPacker
    {
        private readonly DefaultStruct _lengthStruct;
        private readonly int _base;

        public VarLen(string lengthFormat, int baseValue = 1)
        {
            LengthFormat = lengthFormat;
            _lengthStruct = new DefaultStruct(lengthFormat);
            LengthSize = _lengthStruct.Size;
            _base = baseValue;
        }

        public string LengthFormat { get; }
        public int LengthSize { get; }

        public virtual byte[] Pack(object[] args)
        {
            if (args.Length < 1)
            {
                throw new PackError($"{LengthFormat} varlen format requires 1 arg");
            }
            var data = DefaultStruct.ToBytes(args[0]);
            // Prefix the length of the given data to it: pack(length_format, len(data) // base).
            // struct.pack raises struct.error when the length overflows the length format.
            var length = data.Length / _base;
            var max = LengthSize >= 8 ? ulong.MaxValue : (1UL << (8 * LengthSize)) - 1;
            if ((ulong)length > max)
            {
                throw new PackError($"varlen length {length} does not fit in '{LengthFormat}'");
            }
            var prefix = new byte[LengthSize];
            Be.WriteU64(prefix, 0, (ulong)length, (uint)LengthSize);
            return Util.Concat(prefix, data);
        }

        public virtual int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var strLength = (int)Be.ReadU64(data, offset, (uint)LengthSize) * _base;
            unpackList.Add(Util.Slice(data, offset + LengthSize, strLength));
            return offset + LengthSize + strLength;
        }
    }

    /// <summary>Pack/unpack from an unencoded utf8 length + data string (py-ipv8 VarLenUtf8).</summary>
    public sealed class VarLenUtf8 : VarLen
    {
        public VarLenUtf8(string lengthFormat, int baseValue = 1) : base(lengthFormat, baseValue)
        {
        }

        public override byte[] Pack(object[] args)
        {
            if (args.Length < 1)
            {
                throw new PackError("varlenHutf8 format requires 1 arg");
            }
            if (args[0] is string s)
            {
                return base.Pack(new object[] { Util.Utf8(s) });
            }
            throw new PackError($"varlenHutf8 format requires a string, got {args[0]?.GetType().Name ?? "null"}");
        }

        public override int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var encodedData = new List<object>();
            var outOffset = base.Unpack(data, offset, encodedData, args);
            var bytes = (byte[])encodedData[0];
            unpackList.Add(Util.Utf8ToString(bytes, 0, bytes.Length));
            return outOffset;
        }
    }

    /// <summary>Pack/unpack an IPv4 address (py-ipv8 IPv4, format name "ipv4").</summary>
    public sealed class Ipv4 : IPacker
    {
        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is Address address))
            {
                throw new PackError("'ipv4' format requires an Address");
            }
            var packed = new byte[6];
            var hostBytes = InetAton(address.Host);
            Array.Copy(hostBytes, 0, packed, 0, 4);
            Be.WriteU64(packed, 4, (ulong)address.Port, 2);
            return packed;
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            if (offset + 6 > data.Length)
            {
                throw new PackError($"Unpack buffer too small for 'ipv4' at offset {offset}");
            }
            var hostBytes = Util.Slice(data, offset, 4);
            var port = (int)Be.ReadU64(data, offset + 4, 2);
            unpackList.Add(Address.Udpv4(InetNtoa(hostBytes), port));
            return offset + 6;
        }

        /// <summary>Strict dotted-quad parsing (Python socket.inet_aton is lenient, but py-ipv8 only
        /// ever feeds it addresses produced by the socket layer: four decimal octets).</summary>
        internal static byte[] InetAton(string host)
        {
            if (!TryParseDottedQuad(host, out var bytes))
            {
                throw new PackError($"Illegal IPv4 address string {host}");
            }
            return bytes;
        }

        internal static bool TryParseDottedQuad(string host, out byte[] bytes)
        {
            bytes = new byte[4];
            if (string.IsNullOrEmpty(host))
            {
                return false;
            }
            var parts = host.Split('.');
            if (parts.Length != 4)
            {
                return false;
            }
            for (var i = 0; i < 4; i++)
            {
                var part = parts[i];
                if (part.Length == 0 || part.Length > 3)
                {
                    return false;
                }
                foreach (var c in part)
                {
                    if (c < '0' || c > '9')
                    {
                        return false;
                    }
                }
                // inet_pton-style: no leading zeroes ("01" is rejected).
                if (part.Length > 1 && part[0] == '0')
                {
                    return false;
                }
                if (!int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value > 255)
                {
                    return false;
                }
                bytes[i] = (byte)value;
            }
            return true;
        }

        internal static string InetNtoa(byte[] bytes)
            => $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
    }

    /// <summary>
    /// Any address format: IPv4, IPv6 or host format (py-ipv8 Address, formats "address"/"ip_address").
    /// </summary>
    public sealed class AddressPacker : IPacker
    {
        public const int AddressTypeIpv4 = 0x01;
        public const int AddressTypeDomainName = 0x02;
        public const int AddressTypeIpv6 = 0x03;

        private readonly bool _ipOnly;

        public AddressPacker(bool ipOnly)
        {
            _ipOnly = ipOnly;
        }

        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is Address address))
            {
                throw new PackError("'address' format requires an Address");
            }
            if (address.IsIpv4 && Ipv4.TryParseDottedQuad(address.Host, out var bytes4))
            {
                var packed4 = new byte[7];
                packed4[0] = AddressTypeIpv4;
                Array.Copy(bytes4, 0, packed4, 1, 4);
                Be.WriteU64(packed4, 5, (ulong)address.Port, 2);
                return packed4;
            }
            if (System.Net.IPAddress.TryParse(address.Host, out var parsed)
                && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                var bytes16 = parsed.GetAddressBytes();
                var packed16 = new byte[19];
                packed16[0] = AddressTypeIpv6;
                Array.Copy(bytes16, 0, packed16, 1, 16);
                Be.WriteU64(packed16, 17, (ulong)address.Port, 2);
                return packed16;
            }
            if (!_ipOnly)
            {
                var hostBytes = Util.Utf8(address.Host);
                if (hostBytes.Length > 0xFFFF)
                {
                    throw new PackError($"Host string too long: {hostBytes.Length} bytes");
                }
                var packed = new byte[5 + hostBytes.Length];
                packed[0] = AddressTypeDomainName;
                Be.WriteU64(packed, 1, (ulong)hostBytes.Length, 2);
                Array.Copy(hostBytes, 0, packed, 3, hostBytes.Length);
                Be.WriteU64(packed, 3 + hostBytes.Length, (ulong)address.Port, 2);
                return packed;
            }
            throw new PackError($"Unexpected address type {address}");
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            if (offset + 1 > data.Length)
            {
                throw new PackError($"Unpack buffer too small for 'address' at offset {offset}");
            }
            var addressType = data[offset];
            if (addressType == AddressTypeIpv4)
            {
                if (offset + 7 > data.Length)
                {
                    throw new PackError($"Unpack buffer too small for 'address' (IPv4) at offset {offset}");
                }
                var ipBytes = Util.Slice(data, offset + 1, 4);
                var port = (int)Be.ReadU64(data, offset + 5, 2);
                unpackList.Add(Address.Udpv4(Ipv4.InetNtoa(ipBytes), port));
                return offset + 7;
            }
            if (addressType == AddressTypeIpv6)
            {
                if (offset + 19 > data.Length)
                {
                    throw new PackError($"Unpack buffer too small for 'address' (IPv6) at offset {offset}");
                }
                var ipBytes = Util.Slice(data, offset + 1, 16);
                var port = (int)Be.ReadU64(data, offset + 17, 2);
                unpackList.Add(Address.Udpv6(new System.Net.IPAddress(ipBytes).ToString(), port));
                return offset + 19;
            }
            if (!_ipOnly && addressType == AddressTypeDomainName)
            {
                if (offset + 3 > data.Length)
                {
                    throw new PackError($"Unpack buffer too small for 'address' (domain) at offset {offset}");
                }
                var length = (int)Be.ReadU64(data, offset + 1, 2);
                if (offset + 3 + length + 2 > data.Length)
                {
                    throw new PackError($"Unpack buffer too small for 'address' (domain) at offset {offset}");
                }
                var host = Util.Utf8ToString(data, offset + 3, length);
                var port = (int)Be.ReadU64(data, offset + 3 + length, 2);
                unpackList.Add(Address.Domain(host, port));
                return offset + 5 + length;
            }
            throw new PackError($"Cannot unpack address type {addressType}");
        }
    }

    /// <summary>A list of a given packer (py-ipv8 ListOf).</summary>
    public sealed class ListOf : IPacker
    {
        private readonly IPacker _packer;
        private readonly DefaultStruct _lengthStruct;
        private readonly int _lengthSize;

        public ListOf(IPacker packer, string lengthFormat = ">B")
        {
            _packer = packer ?? throw new ArgumentNullException(nameof(packer));
            LengthFormat = lengthFormat;
            _lengthStruct = new DefaultStruct(lengthFormat);
            _lengthSize = _lengthStruct.Size;
        }

        public string LengthFormat { get; }

        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is System.Collections.IList list))
            {
                throw new PackError("list format requires a list");
            }
            var prefix = new byte[_lengthSize];
            Be.WriteU64(prefix, 0, (ulong)list.Count, (uint)_lengthSize);
            var parts = new byte[list.Count + 1][];
            parts[0] = prefix;
            for (var i = 0; i < list.Count; i++)
            {
                parts[i + 1] = _packer.Pack(new[] { list[i] });
            }
            return Util.Concat(parts);
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var length = (int)Be.ReadU64(data, offset, (uint)_lengthSize);
            offset += _lengthSize;

            var result = new List<object>();
            unpackList.Add(result);
            for (var i = 0; i < length; i++)
            {
                offset = _packer.Unpack(data, offset, result, args);
            }
            return offset;
        }
    }

    /// <summary>
    /// A format known to the ``array`` module (like "I", "B", etc.), also adding support for "?"
    /// (py-ipv8 DefaultArray, formats "arrayH-?"/"arrayH-q"/"arrayH-d").
    /// NOTE: py-ipv8 writes these items through CPython's ``array`` module, which uses the MACHINE
    /// byte order (little-endian on all supported platforms) — unlike the big-endian struct packers.
    /// </summary>
    public sealed class DefaultArray : IPacker
    {
        private readonly string _formatStr;
        private readonly string _realFormatStr;
        private readonly DefaultStruct _lengthStruct;
        private readonly int _lengthSize;
        private readonly int _base;

        public DefaultArray(string formatStr, string lengthFormat)
        {
            _formatStr = formatStr;
            _realFormatStr = formatStr == "?" ? "B" : formatStr;
            _lengthStruct = new DefaultStruct(lengthFormat);
            _lengthSize = _lengthStruct.Size;
            _base = ItemSize(_realFormatStr);
        }

        private static int ItemSize(string realFormatStr)
        {
            switch (realFormatStr)
            {
                case "B": return 1;
                case "q": return 8;
                case "d": return 8;
                default: throw new PackError($"Unsupported array format '{realFormatStr}'");
            }
        }

        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is System.Collections.IList list))
            {
                throw new PackError($"array format '{_formatStr}' requires a list");
            }
            var prefix = new byte[_lengthSize];
            Be.WriteU64(prefix, 0, (ulong)list.Count, (uint)_lengthSize);
            var items = new byte[list.Count * _base];
            var offset = 0;
            foreach (var item in list)
            {
                switch (_realFormatStr)
                {
                    case "B":
                        items[offset] = DefaultStruct.Truthy(item) ? (byte)1 : (byte)0;
                        offset += 1;
                        break;
                    case "q":
                        Be.WriteI64(items, offset, DefaultStruct.ToSigned(item, 'q', long.MinValue, long.MaxValue), 8,
                                    littleEndian: true);
                        offset += 8;
                        break;
                    case "d":
                        Be.WriteF64(items, offset, DefaultStruct.ToDouble(item), littleEndian: true);
                        offset += 8;
                        break;
                }
            }
            return Util.Concat(prefix, items);
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            var strLength = (int)Be.ReadU64(data, offset, (uint)_lengthSize) * _base;
            offset += _lengthSize;
            if (offset + strLength > data.Length)
            {
                throw new PackError($"Unpack buffer too small for array '{_formatStr}' at offset {offset}");
            }
            var itemCount = strLength / _base;
            if (_formatStr == "?")
            {
                var bools = new List<object>(itemCount);
                for (var i = 0; i < itemCount; i++)
                {
                    bools.Add(data[offset + i] != 0);
                }
                unpackList.Add(bools);
            }
            else if (_realFormatStr == "q")
            {
                var longs = new List<object>(itemCount);
                for (var i = 0; i < itemCount; i++)
                {
                    longs.Add(Be.ReadI64(data, offset + i * 8, 8, littleEndian: true));
                }
                unpackList.Add(longs);
            }
            else
            {
                var doubles = new List<object>(itemCount);
                for (var i = 0; i < itemCount; i++)
                {
                    doubles.Add(Be.ReadF64(data, offset + i * 8, littleEndian: true));
                }
                unpackList.Add(doubles);
            }
            return offset + strLength;
        }
    }

    /// <summary>
    /// Special format allowing for nested packing (py-ipv8 NestedPayload, format "payload"):
    /// "&gt;H" length prefix + the packed inner Serializable.
    /// </summary>
    public sealed class NestedPayload : IPacker
    {
        private readonly Serializer _serializer;

        public NestedPayload(Serializer serializer)
        {
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
        }

        public byte[] Pack(object[] args)
        {
            if (args.Length < 1 || !(args[0] is Serializable serializable))
            {
                throw new PackError("'payload' format requires a Serializable");
            }
            var data = _serializer.PackSerializable(serializable);
            if (data.Length > 0xFFFF)
            {
                throw new PackError($"Nested payload too large: {data.Length} bytes");
            }
            var prefix = new byte[2];
            Be.WriteU64(prefix, 0, (ulong)data.Length, 2);
            return Util.Concat(prefix, data);
        }

        public int Unpack(byte[] data, int offset, List<object> unpackList, object[] args)
        {
            if (args.Length < 1 || !(args[0] is Type serializableClass))
            {
                throw new PackError("'payload' unpack format requires a Serializable type");
            }
            var size = (int)Be.ReadU64(data, offset, 2);
            offset += 2;
            if (offset + size > data.Length)
            {
                throw new PackError($"Unpack buffer too small for nested payload at offset {offset}");
            }
            var inner = Util.Slice(data, offset, size);
            var unpacked = _serializer.UnpackSerializable(serializableClass, inner, 0).Item1;
            unpackList.Add(unpacked);
            return offset + size;
        }
    }

    /// <summary>Big-endian (and explicit little-endian) byte helpers.</summary>
    public static class Be
    {
        public static ulong ReadU64(byte[] data, int offset, uint size, bool littleEndian = false)
        {
            if (offset + size > data.Length)
            {
                throw new PackError($"Unpack buffer too small at offset {offset} ({size} bytes)");
            }
            ulong result = 0;
            for (var i = 0; i < size; i++)
            {
                var b = data[offset + i];
                result = littleEndian ? result | ((ulong)b << (8 * i)) : (result << 8) | b;
            }
            return result;
        }

        public static long ReadI64(byte[] data, int offset, uint size, bool littleEndian = false)
            => (long)ReadU64(data, offset, size, littleEndian);

        public static float ReadF32(byte[] data, int offset, bool littleEndian = false)
        {
            SpanLike4(data, offset, littleEndian, out var tmp);
            return BitConverter.ToSingle(tmp, 0);
        }

        public static double ReadF64(byte[] data, int offset, bool littleEndian = false)
        {
            var tmp = new byte[8];
            CopyReversed(data, offset, tmp, 8, littleEndian);
            return BitConverter.ToDouble(tmp, 0);
        }

        private static void SpanLike4(byte[] data, int offset, bool littleEndian, out byte[] tmp)
        {
            tmp = new byte[4];
            CopyReversed(data, offset, tmp, 4, littleEndian);
        }

        private static void CopyReversed(byte[] data, int offset, byte[] target, int length, bool littleEndian)
        {
            // target ends up in native (BitConverter) order: little-endian on all our platforms.
            if (BitConverter.IsLittleEndian == littleEndian)
            {
                Array.Copy(data, offset, target, 0, length);
            }
            else
            {
                for (var i = 0; i < length; i++)
                {
                    target[i] = data[offset + length - 1 - i];
                }
            }
        }

        public static void WriteU64(byte[] target, int offset, ulong value, uint size, bool littleEndian = false)
        {
            for (var i = 0; i < size; i++)
            {
                var shift = littleEndian ? 8 * i : 8 * (size - 1 - i);
                target[offset + i] = (byte)((value >> (int)shift) & 0xFF);
            }
        }

        public static void WriteI64(byte[] target, int offset, long value, uint size, bool littleEndian = false)
            => WriteU64(target, offset, unchecked((ulong)value), size, littleEndian);

        public static void WriteF32(byte[] target, int offset, float value, bool littleEndian = false)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian != littleEndian)
            {
                Array.Reverse(bytes);
            }
            Array.Copy(bytes, 0, target, offset, 4);
        }

        public static void WriteF64(byte[] target, int offset, double value, bool littleEndian = false)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian != littleEndian)
            {
                Array.Reverse(bytes);
            }
            Array.Copy(bytes, 0, target, offset, 8);
        }
    }

    /// <summary>
    /// The class performing serialization of Serializable objects (py-ipv8 Serializer).
    /// </summary>
    public sealed class Serializer
    {
        private readonly Dictionary<string, IPacker> _packers;

        public Serializer()
        {
            _packers = new Dictionary<string, IPacker>
            {
                { "?", new DefaultStruct("?") },
                { "B", new DefaultStruct("B") },
                { "BBH", new DefaultStruct("BBH") },
                { "BH", new DefaultStruct("BH") },
                { "c", new DefaultStruct("c") },
                { "f", new DefaultStruct("f") },
                { "d", new DefaultStruct("d") },
                { "H", new DefaultStruct("H") },
                { "HH", new DefaultStruct("HH") },
                { "I", new DefaultStruct("I") },
                { "l", new DefaultStruct("l") },
                { "LL", new DefaultStruct("LL") },
                { "q", new DefaultStruct("q") },
                { "Q", new DefaultStruct("Q") },
                { "QH", new DefaultStruct("QH") },
                { "QL", new DefaultStruct("QL") },
                { "QQHHBH", new DefaultStruct("QQHHBH") },
                { "ccB", new DefaultStruct("ccB") },
                { "4SH", new DefaultStruct("4sH") },
                { "20s", new DefaultStruct("20s") },
                { "32s", new DefaultStruct("32s") },
                { "64s", new DefaultStruct("64s") },
                { "74s", new DefaultStruct("74s") },
                { "c20s", new DefaultStruct("c20s") },
                { "bits", new Bits() },
                { "ipv4", new Ipv4() },
                { "ip_address", new AddressPacker(ipOnly: true) },
                { "address", new AddressPacker(ipOnly: false) },
                { "raw", new Raw() },
                { "varlenBx2", new VarLen(">B", 2) },
                { "varlenH", new VarLen(">H", 1) },
                { "varlenHutf8", new VarLenUtf8(">H", 1) },
                { "varlenIutf8", new VarLenUtf8(">I", 1) },
                { "varlenHx20", new VarLen(">H", 20) },
                { "varlenH-list", new ListOf(new VarLen(">H", 1)) },
                { "varlenI", new VarLen(">I", 1) },
                { "doublevarlenH", new VarLen(">H", 1) },
                { "payload", new NestedPayload(this) },
                { "payload-list", new ListOf(new NestedPayload(this)) },
                { "arrayH-?", new DefaultArray("?", ">H") },
                { "arrayH-q", new DefaultArray("q", ">H") },
                { "arrayH-d", new DefaultArray("d", ">H") },
            };
        }

        public IReadOnlyList<string> GetAvailableFormats()
        {
            var formats = new List<string>();
            foreach (var key in _packers.Keys)
            {
                formats.Add(key);
            }
            return formats;
        }

        public IPacker GetPackerFor(string name)
        {
            if (!_packers.TryGetValue(name, out var packer))
            {
                throw new PackError($"Unknown packer format '{name}'");
            }
            return packer;
        }

        public void AddPacker(string name, IPacker packer)
        {
            _packers[name] = packer ?? throw new ArgumentNullException(nameof(packer));
        }

        /// <summary>Pack data without using a Serializable. Using a Serializable is the preferred method.</summary>
        public byte[] Pack(string fmt, object item) => GetPackerFor(fmt).Pack(new[] { item });

        /// <summary>
        /// Unpack data without using a Serializable: either a packer name (string), a nested payload
        /// type, or a list containing a nested payload type (payload-list).
        /// </summary>
        public (object Value, int Offset) Unpack(object fmt, byte[] data, int offset = 0)
        {
            var unpackList = new List<object>();
            if (fmt is string name)
            {
                offset = GetPackerFor(name).Unpack(data, offset, unpackList, Array.Empty<object>());
            }
            else if (fmt is IReadOnlyList<object> list)
            {
                offset = GetPackerFor("payload-list").Unpack(data, offset, unpackList, new object[] { list[0] });
            }
            else
            {
                offset = GetPackerFor("payload").Unpack(data, offset, unpackList, new[] { fmt });
            }
            return (unpackList[0], offset);
        }

        /// <summary>Serialize a single Serializable instance.</summary>
        public byte[] PackSerializable(Serializable serializable)
        {
            var packed = new List<byte[]>();
            foreach (var packable in serializable.ToPackList())
            {
                try
                {
                    packed.Add(GetPackerFor(packable.Format).Pack(packable.Args));
                }
                catch (PackError)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new PackError($"Could not pack item: {packable}\n{e.GetType().Name}: {e.Message}");
                }
            }
            return Util.Concat(packed.ToArray());
        }

        /// <summary>Serialize a list of Serializable instances.</summary>
        public byte[] PackSerializableList(System.Collections.Generic.IReadOnlyList<Serializable> serializables)
        {
            var parts = new byte[serializables.Count][];
            for (var i = 0; i < serializables.Count; i++)
            {
                parts[i] = PackSerializable(serializables[i]);
            }
            return Util.Concat(parts);
        }

        /// <summary>
        /// Use the formats specified in a serializable type and unpack to an instance of it.
        /// The instance is created through its parameterless constructor and populated by its
        /// <see cref="Serializable.FromUnpackList"/> (py-ipv8's ``from_unpack_list`` classmethod).
        /// </summary>
        public (Serializable Payload, int Offset) UnpackSerializable(Type serializable, byte[] data, int offset = 0)
        {
            var target = (Serializable)(Activator.CreateInstance(serializable)
                ?? throw new PackError($"Cannot instantiate {serializable.Name}"));
            var unpackList = new List<object>();
            foreach (var fmt in target.FormatList)
            {
                try
                {
                    if (fmt is string name)
                    {
                        offset = GetPackerFor(name).Unpack(data, offset, unpackList, Array.Empty<object>());
                    }
                    else if (fmt is Type nestedType)
                    {
                        if (!typeof(Serializable).IsAssignableFrom(nestedType))
                        {
                            throw new PackError($"Format is not a Serializable: {nestedType.Name}");
                        }
                        offset = GetPackerFor("payload").Unpack(data, offset, unpackList, new object[] { nestedType });
                    }
                    else if (fmt is IReadOnlyList<object> listOf)
                    {
                        offset = GetPackerFor("payload-list").Unpack(data, offset, unpackList,
                                                                     new object[] { listOf[0] });
                    }
                    else
                    {
                        throw new PackError($"Unknown format list entry: {fmt}");
                    }
                }
                catch (PackError)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new PackError($"Could not unpack item: {fmt}\n{e.GetType().Name}: {e.Message}");
                }
            }
            target.FromUnpackList(unpackList.ToArray());
            return (target, offset);
        }

        /// <summary>Typed convenience wrapper around <see cref="UnpackSerializable(Type, byte[], int)"/>.</summary>
        public T UnpackSerializableAs<T>(byte[] data, int offset = 0) where T : Serializable
            => (T)UnpackSerializable(typeof(T), data, offset).Payload;

        /// <summary>
        /// Use the formats specified in a list of serializable types and unpack to them.
        /// Returns the list of Serializable instances (plus the raw remainder when ``consumeAll``
        /// is false). Raises a PackError on leftover bytes otherwise.
        /// </summary>
        public List<object> UnpackSerializableList(System.Collections.Generic.IReadOnlyList<Type> serializables,
                                                   byte[] data, int offset = 0, bool consumeAll = true)
        {
            var unpacked = new List<object>();
            foreach (var serializableType in serializables)
            {
                var payloadAndOffset = UnpackSerializable(serializableType, data, offset);
                unpacked.Add(payloadAndOffset.Payload);
                offset = payloadAndOffset.Offset;
            }
            var remainder = Util.SliceFrom(data, offset);
            if (!consumeAll)
            {
                unpacked.Add(remainder);
            }
            else if (remainder.Length > 0)
            {
                var names = new List<string>();
                foreach (var t in serializables)
                {
                    names.Add(t.Name);
                }
                throw new PackError(
                    $"Incoming packet [{string.Join(", ", names)}] (b'{Hexlify(data)}') has extra data: (b'{Hexlify(remainder)}')");
            }
            return unpacked;
        }

        public static string Hexlify(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (var b in data)
            {
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }
    }
}
