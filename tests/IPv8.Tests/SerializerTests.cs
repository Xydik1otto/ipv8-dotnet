// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Text;
using IPv8.Messaging;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>
    /// A2: serializer vectors from vectors.json → serializer, byte-exact (pack AND unpack roundtrip),
    /// plus roundtrip coverage of the individual py-ipv8 packers.
    /// </summary>
    public class SerializerTests
    {
        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        private static string Hexlify(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

        /// <summary>Mirror of gen_vectors.py's MixedPayload: covers H, 20s, bits, varlenHutf8, raw.</summary>
        private sealed class MixedPayload : Serializable
        {
            public int A;
            public byte[] B;
            public int[] BitsValue;
            public string S;
            public byte[] R;

            public MixedPayload()
            {
                A = 0;
                B = Array.Empty<byte>();
                BitsValue = new int[8];
                S = "";
                R = Array.Empty<byte>();
            }

            public MixedPayload(int a, byte[] b, int[] bits, string s, byte[] r)
            {
                A = a;
                B = b;
                BitsValue = bits;
                S = s;
                R = r;
            }

            public override IReadOnlyList<object> FormatList
                => new object[] { "H", "20s", "bits", "varlenHutf8", "raw" };

            public override IList<PackEntry> ToPackList()
                => new List<PackEntry>
                {
                    new PackEntry("H", A),
                    new PackEntry("20s", B),
                    new PackEntry("bits", BitsValue[0], BitsValue[1], BitsValue[2], BitsValue[3],
                                  BitsValue[4], BitsValue[5], BitsValue[6], BitsValue[7]),
                    new PackEntry("varlenHutf8", S),
                    new PackEntry("raw", R),
                };

            public override void FromUnpackList(object[] values)
            {
                A = (int)values[0];
                B = (byte[])values[1];
                BitsValue = new[]
                {
                    (int)values[2], (int)values[3], (int)values[4], (int)values[5],
                    (int)values[6], (int)values[7], (int)values[8], (int)values[9]
                };
                S = (string)values[10];
                R = (byte[])values[11];
            }
        }

        /// <summary>Mirror of gen_vectors.py's FakeAuthPayload (raw-only, BinMemberAuthentication layout).</summary>
        private sealed class FakeAuthPayload : Serializable
        {
            public byte[] PubkeyBin;

            public FakeAuthPayload()
            {
                PubkeyBin = Array.Empty<byte>();
            }

            public FakeAuthPayload(byte[] pubkeyBin)
            {
                PubkeyBin = pubkeyBin;
            }

            public override IReadOnlyList<object> FormatList => new object[] { "raw" };

            public override IList<PackEntry> ToPackList() => new List<PackEntry> { new PackEntry("raw", PubkeyBin) };

            public override void FromUnpackList(object[] values) => PubkeyBin = (byte[])values[0];
        }

        [Fact]
        public void Bits_Golden_Vectors()
        {
            var serializer = new Serializer();
            var bitsPacker = serializer.GetPackerFor("bits");

            Assert.Equal(Vectors.SerializerVector("bits_10110010"),
                         Hexlify(bitsPacker.Pack(new object[] { 1, 0, 1, 1, 0, 0, 1, 0 })));
            Assert.Equal(Vectors.SerializerVector("bits_00000001"),
                         Hexlify(bitsPacker.Pack(new object[] { 0, 0, 0, 0, 0, 0, 0, 1 })));
            Assert.Equal(Vectors.SerializerVector("bits_00000000"),
                         Hexlify(bitsPacker.Pack(new object[] { 0, 0, 0, 0, 0, 0, 0, 0 })));

            // Unpack yields the eight bits, MSB first (py-ipv8 appends bit_7..bit_0 as ints).
            var unpackList = new List<object>();
            var offset = bitsPacker.Unpack(Hex("b2"), 0, unpackList, Array.Empty<object>());
            Assert.Equal(1, offset);
            Assert.Equal(new object[] { 1, 0, 1, 1, 0, 0, 1, 0 }, unpackList.ToArray());
        }

        [Fact]
        public void VarLenH_Golden_Vectors()
        {
            var serializer = new Serializer();

            Assert.Equal(Vectors.SerializerVector("varlenH_hello"),
                         Hexlify(serializer.Pack("varlenH", Encoding.UTF8.GetBytes("hello"))));
            Assert.Equal(Vectors.SerializerVector("varlenH_empty"),
                         Hexlify(serializer.Pack("varlenH", Array.Empty<byte>())));

            // Unpack roundtrip.
            var (value, offset) = serializer.Unpack("varlenH", Hex(Vectors.SerializerVector("varlenH_hello")));
            Assert.Equal(Encoding.UTF8.GetBytes("hello"), (byte[])value);
            Assert.Equal(7, offset);
        }

        [Fact]
        public void AuthPayload_Golden_Vector()
        {
            var serializer = new Serializer();
            var fakePub = Util.Concat(Encoding.ASCII.GetBytes("LibNaCLPK:"),
                                      RangeBytes(0, 32), RangeBytes(32, 32));

            var packed = serializer.PackSerializable(new FakeAuthPayload(fakePub));
            Assert.Equal(Vectors.SerializerVector("auth_payload_fakekey"), Hexlify(packed));

            // Unpack roundtrip.
            var unpacked = serializer.UnpackSerializableAs<FakeAuthPayload>(packed);
            Assert.Equal(fakePub, unpacked.PubkeyBin);
        }

        [Fact]
        public void MixedPayload_Golden_Vector_And_Roundtrip()
        {
            var serializer = new Serializer();
            var payload = new MixedPayload(0xCAFE,
                                           Util.Sha1(Encoding.UTF8.GetBytes("master-key")),
                                           new[] { 1, 0, 1, 1, 0, 0, 1, 0 },
                                           "test str",
                                           new byte[] { 0x01, 0x02, 0x03, (byte)'r', (byte)'a', (byte)'w' });

            var packed = serializer.PackSerializable(payload);
            Assert.Equal(Vectors.SerializerVector("mixed_payload"), Hexlify(packed));

            // Unpack roundtrip (py-ipv8 asserts a == 0xCAFE and s == "test str").
            var unpacked = serializer.UnpackSerializableAs<MixedPayload>(packed);
            Assert.Equal(0xCAFE, unpacked.A);
            Assert.Equal(Util.Sha1(Encoding.UTF8.GetBytes("master-key")), unpacked.B);
            Assert.Equal(new[] { 1, 0, 1, 1, 0, 0, 1, 0 }, unpacked.BitsValue);
            Assert.Equal("test str", unpacked.S);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, (byte)'r', (byte)'a', (byte)'w' }, unpacked.R);
        }

        [Fact]
        public void Struct_Packers_Roundtrip()
        {
            var serializer = new Serializer();

            // H, I, Q, f, d, c and the fixed-size strings, big-endian.
            Assert.Equal("00ff", Hexlify(serializer.Pack("H", 255)));
            Assert.Equal("000000ff", Hexlify(serializer.Pack("I", 255)));
            Assert.Equal("00000000000000ff", Hexlify(serializer.Pack("Q", 255UL)));
            Assert.Equal("ff", Hexlify(serializer.Pack("B", 255)));
            Assert.Equal("ffffffff", Hexlify(serializer.Pack("l", -1)));
            Assert.Equal("ffffffffffffffff", Hexlify(serializer.Pack("q", -1L)));

            // ">f" 1.0 → 3f800000; ">d" 1.0 → 3ff0000000000000 (IEEE 754, big-endian).
            Assert.Equal("3f800000", Hexlify(serializer.Pack("f", 1.0f)));
            Assert.Equal("3ff0000000000000", Hexlify(serializer.Pack("d", 1.0)));

            // 'c' packs a one-byte bytes.
            Assert.Equal("59", Hexlify(serializer.Pack("c", new[] { (byte)0x59 })));

            // "20s" pads with NULs, "74s" roundtrips a 74-byte key.
            Assert.Equal("414243" + new string('0', 34),
                         Hexlify(serializer.Pack("20s", new byte[] { 0x41, 0x42, 0x43 })));

            var (hValue, _) = serializer.Unpack("H", Hex("0102"));
            Assert.Equal(0x0102, hValue);
            var (qValue, _) = serializer.Unpack("Q", Hex("0000000000000001"));
            Assert.Equal(1UL, qValue);
            var (fValue, _) = serializer.Unpack("f", Hex("3f800000"));
            Assert.Equal(1.0f, fValue);
            var (dValue, _) = serializer.Unpack("d", Hex("3ff0000000000000"));
            Assert.Equal(1.0, dValue);
            var (lValue, _) = serializer.Unpack("l", Hex("ffffffff"));
            Assert.Equal(-1, lValue);
            var (qSigned, _) = serializer.Unpack("q", Hex("ffffffffffffffff"));
            Assert.Equal(-1L, qSigned);
            var (cValue, _) = serializer.Unpack("c", Hex("59"));
            Assert.Equal(new byte[] { 0x59 }, (byte[])cValue);
            var (s20Value, _) = serializer.Unpack("20s", Hex("414243" + new string('0', 34)));
            // Python struct ">20s" returns the full 20 bytes, NUL padding included.
            Assert.Equal(new byte[] { 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                         (byte[])s20Value);
        }

        [Fact]
        public void Raw_Swallows_Remainder()
        {
            var serializer = new Serializer();
            var data = new byte[] { 1, 2, 3, 4, 5, 6 };
            var (value, offset) = serializer.Unpack("raw", data, 2);
            Assert.Equal(new byte[] { 3, 4, 5, 6 }, (byte[])value);
            Assert.Equal(data.Length, offset);
        }

        [Fact]
        public void VarlenI_And_Utf8_Variants_Roundtrip()
        {
            var serializer = new Serializer();

            var packedI = serializer.Pack("varlenI", new byte[300]);
            Assert.Equal(304, packedI.Length);
            Assert.Equal(300, ((byte[])serializer.Unpack("varlenI", packedI).Value).Length);

            var packedUtf8 = serializer.Pack("varlenHutf8", "hällo");
            // "hällo" is 6 bytes in UTF-8.
            Assert.Equal("0006" + Hexlify(Encoding.UTF8.GetBytes("hällo")), Hexlify(packedUtf8));
            var (text, _) = serializer.Unpack("varlenHutf8", packedUtf8);
            Assert.Equal("hällo", (string)text);

            // varlenHx20 divides the byte length by 20 (py-ipv8 base=20).
            var packedX20 = serializer.Pack("varlenHx20", new byte[40]);
            Assert.Equal("0002", Hexlify(Util.Slice(packedX20, 0, 2)));
        }

        [Fact]
        public void Ipv4_And_Address_Packers_Roundtrip()
        {
            var serializer = new Serializer();

            var packed = serializer.Pack("ipv4", Address.Udpv4("1.2.3.4", 5000));
            Assert.Equal("010203041388", Hexlify(packed));
            var (address, offset) = serializer.Unpack("ipv4", packed);
            Assert.Equal(new Address(AddressType.Udpv4, "1.2.3.4", 5000), (Address)address);
            Assert.Equal(6, offset);

            // "ip_address" (ip_only): IPv4 → type byte 0x01.
            var packedIp = serializer.Pack("ip_address", Address.Udpv4("10.0.0.1", 1000));
            Assert.Equal("01" + "0a000001" + "03e8", Hexlify(packedIp));
            var (ipUnpacked, _) = serializer.Unpack("ip_address", packedIp);
            Assert.Equal(new Address(AddressType.Udpv4, "10.0.0.1", 1000), (Address)ipUnpacked);

            // Domain addresses are only allowed for the generic "address" packer.
            var packedDomain = serializer.Pack("address", Address.Domain("example.com", 8080));
            Assert.Equal("02" + "000b" + Hexlify(Encoding.UTF8.GetBytes("example.com")) + "1f90",
                         Hexlify(packedDomain));
            var (domainUnpacked, _) = serializer.Unpack("address", packedDomain);
            Assert.Equal(new Address(AddressType.Domain, "example.com", 8080), (Address)domainUnpacked);

            // ip_only rejects domain addresses on pack.
            Assert.Throws<PackError>(() => serializer.Pack("ip_address", Address.Domain("example.com", 8080)));

            // IPv6 via "address" → type byte 0x03, 16 bytes + port.
            var packedV6 = serializer.Pack("address", Address.Udpv6("::1", 42));
            Assert.Equal(19, packedV6.Length);
            Assert.Equal(0x03, packedV6[0]);
            var (v6Unpacked, _) = serializer.Unpack("address", packedV6);
            Assert.Equal(AddressType.Udpv6, ((Address)v6Unpacked).Type);
            Assert.Equal(42, ((Address)v6Unpacked).Port);
        }

        [Fact]
        public void Bits_Byte_Layout_Msb_First_In_Payload()
        {
            // Replicate py-ipv8: bits are the MSB-first byte in a payload sequence.
            var serializer = new Serializer();
            var packed = serializer.PackSerializable(new MixedPayload(
                1, new byte[20], new[] { 0, 0, 0, 0, 0, 0, 0, 1 }, "x", Array.Empty<byte>()));
            // H(0001) 20s(20 NUL bytes) bits(01) varlenHutf8(0001 78) raw().
            Assert.Equal("0001" + new string('0', 40) + "01" + "000178", Hexlify(packed));
        }

        [Fact]
        public void DefaultArray_Bool_And_Q_Roundtrip()
        {
            var serializer = new Serializer();

            var packedBools = serializer.Pack("arrayH-?", new[] { true, false, true });
            Assert.Equal("0003" + "01" + "00" + "01", Hexlify(packedBools));
            var (bools, _) = serializer.Unpack("arrayH-?", packedBools);
            var boolList = Assert.IsType<List<object>>(bools);
            Assert.Equal(new object[] { true, false, true }, boolList.ToArray());

            // py-ipv8 quirk (CPython array module): machine byte order — little-endian items.
            var packedQ = serializer.Pack("arrayH-q", new long[] { 1 });
            Assert.Equal("0001" + "0100000000000000", Hexlify(packedQ));
            var (longs, _) = serializer.Unpack("arrayH-q", packedQ);
            var longList = Assert.IsType<List<object>>(longs);
            Assert.Equal(new object[] { 1L }, longList.ToArray());
        }

        [Fact]
        public void Nested_Payload_Roundtrip()
        {
            var serializer = new Serializer();

            var inner = new MixedPayload(7, new byte[20], new[] { 0, 0, 0, 0, 0, 0, 0, 1 }, "inner",
                                         new byte[] { 9 });
            var packed = serializer.Pack("payload", inner);
            // ">H" length prefix + inner bytes: inner packs to 2+20+1+2+5+1 = 31 bytes (0x1f).
            Assert.Equal(Hexlify(Util.Concat(new byte[] { 0x00, 0x1f },
                                             serializer.PackSerializable(inner))),
                         Hexlify(packed));

            var (unpacked, offset) = serializer.Unpack(typeof(MixedPayload), packed);
            var mixed = Assert.IsType<MixedPayload>(unpacked);
            Assert.Equal(7, mixed.A);
            Assert.Equal("inner", mixed.S);
            Assert.Equal(offset, packed.Length);
        }

        [Fact]
        public void Overlong_VarlenH_Pack_Raises_PackError()
        {
            var serializer = new Serializer();
            Assert.Throws<PackError>(() => serializer.Pack("varlenH", new byte[65536]));
            Assert.Throws<PackError>(() => serializer.Pack("H", 65536));
            Assert.Throws<PackError>(() => serializer.Pack("H", -1));
        }

        [Fact]
        public void Trailing_Bytes_Are_Rejected_In_UnpackSerializableList()
        {
            var serializer = new Serializer();

            // A "raw" packer always swallows the remainder (py-ipv8 behavior), so a trailing-byte
            // rejection needs a bounded payload sequence: varlenH + Q, then two extra bytes.
            var keyBin = Util.Concat(Encoding.ASCII.GetBytes("LibNaCLPK:"), new byte[64]);
            var bounded = Util.Concat(serializer.Pack("varlenH", keyBin),
                                      serializer.Pack("Q", 7UL));
            var withTrailing = Util.Concat(bounded, new byte[] { 1, 2 });

            Assert.Throws<PackError>(() => serializer.UnpackSerializableList(
                new[] { typeof(BinMemberAuthenticationPayload), typeof(GlobalTimeDistributionPayload) },
                withTrailing));
            // consume_all=false appends the remainder instead.
            var unpacked = serializer.UnpackSerializableList(
                new[] { typeof(BinMemberAuthenticationPayload), typeof(GlobalTimeDistributionPayload) },
                withTrailing, consumeAll: false);
            Assert.Equal(3, unpacked.Count);
            Assert.IsType<BinMemberAuthenticationPayload>(unpacked[0]);
            Assert.IsType<GlobalTimeDistributionPayload>(unpacked[1]);
            Assert.Equal(new byte[] { 1, 2 }, (byte[])unpacked[2]);
        }

        private static byte[] RangeBytes(int fromValue, int count)
        {
            var data = new byte[count];
            for (var i = 0; i < count; i++)
            {
                data[i] = (byte)(fromValue + i);
            }
            return data;
        }
    }
}
