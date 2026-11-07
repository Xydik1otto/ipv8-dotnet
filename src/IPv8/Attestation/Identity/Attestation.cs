// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using System.Globalization;
using IPv8.Attestation.TokenTree;

namespace IPv8.Attestation.Identity
{
    /// <summary>
    /// A pointer to Metadata: the business-layer attestation
    /// (port of ipv8/attestation/identity/attestation.py::Attestation).
    /// </summary>
    public class Attestation : AbstractSignedObject
    {
        public Attestation(byte[] metadataPointer, Keyvault.PrivateKey privateKey, byte[] signature)
        {
            MetadataPointer = metadataPointer;
            Sign(privateKey, signature);
        }

        public byte[] MetadataPointer { get; }

        public override byte[] GetPlaintext() => MetadataPointer;

        /// <summary>Read from bytes at the given offset.</summary>
        public static Attestation Unserialize(byte[] data, Keyvault.PublicKey publicKey, int offset = 0)
        {
            var sigLen = publicKey.GetSignatureLength();
            var metadataPointer = Util.Slice(data, offset, 32);
            var signature = Util.Slice(data, offset + 32, sigLen);
            return new Attestation(metadataPointer, null, signature);
        }

        /// <summary>Create an attestation for given metadata using our key.</summary>
        public static Attestation Create(Metadata metadata, Keyvault.PrivateKey privateKey)
            => new Attestation(metadata.GetHash(), privateKey, null);

        /// <summary>Two byte strings for database insertion (metadata hash and signature).</summary>
        public (byte[] MetadataPointer, byte[] Signature) ToDatabaseTuple()
            => (MetadataPointer, Signature);

        public static Attestation FromDatabaseTuple(byte[] metadataPointer, byte[] signature)
            => new Attestation(metadataPointer, null, signature);

        public override string ToString() => $"Attestation({Util.Hex(MetadataPointer)})";
    }

    /// <summary>
    /// A JSON dictionary and a pointer to a Token
    /// (port of ipv8/attestation/identity/metadata.py::Metadata).
    /// </summary>
    public class Metadata : AbstractSignedObject
    {
        public Metadata(byte[] tokenPointer, byte[] serializedJsonDict,
                        Keyvault.PrivateKey privateKey, byte[] signature)
        {
            TokenPointer = tokenPointer;
            SerializedJsonDict = serializedJsonDict;
            Sign(privateKey, signature);
        }

        public byte[] TokenPointer { get; }

        public byte[] SerializedJsonDict { get; }

        /// <summary>Serialized Metadata consists of a token pointer and serialized JSON.</summary>
        public override byte[] GetPlaintext() => Util.Concat(TokenPointer, SerializedJsonDict);

        /// <summary>Unserialize metadata from the given bytes (offset is not supported).</summary>
        public static Metadata Unserialize(byte[] data, Keyvault.PublicKey publicKey, int offset = 0)
        {
            if (offset != 0)
            {
                throw new InvalidOperationException("Offset is not supported for Metadata!");
            }
            var sigLen = publicKey.GetSignatureLength();
            var tokenPointer = Util.Slice(data, 0, 32);
            var jsonDict = Util.Slice(data, 32, data.Length - 32 - sigLen);
            var signature = Util.Slice(data, data.Length - sigLen, sigLen);
            return new Metadata(tokenPointer, jsonDict, null, signature);
        }

        /// <summary>Create new metadata for a token from a JSON dict, signed using our key.</summary>
        public static Metadata Create(Token token, Dictionary<string, object> jsonDict,
                                      Keyvault.PrivateKey privateKey)
            => new Metadata(token.GetHash(), Util.Utf8(IPv8.Database.MiniJson.PythonDumps(jsonDict)), privateKey, null);

        /// <summary>Three byte strings for database insertion (token hash, signature, json dictionary).</summary>
        public (byte[] TokenPointer, byte[] Signature, byte[] SerializedJsonDict) ToDatabaseTuple()
            => (TokenPointer, Signature, SerializedJsonDict);

        public static Metadata FromDatabaseTuple(byte[] tokenPointer, byte[] signature,
                                                 byte[] serializedJsonDict)
            => new Metadata(tokenPointer, serializedJsonDict, null, signature);

        public override string ToString()
            => $"Metadata({Util.Hex(TokenPointer)},\n{Util.Utf8ToString(SerializedJsonDict, 0, SerializedJsonDict.Length)})";

        /// <summary>Parse the serialized JSON dict (py json.loads).</summary>
        public Dictionary<string, object> ParseJsonDict()
        {
            var parsed = IPv8.Database.MiniJson.Parse(
                Util.Utf8ToString(SerializedJsonDict, 0, SerializedJsonDict.Length));
            var result = new Dictionary<string, object>();
            foreach (var pair in (Dictionary<string, object>)parsed)
            {
                result[pair.Key] = pair.Value;
            }
            return result;
        }

        /// <summary>Double-formatted timestamp helper: py time() seconds (unused by the wire format).</summary>
        public static double NowEpochSeconds() => Util.NowEpoch();

        internal static string FormatInvariant(double value)
            => value.ToString("R", CultureInfo.InvariantCulture);
    }
}
