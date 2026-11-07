// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Collections.Generic;
using IPv8.Wallet.Cryptography;

namespace IPv8.Attestation.Schema
{
    /// <summary>
    /// Manager for schemas: specifications of attribute disclosure algorithm parameterization
    /// (port of ipv8/attestation/schema/manager.py::SchemaManager).
    /// </summary>
    public class SchemaManager
    {
        public readonly Dictionary<string, Dictionary<string, object>> Formats =
            new Dictionary<string, Dictionary<string, object>>();

        private readonly Dictionary<string, Func<string, Dictionary<string, Dictionary<string, object>>,
            IdentityAlgorithm>> _algorithms =
                new Dictionary<string, Func<string, Dictionary<string, Dictionary<string, object>>,
                    IdentityAlgorithm>>(StringComparer.Ordinal);

        /// <summary>
        /// Register an algorithm implementation factory under an algorithm name
        /// (py binds the classes ``bonehexact``/``pengbaorange`` lazily; the port wires
        /// implementations through this registry once they are constructed).
        /// </summary>
        public void RegisterAlgorithm(string algorithmName,
            Func<string, Dictionary<string, Dictionary<string, object>>, IdentityAlgorithm> factory)
        {
            _algorithms[algorithmName] = factory;
        }

        /// <summary>Get the factory belonging to a certain algorithm name (py get_algorithm_class).</summary>
        public Func<string, Dictionary<string, Dictionary<string, object>>, IdentityAlgorithm>
            GetAlgorithmClass(string algorithmName)
        {
            if (_algorithms.TryGetValue(algorithmName, out var factory))
            {
                return factory;
            }
            throw new InvalidOperationException(
                $"Attempted to load unknown proof algorithm {algorithmName}!");
        }

        /// <summary>
        /// Register a schema specification. Each schema is defined by an algorithm and its
        /// parameterization.
        /// </summary>
        public void RegisterSchema(string schemaName, string algorithmName,
                                   Dictionary<string, object> parameters)
        {
            var schema = new Dictionary<string, object> { ["algorithm"] = algorithmName };
            foreach (var pair in parameters)
            {
                schema[pair.Key] = pair.Value;
            }
            Formats[schemaName] = schema;
        }

        /// <summary>Register all default formats to this SchemaManager.</summary>
        public void RegisterDefaultSchemas()
        {
            foreach (var pair in DefaultIdentityFormats.Formats)
            {
                RegisterSchema(pair.Key, (string)pair.Value["algorithm"], pair.Value);
            }
        }

        /// <summary>Get an algorithm instance from a schema name.</summary>
        public IdentityAlgorithm GetAlgorithmInstance(string schemaName)
        {
            if (!Formats.TryGetValue(schemaName, out var schema))
            {
                throw new InvalidOperationException($"Unknown schema {schemaName}");
            }
            return GetAlgorithmClass((string)schema["algorithm"])(schemaName, Formats);
        }
    }

    /// <summary>Port of ipv8/attestation/default_identity_formats.py::FORMATS.</summary>
    public static class DefaultIdentityFormats
    {
        public static readonly IReadOnlyDictionary<string, Dictionary<string, object>> Formats =
            new Dictionary<string, Dictionary<string, object>>(StringComparer.Ordinal)
            {
                ["id_metadata"] = new Dictionary<string, object>
                {
                    ["algorithm"] = "bonehexact",
                    ["key_size"] = 32L, // Pairings over 1024 bit space
                    ["hash"] = "sha256_4" // 4 byte hash
                },
                ["id_metadata_big"] = new Dictionary<string, object>
                {
                    ["algorithm"] = "bonehexact",
                    ["key_size"] = 64L, // Pairings over 4096 bit space
                    ["hash"] = "sha256" // 32 byte hash
                },
                ["id_metadata_huge"] = new Dictionary<string, object>
                {
                    ["algorithm"] = "bonehexact",
                    ["key_size"] = 96L, // Pairings over 9216 bit space
                    ["hash"] = "sha512" // 64 byte hash
                },
                ["id_metadata_range_18plus"] = new Dictionary<string, object>
                {
                    ["algorithm"] = "pengbaorange",
                    ["key_size"] = 32L, // Pairings over 1024 bit space
                    ["min"] = 18L,
                    ["max"] = 200L
                }
            };
    }
}
