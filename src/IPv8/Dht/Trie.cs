// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Byte-faithful port of ipv8/dht/trie.py: a prefix tree (trie) over "0"/"1" strings, with
// longest-prefix lookup and suffix enumeration used by the DHT routing table.

using System;
using System.Collections.Generic;

namespace IPv8.Dht
{
    /// <summary>A node within a prefix tree (ipv8/dht/trie.py::Node).</summary>
    internal sealed class TrieNode<T>
    {
        public T Value;
        public bool HasValue;
        public readonly Dictionary<char, TrieNode<T>> Children = new Dictionary<char, TrieNode<T>>();
    }

    /// <summary>This class represents a prefix tree (ipv8/dht/trie.py::Trie).</summary>
    public class Trie<T>
    {
        private readonly string _alphabet;
        private readonly TrieNode<T> _root = new TrieNode<T>();

        public Trie(string alphabet)
        {
            _alphabet = alphabet ?? throw new ArgumentNullException(nameof(alphabet));
        }

        private TrieNode<T> Find(string key)
        {
            var node = _root;
            foreach (var c in key)
            {
                if (!node.Children.TryGetValue(c, out node))
                {
                    break;
                }
            }
            return node;
        }

        /// <summary>Get the value belonging to a given key (raises when the key has no value).</summary>
        public T this[string key]
        {
            get
            {
                var node = Find(key);
                if (node == null || !node.HasValue)
                {
                    throw new KeyNotFoundException(key);
                }
                return node.Value;
            }
            set
            {
                var node = _root;
                foreach (var c in key)
                {
                    if (!_alphabet.Contains(c))
                    {
                        throw new DhtError("Error while adding item to trie");
                    }
                    if (!node.Children.TryGetValue(c, out var nextNode))
                    {
                        nextNode = new TrieNode<T>();
                        node.Children[c] = nextNode;
                    }
                    node = nextNode;
                }
                node.Value = value;
                node.HasValue = true;
            }
        }

        /// <summary>Remove the given key or raise KeyNotFoundException if the key was not found.</summary>
        public void Remove(string key)
        {
            // py-ipv8 __delitem__: collect (char, parent) pairs along the walk, clear the leaf value
            // and prune now-empty leaf branches bottom-up.
            var toRemove = new List<(char C, TrieNode<T> Node)> { (' ', _root) };
            var node = _root;
            foreach (var c in key)
            {
                toRemove.Add((c, node));
                if (!node.Children.TryGetValue(c, out node))
                {
                    break;
                }
            }

            if (node == null || !node.HasValue)
            {
                throw new KeyNotFoundException(key);
            }
            var removeNode = node;

            removeNode.Value = default;
            removeNode.HasValue = false;
            while (!removeNode.HasValue && removeNode.Children.Count == 0 && toRemove.Count > 0)
            {
                var (c, parent) = toRemove[toRemove.Count - 1];
                toRemove.RemoveAt(toRemove.Count - 1);
                parent.Children.Remove(c);
                removeNode = parent;
            }
        }

        /// <summary>Iterate over all stored values.</summary>
        private IEnumerable<T> IterateValues(TrieNode<T> node)
        {
            if (node.HasValue)
            {
                yield return node.Value;
            }
            foreach (var child in node.Children.Values)
            {
                foreach (var value in IterateValues(child))
                {
                    yield return value;
                }
            }
        }

        /// <summary>Get all the stored values as a list.</summary>
        public List<T> Values()
        {
            var result = new List<T>();
            foreach (var value in IterateValues(_root))
            {
                result.Add(value);
            }
            return result;
        }

        /// <summary>
        /// Get the longest matching prefix for the given key and its value. Returns null (pair)
        /// when no node is found at all.
        /// </summary>
        public (string Prefix, T Value)? LongestPrefixItem(string key)
        {
            var prefix = "";
            T value = default;
            var found = false;

            var node = _root;
            for (var index = 0; index < key.Length; index++)
            {
                if (!node.Children.TryGetValue(key[index], out node))
                {
                    break;
                }
                if (node.HasValue)
                {
                    prefix = key.Substring(0, index + 1);
                    value = node.Value;
                    found = true;
                }
            }

            return found ? (prefix, value) : ((string, T)?)null;
        }

        /// <summary>Get the longest matching prefix for the given key (or the default).</summary>
        public string LongestPrefix(string key, string defaultValue = null)
        {
            var result = LongestPrefixItem(key);
            return result.HasValue ? result.Value.Prefix : defaultValue;
        }

        /// <summary>Get the value of the longest matching prefix for the given key (or the default).</summary>
        public T LongestPrefixValue(string key, T defaultValue = default)
        {
            var result = LongestPrefixItem(key);
            return result.HasValue ? result.Value.Value : defaultValue;
        }

        /// <summary>Get the known suffixes for the given key.</summary>
        public List<string> Suffixes(string key)
        {
            var node = Find(key);

            var suffixes = new List<string>();
            if (node == null)
            {
                return suffixes;
            }
            if (node.HasValue)
            {
                suffixes.Add("");
            }

            foreach (var pair in node.Children)
            {
                var c = pair.Key;
                var child = pair.Value;
                if (child.HasValue)
                {
                    suffixes.Add(c.ToString());
                }
                foreach (var nestedSuffix in Suffixes(key + c))
                {
                    var suffix = c + nestedSuffix;
                    if (!suffixes.Contains(suffix))
                    {
                        suffixes.Add(suffix);
                    }
                }
            }

            return suffixes;
        }
    }
}
