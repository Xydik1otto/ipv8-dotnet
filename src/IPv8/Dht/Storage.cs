// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/dht/storage.py: in-memory key-value storage for DHT values (with expiracy).

using System;
using System.Collections.Generic;
using System.Linq;

namespace IPv8.Dht
{
    /// <summary>Class for storing DHT values (py-ipv8 Value).</summary>
    public class DhtValue
    {
        public DhtValue(byte[] id, byte[] data, double maxAge, int version)
        {
            Id = id;
            Data = data;
            LastUpdate = Util.NowEpoch();
            MaxAge = maxAge;
            Version = version;
        }

        public byte[] Id { get; }
        public byte[] Data { get; }
        public double LastUpdate { get; }
        public double MaxAge { get; }
        public int Version { get; }

        /// <summary>The time (in seconds) since the last update.</summary>
        public double Age => Util.NowEpoch() - LastUpdate;

        /// <summary>Whether the maximum time since the last update has been reached.</summary>
        public bool Expired => Age > MaxAge;

        /// <summary>py-ipv8: equality compares only the id.</summary>
        public bool IdEquals(DhtValue other) => other != null && Util.BytesEqual(Id, other.Id);
    }

    /// <summary>Class for storing key-value pairs in memory (py-ipv8 Storage).</summary>
    public class Storage
    {
        /// <summary>py-ipv8 uses a defaultdict(list); entries are created on demand.</summary>
        public readonly Dictionary<byte[], List<DhtValue>> Items
            = new Dictionary<byte[], List<DhtValue>>(ByteArrayEqualityComparer.Instance);

        private List<DhtValue> ItemsForKey(byte[] key)
        {
            if (!Items.TryGetValue(key, out var list))
            {
                list = new List<DhtValue>();
                Items[key] = list;
            }
            return list;
        }

        /// <summary>Store the given data under a certain key.</summary>
        public void Put(byte[] key, byte[] data, byte[] id = null, double maxAge = 86400, int version = 0)
        {
            id ??= Util.Sha1(data);
            var newValue = new DhtValue(id, data, maxAge, version);

            var list = ItemsForKey(key);
            var index = list.FindIndex(v => v.IdEquals(newValue));
            if (index >= 0)
            {
                var oldValue = list[index];
                if (newValue.Version >= oldValue.Version)
                {
                    list.RemoveAt(index);
                    list.Insert(0, newValue);
                    SortFor(key, list);
                }
            }
            else
            {
                list.Insert(0, newValue);
                SortFor(key, list);
            }
        }

        /// <summary>py sort key: values with id == key come last, others first (stable sort).</summary>
        private static void SortFor(byte[] key, List<DhtValue> list)
        {
            var sorted = list.OrderBy(v => Util.BytesEqual(v.Id, key) ? 1 : 0).ToList();
            list.Clear();
            list.AddRange(sorted);
        }

        /// <summary>Get the values stored at the given key.</summary>
        public List<byte[]> Get(byte[] key, int startingPoint = 0, int? limit = null)
        {
            if (!Items.TryGetValue(key, out var list))
            {
                return new List<byte[]>();
            }
            // py: upper_bound = (starting_point + limit) if limit else limit — a falsy limit (0)
            // behaves like None (open ended).
            var upperBound = limit.HasValue && limit.Value != 0 ? startingPoint + limit.Value : list.Count;
            if (startingPoint >= list.Count)
            {
                return new List<byte[]>();
            }
            var result = new List<byte[]>();
            for (var i = startingPoint; i < Math.Min(upperBound, list.Count); i++)
            {
                result.Add(list[i].Data);
            }
            return result;
        }

        /// <summary>Get all values that have not been updated for the given amount of time (in seconds).</summary>
        public List<(byte[] Key, byte[] Data)> ItemsOlderThan(double minAge)
        {
            var items = new List<(byte[], byte[])>();
            foreach (var pair in Items)
            {
                foreach (var value in pair.Value)
                {
                    if (value.Age > minAge)
                    {
                        items.Add((pair.Key, value.Data));
                    }
                }
            }
            return items;
        }

        /// <summary>Remove all expired items (py-ipv8 iterates from the end and stops at the first
        /// non-expired entry — replicated literally).</summary>
        public void Clean()
        {
            foreach (var list in Items.Values)
            {
                for (var index = list.Count - 1; index >= 0; index--)
                {
                    if (list[index].Expired)
                    {
                        list.RemoveAt(index);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }
}
