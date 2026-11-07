// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Port of ipv8/requestcache.py: NumberCache / RandomNumberCache families and the RequestCache
// manager with timer-based timeout expiry, add/has/get/pop/identify semantics, wait_for and the
// passthrough timeout override.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IPv8
{
    /// <summary>
    /// A cache for state information that is uniquely identified by a prefix and a number
    /// (port of ipv8/requestcache.py::NumberCache).
    /// </summary>
    public abstract class NumberCache
    {
        protected NumberCache(RequestCache requestCache, string prefix, int number)
        {
            if (requestCache.Has(prefix, number))
            {
                throw new InvalidOperationException($"This number is already in use '{number}'");
            }
            RequestCache = requestCache;
            Prefix = prefix;
            Number = number;
            _managedFutures = new List<(TaskCompletionSource<object>, object)>();
        }

        public RequestCache RequestCache { get; }

        /// <summary>The prefix of this cache type.</summary>
        public string Prefix { get; }

        /// <summary>The unique number of this cache.</summary>
        public int Number { get; }

        /// <summary>The delay until this cache should be timed out.</summary>
        public virtual double TimeoutDelay => 10.0;

        private readonly List<(TaskCompletionSource<object> Future, object OnTimeout)> _managedFutures;

        /// <summary>
        /// Register a future for this Cache that will be completed (or failed) when this Cache
        /// times out. When the registered on_timeout value is an Exception, the future fails with
        /// it; otherwise it completes with the value.
        /// </summary>
        public void RegisterFuture(TaskCompletionSource<object> future, object onTimeout = null)
            => _managedFutures.Add((future, onTimeout));

        public IReadOnlyList<(TaskCompletionSource<object> Future, object OnTimeout)> ManagedFutures
            => _managedFutures;

        /// <summary>The logic to call when this cache times out.</summary>
        public abstract void OnTimeout();

        public override string ToString() => $"<{GetType().Name} {Prefix}-{Number}>";
    }

    /// <summary>A cache with a randomly generated number (py-ipv8 RandomNumberCache).</summary>
    public abstract class RandomNumberCache : NumberCache
    {
        private static readonly Random Rng = new Random();

        protected RandomNumberCache(RequestCache requestCache, string prefix)
            : base(requestCache, prefix, FindUnclaimedIdentifier(requestCache, prefix))
        {
        }

        /// <summary>Generate a random number for use with this cache.</summary>
        public static int FindUnclaimedIdentifier(RequestCache requestCache, string prefix)
        {
            for (var i = 0; i < 1000; i++)
            {
                var number = (int)(Rng.NextDouble() * 65536);
                if (!requestCache.Has(prefix, number))
                {
                    return number;
                }
            }
            throw new InvalidOperationException("Could not find a number that isn't in use");
        }
    }

    /// <summary>Manager for NumberCache caches (port of ipv8/requestcache.py::RequestCache).</summary>
    public class RequestCache : TaskManager
    {
        private readonly Dictionary<string, NumberCache> _identifiers = new Dictionary<string, NumberCache>();
        private readonly Dictionary<(string Prefix, int Number), TaskCompletionSource<NumberCache>> _waiters
            = new Dictionary<(string, int), TaskCompletionSource<NumberCache>>();
        public readonly object Lock = new object();
        private bool _shutdown;

        /// <summary>
        /// If not null, the timeout to use instead of the one defined in the TimeoutDelay of a
        /// NumberCache (used internally for Passthrough).
        /// </summary>
        private double? _timeoutOverride;

        /// <summary>If not null, the NumberCache (sub)classes to apply the timeout override for.</summary>
        private List<Type> _timeoutFilters;

        /// <summary>
        /// Add CACHE to this RequestCache. Returns the cache when its identifier was not yet added,
        /// otherwise returns null.
        /// </summary>
        public T Add<T>(T cache) where T : NumberCache
        {
            lock (Lock)
            {
                if (_shutdown)
                {
                    foreach (var (future, _) in cache.ManagedFutures)
                    {
                        future.TrySetCanceled();
                    }
                    return null;
                }
                var identifier = CreateIdentifier(cache.Number, cache.Prefix);
                if (_identifiers.ContainsKey(identifier))
                {
                    Console.Error.WriteLine($"add with duplicate identifier \"{identifier}\"");
                    return null;
                }
                _identifiers[identifier] = cache;

                var timeoutDelay = cache.TimeoutDelay;
                if (_timeoutOverride.HasValue
                    && (_timeoutFilters == null
                        || _timeoutFilters.Any(f => f.IsAssignableFrom(cache.GetType()))))
                {
                    // Only overwrite the timeout if an overwrite is set.
                    // Only overwrite the timeout if no class filters are set.
                    // Otherwise, only overwrite the timeout if the cache class is in the filter.
                    timeoutDelay = _timeoutOverride.Value;
                }

                RegisterTask(cache, () => OnTimeout(cache), delay: timeoutDelay);
                if (_waiters.TryGetValue((cache.Prefix, cache.Number), out var waiter))
                {
                    _waiters.Remove((cache.Prefix, cache.Number));
                    waiter.TrySetResult(cache);
                }
                return cache;
            }
        }

        /// <summary>Returns true when the identifier is part of this RequestCache.</summary>
        public bool Has(string prefix, int number)
        {
            lock (Lock)
            {
                return _identifiers.ContainsKey(CreateIdentifier(number, prefix));
            }
        }

        /// <summary>
        /// Returns the cache associated with the identifier when it exists, otherwise returns null.
        /// </summary>
        public NumberCache Get(string prefix, int number)
        {
            lock (Lock)
            {
                return _identifiers.TryGetValue(CreateIdentifier(number, prefix), out var cache)
                    ? cache
                    : null;
            }
        }

        /// <summary>
        /// Returns the cache associated with the identifier, and removes it from this RequestCache,
        /// when it exists, otherwise throws a KeyNotFoundException.
        /// </summary>
        public NumberCache Pop(string prefix, int number)
        {
            NumberCache cache;
            lock (Lock)
            {
                var identifier = CreateIdentifier(number, prefix);
                if (!_identifiers.TryGetValue(identifier, out cache))
                {
                    throw new KeyNotFoundException($"{prefix}-{number}");
                }
                _identifiers.Remove(identifier);
            }
            CancelPendingTask(cache);
            return cache;
        }

        /// <summary>
        /// Returns a task that fires if or when the given cache is registered. With a timeout, the
        /// task is cancelled after the given number of seconds without a registration.
        /// </summary>
        public Task<NumberCache> WaitFor(string prefix, int number, double? timeout = null)
        {
            var result = Get(prefix, number);
            if (result != null)
            {
                return Task.FromResult(result);
            }
            var tcs = new TaskCompletionSource<NumberCache>(TaskCreationOptions.RunContinuationsAsynchronously);
            var key = (prefix, number);
            lock (Lock)
            {
                _waiters[key] = tcs;
            }
            if (timeout.HasValue)
            {
                RegisterAnonymousTask("Watch RequestCache Future", () =>
                {
                    lock (Lock)
                    {
                        if (_waiters.TryGetValue(key, out var waiter) && waiter == tcs)
                        {
                            _waiters.Remove(key);
                            waiter.TrySetCanceled();
                        }
                    }
                }, delay: timeout.Value);
            }
            return tcs.Task;
        }

        /// <summary>
        /// A scope (use with ``using``) that overwrites the timeout_delay of NumberCaches added
        /// within it. Can be used to shorten or eliminate timeouts of external code. Optionally
        /// restricts the override to subclasses of the given cache classes.
        /// </summary>
        public IDisposable Passthrough(double timeout = 0.0, params Type[] filters)
        {
            _timeoutOverride = timeout;
            _timeoutFilters = filters.Length == 0 ? null : filters.ToList();
            return new Scope(this);
        }

        private sealed class Scope : IDisposable
        {
            private readonly RequestCache _requestCache;

            public Scope(RequestCache requestCache) => _requestCache = requestCache;

            public void Dispose()
            {
                _requestCache._timeoutOverride = null;
                _requestCache._timeoutFilters = null;
            }
        }

        /// <summary>
        /// Called TimeoutDelay seconds after the cache was added to this RequestCache, except when
        /// it has been popped before the timeout expires.
        /// </summary>
        private void OnTimeout(NumberCache cache)
        {
            // The OnTimeout call could have already removed the identifier from the cache using pop.
            var identifier = CreateIdentifier(cache.Number, cache.Prefix);
            lock (Lock)
            {
                _identifiers.Remove(identifier);
            }

            cache.OnTimeout();

            foreach (var (future, onTimeout) in cache.ManagedFutures)
            {
                if (!future.Task.IsCompleted)
                {
                    if (onTimeout is Exception exception)
                    {
                        future.TrySetException(exception);
                    }
                    else
                    {
                        future.TrySetResult(onTimeout);
                    }
                }
            }

            CancelPendingTask(cache);
        }

        private static string CreateIdentifier(int number, string prefix) => $"{prefix}:{number}";

        /// <summary>Clear the cache, canceling all pending tasks.</summary>
        public List<PendingTask> Clear()
        {
            var tasks = CancelAllPendingTasks();
            lock (Lock)
            {
                _identifiers.Clear();
            }
            return tasks;
        }

        /// <summary>Clear the cache, cancel all pending tasks and disallow new caches being added.</summary>
        public void Shutdown()
        {
            List<NumberCache> caches;
            lock (Lock)
            {
                _shutdown = true;
                caches = new List<NumberCache>(_identifiers.Values);
            }
            CancelAllPendingTasks();
            foreach (var cache in caches)
            {
                // Cancel all managed futures.
                foreach (var (future, _) in cache.ManagedFutures)
                {
                    future.TrySetCanceled();
                }
            }
            lock (Lock)
            {
                _identifiers.Clear();
            }
        }
    }
}
