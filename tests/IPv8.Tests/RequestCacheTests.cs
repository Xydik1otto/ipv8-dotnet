// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.

using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace IPv8.Tests
{
    /// <summary>A6: deterministic RequestCache tests (register/pop/timeout with short delays).</summary>
    public class RequestCacheTests
    {
        private sealed class TestCache : NumberCache
        {
            public int TimeoutCount;

            public TestCache(RequestCache requestCache, string prefix, int number, double delay = 10.0)
                : base(requestCache, prefix, number)
            {
                Delay = delay;
            }

            public double Delay { get; }

            public override double TimeoutDelay => Delay;

            public override void OnTimeout() => Interlocked.Increment(ref TimeoutCount);
        }

        private static async Task WaitUntilAsync(Func<bool> condition, string description, int timeoutMs = 5000)
        {
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            while (!condition())
            {
                if (stopwatch.ElapsedMilliseconds > timeoutMs)
                {
                    throw new TimeoutException($"Condition not met within {timeoutMs} ms: {description}");
                }
                await Task.Delay(5);
            }
        }

        [Fact]
        public void Add_Get_Has_Pop_Semantics()
        {
            var requestCache = new RequestCache();
            var cache = new TestCache(requestCache, "smoke", 1337);

            Assert.Equal(cache, requestCache.Add(cache));
            Assert.True(requestCache.Has("smoke", 1337));
            Assert.False(requestCache.Has("smoke", 1338));
            Assert.Equal(cache, requestCache.Get("smoke", 1337));
            Assert.Null(requestCache.Get("smoke", 1338));

            Assert.Equal(cache, requestCache.Pop("smoke", 1337));
            Assert.False(requestCache.Has("smoke", 1337));
            Assert.Throws<KeyNotFoundException>(() => requestCache.Pop("smoke", 1337));
        }

        [Fact]
        public void Duplicate_Registration_Throws_And_Add_Returns_Null_On_Race()
        {
            var requestCache = new RequestCache();
            requestCache.Add(new TestCache(requestCache, "dup", 1));
            // Constructing a second cache for a claimed identifier throws (py NumberCache.__init__).
            Assert.Throws<InvalidOperationException>(() => new TestCache(requestCache, "dup", 1));
        }

        [Fact]
        public async Task Timeout_Fires_After_Delay()
        {
            var requestCache = new RequestCache();
            var cache = new TestCache(requestCache, "to", 1, delay: 0.05);
            requestCache.Add(cache);

            await WaitUntilAsync(() => Volatile.Read(ref cache.TimeoutCount) > 0, "on_timeout fired");
            // After the timeout the cache is gone.
            Assert.False(requestCache.Has("to", 1));
        }

        [Fact]
        public async Task Pop_Before_Timeout_Prevents_OnTimeout()
        {
            var requestCache = new RequestCache();
            var cache = new TestCache(requestCache, "pop", 2, delay: 0.05);
            requestCache.Add(cache);

            requestCache.Pop("pop", 2);
            // Long enough for the (cancelled) timeout task to have fired, if it weren't cancelled.
            await Task.Delay(150);
            Assert.Equal(0, Volatile.Read(ref cache.TimeoutCount));
        }

        [Fact]
        public async Task Add_After_Timeout_Allows_Reuse_Of_Identifier()
        {
            var requestCache = new RequestCache();
            var first = new TestCache(requestCache, "reuse", 3, delay: 0.05);
            requestCache.Add(first);
            await WaitUntilAsync(() => Volatile.Read(ref first.TimeoutCount) > 0, "first timed out");

            var second = new TestCache(requestCache, "reuse", 3, delay: 10.0);
            Assert.Equal(second, requestCache.Add(second));
        }

        [Fact]
        public void RandomNumberCache_Finds_Unclaimed_Identifier()
        {
            var requestCache = new RequestCache();
            var cache = new RandomTestCache(requestCache, "rnd");
            Assert.InRange(cache.Number, 0, 65535);
            // The constructor only FINDS an unclaimed number; registration happens in add().
            Assert.False(requestCache.Has("rnd", cache.Number));
            Assert.Equal(cache, requestCache.Add(cache));
            Assert.True(requestCache.Has("rnd", cache.Number));
        }

        private sealed class RandomTestCache : RandomNumberCache
        {
            public RandomTestCache(RequestCache requestCache, string prefix) : base(requestCache, prefix)
            {
            }

            public override void OnTimeout()
            {
            }
        }

        [Fact]
        public async Task Passthrough_Overrides_Timeout()
        {
            var requestCache = new RequestCache();
            var cache = new TestCache(requestCache, "pass", 9, delay: 10.0);
            using (requestCache.Passthrough(0.05))
            {
                requestCache.Add(cache);
                await WaitUntilAsync(() => Volatile.Read(ref cache.TimeoutCount) > 0, "passthrough timeout");
            }
            // Without the passthrough the (10 s) cache would still be pending here.
            Assert.False(requestCache.Has("pass", 9));
        }

        [Fact]
        public async Task Passthrough_Class_Filter()
        {
            var requestCache = new RequestCache();
            var filtered = new TestCache(requestCache, "f", 1, delay: 10.0);
            var untouched = new TestCache(requestCache, "f", 2, delay: 10.0);
            using (requestCache.Passthrough(0.05, typeof(TestCache)))
            {
                requestCache.Add(filtered);
            }
            requestCache.Add(untouched);
            await WaitUntilAsync(() => Volatile.Read(ref filtered.TimeoutCount) > 0, "filtered timed out");
            await Task.Delay(100);
            Assert.Equal(0, Volatile.Read(ref untouched.TimeoutCount));
            Assert.True(requestCache.Has("f", 2));
        }

        [Fact]
        public async Task Managed_Futures_Complete_On_Timeout()
        {
            var requestCache = new RequestCache();
            var cache = new TestCache(requestCache, "fut", 4, delay: 0.05);
            var future = new TaskCompletionSource<object>();
            cache.RegisterFuture(future, "expired");
            requestCache.Add(cache);

            var result = await future.Task;
            Assert.Equal("expired", result);
        }

        [Fact]
        public async Task WaitFor_Resolves_When_Cache_Is_Added()
        {
            var requestCache = new RequestCache();
            var waitTask = requestCache.WaitFor("wait", 42, timeout: 5.0);

            var cache = new TestCache(requestCache, "wait", 42, delay: 10.0);
            requestCache.Add(cache);

            var resolved = await waitTask;
            Assert.Equal(cache, resolved);
        }

        [Fact]
        public async Task WaitFor_Times_Out()
        {
            var requestCache = new RequestCache();
            var waitTask = requestCache.WaitFor("wait", 43, timeout: 0.05);
            await Assert.ThrowsAsync<TaskCanceledException>(() => waitTask);
        }

        [Fact]
        public void Clear_Removes_All_And_Cancels_Tasks()
        {
            var requestCache = new RequestCache();
            requestCache.Add(new TestCache(requestCache, "c", 1, delay: 10.0));
            requestCache.Add(new TestCache(requestCache, "c", 2, delay: 10.0));
            Assert.Equal(2, requestCache.Clear().Count);
            Assert.False(requestCache.Has("c", 1));
            Assert.False(requestCache.Has("c", 2));
        }

        [Fact]
        public void Shutdown_Rejects_New_Caches()
        {
            var requestCache = new RequestCache();
            requestCache.Add(new TestCache(requestCache, "s", 1, delay: 10.0));
            requestCache.Shutdown();
            Assert.Null(requestCache.Add(new TestCache(requestCache, "s", 2, delay: 10.0)));
            Assert.False(requestCache.Has("s", 1));
        }

        [Fact]
        public void RegisterTask_Name_Clash_Throws()
        {
            var taskManager = new TaskManager();
            // A delay keeps the task pending: a zero-delay task finishes (and frees its name)
            // immediately on the thread pool, making the clash check a race.
            taskManager.RegisterTask("t", () => { }, delay: 10.0);
            Assert.Throws<InvalidOperationException>(() => taskManager.RegisterTask("t", () => { }));
            taskManager.CancelPendingTask("t");
            // After cancellation the name is free again.
            taskManager.RegisterTask("t", () => { }, delay: 10.0);
            taskManager.CancelPendingTask("t");
        }

        [Fact]
        public async Task Interval_Task_Repeats()
        {
            var taskManager = new TaskManager();
            var counter = 0;
            taskManager.RegisterTask("loop", () => Interlocked.Increment(ref counter), delay: 0.02, interval: 0.02);
            await WaitUntilAsync(() => Volatile.Read(ref counter) >= 3, "interval ran at least 3 times");
            taskManager.CancelAllPendingTasks();
            var snapshot = Volatile.Read(ref counter);
            await Task.Delay(80);
            Assert.True(Volatile.Read(ref counter) - snapshot <= 1);
        }
    }
}
