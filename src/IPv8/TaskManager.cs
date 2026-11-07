// SPDX-License-Identifier: LGPL-3.0-or-later
// Port of Tribler/py-ipv8 (https://github.com/Tribler/py-ipv8) — LGPL-3.0-or-later.
//
// Minimal port of ipv8/taskmanager.py: named/anonymous tasks that run after a delay and/or at an
// interval, cancellable by name. py-ipv8 schedules asyncio coroutines; here a task body is a plain
// Action executed on the thread pool (timers) or inline (zero delay, zero interval). Interval tasks
// first fire after ``delay`` (which defaults to the interval), exactly like interval_runner.

using System;
using System.Collections.Generic;
using System.Threading;

namespace IPv8
{
    /// <summary>A registered task handle (py-ipv8 stores asyncio Tasks; we store timer-backed handles).</summary>
    public sealed class PendingTask : IDisposable
    {
        internal volatile bool Cancelled;

        public object Name { get; internal set; }
        public Action Body { get; internal set; }
        public double Interval { get; internal set; }
        public double StartTime { get; internal set; }
        internal Timer Timer;
        internal Task InlineTask;

        /// <summary>Whether this task has finished or was cancelled.</summary>
        public bool Done => Cancelled || (InlineTask != null && InlineTask.IsCompleted);

        public void Dispose()
        {
            Cancelled = true;
            Timer?.Dispose();
            Timer = null;
        }
    }

    /// <summary>
    /// Provides a set of tools to maintain a list of tasks that are to be executed during the
    /// lifetime of an arbitrary object, usually getting killed with it (port of
    /// ipv8/taskmanager.py::TaskManager, minimal).
    /// </summary>
    public class TaskManager
    {
        private readonly object _taskLock = new object();
        private readonly Dictionary<object, PendingTask> _pendingTasks = new Dictionary<object, PendingTask>();
        private bool _shutdown;
        private int _counter;

        /// <summary>
        /// Register a task so it can be canceled at shutdown time or by name. A task with an
        /// interval first runs after ``delay`` (defaulting to the interval) and then repeats.
        /// </summary>
        public PendingTask RegisterTask(object name, Action userTask, double delay = 0, double interval = 0)
        {
            if (userTask == null)
            {
                throw new ArgumentNullException(nameof(userTask));
            }
            if (userTask.Target is PendingTask)
            {
                throw new ArgumentException("Cannot register a PendingTask as a task body");
            }
            lock (_taskLock)
            {
                if (_shutdown)
                {
                    return null;
                }
                if (IsPendingTaskActive(name))
                {
                    throw new InvalidOperationException($"Task already exists: '{name}'");
                }
                var task = new PendingTask
                {
                    Name = name,
                    Body = userTask,
                    Interval = interval,
                    StartTime = Util.NowEpoch(),
                };
                if (interval > 0 || delay > 0)
                {
                    // The default delay for looping calls is the same as the interval.
                    var dueTime = delay > 0 ? delay : interval;
                    var period = interval > 0 ? interval : Timeout.Infinite;
                    task.Timer = new Timer(_ => RunIfAlive(task), null,
                                           (long)(dueTime * 1000), period > 0 ? (long)(period * 1000) : -1);
                }
                else
                {
                    // Zero delay and zero interval: run immediately (py-ipv8 ensure_future schedules
                    // on the loop; we run inline for determinism).
                    task.InlineTask = Task.Run(() =>
                    {
                        if (!task.Cancelled)
                        {
                            Invoke(userTask);
                        }
                        lock (_taskLock)
                        {
                            _pendingTasks.Remove(name);
                        }
                    });
                }
                _pendingTasks[name] = task;
                return task;
            }
        }

        /// <summary>Wrapper for register_task to derive a unique name from the basename.</summary>
        public PendingTask RegisterAnonymousTask(string basename, Action userTask,
                                                 double delay = 0, double interval = 0)
        {
            int counter;
            lock (_taskLock)
            {
                counter = ++_counter;
            }
            return RegisterTask(basename + " " + counter, userTask, delay, interval);
        }

        private void RunIfAlive(PendingTask task)
        {
            if (task.Cancelled)
            {
                return;
            }
            Invoke(task.Body);
        }

        private static void Invoke(Action body)
        {
            try
            {
                body();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Task resulted in error: {e.GetType().Name}\n{e}");
            }
        }

        /// <summary>Cancels the named task (no-op when it does not exist).</summary>
        public void CancelPendingTask(object name)
        {
            lock (_taskLock)
            {
                if (_pendingTasks.TryGetValue(name, out var pendingTask))
                {
                    if (!pendingTask.Done)
                    {
                        pendingTask.Dispose();
                        _pendingTasks.Remove(name);
                    }
                }
            }
        }

        /// <summary>
        /// Cancels all the registered tasks. Usually called when stopping or destroying the object.
        /// </summary>
        public List<PendingTask> CancelAllPendingTasks()
        {
            lock (_taskLock)
            {
                var cancelled = new List<PendingTask>();
                foreach (var name in new List<object>(_pendingTasks.Keys))
                {
                    if (_pendingTasks.TryGetValue(name, out var task) && !task.Done)
                    {
                        task.Dispose();
                        _pendingTasks.Remove(name);
                        cancelled.Add(task);
                    }
                }
                return cancelled;
            }
        }

        /// <summary>Return a boolean determining if a task is active.</summary>
        public bool IsPendingTaskActive(object name)
        {
            lock (_taskLock)
            {
                return _pendingTasks.TryGetValue(name, out var pendingTask) && !pendingTask.Done;
            }
        }

        /// <summary>Return a task if it exists. Otherwise, return null.</summary>
        public PendingTask GetTask(object name)
        {
            lock (_taskLock)
            {
                return _pendingTasks.TryGetValue(name, out var pendingTask) ? pendingTask : null;
            }
        }

        /// <summary>Clear the task manager, cancel all pending tasks and disallow new tasks.</summary>
        public void ShutdownTaskManager()
        {
            lock (_taskLock)
            {
                _shutdown = true;
                foreach (var task in _pendingTasks.Values)
                {
                    task.Dispose();
                }
                _pendingTasks.Clear();
            }
        }
    }
}
