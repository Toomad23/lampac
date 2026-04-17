using System.Collections.Concurrent;
using System.Threading;

namespace Shared.Engine
{
    public class SemaphorManager : IDisposable
    {
        #region static
        private static readonly ConcurrentDictionary<string, SemaphoreEntry> _semaphoreLocks = new();
        private static readonly Timer _cleanupTimer = new(_ => Cleanup(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

        public static int Stat_ContSemaphoreLocks => _semaphoreLocks.IsEmpty ? 0 : _semaphoreLocks.Count;

        static int _updatingDb = 0;
        static void Cleanup()
        {
            if (Interlocked.Exchange(ref _updatingDb, 1) == 1)
                return;

            try
            {
                var threshold = DateTime.UtcNow - TimeSpan.FromSeconds(90);

                foreach (var kvp in _semaphoreLocks)
                {
                    var entry = kvp.Value;

                    // Why: Fast-path skip if the entry is still in use or was touched recently.
                    // Full atomic decision is made under entry lock below (M-6 fix).
                    if (Volatile.Read(ref entry._activeUsers) != 0 || entry.LastUsed >= threshold)
                        continue;

                    // Why: TryClaimForDispose performs the refcount/lastUsed re-check under the
                    // entry's own lock and atomically marks the entry as disposed. Only after a
                    // successful claim do we remove from the dictionary and dispose the underlying
                    // SemaphoreSlim. This prevents the prior race where a caller holding a
                    // reference from GetOrAdd would see an ObjectDisposedException, and also
                    // prevents two concurrent callers from ending up with different semaphores
                    // for the same key (broken mutual exclusion).
                    if (entry.TryClaimForDispose(threshold))
                    {
                        _semaphoreLocks.TryRemove(new KeyValuePair<string, SemaphoreEntry>(kvp.Key, entry));
                        entry.DisposeInternal();
                    }
                }
            }
            catch { }
            finally
            {
                Volatile.Write(ref _updatingDb, 0);
            }
        }

        // Why: Constructor-time acquisition must retry if we happened to fetch an entry that
        // Cleanup disposed in between GetOrAdd and Checkout. In practice this only loops when a
        // disposed entry is still briefly visible in the dictionary.
        static SemaphoreEntry AcquireEntry(string key)
        {
            while (true)
            {
                var entry = _semaphoreLocks.GetOrAdd(key, _ => new SemaphoreEntry(new SemaphoreSlim(1, 1)));
                if (entry.TryCheckout())
                    return entry;

                // Stale/disposed entry raced with us; evict it (only if it's still the same
                // reference) and try again.
                _semaphoreLocks.TryRemove(new KeyValuePair<string, SemaphoreEntry>(key, entry));
            }
        }
        #endregion

        SemaphoreEntry semaphore { get; set; }
        CancellationToken cancellationToken;

        bool regwait, releaseLock;
        // Why: Guarantees the constructor-side TryCheckout increment is balanced by exactly one
        // decrement, no matter how many times Release() is called (existing callers often call
        // Release in a finally even when WaitAsync wasn't reached).
        int checkoutReleased;


        public SemaphorManager(string key)
        {
            cancellationToken = new CancellationTokenSource(TimeSpan.FromSeconds(40)).Token;
            semaphore = AcquireEntry(key);
        }

        public SemaphorManager(string key, TimeSpan timeSpan)
        {
            cancellationToken = new CancellationTokenSource(timeSpan).Token;
            semaphore = AcquireEntry(key);
        }

        public SemaphorManager(string key, CancellationToken cancellationToken)
        {
            this.cancellationToken = cancellationToken;
            semaphore = AcquireEntry(key);
        }


        public Task WaitAsync(TimeSpan timeSpan)
        {
            regwait = true;
            return semaphore.WaitAsync(timeSpan);
        }

        public Task WaitAsync(CancellationToken cancellationToken)
        {
            regwait = true;
            return semaphore.WaitAsync(cancellationToken);
        }

        public Task WaitAsync()
        {
            regwait = true;
            return semaphore.WaitAsync(cancellationToken);
        }


        public void Release()
        {
            try
            {
                if (regwait && releaseLock == false)
                {
                    releaseLock = true;
                    semaphore.Release();
                }
            }
            catch { }
            finally
            {
                // Why: Decrement the constructor-time checkout exactly once per instance,
                // independent of whether Release was reached after a successful WaitAsync.
                // This keeps activeUsers accurate so Cleanup only disposes truly idle entries.
                ReleaseCheckout();
            }
        }

        void ReleaseCheckout()
        {
            if (Interlocked.Exchange(ref checkoutReleased, 1) == 0)
                semaphore.Checkin();
        }

        // Why: enables `using var sm = new SemaphorManager(key); await sm.WaitAsync(); ...`
        // in place of the verbose try/finally { sm.Release(); } pattern. Dispose delegates to
        // Release, which is idempotent (releaseLock guard) and decrements the checkout counter
        // even when WaitAsync was skipped — matching the existing semantics.
        public void Dispose() => Release();


        async public Task Invoke(Action action)
        {
            try
            {
                await semaphore.WaitAsync(cancellationToken);
                action();
            }
            finally
            {
                semaphore.Release();
                ReleaseCheckout();
            }
        }

        async public Task Invoke(Func<Task> func)
        {
            try
            {
                await semaphore.WaitAsync(cancellationToken);
                await func();
            }
            finally
            {
                semaphore.Release();
                ReleaseCheckout();
            }
        }


        async public Task<T> Invoke<T>(Func<T> func)
        {
            try
            {
                await semaphore.WaitAsync(cancellationToken);
                return func();
            }
            finally
            {
                semaphore.Release();
                ReleaseCheckout();
            }
        }

        async public Task<T> Invoke<T>(Func<Task<T>> func)
        {
            try
            {
                await semaphore.WaitAsync(cancellationToken);
                return await func();
            }
            finally
            {
                semaphore.Release();
                ReleaseCheckout();
            }
        }


        #region SemaphoreEntry
        private sealed class SemaphoreEntry : IDisposable
        {
            private readonly SemaphoreSlim _semaphore;
            private readonly object _gate = new();
            // Why: exposed as internal field so Cleanup can do a lock-free "is this worth
            // considering?" pre-check before taking the entry lock.
            internal int _activeUsers;
            private bool _disposed;

            public SemaphoreEntry(SemaphoreSlim semaphore)
            {
                _semaphore = semaphore;
                Touch();
            }

            public DateTime LastUsed { get; private set; }

            public void Touch()
            {
                LastUsed = DateTime.UtcNow;
            }

            // Why: Atomic checkout. Returns false if the entry was already claimed by Cleanup
            // for disposal, forcing the caller to retry with a fresh GetOrAdd.
            public bool TryCheckout()
            {
                lock (_gate)
                {
                    if (_disposed)
                        return false;

                    _activeUsers++;
                    Touch();
                    return true;
                }
            }

            // Why: Mirror of TryCheckout. Called exactly once per SemaphorManager instance to
            // balance the initial checkout. Updates LastUsed so that an entry seen as idle by
            // Cleanup is truly idle from this moment onward.
            public void Checkin()
            {
                lock (_gate)
                {
                    if (_activeUsers > 0)
                        _activeUsers--;
                    Touch();
                }
            }

            // Why: Atomic claim for disposal. Only succeeds when no callers are checked out AND
            // the entry is still stale under lock (re-checked because another thread may have
            // just incremented). Sets _disposed so any racing TryCheckout fails and retries.
            public bool TryClaimForDispose(DateTime threshold)
            {
                lock (_gate)
                {
                    if (_disposed)
                        return false;
                    if (_activeUsers != 0)
                        return false;
                    if (LastUsed >= threshold)
                        return false;

                    _disposed = true;
                    return true;
                }
            }

            public Task WaitAsync(TimeSpan timeSpan)
            {
                Touch();
                return _semaphore.WaitAsync(timeSpan);
            }

            public Task WaitAsync(CancellationToken cancellationToken)
            {
                Touch();
                return _semaphore.WaitAsync(cancellationToken);
            }

            public void Release()
            {
                Touch();
                _semaphore.Release();
            }

            // Why: Only called from Cleanup AFTER TryClaimForDispose succeeded. Regular callers
            // must never dispose the underlying SemaphoreSlim directly.
            internal void DisposeInternal()
            {
                _semaphore.Dispose();
            }

            public void Dispose()
            {
                // Why: Kept for backward compat — the type is IDisposable — but is intentionally
                // a no-op. Disposal is driven exclusively by Cleanup through DisposeInternal
                // under the refcount gate.
            }
        }
        #endregion
    }
}
