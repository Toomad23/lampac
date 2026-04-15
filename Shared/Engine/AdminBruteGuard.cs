using Microsoft.Extensions.Caching.Memory;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Shared.Engine
{
    // Shared brute-force counter used by Accsdb middleware and AdminController.
    // Lives in Shared so BaseModule (which cannot reference Lampac) can use it.
    public static class AdminBruteGuard
    {
        public const string CacheKeyPrefix = "Accsdb:auth:attempts:IP:";

        // Returns current attempt count after incrementing; expiry resets each calendar day.
        public static int Increment(IMemoryCache cache, string ip)
        {
            string key = CacheKeyPrefix + ip;
            var box = cache.GetOrCreate(key, e =>
            {
                e.AbsoluteExpiration = DateTime.Today.AddDays(1);
                return new int[1];
            });
            return Interlocked.Increment(ref box[0]);
        }

        public static int Get(IMemoryCache cache, string ip)
        {
            string key = CacheKeyPrefix + ip;
            return cache.TryGetValue(key, out int[] box) ? Volatile.Read(ref box[0]) : 0;
        }

        // Exponential backoff: 1s * 2^(n-5), capped at 30s, only after 5 failures.
        public static Task BackoffAsync(int attempts)
        {
            if (attempts <= 5) return Task.CompletedTask;
            int exp = Math.Min(attempts - 5, 5); // 2^0..2^5 = 1..32, capped below
            int ms = (int)Math.Min(Math.Pow(2, exp - 1) * 1000, 30_000);
            return Task.Delay(ms);
        }
    }
}
