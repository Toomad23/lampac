using Shared;
using Shared.Models.Base;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Web;

namespace Merchant
{
    public class MerchantController : BaseController
    {
        // Why: L-16 — the shared Shared.Engine.Http client installs
        // `ServerCertificateCustomValidationCallback = (..) => true`, i.e. it accepts
        // ANY TLS certificate. That is acceptable for best-effort scraping, but it is
        // unacceptable for PSP outbound calls: a MitM on api.b2pay.io /
        // api.cryptocloud.plus / api.streampay.org could approve a fake "paid" response
        // and credit a premium subscription. StrictHttpClient uses default platform
        // certificate validation and is shared across Merchant/* for socket pooling.
        public static readonly HttpClient StrictHttpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate
            // NOTE: do NOT override ServerCertificateCustomValidationCallback — default validation is what we want.
        })
        {
            Timeout = TimeSpan.FromSeconds(15)
        };


        static DateTime LastWriteTimeUsers = default;

        // Why: structured dedup replaces raw substring match on a concatenated file blob (M-31).
        // Key format is "{merch}\0{order}" — \0 can't appear in a CSV field, so collisions are impossible.
        static HashSet<string> _users = null;

        // Why: one lock per (merch, order) serialises concurrent callbacks for the same payment (H-23)
        // so only the first wins the dedup check; others see the entry and exit without crediting again.
        //
        // Why (DoS): unbounded ConcurrentDictionary<string, SemaphoreSlim> grew forever with arbitrary
        // attacker-controlled keys. Each SemaphoreSlim holds a ManualResetEvent (kernel primitive),
        // eventually exhausting OS handles. Track lastUsed and sweep entries older than 10 min on
        // every insert; cap hard at 10 000 entries (drop oldest when exceeded).
        static readonly ConcurrentDictionary<string, (SemaphoreSlim sem, long lastUsedTicks)> _payLocks = new();
        const int _payLocksMaxEntries = 10_000;
        static readonly TimeSpan _payLocksTtl = TimeSpan.FromMinutes(10);

        static SemaphoreSlim GetPayLock(string key)
        {
            var entry = _payLocks.AddOrUpdate(
                key,
                _ => (new SemaphoreSlim(1, 1), DateTime.UtcNow.Ticks),
                (_, existing) => (existing.sem, DateTime.UtcNow.Ticks));

            // Opportunistic sweep — O(n) but n is bounded, runs at most once per add.
            // Why: we intentionally DO NOT Dispose() evicted semaphores. A concurrent caller
            // that acquired the ref before eviction may still hold Wait/Release on it;
            // disposing here would throw ObjectDisposedException on their Release(). The GC
            // reclaims the SemaphoreSlim (managed type) once no references remain.
            long thresholdTicks = DateTime.UtcNow.Add(-_payLocksTtl).Ticks;
            foreach (var kv in _payLocks)
            {
                if (kv.Value.lastUsedTicks < thresholdTicks)
                    _payLocks.TryRemove(new KeyValuePair<string, (SemaphoreSlim, long)>(kv.Key, kv.Value));
            }

            // Hard cap — if still over budget, evict oldest entries.
            if (_payLocks.Count > _payLocksMaxEntries)
            {
                foreach (var kv in _payLocks.OrderBy(p => p.Value.lastUsedTicks).Take(_payLocks.Count - _payLocksMaxEntries))
                    _payLocks.TryRemove(new KeyValuePair<string, (SemaphoreSlim, long)>(kv.Key, kv.Value));
            }

            return entry.sem;
        }

        // Why: guards reload-from-disk so two concurrent callbacks don't race on reading users.txt
        // and building _users from a half-written file.
        static readonly object _loadLock = new object();

        static string dedupKey(string merch, string order) => $"{merch}\0{order}";

        static void loadUsersIfStale()
        {
            var lastWriteTimeUsers = System.IO.File.GetLastWriteTime("merchant/users.txt");

            if (_users != null && LastWriteTimeUsers == lastWriteTimeUsers)
                return;

            lock (_loadLock)
            {
                // Re-check inside the lock to avoid duplicate reloads.
                lastWriteTimeUsers = System.IO.File.GetLastWriteTime("merchant/users.txt");
                if (_users != null && LastWriteTimeUsers == lastWriteTimeUsers)
                    return;

                var set = new HashSet<string>();

                if (System.IO.File.Exists("merchant/users.txt"))
                {
                    foreach (string line in System.IO.File.ReadAllLines("merchant/users.txt"))
                    {
                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        // Format: email,expires,merch,order
                        var data = line.Split(',');
                        if (data.Length >= 4)
                            set.Add(dedupKey(data[2], data[3]));
                    }
                }

                _users = set;
                LastWriteTimeUsers = lastWriteTimeUsers;
            }
        }

        public static void PayConfirm(string email, string merch, string order, int days = 0)
        {
            // Why: serialise check-mutate-append per (merch, order) — H-23 race on double-credit.
            var sem = GetPayLock(dedupKey(merch, order));

            sem.Wait();
            try
            {
                loadUsersIfStale();

                string key = dedupKey(merch, order);

                // Why: HashSet.Add returns false if the entry already exists — replaces the
                // substring-based dedup which false-positived when `order` appeared as a substring
                // of another payment's field (M-31).
                if (!_users.Add(key))
                    return;

                DateTime ex = default;

                if (days > 0)
                {
                    if (AppInit.conf.accsdb.findUser(email) is AccsUser user)
                    {
                        ex = user.expires;
                        ex = ex > DateTime.UtcNow ? ex.AddDays(days) : DateTime.UtcNow.AddDays(days);
                        user.expires = ex;
                        user.group = AppInit.conf.Merchant.defaultGroup;
                    }
                    else
                    {
                        ex = DateTime.UtcNow.AddDays(days);
                        AppInit.conf.accsdb.users.Add(new AccsUser()
                        {
                            id = email.ToLowerAndTrim(),
                            expires = ex,
                            group = AppInit.conf.Merchant.defaultGroup
                        });
                    }
                }
                else
                {
                    if (AppInit.conf.accsdb.findUser(email) is AccsUser user)
                    {
                        ex = user.expires;
                        ex = ex > DateTime.UtcNow ? ex.AddMonths(AppInit.conf.Merchant.accessForMonths) : DateTime.UtcNow.AddMonths(AppInit.conf.Merchant.accessForMonths);
                        user.expires = ex;
                        user.group = AppInit.conf.Merchant.defaultGroup;
                    }
                    else
                    {
                        ex = DateTime.UtcNow.AddMonths(AppInit.conf.Merchant.accessForMonths);
                        AppInit.conf.accsdb.users.Add(new AccsUser()
                        {
                            id = email.ToLowerAndTrim(),
                            expires = ex,
                            group = AppInit.conf.Merchant.defaultGroup
                        });
                    }
                }

                // Why: append-only audit log (same on-disk format as before, so existing deployments
                // and AppInit.cs loader keep working).
                System.IO.File.AppendAllText("merchant/users.txt", $"{email.ToLowerAndTrim()},{ex.ToFileTimeUtc()},{merch},{order}\n");

                LastWriteTimeUsers = System.IO.File.GetLastWriteTime("merchant/users.txt");
            }
            finally
            {
                sem.Release();
            }
        }


        public static void WriteLog(string merch, string content)
        {
            try
            {
                System.IO.File.AppendAllText($"merchant/log/{merch}.txt", content + "\n\n\n");
            }
            catch { }
        }


        public static string decodeEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;

            return HttpUtility.UrlDecode(email.ToLowerAndTrim());
        }
    }
}
