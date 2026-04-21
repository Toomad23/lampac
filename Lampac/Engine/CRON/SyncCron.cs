using Shared;
using Shared.Engine;
using Shared.Models;
using System;
using System.Threading;

namespace Lampac.Engine.CRON
{
    public static class SyncCron
    {
        public static void Run()
        {
            _cronTimer = new Timer(cron, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(1));
        }

        static Timer _cronTimer;

        static int _updatingDb = 0;

        // Why (round5.6): slave used to swallow the master's entire AppInit and
        // overwrite the running conf (globalproxy, chromium.executablePath,
        // filesystem paths, Merchant secrets, …). A MITM / hijacked DNS / compromised
        // master becomes instant RCE on every slave. Gate the fetch:
        //  1) require HTTPS on api_host (prevent passive MITM),
        //  2) require api_host to match an explicit sync.allowHosts entry
        //     (empty list → refuse to sync),
        //  3) even in sync_full mode, never mass-assign — copy only the
        //     explicitly whitelisted fields below.
        static bool IsApiHostAllowed(string apiHost, string[] allowHosts)
        {
            if (string.IsNullOrEmpty(apiHost) || allowHosts == null || allowHosts.Length == 0)
                return false;

            if (!Uri.TryCreate(apiHost, UriKind.Absolute, out var uri))
                return false;

            // Require HTTPS — plain HTTP is susceptible to on-path rewrite of the
            // config blob.
            if (uri.Scheme != Uri.UriSchemeHttps)
                return false;

            foreach (var allowed in allowHosts)
            {
                if (string.IsNullOrWhiteSpace(allowed))
                    continue;

                if (string.Equals(allowed.Trim(), uri.Host, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        // Apply only the fields a master is allowed to push to a slave. Everything
        // else (globalproxy, chromium, filesystem paths, Merchant secrets, …)
        // stays sourced from the slave's own init.conf.
        static void ApplyWhitelistedFields(AppInit current, AppInit fromMaster)
        {
            if (current?.accsdb != null && fromMaster?.accsdb != null)
            {
                current.accsdb.users = fromMaster.accsdb.users;
                current.accsdb.accounts = fromMaster.accsdb.accounts;
                current.accsdb.white_uids = fromMaster.accsdb.white_uids;
                current.accsdb.shared_passwd = fromMaster.accsdb.shared_passwd;
            }
        }

        async static void cron(object state)
        {
            if (Interlocked.Exchange(ref _updatingDb, 1) == 1)
                return;

            try
            {
                var sync = AppInit.conf?.sync;

                if (sync == null || !sync.enable || sync.type != "slave" || string.IsNullOrEmpty(sync.api_host) || string.IsNullOrEmpty(sync.api_passwd))
                    return;

                if (!IsApiHostAllowed(sync.api_host, sync.allowHosts))
                    return;

                var init = await Http.Get<AppInit>(sync.api_host + "/api/sync", timeoutSeconds: 5, headers: HeadersModel.Init("localrequest", sync.api_passwd), weblog: false);
                if (init != null)
                {
                    // Why: drop the bulk replace path entirely. Even when the operator
                    // asked for `sync_full`, mass-assigning AppInit.conf gives the
                    // master full control over the slave's filesystem paths and
                    // subprocess binaries. Treat sync_full as "sync more fields",
                    // not "replace the whole config".
                    ApplyWhitelistedFields(AppInit.conf, init);
                }
            }
            catch { }
            finally
            {
                Volatile.Write(ref _updatingDb, 0);
            }
        }
    }
}
