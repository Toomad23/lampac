using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Shared;
using Shared.Engine;
using Shared.Models;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Lampac.Engine.Middlewares
{
    public class Accsdb
    {
        static readonly Regex rexJac = new Regex("^/(api/v2.0/indexers|api/v1.0/|toloka|rutracker|rutor|torrentby|nnmclub|kinozal|bitru|selezen|megapeer|animelayer|anilibria|anifilm|toloka|lostfilm|bigfangroup|mazepa)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex rexStaticAssets = new Regex("\\.(js|css|ico|png|svg|jpe?g|woff|webmanifest)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex rexProxyPath = new Regex("/(proxy|proxyimg([^/]+)?)/", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex rexTmdbPath = new Regex("^/tmdb/[^/]+/", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly Regex rexLockBypass = new Regex("^/(testaccsdb|proxy/|proxyimg|lifeevents|externalids|sisi/(bookmarks|historys)|(ts|transcoding|dlna|storage|bookmark|tmdb|cub)/|timecode)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        static Accsdb() 
        {
            Directory.CreateDirectory("cache/logs/accsdb");
        }

        private readonly RequestDelegate _next;
        IMemoryCache memoryCache;

        public Accsdb(RequestDelegate next, IMemoryCache mem)
        {
            _next = next;
            memoryCache = mem;
        }

        public Task Invoke(HttpContext httpContext)
        {
            var requestInfo = httpContext.Features.Get<RequestModel>();

            #region manifest/install
            // Why (FL-1): the previous implementation cached the
            // File.Exists("module/manifest.json") result in a static bool and
            // never re-checked it. If the manifest was deleted (or the module/
            // directory wiped) after startup, the install redirect never fired
            // again; conversely if the admin created the manifest after boot
            // without restarting, the redirect loop persisted. The existence
            // check is cheap so re-evaluate on every request inside this branch.
            if (!File.Exists("module/manifest.json"))
            {
                if (httpContext.Request.Path.Value.StartsWith("/admin/manifest/install", StringComparison.OrdinalIgnoreCase))
                    return _next(httpContext);

                httpContext.Response.Redirect("/admin/manifest/install");
                return Task.CompletedTask;
            }
            #endregion

            #region admin
            if (httpContext.Request.Path.Value.StartsWith("/admin", StringComparison.OrdinalIgnoreCase))
            {
                if (httpContext.Request.Cookies.TryGetValue("passwd", out string passwd))
                {
                    if (Shared.Engine.CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
                        return _next(httpContext);

                    // Wrong password — increment brute force counter and apply backoff
                    int attempts = AdminBruteGuard.Increment(memoryCache, requestInfo.IP);

                    if (attempts > 10)
                        return httpContext.Response.WriteAsync("Too many attempts, try again tomorrow.", httpContext.RequestAborted);

                    return AdminBruteGuard.BackoffAsync(attempts).ContinueWith(_ =>
                    {
                        httpContext.Response.Redirect("/admin/auth");
                        return Task.CompletedTask;
                    }, httpContext.RequestAborted).Unwrap();
                }

                if (httpContext.Request.Path.Value.StartsWith("/admin/auth", StringComparison.OrdinalIgnoreCase))
                    return _next(httpContext);

                httpContext.Response.Redirect("/admin/auth");
                return Task.CompletedTask;
            }
            #endregion

            if (requestInfo.IsLocalRequest || requestInfo.IsAnonymousRequest)
                return _next(httpContext);

            #region jacred
            if (rexJac.IsMatch(httpContext.Request.Path.Value))
            {
                if (!string.IsNullOrEmpty(AppInit.conf.apikey))
                {
                    if (AppInit.conf.apikey != httpContext.Request.Query["apikey"])
                        return Task.CompletedTask;
                }

                return _next(httpContext);
            }
            #endregion

            if (AppInit.conf.accsdb.enable || (!requestInfo.IsLocalIp && !AppInit.conf.WAF.allowExternalIpAccess))
            {
                var accsdb = AppInit.conf.accsdb;

                if (httpContext.Request.Path.Value.StartsWith("/testaccsdb", StringComparison.OrdinalIgnoreCase) && accsdb.shared_passwd != null && requestInfo.user_uid == accsdb.shared_passwd)
                {
                    requestInfo.IsLocalRequest = true;
                    return _next(httpContext);
                }

                if (!string.IsNullOrEmpty(accsdb.premium_pattern) && !Regex.IsMatch(httpContext.Request.Path.Value, accsdb.premium_pattern, RegexOptions.IgnoreCase))
                    return _next(httpContext);

                if (!string.IsNullOrEmpty(accsdb.whitepattern) && Regex.IsMatch(httpContext.Request.Path.Value, accsdb.whitepattern, RegexOptions.IgnoreCase))
                {
                    requestInfo.IsAnonymousRequest = true;
                    return _next(httpContext);
                }

                bool limitip = false;

                var user = requestInfo.user;

                if (requestInfo.user_uid != null && accsdb.white_uids != null && accsdb.white_uids.Contains(requestInfo.user_uid))
                    return _next(httpContext);

                string uri = httpContext.Request.Path.Value + httpContext.Request.QueryString.Value;

                if (IsLockHostOrUser(memoryCache, requestInfo.user_uid, requestInfo.IP, uri, out limitip) 
                    || user == null 
                    || user.ban 
                    || DateTime.UtcNow > user.expires)
                {
                    if (httpContext.Request.Path.Value.StartsWith("/proxy/", StringComparison.OrdinalIgnoreCase) ||
                        httpContext.Request.Path.Value.StartsWith("/proxyimg", StringComparison.OrdinalIgnoreCase))
                    {
                        string hash = rexProxyPath.Replace(httpContext.Request.Path.Value, "");
                        if (ProxyLink.Decrypt(hash, requestInfo.IP)?.uri != null)
                            return _next(httpContext);
                    }

                    if (uri.StartsWith("/tmdb/api.themoviedb.org/", StringComparison.OrdinalIgnoreCase) || 
                        uri.StartsWith("/tmdb/api/", StringComparison.OrdinalIgnoreCase))
                    {
                        httpContext.Response.Redirect("https://api.themoviedb.org/" + rexTmdbPath.Replace(httpContext.Request.Path.Value, ""));
                        return Task.CompletedTask;
                    }

                    if (rexStaticAssets.IsMatch(httpContext.Request.Path.Value))
                    {
                        if (uri.StartsWith("/tmdb/image.tmdb.org/", StringComparison.OrdinalIgnoreCase) || 
                            uri.StartsWith("/tmdb/img/", StringComparison.OrdinalIgnoreCase))
                        {
                            httpContext.Response.Redirect("https://image.tmdb.org/" + rexTmdbPath.Replace(httpContext.Request.Path.Value, ""));
                            return Task.CompletedTask;
                        }

                        httpContext.Response.StatusCode = 404;
                        httpContext.Response.ContentType = "application/octet-stream";
                        return Task.CompletedTask;
                    }

                    #region msg
                    string msg = limitip ? $"Превышено допустимое количество ip/запросов на аккаунт."
                        : string.IsNullOrEmpty(requestInfo.user_uid) ? accsdb.authMesage
                        : accsdb.denyMesage.Replace("{account_email}", requestInfo.user_uid).Replace("{user_uid}", requestInfo.user_uid).Replace("{host}", httpContext.Request.Host.Value);

                    if (user != null)
                    {
                        if (user.ban)
                            msg = user.ban_msg ?? "Вы заблокированы";

                        else if (DateTime.UtcNow > user.expires)
                        {
                            msg = accsdb.expiresMesage
                                .Replace("{account_email}", requestInfo.user_uid)
                                .Replace("{user_uid}", requestInfo.user_uid)
                                .Replace("{expires}", user.expires.ToString("dd.MM.yyyy"));
                        }
                    }
                    #endregion

                    #region denymsg
                    string denymsg = limitip ? $"Превышено допустимое количество ip/запросов на аккаунт." : null;

                    if (user != null)
                    {
                        if (user.ban)
                            denymsg = user.ban_msg ?? "Вы заблокированы";

                        else if (DateTime.UtcNow > user.expires)
                        {
                            denymsg = accsdb.expiresMesage
                                .Replace("{account_email}", requestInfo.user_uid)
                                .Replace("{user_uid}", requestInfo.user_uid)
                                .Replace("{expires}", user.expires.ToString("dd.MM.yyyy"));
                        }
                    }
                    #endregion

                    return httpContext.Response.WriteAsJsonAsync(new { accsdb = true, msg, denymsg, user }, httpContext.RequestAborted);
                }
            }

            return _next(httpContext);
        }


        #region IsLock
        static bool IsLockHostOrUser(IMemoryCache memoryCache, string account_email, string userip, string uri, out bool islock)
        {
            if (string.IsNullOrEmpty(account_email))
            {
                islock = false;
                return islock;
            }

            if (rexLockBypass.IsMatch(uri))
            {
                // Hot paths skip the slow maxlock_day check but still enforce a generous
                // per-IP hourly ceiling to prevent unlimited abuse.
                const int hotPathHourlyCap = 10000;
                string hotKey = $"Accsdb:hotpath_hour:{userip}:{DateTime.Now.Hour}";
                var hotCounter = memoryCache.GetOrCreate(hotKey, entry =>
                {
                    entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                    return new int[1];
                });
                int hotCount = System.Threading.Interlocked.Increment(ref hotCounter[0]);
                if (hotCount > hotPathHourlyCap)
                {
                    islock = true;
                    return islock;
                }
                islock = false;
                return islock;
            }

            if (IsLockIpHour(memoryCache, account_email, userip, out islock, out ConcurrentDictionary<string, byte> ips) | 
                IsLockReqHour(memoryCache, account_email, uri, out islock, out ConcurrentDictionary<string, byte> urls))
            {
                setLogs("lock_hour", account_email);
                countlock_day(memoryCache, true, account_email);

                File.WriteAllLines($"cache/logs/accsdb/{CrypTo.md5(account_email)}.ips.log", ips.Keys);
                File.WriteAllLines($"cache/logs/accsdb/{CrypTo.md5(account_email)}.urls.log", urls.Keys);

                return islock;
            }

            if (countlock_day(memoryCache, false, account_email) > AppInit.conf.accsdb.maxlock_day)
            {
                if (AppInit.conf.accsdb.blocked_hour != -1)
                    memoryCache.Set($"Accsdb:blocked_hour:{account_email}", 0, DateTime.Now.AddHours(AppInit.conf.accsdb.blocked_hour));

                setLogs("lock_day", account_email);
                islock = true;
                return islock;
            }

            if (memoryCache.TryGetValue($"Accsdb:blocked_hour:{account_email}", out _))
            {
                setLogs("blocked", account_email);
                islock = true;
                return islock;
            }

            islock = false;
            return islock;
        }


        static bool IsLockIpHour(IMemoryCache memoryCache, string account_email, string userip, out bool islock, out ConcurrentDictionary<string, byte> ips)
        {
            ips = memoryCache.GetOrCreate($"Accsdb:IsLockIpHour:{account_email}:{DateTime.Now.Hour}", entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return new ConcurrentDictionary<string, byte>();
            });

            ips.TryAdd(userip, 0);

            if (ips.Count > AppInit.conf.accsdb.maxip_hour)
            {
                islock = true;
                return islock;
            }

            islock = false;
            return islock;
        }

        static bool IsLockReqHour(IMemoryCache memoryCache, string account_email, string uri, out bool islock, out ConcurrentDictionary<string, byte> urls)
        {
            urls = memoryCache.GetOrCreate($"Accsdb:IsLockReqHour:{account_email}:{DateTime.Now.Hour}", entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return new ConcurrentDictionary<string, byte>();
            });

            urls.TryAdd(uri, 0);

            if (urls.Count > AppInit.conf.accsdb.maxrequest_hour)
            {
                islock = true;
                return islock;
            }

            islock = false;
            return islock;
        }
        #endregion


        #region setLogs
        static readonly object _logsLockObj = new object();
        static string logsLock = string.Empty;

        static void setLogs(string name, string account_email)
        {
            lock (_logsLockObj)
            {
                string logFile = $"cache/logs/accsdb/{DateTime.Now:dd-MM-yyyy}.lock.txt";
                if (logsLock != string.Empty && !File.Exists(logFile))
                    logsLock = string.Empty;

                string line = $"{name} / {account_email} / {CrypTo.md5(account_email)}.*.log";

                if (!logsLock.Contains(line))
                {
                    logsLock += $"{DateTime.Now}: {line}\n";
                    File.WriteAllText(logFile, logsLock);
                }
            }
        }
        #endregion

        #region countlock_day
        static int countlock_day(IMemoryCache memoryCache, bool update, string account_email)
        {
            var lockhour = memoryCache.GetOrCreate($"Accsdb:lock_day:{account_email}:{DateTime.Now.Day}", entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                return new ConcurrentDictionary<int, byte>();
            });

            if (update)
                lockhour.TryAdd(DateTime.Now.Hour, 0);

            return lockhour.Count;
        }
        #endregion
    }
}
