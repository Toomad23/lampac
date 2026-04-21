using Microsoft.EntityFrameworkCore;
using Shared.Models;
using Shared.Models.Base;
using Shared.Models.Proxy;
using Shared.Models.SQL;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Shared.Engine
{
    public class ProxyLink : IProxyLink
    {
        #region ProxyLink
        static readonly ConcurrentDictionary<string, ProxyLinkModel> links = new();

        // HMAC-SHA256 key derived from rootPasswd — prevents forging non-AES proxy link IDs.
        // Lazy-initialized because rootPasswd is set in Program.Run(), after static constructors.
        static volatile byte[] _proxyLinkKey;
        static byte[] proxyLinkKey
        {
            get
            {
                if (_proxyLinkKey == null)
                    _proxyLinkKey = SHA256.HashData(Encoding.UTF8.GetBytes((AppInit.rootPasswd ?? "fallback") + "|proxylink"));
                return _proxyLinkKey;
            }
        }

        static string HmacId(string uri, string reqip)
        {
            using var h = new HMACSHA256(proxyLinkKey);
            byte[] bytes = h.ComputeHash(Encoding.UTF8.GetBytes(uri + "|" + reqip));
            // First 16 bytes as hex → 32 lowercase chars; matches IsAes length heuristic.
            return Convert.ToHexString(bytes, 0, 16).ToLower();
        }

        // Why (M-9): extract the extension from the URI's local path only so that query/fragment
        // values cannot spoof the served file type (e.g. `/evil.exe?ext=.png`). Returns
        // string.Empty when the URI is malformed or has no recognisable extension, in which
        // case callers fall back to their default-suffix behaviour.
        static string GetUriPathExtension(string uri)
        {
            if (string.IsNullOrEmpty(uri))
                return string.Empty;

            try
            {
                // Strip any " or " / "#" fragment that upstream code appends to raw uri values.
                string clean = uri;
                int orIdx = clean.IndexOf(" or ", StringComparison.Ordinal);
                if (orIdx > 0)
                    clean = clean.Substring(0, orIdx);
                int hashIdx = clean.IndexOf('#');
                if (hashIdx > 0)
                    clean = clean.Substring(0, hashIdx);

                string pathOnly;
                if (Uri.TryCreate(clean, UriKind.Absolute, out var parsed))
                {
                    pathOnly = parsed.LocalPath;
                }
                else
                {
                    // Relative/opaque fallback: manually trim query.
                    int q = clean.IndexOf('?');
                    pathOnly = q >= 0 ? clean.Substring(0, q) : clean;
                }

                string ext = System.IO.Path.GetExtension(pathOnly);
                return string.IsNullOrEmpty(ext) ? string.Empty : ext.ToLowerInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        static readonly Timer _cronTimer = new Timer(Cron, null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

        public static int Stat_ContLinks => links.IsEmpty ? 0 : links.Count;
        #endregion


        #region Encrypt
        public string Encrypt(string uri, string plugin, DateTime ex = default, bool IsProxyImg = false) => Encrypt(uri, null, verifyip: false, ex: ex, plugin: plugin, IsProxyImg: IsProxyImg);

        public static string Encrypt(string uri, ProxyLinkModel p, bool forceMd5 = false) => Encrypt(uri, p.reqip, p.headers, p.proxy, p.plugin, p.verifyip, forceMd5: forceMd5);

        public static string Encrypt(string uri, string reqip, List<HeadersModel> headers = null, WebProxy proxy = null, string plugin = null, bool verifyip = true, DateTime ex = default, bool forceMd5 = false, bool IsProxyImg = false)
        {
            if (string.IsNullOrWhiteSpace(uri))
                return string.Empty;

            string hash;
            bool IsMd5 = false;
            string uri_clear = uri.Contains("#") ? uri.Split("#")[0].Trim() : uri.Trim();

            if (plugin == "posterapi")
            {
                hash = AesTo.Encrypt(JsonSerializer.Serialize(new AesPayload() { u = uri_clear }));
            }
            else if (!forceMd5 && AppInit.conf.serverproxy.encrypt_aes && (headers == null || headers.Count == 0) && proxy == null && !uri_clear.Contains(" or "))
            {
                if (verifyip && AppInit.conf.serverproxy.verifyip)
                {
                    hash = AesTo.Encrypt(JsonSerializer.Serialize(new AesPayload()
                    {
                        p = plugin,
                        u = uri_clear,
                        i = reqip,
                        v = true,
                        e = DateTime.Now.AddHours(36)
                    }));
                }
                else
                {
                    hash = AesTo.Encrypt(JsonSerializer.Serialize(new AesPayload() { p = plugin, u = uri_clear }));
                }
            }
            else
            {
                IsMd5 = true;
                hash = HmacId(uri_clear, verifyip && AppInit.conf.serverproxy.verifyip ? (reqip ?? string.Empty) : string.Empty);
            }

            // Why (M-9): previously the code ran uri.Contains(".png") etc. against the full URI,
            // including query/fragment. `https://attacker.tld/evil.exe?ext=.png` would be tagged
            // as `.png`, spoofing the served MIME/extension. Extract the extension from the real
            // path portion only and check it against a whitelist; fall back to the existing
            // defaults when the path has no recognised extension.
            string pathExt = GetUriPathExtension(uri);

            if (IsProxyImg)
            {
                if (pathExt == ".png")
                    hash += ".png";
                else if (pathExt == ".webp")
                    hash += ".webp";
                else
                    hash += ".jpg";
            }
            else
            {
                if (pathExt == ".m3u8")
                    hash += ".m3u8";
                else if (pathExt == ".m3u")
                    hash += ".m3u";
                else if (pathExt == ".mpd")
                    hash += ".mpd";
                else if (pathExt == ".webm")
                    hash += ".webm";
                else if (pathExt == ".ts")
                    hash += ".ts";
                else if (pathExt == ".m4s")
                    hash += ".m4s";
                else if (pathExt == ".mp4")
                    hash += ".mp4";
                else if (pathExt == ".mov")
                    hash += ".mov";
                else if (pathExt == ".mkv")
                    hash += ".mkv";
                else if (pathExt == ".aac")
                    hash += ".aac";
                else if (pathExt == ".vtt")
                    hash += ".vtt";
                else if (pathExt == ".srt")
                    hash += ".srt";
                else if (pathExt == ".jpg" || pathExt == ".jpeg")
                    hash += ".jpg";
                else if (pathExt == ".png")
                    hash += ".png";
                else if (pathExt == ".webp")
                    hash += ".webp";
            }

            if (IsMd5)
            {
                var md = new ProxyLinkModel(verifyip ? reqip : null, headers, proxy, uri_clear, plugin, verifyip, ex: ex);
                links.AddOrUpdate(hash, md, (d, u) => md);
            }

            return hash;
        }
        #endregion

        #region Decrypt
        public static ProxyLinkModel Decrypt(string hash, string reqip)
        {
            if (string.IsNullOrEmpty(hash))
                return null;

            if (IsAes(hash))
            {
                ReadOnlySpan<char> hashSpan = hash.AsSpan();
                int dot = hash.LastIndexOf('.');
                if (dot > 0)
                    hashSpan = hashSpan.Slice(0, dot);

                string dec = AesTo.Decrypt(hashSpan);
                if (string.IsNullOrEmpty(dec))
                    return null;

                var root = JsonSerializer.Deserialize<AesPayload>(dec);
                if (root == null)
                    return null;

                if (root.v)
                {
                    // verifyip=true must fail-closed when caller cannot provide the request IP:
                    // if reqip is null we have no evidence of binding, so reject.
                    if (reqip == null || root.i != reqip)
                        return null;

                    if (DateTime.Now > root.e)
                        return null;
                }

                List<HeadersModel> headers = null;

                if (root.h != null && root.h.Count > 0)
                    headers = HeadersModel.Init(root.h);

                return new ProxyLinkModel(reqip, headers, null, root.u, root.p);
            }

            if (!links.TryGetValue(hash, out ProxyLinkModel val))
            {
                try
                {
                    if (IsUseSql(hash))
                    {
                        using (var sqlDb = ProxyLinkContext.Factory != null
                            ? ProxyLinkContext.Factory.CreateDbContext()
                            : new ProxyLinkContext())
                        {
                            var link = sqlDb.links.Find(hash);

                            if (link != null && link.ex > DateTime.Now)
                            {
                                val = JsonSerializer.Deserialize<ProxyLinkModel>(link.json);
                                val.id = link.Id;
                                val.ex = link.ex;
                            }
                        }
                    }
                }
                catch { }
            }

            if (val != null)
            {
                if (val.verifyip == false || AppInit.conf.serverproxy.verifyip == false || val.reqip == string.Empty || reqip == null || reqip == val.reqip)
                    return val;
            }

            return null;
        }
        #endregion

        #region IsAes
        public static bool IsAes(ReadOnlySpan<char> hash)
        {
            if (hash.IsEmpty)
                return false;

            if (hash.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                return false;

            // Ищем первый из ?, &, .
            int idx = hash.IndexOfAny('?', '&', '.');

            ReadOnlySpan<char> firstPart;
            if (idx >= 0)
                firstPart = hash.Slice(0, idx);
            else
                firstPart = hash;

            // Если длина 32 — это не AES
            return firstPart.Length != 32;
        }
        #endregion

        #region IsUseSql
        static bool IsUseSql(ReadOnlySpan<char> hash)
        {
            if (AppInit.conf.mikrotik)
                return false;

            bool useSql = true;
            if (AppInit.conf.serverproxy.image.noSqlDb)
            {
                int dot = hash.LastIndexOf('.');
                if (dot > 0)
                {
                    ReadOnlySpan<char> ext = hash.Slice(dot + 1);

                    useSql = ext switch
                    {
                        var e when e.Equals("jpg", StringComparison.OrdinalIgnoreCase) => false,
                        var e when e.Equals("jpeg", StringComparison.OrdinalIgnoreCase) => false,
                        var e when e.Equals("png", StringComparison.OrdinalIgnoreCase) => false,
                        var e when e.Equals("webp", StringComparison.OrdinalIgnoreCase) => false,
                        _ => true
                    };
                }
            }

            return useSql;
        }
        #endregion


        #region Cron
        static HashSet<string> tempLinks = new(1000), sqlLinks = new(1000), delete_ids = new(1000);

        static int cronRound = 0;

        static DateTime _nextClearDb = DateTime.Now.AddMinutes(5);

        static int _updatingDb = 0;

        async static void Cron(object state)
        {
            if (links.IsEmpty)
                return;

            if (Interlocked.Exchange(ref _updatingDb, 1) == 1)
                return;

            try
            {
                if (cronRound >= 60)
                {
                    cronRound = 0;
                    tempLinks.Clear();
                }

                cronRound++;
                var now = DateTime.Now;

                if (now > _nextClearDb)
                {
                    _nextClearDb = now.AddMinutes(5);

                    using (var sqlDb = new ProxyLinkContext())
                    {
                        await sqlDb.links
                            .Where(i => now > i.ex)
                            .ExecuteDeleteAsync();
                    }
                }
                else
                {
                    sqlLinks.Clear();
                    delete_ids.Clear();

                    foreach (var link in links)
                    {
                        try
                        {
                            if (IsUseSql(link.Key) == false || link.Value.proxy != null || now.AddMinutes(5) > link.Value.ex || link.Value.uri.Contains(" or "))
                            {
                                if (now > link.Value.ex)
                                    delete_ids.Add(link.Key);
                            }
                            else
                            {
                                if (tempLinks.Contains(link.Key))
                                    delete_ids.Add(link.Key);
                                else
                                {
                                    sqlLinks.Add(link.Key);
                                }
                            }
                        }
                        catch { }
                    }

                    if (delete_ids.Count > 0)
                    {
                        foreach (string removeId in delete_ids)
                            links.TryRemove(removeId, out _);
                    }

                    if (sqlLinks.Count > 0)
                    {
                        using (var sqlDb = new ProxyLinkContext())
                        {
                            await sqlDb.links
                                .Where(x => sqlLinks.Contains(x.Id))
                                .ExecuteDeleteAsync();

                            foreach (string linkId in sqlLinks)
                            {
                                if (links.TryRemove(linkId, out var link))
                                {
                                    if (link.id == null)
                                        link.id = linkId;

                                    sqlDb.links.Add(new ProxyLinkSqlModel()
                                    {
                                        Id = linkId,
                                        ex = link.ex,
                                        json = JsonSerializer.Serialize(link)
                                    });
                                }
                            }

                            await sqlDb.SaveChangesAsync();

                            foreach (string removeLink in sqlLinks)
                                tempLinks.Add(removeLink);
                        }
                    }
                }
            }
            catch (Exception ex) 
            { 
                Console.WriteLine($"ProxyLink: {ex}"); 
            }
            finally 
            {
                Volatile.Write(ref _updatingDb, 0);
            }
        }
        #endregion




        sealed class AesPayload
        {
            public string p { get; set; }
            public string u { get; set; }
            public string i { get; set; }
            public bool v { get; set; }
            public DateTime e { get; set; }
            public Dictionary<string, string> h { get; set; }
        }
    }
}
