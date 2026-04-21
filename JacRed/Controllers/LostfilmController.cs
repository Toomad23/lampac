using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace JacRed.Controllers
{
    [Route("lostfilm/[action]")]
    public class LostfilmController : JacBaseController
    {
        #region search
        public static Task<bool> search(string host, ConcurrentBag<TorrentDetails> torrents, string query)
        {
            if (!jackett.Lostfilm.enable || string.IsNullOrEmpty(jackett.Lostfilm.cookie ?? jackett.Lostfilm.login.u) || jackett.Lostfilm.showdown)
                return Task.FromResult(false);

            return Joinparse(torrents, () => parsePage(host, query));
        }
        #endregion


        #region parseMagnet
        async public Task<ActionResult> parseMagnet(string episodeid)
        {
            if (!jackett.Lostfilm.enable)
                return Content("disable");

            // Why (FM-15): `episodeid` is attacker-controlled and is interpolated into
            // v_search.php?a=... — a non-numeric value pivots the request to other paths
            // or parameter-injects. Mirror the Rutracker fix pattern.
            if (!int.TryParse(episodeid, out int eid) || eid <= 0)
                return Content("invalid id");

            var _t = await getTorrent(eid);
            if (_t != null)
                return File(_t, "application/x-bittorrent");

            return Content("error");
        }
        #endregion

        #region parsePage
        async static ValueTask<List<TorrentDetails>> parsePage(string host, string query)
        {
            var proxyManager = new ProxyManager("lostfilm", jackett.Lostfilm);

            #region html
            bool validrq = false;
            string html = await Http.Get($"{jackett.Lostfilm.host}/search/?q={HttpUtility.UrlEncode(query)}", timeoutSeconds: jackett.timeoutSeconds, proxy: proxyManager.Get());

            if (html != null && html.Contains("onClick=\"FollowSerial("))
            {
                string serie = Regex.Match(html, "href=\"/series/([^\"]+)\" class=\"no-decoration\"").Groups[1].Value;
                if (!string.IsNullOrWhiteSpace(serie))
                {
                    html = await Http.Get($"{jackett.Lostfilm.host}/series/{serie}/seasons/", timeoutSeconds: jackett.timeoutSeconds);
                    if (html != null && html.Contains("LostFilm.TV"))
                        validrq = true;
                }
            }

            if (!validrq)
            {
                consoleErrorLog("lostfilm");
                return null;
            }
            #endregion

            var torrents = new List<TorrentDetails>();

            foreach (string row in html.Split("<tr>").Skip(1))
            {
                if (string.IsNullOrWhiteSpace(row))
                    continue;

                #region Локальный метод - Match
                string Match(string val, string pattern, int index = 1)
                {
                    string res = HttpUtility.HtmlDecode(new Regex(pattern, RegexOptions.IgnoreCase).Match(val).Groups[index].Value.Trim());
                    res = Regex.Replace(res, "[\n\r\t ]+", " ");
                    return res.Trim();
                }
                #endregion

                #region Данные раздачи
                DateTime createTime = tParse.ParseCreateTime(Match(row, "data-released=\"([0-9]{2}\\.[0-9]{2}\\.[0-9]{4})\">([^<]+)</span>"), "dd.MM.yyyy");

                string url = Match(html, "href=\"/(series/[^/]+/seasons)\" class=\"item  active\">Гид по сериям</a>");
                string sinfo = Match(row, "title=\"Перейти к серии\">([^<]+)</td>");
                string name = Match(html, "<h1 class=\"title-ru\" itemprop=\"name\">([^<]+)</h1>");
                string originalname = Match(html, "<h2 class=\"title-en\" itemprop=\"alternativeHeadline\">([^<]+)</h2>");

                if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(originalname) || string.IsNullOrWhiteSpace(sinfo))
                    continue;
                #endregion

                string episodeid = Match(row, "onclick=\"PlayEpisode\\('([0-9]+)'\\)\"");
                if (string.IsNullOrWhiteSpace(episodeid))
                    continue;

                torrents.Add(new TorrentDetails()
                {
                    types = new string[] { "serial" },
                    url = $"{jackett.Lostfilm.host}/{url}",
                    title = $"{name} / {originalname} / {sinfo} [{createTime.Year}, 1080p]",
                    sid = 1,
                    createTime = createTime,
                    parselink = $"{host}/lostfilm/parsemagnet?episodeid={episodeid}",
                    name = name,
                    originalname = originalname,
                    relased = createTime.Year
                });
            }

            return torrents;
        }
        #endregion


        #region getTorrent
        async Task<byte[]> getTorrent(int episodeid)
        {
            try
            {
                string cookie = await getCookie();
                if (string.IsNullOrEmpty(cookie))
                    return null;

                var proxyManager = new ProxyManager("lostfilm", jackett.Lostfilm);
                var proxy = proxyManager.Get();

                // Получаем ссылку на поиск
                string v_search = await Http.Get($"{jackett.Lostfilm.host}/v_search.php?a={episodeid}", proxy: proxy, cookie: cookie);
                string retreSearchUrl = new Regex("url=(\")?(https?://[^/]+/[^\"]+)").Match(v_search ?? "").Groups[2].Value.Trim();
                if (!string.IsNullOrWhiteSpace(retreSearchUrl) && isLostfilmHost(retreSearchUrl))
                {
                    // Загружаем HTML поиска
                    // Why (FH-15): the scraped `retreSearchUrl` is an arbitrary external URL.
                    // Re-sending the Lostfilm session cookie to a non-Lostfilm host exfiltrates
                    // credentials. Gate the fetch (and the torrent download below) with an
                    // allow-list based on the configured Lostfilm host's registrable domain.
                    string shtml = await Http.Get(retreSearchUrl, proxy: proxy, cookie: cookie);
                    if (!string.IsNullOrWhiteSpace(shtml))
                    {
                        var match = new Regex("<div class=\"inner-box--link main\"><a href=\"([^\"]+)\">([^<]+)</a></div>").Match(Regex.Replace(shtml, "[\n\r\t]+", ""));
                        while (match.Success)
                        {
                            if (Regex.IsMatch(match.Groups[2].Value, "(2160p|2060p|1440p|1080p|720p)", RegexOptions.IgnoreCase))
                            {
                                string torrentFile = match.Groups[1].Value;
                                string quality = Regex.Match(match.Groups[2].Value, "(2160p|2060p|1440p|1080p|720p)").Groups[1].Value;

                                if (!string.IsNullOrWhiteSpace(torrentFile) && !string.IsNullOrWhiteSpace(quality) && isLostfilmHost(torrentFile))
                                {
                                    // Why (FH-15): `torrentFile` is scraped from the retreSearchUrl response
                                    // (attacker-influenceable). Apply the same allow-list before re-sending
                                    // the Lostfilm session cookie.
                                    byte[] torrent = await Http.Download(torrentFile, referer: $"{jackett.Lostfilm.host}/", proxy: proxy, cookie: cookie);
                                    if (BencodeTo.Magnet(torrent) != null)
                                        return torrent;
                                }
                            }

                            match = match.NextMatch();
                        }
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"JacRed/lostfilm getTorrent: {ex.Message}"); }

            return null;
        }

        // Why (FH-15): host allow-list for URLs scraped out of Lostfilm responses. Accepts the
        // configured Lostfilm host, any subdomain of its registrable domain (e.g. tracktor.lostfilm.tv),
        // and the known tracktor.in CDN used by Lostfilm. Everything else is rejected before we
        // attach the session cookie to a second-hop request.
        static bool isLostfilmHost(string absoluteUrl)
        {
            if (string.IsNullOrWhiteSpace(absoluteUrl))
                return false;

            if (!Uri.TryCreate(absoluteUrl, UriKind.Absolute, out var uri))
                return false;

            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                return false;

            string host = uri.Host.ToLowerInvariant();

            if (host == "tracktor.in" || host.EndsWith(".tracktor.in"))
                return true;

            string configured = jackett.Lostfilm.host ?? string.Empty;
            if (!Uri.TryCreate(configured, UriKind.Absolute, out var cfg))
                return false;

            string cfgHost = cfg.Host.ToLowerInvariant();
            if (host == cfgHost)
                return true;

            // Derive the registrable domain (last two labels) and allow same-family subdomains.
            string[] parts = cfgHost.Split('.');
            if (parts.Length < 2)
                return false;

            string family = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
            return host == family || host.EndsWith("." + family);
        }
        #endregion

        #region getCookie
        static readonly System.Net.Http.HttpClient loginHttpClient = new System.Net.Http.HttpClient(new System.Net.Http.SocketsHttpHandler()
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10)
        });

        async static ValueTask<string> getCookie()
        {
            if (!string.IsNullOrEmpty(jackett.Lostfilm.cookie))
                return jackett.Lostfilm.cookie;

            string authKey = "Lostfilm:TakeLogin()";
            if (Startup.memoryCache.TryGetValue(authKey, out string _cookie))
                return _cookie;

            if (Startup.memoryCache.TryGetValue($"{authKey}:error", out _))
                return null;

            Startup.memoryCache.Set($"{authKey}:error", 0, TimeSpan.FromSeconds(20));

            try
            {
                var postParams = new Dictionary<string, string>
                {
                    { "act", "users" },
                    { "type", "login" },
                    { "mail", jackett.Lostfilm.login.u },
                    { "pass", jackett.Lostfilm.login.p },
                    { "need_captcha", "" },
                    { "captcha", "" },
                    { "rem", "1" }
                };

                using var postContent = new System.Net.Http.FormUrlEncodedContent(postParams);
                var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, $"{jackett.Lostfilm.host}/ajaxik.users.php") { Content = postContent };
                foreach (var h in Http.defaultFullHeaders)
                    request.Headers.TryAddWithoutValidation(h.Key, h.Value);

                using var response = await loginHttpClient.SendAsync(request);
                if (response.Headers.TryGetValues("Set-Cookie", out var cook))
                {
                    string cookie = string.Empty;
                    foreach (string line in cook)
                    {
                        if (string.IsNullOrWhiteSpace(line))
                            continue;

                        cookie += " " + line;
                    }

                    if (cookie.Contains("lf_session=") && cookie.Contains("lnk_uid="))
                    {
                        cookie = Regex.Replace(cookie.Trim(), ";$", "");
                        Startup.memoryCache.Set(authKey, cookie, DateTime.Today.AddDays(1));
                        return cookie;
                    }
                }
            }
            // Why (FL-16): type only — never the raw ex.Message (may leak URLs/creds to logs).
            catch (Exception ex) { Console.WriteLine($"JacRed/lostfilm getCookie: {ex.GetType().Name}"); }

            return null;
        }
        #endregion
    }
}
