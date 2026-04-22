using Microsoft.AspNetCore.Mvc;
using Microsoft.Playwright;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared.Engine.RxEnumerate;
using Shared.Engine.Utilities;
using Shared.Models.Online.Settings;
using Shared.PlaywrightCore;
using System.Net.WebSockets;
using System.Text;
using System.Threading;

namespace Online.Controllers
{
    // Spectre balancer, ported from lampac-nextgen/Modules/OnlineRUS/Spectre/.
    //
    // Source (nextgen) is a module-style plugin with ModInit / ModuleConf /
    // Controller. Our fork is monolithic: controllers extend BaseOnlineController<T>
    // and settings live on AppInit.conf.<Name>. This file is the monolithic port.
    //
    // Core mechanic:
    //   1. Resolve movie metadata via apihost (search -> token_movie).
    //   2. Render iframe HTML inside Playwright pointed at kinogo-go.tv; intercept
    //      the /movies/ POST to extract hlsSource qualities and the WebSocket URI.
    //   3. Open a ClientWebSocket to the streamer; it replies with an `edge_hash`
    //      that must be injected into every subsequent segment request as
    //      `Accepts-Controls`. Without this header segment fetches are blocked.
    //   4. Keep-alive: send "playing" every 30s, reset every 15min of inactivity.
    //
    // Security adaptations vs. nextgen:
    //   * Every external host we dereference (apihost, linkhost, wsUri) is
    //     validated via SsrfGuard before use (fail-closed).
    //   * The final Redirect(...) goes through HostStreamProxy + SsrfGuard so we
    //     cannot be coerced into an open-redirect to RFC1918 targets.
    //   * The Authorizations bearer is a constant upstream credential (not
    //     user-derived), kept verbatim from nextgen — not logged.
    //   * Our fork's EventProxyApiCreateHttpRequest record does NOT carry a
    //     `userdata` field (unlike nextgen), so the dynamic resolution handover
    //     (quality change -> playback_start) cannot key off that channel. We
    //     preserve the keep-alive + edge_hash injection (the anti-bot core),
    //     and infer the current segment index from the request URL so that
    //     seeked / playing events still fire. Resolution changes will simply
    //     look like a seek to the remote player-telemetry.
    public class Spectre : BaseOnlineController<SpectreSettings>
    {
        #region WebSocket state (shared across controller instances)
        // Controllers are transient per request; the WS + edge_hash state must
        // live on static fields to survive across the redirect hop between
        // /lite/spectre/video and subsequent proxy-stream segment fetches.
        static ClientWebSocket ws;
        static CancellationTokenSource wscts;
        static DateTime lastreq;
        static readonly Timer timer;
        static string edge_hash, resolution, requestOrigin, requestReferer;
        static int current_time = 0, last_time = 0;
        static readonly object last_time_lock = new(), resolution_lock = new();
        static readonly object wsLock = new();
        #endregion

        static Spectre()
        {
            timer = new Timer(_ =>
            {
                if (ws != null && lastreq != default && DateTime.Now.AddMinutes(-15) > lastreq)
                    ClearConnect();
            }, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(1));

            EventListener.ProxyApiCreateHttpRequest += async e =>
            {
                if (e.plugin == null || !e.plugin.Equals("Spectre", StringComparison.OrdinalIgnoreCase))
                    return;

                // Wait briefly for the WS handshake to deliver edge_hash. If we
                // never get one, abandon the hook — we don't want to silently
                // strip Authorizations from unrelated plugins.
                var sw = System.Diagnostics.Stopwatch.StartNew();
                while (edge_hash == null && sw.Elapsed < TimeSpan.FromSeconds(20))
                    await Task.Delay(10);

                if (edge_hash == null)
                    return;

                lastreq = DateTime.Now;

                #region current_time (inferred from segment index in URL)
                // nextgen keyed this off decryptLink.userdata (per-quality tag);
                // our fork's event record lacks userdata, so we parse the segment
                // index from the proxied URL and derive elapsed seconds.
                string segId = Regex.Match(e.requestMessage.RequestUri?.ToString() ?? string.Empty, "/seg-([0-9]+)-").Groups[1].Value;
                int seg = int.TryParse(segId, out int s) ? s : 0;

                if (25 >= seg)
                {
                    current_time = 0;
                    last_time = 0;
                }
                else
                {
                    bool sendSeeked = false;

                    lock (last_time_lock)
                    {
                        current_time = (seg - 25) * 6;
                        if (last_time == 0)
                            last_time = current_time;

                        if ((current_time - last_time) > 90)
                            sendSeeked = true;

                        last_time = current_time;
                    }

                    if (sendSeeked)
                    {
                        await WsSendAsync("seeked");
                        await Task.Delay(1000);
                    }
                }
                #endregion

                #region requestMessage headers (Spectre anti-bot shape)
                e.requestMessage.Headers.Clear();

                e.requestMessage.Headers.TryAddWithoutValidation("Connection", "keep-alive");
                e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua", Http.defaultUaHeaders["sec-ch-ua"]);
                e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua-mobile", "?0");
                e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua-platform", "\"Windows\"");
                e.requestMessage.Headers.TryAddWithoutValidation("User-Agent", Http.UserAgent);
                e.requestMessage.Headers.TryAddWithoutValidation("Accept", "*/*");
                e.requestMessage.Headers.TryAddWithoutValidation("Accept-Language", "ru-RU,ru;q=0.9,uk-UA;q=0.8,uk;q=0.7,en-US;q=0.6,en;q=0.5");
                e.requestMessage.Headers.TryAddWithoutValidation("Accepts-Controls", edge_hash);
                // Upstream-constant bearer token; kept verbatim from nextgen. Not
                // a user secret; never originates from a request parameter.
                e.requestMessage.Headers.TryAddWithoutValidation("Authorizations", "Bearer pXzvbyDGLYyB6VkwsWZDv3iMKZtsXNzpzRyxZUcsKHXxsSeaYakbo3hw9mBFRc5VQTpqAX6BW8aDEqyLaHYcXSQiV6KHYTVTK6MYRphNAy5sBjtrevqkDzKmLqNdfMZGEU9NELjmtKfZy3RNGzCd767sNh1mXEj4tCcvqndHtzmwAbZNkhm4ghDEasodotMBewypNQ56uotJAQGX11csfeRfBAPk8DcUWWkkqzxca8vbnEw12vUFbBzT6hz8ZB3F3dzUhUXoL2cr1WM1bXQArRCS1MUNMz3X5WDMMQoZKxj2AMTRqp7QQX4dDB9B7VzEZTmyFULhm1AcHHMkoMvSVvKYoBoAKLycYAgMHeD4ECJcGEAGpnkJhrV57zQ7");
                if (!string.IsNullOrEmpty(requestOrigin))
                    e.requestMessage.Headers.TryAddWithoutValidation("Origin", requestOrigin);
                e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
                e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "cors");
                e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "empty");
                if (!string.IsNullOrEmpty(requestReferer))
                    e.requestMessage.Headers.TryAddWithoutValidation("Referer", requestReferer);
                e.requestMessage.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br, zstd");

                if (e.requestMessage.Content?.Headers != null)
                    e.requestMessage.Content.Headers.Clear();
                #endregion
            };
        }

        public Spectre() : base(AppInit.conf.Spectre)
        {
            loadKitInitialization = (j, i, c) =>
            {
                if (j.ContainsKey("m4s"))
                    i.m4s = c.m4s;
                return i;
            };
        }

        [HttpGet]
        [Route("lite/spectre")]
        async public Task<ActionResult> Index(string orid, string imdb_id, long kinopoisk_id, string title, string original_title, int serial, string original_language, int year, int t = -1, int s = -1, bool origsource = false, bool rjson = false, bool similar = false)
        {
            if (similar)
                return await RouteSpiderSearch(title, origsource, rjson);

            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            var result = await search(orid, imdb_id, kinopoisk_id, title, serial, original_language, year);
            if (result.category_id == 0 || result.data == null)
                return OnError();

            JToken data = result.data;
            string tokenMovie = data["token_movie"] != null ? data.Value<string>("token_movie") : null;
            var frame = await iframe(tokenMovie);
            if (frame.all == null)
                return OnError();

            if (result.category_id is 1 or 3)
            {
                #region Фильм
                var videos = frame.all["theatrical"].ToObject<Dictionary<string, Dictionary<string, JObject>>>();

                var mtpl = new MovieTpl(title, original_title, videos.Count);

                foreach (var i in videos)
                {
                    var file = i.Value.First().Value;

                    string translation = file.Value<string>("translation");
                    string quality = file.Value<string>("quality");
                    long id = file.Value<long>("id");
                    bool uhd = init.m4s ? file.Value<bool>("uhd") : false;

                    string link = $"{host}/lite/spectre/video?id_file={id}&token_movie={data.Value<string>("token_movie")}";
                    string streamlink = accsArgs($"{link.Replace("/video", "/video.m3u8")}&play=true");

                    mtpl.Append(translation, link, "call", streamlink, voice_name: uhd ? "2160p" : quality, quality: uhd ? "2160p" : "");
                }

                return await ContentTpl(mtpl);
                #endregion
            }
            else
            {
                #region Сериал
                string defaultargs = $"&orid={orid}&imdb_id={imdb_id}&kinopoisk_id={kinopoisk_id}&title={HttpUtility.UrlEncode(title)}&original_title={HttpUtility.UrlEncode(original_title)}&year={year}&original_language={original_language}";

                if (s == -1)
                {
                    #region Сезоны
                    string q = null;

                    try
                    {
                        if (init.m4s)
                            q = frame.active.Value<bool>("uhd") == true ? "2160p" : null;
                    }
                    catch { }

                    Dictionary<string, JToken> seasons;
                    if (frame.all["seasons"] != null)
                        seasons = frame.all["seasons"].ToObject<Dictionary<string, JToken>>();
                    else
                        seasons = frame.all.ToObject<Dictionary<string, JToken>>();

                    if (seasons.First().Key.StartsWith("t"))
                    {
                        var tpl = new SeasonTpl(q);

                        var seasonNumbers = new HashSet<int>();

                        foreach (var translation in seasons)
                        {
                            var file = translation.Value["file"];
                            if (file == null)
                                continue;

                            foreach (var season in file.ToObject<Dictionary<string, object>>())
                            {
                                if (int.TryParse(season.Key, out int seasonNumber))
                                    seasonNumbers.Add(seasonNumber);
                            }
                        }

                        if (!seasonNumbers.Any())
                            seasonNumbers.Add(frame.active.Value<int>("seasons"));

                        foreach (int i in seasonNumbers.OrderBy(i => i))
                            tpl.Append($"{i} сезон", $"{host}/lite/spectre?rjson={rjson}&s={i}{defaultargs}", i.ToString());

                        return await ContentTpl(tpl);
                    }
                    else
                    {
                        var tpl = new SeasonTpl(q, seasons.Count);

                        foreach (var season in seasons)
                            tpl.Append($"{season.Key} сезон", $"{host}/lite/spectre?rjson={rjson}&s={season.Key}{defaultargs}", season.Key);

                        return await ContentTpl(tpl);
                    }
                    #endregion
                }
                else
                {
                    var vtpl = new VoiceTpl();
                    var etpl = new EpisodeTpl();
                    var voices = new HashSet<int>();

                    string sArhc = s.ToString();

                    if (frame.all[sArhc] is JArray)
                    {
                        #region Перевод
                        foreach (var episode in frame.all[sArhc])
                        {
                            foreach (var voice in episode.ToObject<Dictionary<string, JObject>>().Select(i => i.Value))
                            {
                                int id_translation = voice.Value<int>("id_translation");
                                if (voices.Contains(id_translation))
                                    continue;

                                voices.Add(id_translation);

                                if (t == -1)
                                    t = id_translation;

                                string link = $"{host}/lite/spectre?rjson={rjson}&s={s}&t={id_translation}{defaultargs}";
                                bool active = t == id_translation;

                                vtpl.Append(voice.Value<string>("translation"), active, link);
                            }
                        }
                        #endregion

                        foreach (var episode in frame.all[sArhc])
                        {
                            foreach (var voice in episode.ToObject<Dictionary<string, JObject>>().Select(i => i.Value))
                            {
                                if (voice.Value<int>("id_translation") != t)
                                    continue;

                                string translation = voice.Value<string>("translation");
                                int e = voice.Value<int>("episode");

                                string link = $"{host}/lite/spectre/video?id_file={voice.Value<long>("id")}&token_movie={data.Value<string>("token_movie")}";
                                string streamlink = accsArgs($"{link.Replace("/video", "/video.m3u8")}&play=true");

                                if (e > 0)
                                    etpl.Append($"{e} серия", title ?? original_title, sArhc, e.ToString(), link, "call", voice_name: translation, streamlink: streamlink);
                            }
                        }
                    }
                    else if (frame.all.ToObject<Dictionary<string, object>>().First().Key.StartsWith("t"))
                    {
                        #region Перевод
                        foreach (var node in frame.all)
                        {
                            if (!node.First["file"].ToObject<Dictionary<string, object>>().ContainsKey(sArhc))
                                continue;

                            var voice = node.First["file"].First.First.First.First;
                            int id_translation = voice.Value<int>("id_translation");
                            if (voices.Contains(id_translation))
                                continue;

                            voices.Add(id_translation);

                            if (t == -1)
                                t = id_translation;

                            string link = $"{host}/lite/spectre?rjson={rjson}&s={s}&t={id_translation}{defaultargs}";
                            bool active = t == id_translation;

                            vtpl.Append(voice.Value<string>("translation"), active, link);
                        }
                        #endregion

                        foreach (var node in frame.all)
                        {
                            foreach (var season in node.First["file"].ToObject<Dictionary<string, object>>())
                            {
                                if (season.Key != sArhc)
                                    continue;

                                if (season.Value is JArray)
                                {
                                    // NOTE: nextgen left this branch empty; kept for parity.
                                }
                                else if (season.Value is JObject sjob)
                                {
                                    foreach (var episode in sjob.ToObject<Dictionary<string, JObject>>())
                                    {
                                        if (episode.Value.Value<int>("id_translation") != t)
                                            continue;

                                        string translation = episode.Value.Value<string>("translation");
                                        int e = episode.Value.Value<int>("episode");

                                        string link = $"{host}/lite/spectre/video?id_file={episode.Value.Value<long>("id")}&token_movie={data.Value<string>("token_movie")}";
                                        string streamlink = accsArgs($"{link.Replace("/video", "/video.m3u8")}&play=true");

                                        if (e > 0)
                                            etpl.Append($"{e} серия", title ?? original_title, sArhc, e.ToString(), link, "call", voice_name: translation, streamlink: streamlink);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        #region Перевод
                        foreach (var episode in frame.all[sArhc].ToObject<Dictionary<string, Dictionary<string, JObject>>>())
                        {
                            foreach (var voice in episode.Value.Select(i => i.Value))
                            {
                                int id_translation = voice.Value<int>("id_translation");
                                if (voices.Contains(id_translation))
                                    continue;

                                voices.Add(id_translation);

                                if (t == -1)
                                    t = id_translation;

                                string link = $"{host}/lite/spectre?rjson={rjson}&s={s}&t={id_translation}{defaultargs}";
                                bool active = t == id_translation;

                                vtpl.Append(voice.Value<string>("translation"), active, link);
                            }
                        }
                        #endregion

                        foreach (var episode in frame.all[sArhc].ToObject<Dictionary<string, Dictionary<string, JObject>>>())
                        {
                            foreach (var voice in episode.Value.Select(i => i.Value))
                            {
                                string translation = voice.Value<string>("translation");
                                if (voice.Value<int>("id_translation") != t)
                                    continue;

                                string link = $"{host}/lite/spectre/video?id_file={voice.Value<long>("id")}&token_movie={data.Value<string>("token_movie")}";
                                string streamlink = accsArgs($"{link.Replace("/video", "/video.m3u8")}&play=true");

                                etpl.Append($"{episode.Key} серия", title ?? original_title, sArhc, episode.Key, link, "call", voice_name: translation, streamlink: streamlink);
                            }
                        }
                    }

                    etpl.Append(vtpl);

                    return await ContentTpl(etpl);
                }
                #endregion
            }
        }


        #region Video
        [HttpGet]
        [Route("lite/spectre/video")]
        [Route("lite/spectre/video.m3u8")]
        async public Task<ActionResult> Video(long id_file, string token_movie, bool play)
        {
            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            ClearConnect();

            string linkhostUri = $"{init.linkhost}/?token_movie={token_movie}&token={init.token}";

            // SSRF gate: linkhost comes from a (runtime-mutable) config value.
            // Basic check is enough here — the actual fetch goes through
            // Playwright in goMovie which is then constrained by our UA/proxy
            // setup, but we fail-closed if someone points linkhost at RFC1918.
            if (!SsrfGuard.IsAllowedPublicUriBasic(linkhostUri))
                return OnError("linkhost");

            var result = await goMovie(linkhostUri, id_file);
            if (result.streams.data == null || result.streams.data.Count == 0 || string.IsNullOrEmpty(result.wsUri))
                return OnError();

            // Start WS only if the handshake URI is public. wsUri comes from a
            // JSON field (pnr) returned by a third-party endpoint — treat as
            // user-tainted and reject private IP / non-ws schemes.
            if (!IsAllowedWebSocketUri(result.wsUri))
                return OnError("ws uri");

            StartWebSocket(result.wsUri);

            var first = result.streams.Firts();

            if (play)
                return Redirect(first.link);

            return ContentTo(VideoTpl.ToJson("play", first.link, "auto",
                streamquality: result.streams,
                vast: init.vast,
                hls_manifest_timeout: (int)TimeSpan.FromSeconds(30).TotalMilliseconds
            ));
        }
        #endregion

        #region SpiderSearch
        [HttpGet]
        [Route("lite/spectre-search")]
        async public Task<ActionResult> RouteSpiderSearch(string title, bool origsource = false, bool rjson = false)
        {
            if (string.IsNullOrWhiteSpace(title))
                return OnError();

            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            var cache = await InvokeCacheResult<JArray>($"spectre:search:{title}", 40, async e =>
            {
                var root = await httpHydra.Get<JObject>($"{init.apihost}/?token={init.token}&name={HttpUtility.UrlEncode(title)}&list", safety: true);
                if (root == null || !root.ContainsKey("data"))
                    return e.Fail("data");

                return e.Success(root["data"].ToObject<JArray>());
            });

            return await ContentTpl(cache, () =>
            {
                var stpl = new SimilarTpl(cache.Value.Count);

                foreach (var j in cache.Value)
                {
                    string uri = $"{host}/lite/spectre?orid={j.Value<string>("token_movie")}";
                    stpl.Append(j.Value<string>("name") ?? j.Value<string>("original_name"), j.Value<int>("year").ToString(), string.Empty, uri, PosterApi.Size(j.Value<string>("poster")));
                }

                return stpl;
            });
        }
        #endregion

        #region search
        async ValueTask<(bool refresh_proxy, int category_id, JToken data)> search(string token_movie, string imdb_id, long kinopoisk_id, string title, int serial, string original_language, int year)
        {
            string memKey = $"spectre:view:{kinopoisk_id}:{imdb_id}";
            if (0 >= kinopoisk_id && string.IsNullOrEmpty(imdb_id))
                memKey = $"spectre:viewsearch:{title}:{serial}:{original_language}:{year}";

            if (!string.IsNullOrEmpty(token_movie))
                memKey = $"spectre:view:{token_movie}";

            JObject root;

            if (!hybridCache.TryGetValue(memKey, out (int category_id, JToken data) res))
            {
                string stitle = title.ToLowerAndTrim();

                if (memKey.Contains(":viewsearch:"))
                {
                    if (string.IsNullOrWhiteSpace(title) || year == 0)
                        return default;

                    root = await httpHydra.Get<JObject>($"{init.apihost}/?token={init.token}&name={HttpUtility.UrlEncode(title)}&list={(serial == 1 ? "serial" : "movie")}", safety: true);
                    if (root == null)
                        return (true, 0, null);

                    if (root.ContainsKey("data"))
                    {
                        foreach (var item in root["data"])
                        {
                            if (item.Value<string>("name")?.ToLowerAndTrim() == stitle)
                            {
                                int y = item.Value<int>("year");
                                if (y > 0 && (y == year || y == (year - 1) || y == (year + 1)))
                                {
                                    if (original_language == "ru" && item.Value<string>("country")?.ToLowerAndTrim() != "россия")
                                        continue;

                                    res.data = item;
                                    res.category_id = item.Value<int>("category_id");
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    root = await httpHydra.Get<JObject>($"{init.apihost}/?token={init.token}&kp={kinopoisk_id}&imdb={imdb_id}&token_movie={token_movie}", safety: true);
                    if (root == null)
                        return (true, 0, null);

                    if (root.ContainsKey("data"))
                    {
                        res.data = root.GetValue("data");
                        res.category_id = res.data.Value<int>("category");
                    }
                }

                if (res.data != null || (root.ContainsKey("error_info") && root.Value<string>("error_info") == "not movie"))
                    hybridCache.Set(memKey, res, cacheTime(res.category_id is 1 or 3 ? 120 : 40));
                else
                    hybridCache.Set(memKey, res, cacheTime(2));
            }

            return (false, res.category_id, res.data);
        }
        #endregion


        #region iframe
        async Task<(JToken all, JToken active)> iframe(string token_movie)
        {
            if (string.IsNullOrEmpty(token_movie))
                return default;

            string memKey = $"spectre:iframe:{token_movie}";
            if (!hybridCache.TryGetValue(memKey, out (JToken all, JToken active) cache))
            {
                string json = null;

                string uri = $"{init.linkhost}/?token_movie={token_movie}&token={init.token}";

                await httpHydra.GetSpan(uri, safety: true, addheaders: HeadersModel.Init(
                    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
                    ("referer", "https://kinogo-go.tv/"),
                    ("sec-fetch-dest", "iframe"),
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-site", "cross-site"),
                    ("upgrade-insecure-requests", "1")
                ),
                spanAction: html =>
                {
                    json = Rx.Match(html, "fileList = JSON.parse\\('([^\n\r]+)'\\);");
                });

                if (string.IsNullOrEmpty(json))
                    return default;

                try
                {
                    var root = JsonConvert.DeserializeObject<JObject>(json);
                    if (root == null || !root.ContainsKey("all"))
                        return default;

                    cache = (root["all"], root["active"]);

                    hybridCache.Set(memKey, cache, cacheTime(40));
                }
                catch { return default; }
            }

            return cache;
        }
        #endregion

        #region goMovie
        async Task<(StreamQualityTpl streams, string wsUri)> goMovie(string uri, long id_file)
        {
            try
            {
                string wsUri = null;
                var streamquality = new StreamQualityTpl();

                using (var browser = new PlaywrightBrowser())
                {
                    var page = await browser.NewPageAsync(init.plugin, proxy: proxy_data).ConfigureAwait(false);
                    if (page == null)
                        return default;

                    await page.RouteAsync("**/*", async route =>
                    {
                        try
                        {
                            if (route.Request.Url.Contains("kinogo-go.tv"))
                            {
                                await route.FulfillAsync(new RouteFulfillOptions
                                {
                                    Body = PlaywrightBase.IframeHtml(uri)
                                });
                            }
                            else if (route.Request.Method == "POST" && route.Request.Url.Contains("/movies/"))
                            {
                                string newUrl = Regex.Replace(route.Request.Url, "/[0-9]+$", $"/{id_file}");

                                var fetchHeaders = route.Request.Headers;
                                fetchHeaders.TryAdd("Accept-Encoding", "gzip, deflate, br, zstd");
                                fetchHeaders.TryAdd("Cache-Control", "no-cache");
                                fetchHeaders.TryAdd("DNT", "1");
                                fetchHeaders.TryAdd("Pragma", "no-cache");
                                fetchHeaders.TryAdd("Priority", "u=1, i");
                                fetchHeaders.TryAdd("Sec-Fetch-Dest", "empty");
                                fetchHeaders.TryAdd("Sec-Fetch-Mode", "cors");
                                fetchHeaders.TryAdd("Sec-Fetch-Site", "same-origin");
                                fetchHeaders.TryAdd("Sec-Fetch-Storage-access", "active");

                                var fetchResponse = await route.FetchAsync(new RouteFetchOptions
                                {
                                    Url = newUrl,
                                    Method = "POST",
                                    Headers = fetchHeaders,
                                    PostData = route.Request.PostDataBuffer
                                }).ConfigureAwait(false);

                                string json = await fetchResponse.TextAsync().ConfigureAwait(false);
                                var jo = JsonConvert.DeserializeObject<JObject>(json);

                                if (jo == null || jo["hlsSource"] == null)
                                {
                                    await route.FulfillAsync(new RouteFulfillOptions
                                    {
                                        Status = fetchResponse.Status,
                                        Body = json,
                                        Headers = fetchResponse.Headers
                                    }).ConfigureAwait(false);
                                    return;
                                }

                                var reqHeaders = route.Request.Headers;
                                reqHeaders.TryGetValue("referer", out requestReferer);
                                reqHeaders.TryGetValue("origin", out requestOrigin);

                                wsUri = jo.Value<string>("pnr") + $"?sid={jo.Value<string>("pnk")}&v=2.1&t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";

                                var selectedItem =
                                    jo["hlsSource"]
                                        .Children<JObject>()
                                        .FirstOrDefault(x => (bool?)x["default"] == true)
                                    ??
                                    jo["hlsSource"]
                                        .FirstOrDefault() as JObject;

                                if (selectedItem != null)
                                {
                                    foreach (var q in selectedItem["quality"].Children<JProperty>())
                                    {
                                        if (!init.m4s && (q.Name == "2160" || q.Name == "1440"))
                                            continue;

                                        string link = (string)q.Value;
                                        if (string.IsNullOrWhiteSpace(link))
                                            continue;

                                        if (string.IsNullOrEmpty(resolution))
                                            resolution = q.Name;

                                        link = link
                                            .Split(new[] { " or " }, StringSplitOptions.RemoveEmptyEntries)
                                            .FirstOrDefault()
                                            ?.Trim();

                                        if (string.IsNullOrWhiteSpace(link))
                                            continue;

                                        // SSRF gate on the stream link before we
                                        // advertise it to the client — it eventually
                                        // feeds HostStreamProxy / EventListener hook.
                                        if (!SsrfGuard.IsAllowedPublicUriBasic(link))
                                            continue;

                                        streamquality.Append(HostStreamProxy(link), $"{q.Name}p");
                                    }
                                }

                                browser.SetPageResult(null);

                                await route.FulfillAsync(new RouteFulfillOptions
                                {
                                    Status = fetchResponse.Status,
                                    Body = json,
                                    Headers = fetchResponse.Headers
                                }).ConfigureAwait(false);
                            }
                            else
                            {
                                if (browser.IsCompleted ||
                                    route.Request.Url.Contains("/stat") ||
                                    route.Request.Url.Contains("/lists.php") ||
                                    route.Request.Url.EndsWith(".cekh8i") ||
                                    route.Request.Url.EndsWith(".css") ||
                                    route.Request.Url.EndsWith(".svg") ||
                                    route.Request.Url.EndsWith("blank.mp4"))
                                {
                                    await route.AbortAsync();
                                    return;
                                }

                                await route.ContinueAsync();
                            }
                        }
                        catch { }
                    });

                    PlaywrightBase.GotoAsync(page, "https://kinogo-go.tv/");

                    await browser.WaitPageResult(15);
                }

                return (streamquality, wsUri);
            }
            catch
            {
                return default;
            }
        }
        #endregion

        #region WebSocket
        static bool IsAllowedWebSocketUri(string uri)
        {
            if (string.IsNullOrWhiteSpace(uri))
                return false;

            if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri parsed))
                return false;

            // Map ws://host -> http://host / wss://host -> https://host and reuse
            // SsrfGuard's IP-literal + scheme rejection. DNS resolution happens
            // just-in-time during connect; this is the primary fail-closed guard
            // against RFC1918 / loopback targets fed through the `pnr` JSON field.
            string scheme = parsed.Scheme;
            if (scheme != "ws" && scheme != "wss")
                return false;

            var builder = new UriBuilder(parsed) { Scheme = scheme == "wss" ? "https" : "http" };
            return SsrfGuard.IsAllowedPublicUriBasic(builder.Uri.ToString());
        }

        void StartWebSocket(string wsUri)
        {
            lock (wsLock)
            {
                try
                {
                    if (ws != null)
                        return;

                    ws = new ClientWebSocket();
                    ws.Options.SetRequestHeader("User-Agent", Http.UserAgent);

                    wscts = new CancellationTokenSource();
                }
                catch { ClearConnect(); return; }
            }

            _ = Task.Run(async () =>
            {
                try
                {
                    await ws.ConnectAsync(new Uri(wsUri), wscts.Token);

                    var receiveBuffer = new byte[16 * 1024];

                    _ = Task.Factory.StartNew(async () =>
                    {
                        try
                        {
                            while (!wscts.Token.IsCancellationRequested && ws.State == WebSocketState.Open)
                            {
                                var result = await ws.ReceiveAsync(new ArraySegment<byte>(receiveBuffer), wscts.Token);
                                if (wscts.Token.IsCancellationRequested)
                                    return;

                                if (result.MessageType == WebSocketMessageType.Close)
                                {
                                    ClearConnect();
                                    break;
                                }

                                string message = Encoding.UTF8.GetString(receiveBuffer, 0, result.Count);

                                string hash = Regex.Match(message ?? string.Empty, "\"edge_hash\":\"([^\"]+)\"").Groups[1].Value;
                                if (!string.IsNullOrEmpty(hash))
                                    edge_hash = hash;
                            }
                        }
                        catch { }
                    }, wscts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

                    _ = Task.Factory.StartNew(async () =>
                    {
                        while (!wscts.Token.IsCancellationRequested && ws.State == WebSocketState.Open)
                        {
                            try
                            {
                                await Task.Delay(TimeSpan.FromSeconds(30), wscts.Token);
                                if (wscts.Token.IsCancellationRequested)
                                    return;

                                await WsSendAsync("playing");
                            }
                            catch { }
                        }
                    }, wscts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

                    long unixtime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    await WsSendAsync("playback_start", unixtime);
                    await WsSendAsync("init", unixtime);
                }
                catch
                {
                    ClearConnect();
                }
            });
        }

        static Task WsSendAsync(string type, long unixtime = 0)
        {
            if (ws == null || ws.State != WebSocketState.Open)
                return Task.CompletedTask;

            if (unixtime == 0)
                unixtime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            string payload = JsonConvert.SerializeObject(new
            {
                type,
                current_time,
                resolution,
                track_id = "1",
                speed = 1,
                subtitle = -1,
                ts = unixtime
            });

            try
            {
                return ws.SendAsync(
                  new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
                  WebSocketMessageType.Text,
                  true,
                  wscts?.Token ?? CancellationToken.None
                );
            }
            catch
            {
                return Task.CompletedTask;
            }
        }
        #endregion

        #region ClearConnect
        static void ClearConnect()
        {
            lock (wsLock)
            {
                edge_hash = null;
                resolution = null;
                current_time = 0;
                last_time = 0;
                lastreq = DateTime.Now;

                try
                {
                    wscts?.Cancel();
                }
                catch { }

                try
                {
                    if (ws != null)
                        _ = ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
                }
                catch { }

                ws = null;
                wscts = null;
            }
        }
        #endregion
    }
}
