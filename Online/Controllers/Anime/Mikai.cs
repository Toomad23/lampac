using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using Shared.Engine.RxEnumerate;

namespace Online.Controllers
{
    // Ported from lampac-nextgen Modules/OnlineAnime/Mikai.
    // Source site: https://api.mikai.me (Ukrainian anime aggregator, Ashdi-backed).
    // Flow: JSON search -> JSON anime details with players -> Ashdi embed URLs.
    //
    // Security: playLink values come from an upstream API (mikai.me) and point
    // at Ashdi embed pages. Our Video endpoint fetches those embeds server-side
    // to extract the HLS manifest, so we run SsrfGuard.IsAllowedPublicUriAsync
    // on the URL (DNS-aware check that refuses RFC1918/loopback/link-local/
    // metadata) before any request is made. We also restrict the allowed host
    // to known Ashdi variants (ashdi.*), so a compromised upstream cannot
    // redirect us to arbitrary third-party sites.
    public class Mikai : BaseOnlineController
    {
        public Mikai() : base(AppInit.conf.Mikai) { }

        // Only allow ashdi.* hostnames. The nextgen Mikai relied on a shared
        // /lite/ashdi/vod.m3u8 endpoint that is not present in this fork, so
        // we inline the iframe fetch here and pin the host.
        static bool IsAllowedAshdiHost(string host)
        {
            if (string.IsNullOrEmpty(host))
                return false;

            // Case-insensitive match on "ashdi.<tld>" (letters/digits/dot/dash).
            return Regex.IsMatch(host, "^ashdi\\.[A-Za-z0-9.-]+$", RegexOptions.IgnoreCase);
        }

        [HttpGet]
        [Route("lite/mikai")]
        async public Task<ActionResult> Index(string title, string original_title, int year, int animeid = 0, int t = -1, bool rjson = false)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            string enc_title = HttpUtility.UrlEncode(title);
            string enc_original_title = HttpUtility.UrlEncode(original_title);

            if (animeid == 0)
            {
                #region Поиск
                if (string.IsNullOrWhiteSpace(title))
                    return OnError();

                rhubFallbackSearch:
                var search = await InvokeCacheResult<List<(int id, string title, string year, string poster)>>($"mikai:search:{title}", 40, async e =>
                {
                    var root = await httpHydra.Get<JObject>($"{init.corsHost()}/v1/anime/search?page=1&limit=24&sort=year&order=desc&name={HttpUtility.UrlEncode(title)}");
                    var items = root?["result"] as JArray;
                    if (items == null || items.Count == 0)
                        return e.Fail("search", refresh_proxy: true);

                    var list = new List<(int id, string title, string year, string poster)>();

                    foreach (var item in items)
                    {
                        int id = item.Value<int?>("id") ?? 0;
                        if (id == 0)
                            continue;

                        var names = item["details"]?["names"];
                        string itemTitle = names?.Value<string>("name")
                            ?? names?.Value<string>("nameEnglish")
                            ?? names?.Value<string>("nameNative")
                            ?? item.Value<string>("slug");
                        if (string.IsNullOrWhiteSpace(itemTitle))
                            continue;

                        int yr = item.Value<int?>("year") ?? 0;
                        string posterUid = item["media"]?.Value<string>("posterUid");
                        string poster = string.IsNullOrWhiteSpace(posterUid)
                            ? string.Empty
                            : PosterApi.Size($"https://images.mikai.me/poster/small/{posterUid}.webp");

                        list.Add((id, itemTitle, yr > 0 ? yr.ToString() : string.Empty, poster));
                    }

                    if (list.Count == 0)
                        return e.Fail("catalog");

                    return e.Success(list);
                });

                if (IsRhubFallback(search))
                    goto rhubFallbackSearch;

                if (!search.IsSuccess)
                    return OnError(search.ErrorMsg);

                var stpl = new SimilarTpl(search.Value.Count);

                foreach (var item in search.Value)
                {
                    string link = $"{host}/lite/mikai?rjson={rjson}&title={enc_title}&original_title={enc_original_title}&year={year}&animeid={item.id}";
                    stpl.Append(item.title, item.year, string.Empty, link, item.poster);
                }

                return await ContentTpl(stpl);
                #endregion
            }

            #region Anime detail -> voices / episodes
            rhubFallbackAnime:
            var anime = await InvokeCacheResult<(string slug, string name, string nameNative, string nameEnglish, List<(string title, List<(int number, string playLink)> episodes)> voices)>($"mikai:anime:{animeid}", 20, async e =>
            {
                var root = await httpHydra.Get<JObject>($"{init.corsHost()}/v1/anime/{animeid}");
                var result = root?["result"];
                var players = result?["players"] as JArray;
                if (players == null || players.Count == 0)
                    return e.Fail("players", refresh_proxy: true);

                var names = result["details"]?["names"];
                var voicesList = new List<(string title, List<(int number, string playLink)> episodes)>();

                foreach (var player in players)
                {
                    var providers = player["providers"] as JArray;
                    if (providers == null)
                        continue;

                    JToken ashdi = null;
                    foreach (var p in providers)
                    {
                        if (string.Equals(p.Value<string>("name"), "ASHDI", StringComparison.OrdinalIgnoreCase))
                        {
                            ashdi = p;
                            break;
                        }
                    }

                    var eps = ashdi?["episodes"] as JArray;
                    if (eps == null || eps.Count == 0)
                        continue;

                    var episodes = new List<(int number, string playLink)>();
                    foreach (var ep in eps)
                    {
                        string playLink = ep.Value<string>("playLink");
                        if (string.IsNullOrWhiteSpace(playLink))
                            continue;

                        episodes.Add((ep.Value<int?>("number") ?? 0, playLink));
                    }

                    if (episodes.Count == 0)
                        continue;

                    string voiceTitle = player["team"]?.Value<string>("name");
                    if (string.IsNullOrWhiteSpace(voiceTitle))
                        voiceTitle = "ASHDI";

                    voicesList.Add((voiceTitle, episodes));
                }

                if (voicesList.Count == 0)
                    return e.Fail("ashdi providers");

                return e.Success((
                    result.Value<string>("slug"),
                    names?.Value<string>("name"),
                    names?.Value<string>("nameNative"),
                    names?.Value<string>("nameEnglish"),
                    voicesList
                ));
            });

            if (IsRhubFallback(anime))
                goto rhubFallbackAnime;

            if (!anime.IsSuccess)
                return OnError(anime.ErrorMsg);

            if (t < 0 || t >= anime.Value.voices.Count)
                t = 0;

            var currentVoice = anime.Value.voices[t];

            var vtpl = new VoiceTpl(anime.Value.voices.Count);
            for (int i = 0; i < anime.Value.voices.Count; i++)
            {
                string link = $"{host}/lite/mikai?rjson={rjson}&title={enc_title}&original_title={enc_original_title}&year={year}&animeid={animeid}&t={i}";
                vtpl.Append(anime.Value.voices[i].title, i == t, link);
            }

            var ordered = currentVoice.episodes.OrderBy(x => x.number).ToList();
            if (ordered.Count == 0)
                return OnError("episodes");

            string season = DetectSeason(anime.Value.slug, anime.Value.name, anime.Value.nameNative, anime.Value.nameEnglish);

            var etpl = new EpisodeTpl(vtpl, ordered.Count);

            for (int i = 0; i < ordered.Count; i++)
            {
                var item = ordered[i];

                if (!Uri.TryCreate(item.playLink, UriKind.Absolute, out Uri playUri) || !IsAllowedAshdiHost(playUri.Host))
                    continue;

                int episodeNum = item.number > 0 ? item.number : i + 1;
                string episodeTitle = $"{episodeNum} серия";
                string link = accsArgs($"{host}/lite/mikai/video?uri={HttpUtility.UrlEncode(item.playLink)}&title={HttpUtility.UrlEncode(title)}&original_title={HttpUtility.UrlEncode(original_title)}");

                etpl.Append(episodeTitle, title ?? original_title, season, episodeNum.ToString(), link, "call", streamlink: $"{link}&play=true", vast: init.vast);
            }

            return await ContentTpl(etpl);
            #endregion
        }

        #region Video
        [HttpGet]
        [Route("lite/mikai/video")]
        [Route("lite/mikai/video.m3u8")]
        async public ValueTask<ActionResult> Video(string uri, string title, string original_title, bool play)
        {
            if (await IsRequestBlocked(rch: true, rch_check: !play))
                return badInitMsg;

            if (string.IsNullOrEmpty(uri))
                return OnError();

            // Why: `uri` is user-supplied (we put it there, but the request is
            // still cache-scoped per user). Enforce an ashdi.* allow-list plus
            // SsrfGuard.IsAllowedPublicUriAsync — the latter does a DNS lookup
            // and refuses addresses that resolve to RFC1918/loopback/link-local/
            // metadata ranges, so an attacker cannot weaponise this endpoint
            // into a server-side probe of the LAN.
            if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri parsed))
                return OnError();

            if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
                return OnError();

            if (!IsAllowedAshdiHost(parsed.Host))
                return OnError();

            if (!await Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriAsync(uri))
                return OnError();

            rhubFallback:
            var cache = await InvokeCacheResult<string>($"mikai:video:{uri}", 20, async e =>
            {
                string hls = null;

                await httpHydra.GetSpan(uri, addheaders: HeadersModel.Init("referer", init.host), spanAction: iframe =>
                {
                    // Ashdi embeds wrap the HLS inside Playerjs/file:"..."
                    hls = Rx.Match(iframe, "file:([\t ]+)?\"(https?://[^\"]+\\.m3u8)\"", index: 2);
                });

                if (string.IsNullOrEmpty(hls))
                    return e.Fail("hls", refresh_proxy: true);

                // Reject a poisoned upstream iframe that points at private ranges.
                if (!Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriBasic(hls))
                    return e.Fail("hls");

                return e.Success(hls);
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            if (!cache.IsSuccess)
                return OnError(cache.ErrorMsg);

            string link = HostStreamProxy(cache.Value);

            if (play)
                return RedirectToPlay(link);

            return ContentTo(VideoTpl.ToJson("play", link, title ?? original_title, vast: init.vast));
        }
        #endregion

        static string DetectSeason(params string[] sources)
        {
            if (sources == null)
                return "1";

            foreach (var source in sources)
            {
                if (string.IsNullOrWhiteSpace(source))
                    continue;

                var match = Regex.Match(source, @"(?<!\d)(\d{1,2})\s*[- ]?(?:сезон|sezon|season)\b", RegexOptions.IgnoreCase);
                if (match.Success)
                    return match.Groups[1].Value;
            }

            return "1";
        }
    }
}
