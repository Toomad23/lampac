using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace Online.Controllers
{
    // Ported from lampac-nextgen Modules/OnlineAnime/AnimeON.
    // Source site: https://animeon.club (Ukrainian anime aggregator).
    // Flow: JSON search -> translations -> episodes. Stream URL (fileUrl) is
    // served directly from the upstream API response, so we only SSRF-guard
    // the URL before calling HostStreamProxy which already does egress checks
    // but we belt-and-brace here because the upstream may return an arbitrary
    // host (ashdi.vip etc.) that we do not control.
    public class AnimeON : BaseOnlineController
    {
        public AnimeON() : base(AppInit.conf.AnimeON) { }

        [HttpGet]
        [Route("lite/animeon")]
        async public Task<ActionResult> Index(string imdb_id, string title, string original_title, int year, int t = -1, int s = -1, int animeid = 0, bool rjson = false)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            if (animeid == 0 && string.IsNullOrWhiteSpace(title))
                return OnError();

            string enc_title = HttpUtility.UrlEncode(title);
            string enc_original_title = HttpUtility.UrlEncode(original_title);

            if (animeid == 0)
            {
                #region Поиск
                rhubFallbackSearch:
                var search = await InvokeCacheResult<List<(int id, int season, string imdbId, string title, string year, string poster)>>($"animeon:search:{title}", 40, async e =>
                {
                    var root = await httpHydra.Get<JObject>($"{init.corsHost()}/api/anime/search?text={HttpUtility.UrlEncode(title)}");
                    if (root == null)
                        return e.Fail("search", refresh_proxy: true);

                    var result = root["result"] as JArray;
                    if (result == null || result.Count == 0)
                        return e.Fail("result");

                    var catalog = new List<(int id, int season, string imdbId, string title, string year, string poster)>(result.Count);

                    foreach (var node in result)
                    {
                        int id = node.Value<int?>("id") ?? 0;
                        if (id == 0)
                            continue;

                        string itemTitle = node.Value<string>("titleUa") ?? node.Value<string>("titleEn");
                        if (string.IsNullOrWhiteSpace(itemTitle))
                            continue;

                        catalog.Add((
                            id,
                            node.Value<int?>("season") ?? 0,
                            node.Value<string>("imdbId"),
                            itemTitle,
                            node.Value<string>("releaseDate"),
                            node["image"]?.Value<string>("preview")
                        ));
                    }

                    if (catalog.Count == 0)
                        return e.Fail("catalog");

                    return e.Success(catalog);
                });

                if (IsRhubFallback(search))
                    goto rhubFallbackSearch;

                if (!search.IsSuccess)
                    return OnError(search.ErrorMsg);

                if (search.Value.Count == 1 && !string.IsNullOrWhiteSpace(imdb_id) && string.Equals(search.Value[0].imdbId, imdb_id, StringComparison.OrdinalIgnoreCase))
                    return LocalRedirect(accsArgs($"/lite/animeon?rjson={rjson}&s={search.Value[0].season}&imdb_id={HttpUtility.UrlEncode(imdb_id)}&title={enc_title}&original_title={enc_original_title}&year={year}&animeid={search.Value[0].id}"));

                var stpl = new SimilarTpl(search.Value.Count);

                foreach (var item in search.Value)
                {
                    string link = $"{host}/lite/animeon?rjson={rjson}&s={item.season}&imdb_id={HttpUtility.UrlEncode(imdb_id)}&title={enc_title}&original_title={enc_original_title}&year={year}&animeid={item.id}";
                    string poster = string.IsNullOrEmpty(item.poster) ? null : PosterApi.Size($"{init.host}/api/uploads/images/{item.poster}");
                    stpl.Append(item.title, item.year, string.Empty, link, poster);
                }

                return await ContentTpl(stpl);
                #endregion
            }

            #region Translations
            rhubFallbackTranslations:
            var translations = await InvokeCacheResult<List<(int translationId, int playerId, string title)>>($"animeon:translations:{animeid}", 20, async e =>
            {
                var root = await httpHydra.Get<JObject>($"{init.corsHost()}/api/player/{animeid}/translations");
                var items = root?["translations"] as JArray;
                if (items == null || items.Count == 0)
                    return e.Fail("translations");

                var list = new List<(int translationId, int playerId, string title)>();

                foreach (var node in items)
                {
                    int translationId = node["translation"]?.Value<int?>("id") ?? 0;
                    if (translationId == 0)
                        continue;

                    int playerId = 0;
                    var players = node["player"] as JArray;
                    if (players != null)
                    {
                        foreach (var p in players)
                        {
                            if (string.Equals(p.Value<string>("name"), "Ashdi", StringComparison.OrdinalIgnoreCase))
                            {
                                playerId = p.Value<int?>("id") ?? 0;
                                break;
                            }
                        }
                    }

                    if (playerId == 0)
                        continue;

                    string voiceTitle = node["translation"]?.Value<string>("name") ?? "Ashdi";
                    list.Add((translationId, playerId, voiceTitle));
                }

                if (list.Count == 0)
                    return e.Fail("ashdi translations");

                return e.Success(list);
            });

            if (IsRhubFallback(translations))
                goto rhubFallbackTranslations;

            if (!translations.IsSuccess)
                return OnError(translations.ErrorMsg);

            if (t < 0 || t >= translations.Value.Count)
                t = 0;

            var currentTranslation = translations.Value[t];
            #endregion

            #region Episodes
            rhubFallbackEpisodes:
            var episodes = await InvokeCacheResult<List<(int episode, string title, string fileUrl)>>($"animeon:episodes:{animeid}:{currentTranslation.playerId}:{currentTranslation.translationId}", 20, async e =>
            {
                var root = await httpHydra.Get<JObject>($"{init.corsHost()}/api/player/{animeid}/episodes?take=100&skip=-1&playerId={currentTranslation.playerId}&translationId={currentTranslation.translationId}");
                var items = root?["episodes"] as JArray;
                if (items == null || items.Count == 0)
                    return e.Fail("episodes");

                var list = new List<(int episode, string title, string fileUrl)>();

                foreach (var node in items)
                {
                    string file = node.Value<string>("fileUrl");
                    if (string.IsNullOrWhiteSpace(file))
                        continue;

                    int episode = node.Value<int?>("episode") ?? 0;
                    string epTitle = episode > 0 ? $"{episode} серия" : "Серия";

                    list.Add((episode, epTitle, file));
                }

                if (list.Count == 0)
                    return e.Fail("episode list");

                return e.Success(list);
            });

            if (IsRhubFallback(episodes))
                goto rhubFallbackEpisodes;

            if (!episodes.IsSuccess)
                return OnError(episodes.ErrorMsg);
            #endregion

            var vtpl = new VoiceTpl(translations.Value.Count);
            for (int i = 0; i < translations.Value.Count; i++)
            {
                var voice = translations.Value[i];
                string link = $"{host}/lite/animeon?rjson={rjson}&imdb_id={HttpUtility.UrlEncode(imdb_id)}&title={enc_title}&original_title={enc_original_title}&year={year}&animeid={animeid}&s={s}&t={i}";
                vtpl.Append(voice.title, i == t, link);
            }

            var etpl = new EpisodeTpl(vtpl, episodes.Value.Count);
            string sArch = s.ToString();

            for (int i = 0; i < episodes.Value.Count; i++)
            {
                var item = episodes.Value[i];

                // Why: fileUrl comes from an upstream JSON we do not own. Reject any URL
                // that is not a publicly routable http(s) endpoint before we echo it into
                // the response / hand it to HostStreamProxy. This protects against crafted
                // or compromised upstream responses that point at RFC1918 / loopback.
                if (!Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriBasic(item.fileUrl))
                    continue;

                string stream = HostStreamProxy(item.fileUrl);
                string epNum = item.episode > 0 ? item.episode.ToString() : (i + 1).ToString();

                etpl.Append(item.title, title ?? original_title, sArch, epNum, stream, vast: init.vast);
            }

            return await ContentTpl(etpl);
        }
    }
}
