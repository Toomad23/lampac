using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared.Engine.RxEnumerate;

namespace Online.Controllers
{
    // Ported from lampac-nextgen Modules/OnlineAnime/Dreamerscast.
    // Source site: https://dreamerscast.com (Ukrainian anime aggregator).
    // Flow: POST search -> GET release page -> parse Playerjs base64 blob ->
    // extract HLS URLs.
    //
    // Security: the `uri` parameter is user-supplied and is joined to
    // init.host before a server-side GET. We therefore reject any uri whose
    // absolute form resolves to a host other than init.host (prevents SSRF
    // via an attacker-controlled full URL in the `uri` slot). The extracted
    // HLS URL can also originate from an untrusted upstream (CDN-controlled),
    // so the episode loop runs SsrfGuard.IsAllowedPublicUriBasic before the
    // URL is echoed to the client.
    public class Dreamerscast : BaseOnlineController
    {
        public Dreamerscast() : base(AppInit.conf.Dreamerscast) { }

        // Resolves a caller-supplied `uri` against init.host and returns the
        // absolute URL iff the resulting host matches the configured site.
        // Returns null when the input is missing, malformed, or escapes to a
        // different host.
        string ResolveReleaseUri(string uri)
        {
            if (string.IsNullOrWhiteSpace(uri) || string.IsNullOrEmpty(init?.host))
                return null;

            if (!Uri.TryCreate(init.host, UriKind.Absolute, out Uri baseUri))
                return null;

            Uri resolved;
            try
            {
                resolved = new Uri(baseUri, uri);
            }
            catch
            {
                return null;
            }

            if (resolved.Scheme != Uri.UriSchemeHttp && resolved.Scheme != Uri.UriSchemeHttps)
                return null;

            // Lock the resolved host to the configured site; .Host match is
            // case-insensitive by Uri semantics already.
            if (!resolved.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase))
                return null;

            return resolved.ToString();
        }

        [HttpGet]
        [Route("lite/dreamerscast")]
        async public Task<ActionResult> Index(string title, int year, string uri, int s = 1, bool rjson = false, bool similar = false)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            if (string.IsNullOrWhiteSpace(uri))
            {
                if (string.IsNullOrWhiteSpace(title))
                    return OnError();

                #region Поиск
                rhubFallbackSearch:
                var cache = await InvokeCacheResult<List<(string title, int year, string uri, string s, string img)>>($"dreamerscast:search:{title}", 40, async e =>
                {
                    var search = await httpHydra.Post<JObject>(
                        $"{init.corsHost()}/",
                        $"search={HttpUtility.UrlEncode(title)}&status=&pageSize=16&pageNumber=1",
                        addheaders: HeadersModel.Init(
                            ("x-requested-with", "XMLHttpRequest"),
                            ("referer", init.host + "/")
                        ));

                    var releases = search?["releases"] as JArray;
                    if (releases == null)
                        return e.Fail("search", refresh_proxy: true);

                    var catalog = new List<(string title, int year, string uri, string s, string img)>();

                    foreach (var item in releases)
                    {
                        string img = item.Value<string>("image");

                        if (!string.IsNullOrEmpty(img) && img.StartsWith("//"))
                            img = "https:" + img;
                        else if (!string.IsNullOrEmpty(img) && img.StartsWith("/"))
                            img = init.host + img;

                        string original = item.Value<string>("original") ?? string.Empty;
                        string animeSeason = Regex.Match(original, " ([0-9]+)nd ").Groups[1].Value;
                        if (string.IsNullOrWhiteSpace(animeSeason))
                            animeSeason = "1";

                        catalog.Add((
                            item.Value<string>("russian") ?? original,
                            item.Value<int?>("dateissue") ?? 0,
                            item.Value<string>("url"),
                            animeSeason,
                            img
                        ));
                    }

                    if (catalog.Count == 0)
                        return e.Fail("catalog");

                    return e.Success(catalog);
                });

                if (IsRhubFallback(cache))
                    goto rhubFallbackSearch;

                if (!cache.IsSuccess)
                    return OnError(cache.ErrorMsg);

                if (!similar && cache.Value.Count == 1)
                    return LocalRedirect(accsArgs($"/lite/dreamerscast?rjson={rjson}&title={HttpUtility.UrlEncode(title)}&uri={HttpUtility.UrlEncode(cache.Value[0].uri)}&s={cache.Value[0].s}"));

                return await ContentTpl(cache, () =>
                {
                    var stpl = new SimilarTpl(cache.Value.Count);

                    foreach (var res in cache.Value)
                    {
                        string link = $"{host}/lite/dreamerscast?title={HttpUtility.UrlEncode(title)}&uri={HttpUtility.UrlEncode(res.uri)}&s={res.s}";
                        stpl.Append(res.title, res.year.ToString(), string.Empty, link, PosterApi.Size(res.img));
                    }

                    return stpl;
                });
                #endregion
            }
            else
            {
                // Why: `uri` is user-controlled; join it to init.host and refuse the
                // request if the resolved host escapes the configured site. Without
                // this, an attacker could pass a full URL like
                // http://169.254.169.254/... and exfiltrate cloud metadata via the
                // server-side GET below.
                string releaseUri = ResolveReleaseUri(uri);
                if (releaseUri == null)
                    return OnError();

                #region Серии
                rhubFallbackRelease:
                var cache = await InvokeCacheResult<List<(string name, string episode, string hls)>>($"dreamerscast:release:{releaseUri}", 20, async e =>
                {
                    var episodes = new List<(string name, string episode, string hls)>();

                    await httpHydra.GetSpan(releaseUri, html =>
                    {
                        // Why: upstream embeds the player payload between
                        // Playerjs("#2...","); — extract the middle slice so we can
                        // base64-decode it. Use Regex.Match since Rx.Slice is not
                        // available in this branch.
                        string base64 = Rx.Match(html, "Playerjs\\(\"#2([^\"]+)\"\\);");
                        if (string.IsNullOrEmpty(base64))
                            return;

                        string json = CrypTo.DecodeBase64(Regex.Replace(base64, "//[^=]+==", ""));
                        if (string.IsNullOrEmpty(json))
                            return;

                        try
                        {
                            var root = JsonConvert.DeserializeObject<JObject>(json);
                            var files = root?["file"] as JArray;
                            if (files == null)
                                return;

                            foreach (var item in files)
                            {
                                string fileField = item.Value<string>("file");
                                string hls = GetHls(fileField);
                                if (hls == null)
                                    continue;

                                string nm = item.Value<string>("title");

                                episodes.Add((
                                    nm,
                                    Regex.Match(nm ?? string.Empty, "([0-9]+)").Groups[1].Value,
                                    hls
                                ));
                            }
                        }
                        catch { }
                    });

                    if (episodes.Count == 0)
                        return e.Fail("episodes", refresh_proxy: true);

                    return e.Success(episodes);
                });

                if (IsRhubFallback(cache))
                    goto rhubFallbackRelease;

                if (!cache.IsSuccess)
                    return OnError(cache.ErrorMsg);

                return await ContentTpl(cache, () =>
                {
                    string season = s.ToString();
                    var etpl = new EpisodeTpl(cache.Value.Count);

                    foreach (var item in cache.Value)
                    {
                        // Why: hls originated from an upstream base64 blob. Reject any
                        // URL that is not a public http(s) endpoint before echoing it
                        // to the client / HostStreamProxy.
                        if (!Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriBasic(item.hls))
                            continue;

                        string ep = string.IsNullOrWhiteSpace(item.episode) ? "1" : item.episode;
                        string nm = string.IsNullOrWhiteSpace(item.name) ? $"{ep} серия" : item.name;

                        etpl.Append(nm, title, season, ep, HostStreamProxy(item.hls), vast: init.vast);
                    }

                    return etpl;
                });
                #endregion
            }
        }

        static string GetHls(string file)
        {
            if (string.IsNullOrEmpty(file))
                return null;

            foreach (Match match in Regex.Matches(file, "https?://[^\\s]+"))
            {
                string url = match.Value;
                if (url.Contains("/hls/"))
                    return url.Trim().TrimEnd(',', ';');
            }

            return null;
        }
    }
}
