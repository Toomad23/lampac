using Microsoft.AspNetCore.Mvc;
using Shared.Engine.RxEnumerate;
using Shared.Engine.Utilities;
using Shared.Models.Online.Settings;

namespace Online.Controllers
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/LeProduction).
    //
    // LeProduction is a simple HTTP balancer (no Playwright) backed by le-production.tv.
    // Flow:
    //   1. GET /index.php?do=search&story=...   -> scrape anchor tags <a href="film/...">
    //   2. GET /{href}                          -> extract iframe src (id="omfg" or /playlist_iframe/...)
    //   3. GET {iframe}                         -> extract `file: [...]` JSON-ish block
    //   4. Regex out [1080p]https://... and render a MovieTpl with all qualities
    //
    // Adaptation notes vs. upstream:
    //   * Upstream used [Staticache] — we do not have that attribute, so we rely on
    //     InvokeCacheResult for search caching (4h) and view caching (20 multiaccess),
    //     matching the semantics Staticache would have provided.
    //   * Upstream used OnlinesSettings directly; we reuse it as our BaseOnlineController<T>
    //     default already accepts it.
    //   * Stream URLs scraped from the iframe are proxied through HostStreamProxy, so
    //     SSRF protection applies automatically when streamproxy is enabled.
    public class LeProduction : BaseOnlineController
    {
        public LeProduction() : base(AppInit.conf.LeProduction) { }

        [HttpGet]
        [Route("lite/leproduction")]
        async public Task<ActionResult> Index(string title, string original_title, int clarification, int serial = 0, string href = null)
        {
            if (serial == 1)
                return OnError();

            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            rhubFallback:

            #region search
            if (string.IsNullOrEmpty(href))
            {
                string searchTitle = clarification == 1 ? title : (original_title ?? title);
                if (string.IsNullOrWhiteSpace(searchTitle))
                    return OnError();

                var search = await InvokeCacheResult<(string href, SimilarTpl similar)>($"leproduction:search:{searchTitle}", TimeSpan.FromHours(4), async e =>
                {
                    string newsHref = null;
                    var similar = new SimilarTpl();

                    string searchUrl = $"{init.host}/index.php?do=search&subaction=search&search_start=0&full_search=0&result_from=1&story={HttpUtility.UrlEncode(searchTitle)}";
                    await httpHydra.GetSpan(searchUrl, spanAction: html =>
                    {
                        string stitle = StringConvert.SearchName(title);
                        string soriginal = StringConvert.SearchName(original_title);

                        var rx = Rx.Matches("<a\\s+href=\"https?://[^/]+/(film/[0-9]+-[^\"]+\\.html)\"[^>]*>([^<]+)</a>", html, options: RegexOptions.IgnoreCase);

                        foreach (var row in rx.Rows())
                        {
                            var g = row.Groups();
                            string itemHref = g[1].Value;
                            string itemTitle = Regex.Replace(g[2].Value, "<[^>]*>", string.Empty).Trim();

                            if (string.IsNullOrWhiteSpace(itemHref) || string.IsNullOrWhiteSpace(itemTitle))
                                continue;

                            similar.Append(itemTitle, string.Empty, string.Empty, itemHref, string.Empty);

                            string normalized = StringConvert.SearchName(itemTitle);
                            if (newsHref == null && !string.IsNullOrWhiteSpace(stitle) && normalized.Contains(stitle))
                                newsHref = itemHref;
                            else if (newsHref == null && !string.IsNullOrWhiteSpace(soriginal) && normalized.Contains(soriginal))
                                newsHref = itemHref;
                        }
                    });

                    if (newsHref == null && similar.Length > 0)
                        return e.Success((null, similar));

                    if (string.IsNullOrWhiteSpace(newsHref))
                        return e.Fail("search", refresh_proxy: true);

                    return e.Success((newsHref, similar));
                });

                if (!search.IsSuccess)
                {
                    if (IsRhubFallback(search))
                        goto rhubFallback;

                    return OnError(search.ErrorMsg);
                }

                if (search.Value.href == null)
                    return await ContentTpl(search.Value.similar);

                href = search.Value.href;
            }
            #endregion

            // Why: href is scraped from le-production's own search page but we still route it
            // back as {init.host}/{href}. Guard against a hostile response smuggling a full URL
            // that resolves to an internal address (RFC1918 / metadata) when combined with
            // init.host reassignment in kit overrides. A conservative allowlist check keeps
            // this fail-closed without breaking legitimate film/NNN-...html slugs.
            if (href.Contains("://") && !SsrfGuard.IsAllowedPublicUriBasic(href))
                return OnError();

            var cache = await InvokeCacheResult<string>($"leproduction:view:{href}", 20, async e =>
            {
                string iframe = null;

                string pageUri = href.Contains("://") ? href : $"{init.host}/{href}";
                await httpHydra.GetSpan(pageUri, spanAction: html =>
                {
                    iframe = Rx.Match(html, "<iframe[^>]+id=\"omfg\"[^>]+src=\"([^\"]+)\"");
                    if (string.IsNullOrWhiteSpace(iframe))
                        iframe = Rx.Match(html, "<iframe[^>]+src=\"(https?://[^/]+/playlist_iframe/[0-9]+/?[^\"]*)\"");
                });

                if (string.IsNullOrWhiteSpace(iframe))
                    return e.Fail("iframe", refresh_proxy: true);

                // Why: the iframe src comes from scraped HTML; reject non-public destinations
                // before we dereference it with our credentials/proxy.
                if (!SsrfGuard.IsAllowedPublicUriBasic(iframe))
                    return e.Fail("iframe-ssrf");

                string fileBlock = null;

                await httpHydra.GetSpan(iframe, addheaders: HeadersModel.Init("referer", pageUri), spanAction: html =>
                {
                    fileBlock = Rx.Match(html, "file\\s*:\\s*(\\[[\\s\\S]*?\\])\\s*,\\s*embed\\s*:");
                });

                if (string.IsNullOrWhiteSpace(fileBlock))
                    return e.Fail("fileBlock", refresh_proxy: true);

                return e.Success(fileBlock);
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            return await ContentTpl(cache, () =>
            {
                var mtpl = new MovieTpl(title, original_title, 1);
                var streamQuality = new StreamQualityTpl();

                foreach (Match m in Regex.Matches(cache.Value, "\\[([0-9]+p)\\](https?://[^,\\[\"\t\n ]+)", RegexOptions.IgnoreCase))
                {
                    string link = m.Groups[2].Value;
                    // Why: streams are scraped; final SSRF check before embedding into the player.
                    if (!SsrfGuard.IsAllowedPublicUriBasic(link))
                        continue;

                    streamQuality.Append(HostStreamProxy(link), m.Groups[1].Value);
                }

                if (!streamQuality.Any())
                    return null;

                var first = streamQuality.Firts();
                mtpl.Append("По умолчанию", first.link, quality: first.quality, streamquality: streamQuality, vast: init.vast);
                return mtpl;
            });
        }
    }
}
