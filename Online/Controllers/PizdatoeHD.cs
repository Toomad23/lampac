using Microsoft.AspNetCore.Mvc;
using Microsoft.Playwright;
using Shared.Engine.Online;
using Shared.Engine.Utilities;
using Shared.Models.Online.PizdatoeHD;
using Shared.Models.Online.Settings;
using Shared.PlaywrightCore;
using BrowserCookie = Microsoft.Playwright.Cookie;

namespace Online.Controllers
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/PizdatoeHD/Controller.cs).
    //
    // PizdatoeHD drives rezka.ag through Playwright. Flow:
    //   1. search: GET {host}/search/?do=search&subaction=search&q=... -> scrape .b-content__inline_item
    //   2. embed: GET {host}/{href}                                    -> extract translator/season HTML
    //   3. movie: either POST /get_cdn_series/ (response listener) or GET {host}/{voice} for links
    //   4. decode the base64-trashed streams list and render player JSON
    //
    // Adaptation notes vs. upstream:
    //   * nextgen's offline DB cache (data/PizdatoeDb.json) + CronParse is intentionally omitted.
    //     Live search covers the same lookups at a small latency cost and avoids a standing
    //     background job that would need its own Playwright budget.
    //   * init.host and init.cdn are operator-configured; both are SsrfGuard'd because a rogue
    //     value would otherwise let Playwright pivot into the internal network.
    //   * Playwright URL targets (search_uri, href page, voice page, AJAX endpoint) are all
    //     checked against SsrfGuard before GotoAsync — whitelist-only public destinations.
    //   * Stream/subtitle URLs extracted by PizdatoeHDInvoke are already SsrfGuard'd inside the
    //     engine; this controller adds defence-in-depth checks at the HTTP boundary.
    public class PizdatoeHD : BaseOnlineController<PizdatoeHDSettings>
    {
        PizdatoeHDInvoke oninvk;

        public PizdatoeHD() : base(AppInit.conf.PizdatoeHD)
        {
            requestInitializationAsync = () =>
            {
                // Why: init.cdn rewrites the stream URL host. It must be a public http(s) URL —
                // if an operator mis-configures it as 127.0.0.1 we would happily stream from
                // loopback. Drop the rewrite (fail-open to the real origin URL) if cdn is unsafe.
                string cdn = init.cdn;
                if (!string.IsNullOrWhiteSpace(cdn) && !SsrfGuard.IsAllowedPublicUriBasic(cdn))
                    cdn = null;

                oninvk = new PizdatoeHDInvoke
                (
                    host,
                    "lite/pizdatoehd",
                    init,
                    streamfile =>
                    {
                        if (!string.IsNullOrEmpty(cdn) && !streamfile.Contains(".vtt"))
                            return HostStreamProxy(Regex.Replace(streamfile, "https?://[^/]+", cdn));

                        return HostStreamProxy(streamfile);
                    }
                );

                return ValueTask.CompletedTask;
            };
        }

        [HttpGet]
        [Route("lite/pizdatoehd")]
        async public Task<ActionResult> Index(string imdb_id, long kinopoisk_id, string title, string original_title, int clarification, int year, string href, string t, int s = -1, bool rjson = false, bool similar = false)
        {
            if (PlaywrightBrowser.Status == PlaywrightStatus.disabled && !(init.rhub || init.priorityBrowser == "http"))
                return OnError();

            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            if (string.IsNullOrWhiteSpace(href) && string.IsNullOrWhiteSpace(title))
                return OnError();

            // Why: init.host is operator-configured. A bad value would otherwise turn into a
            // Playwright navigation to an internal host. Reject early fail-closed.
            if (string.IsNullOrWhiteSpace(init.host) || !SsrfGuard.IsAllowedPublicUriBasic(init.host))
                return OnError();

            using (var browser = new PlaywrightBrowser(init.priorityBrowser))
            {
                IPage page = null;

                #region search
                if (string.IsNullOrEmpty(href))
                {
                    var search = await InvokeCacheResult<PizdatoeSearchModel>($"pizdatoehd:search:{title}:{original_title}:{clarification}:{year}", TimeSpan.FromHours(4), async e =>
                    {
                        try
                        {
                            string q = HttpUtility.UrlEncode(clarification == 1 ? title : (original_title ?? title));
                            string search_uri = $"{init.host}/search/?do=search&subaction=search&q={q}";

                            // Defence-in-depth: re-check that the composed URL is still public.
                            if (!SsrfGuard.IsAllowedPublicUriBasic(search_uri))
                                return e.Fail("search-ssrf");

                            page = await browser.NewPageAsync(init.plugin, init.headers, proxy: proxy_data, imitationHuman: init.imitationHuman).ConfigureAwait(false);
                            if (page == null)
                                return e.Fail("page");

                            await AdsBlockRouteAsync(page);

                            var result = await page.GotoAsync(search_uri, new PageGotoOptions()
                            {
                                WaitUntil = WaitUntilState.DOMContentLoaded,
                                Timeout = 10_000
                            });

                            if (result == null)
                                return e.Fail("page-load", refresh_proxy: true);

                            string html = await result.TextAsync();
                            if (string.IsNullOrEmpty(html))
                                return e.Fail("page-content");

                            var content = oninvk.Search(html, title, original_title, year);
                            if (content == null || content.IsError)
                                return e.Fail("search-parse", refresh_proxy: true);

                            if (content.IsEmpty)
                            {
                                if (rch?.enable == true || content.content != null)
                                    return e.Fail(content.content ?? "empty");
                            }

                            return e.Success(content);
                        }
                        catch
                        {
                            return e.Fail("catch");
                        }
                    });

                    if (!search.IsSuccess)
                        return ShowError(string.IsNullOrEmpty(search.ErrorMsg) ? "поиск не дал результатов" : search.ErrorMsg);

                    if (similar || string.IsNullOrEmpty(search.Value?.href))
                    {
                        if (search.Value?.IsEmpty == true)
                            return ShowError(search.Value.content ?? "поиск не дал результатов");

                        return await ContentTpl(search, () =>
                        {
                            if (search.Value.similar == null)
                                return default;

                            var stpl = new SimilarTpl(search.Value.similar.Count);
                            string enc_title = HttpUtility.UrlEncode(title);
                            string enc_original_title = HttpUtility.UrlEncode(original_title);

                            foreach (var item in search.Value.similar)
                            {
                                string link = $"{host}/lite/pizdatoehd?rjson={rjson}&title={enc_title}&original_title={enc_original_title}&href={HttpUtility.UrlEncode(item.href)}";
                                stpl.Append(item.title, item.year, string.Empty, link, PosterApi.Size(item.img));
                            }

                            return stpl;
                        });
                    }

                    href = search.Value.href;
                }
                #endregion

                #region embed (movie/season list)
                var cache = await InvokeCacheResult<PizdatoeRootObject>($"pizdatoehd:{href}", 15, async e =>
                {
                    try
                    {
                        // Why: href arrives from the cached search step (internal trusted source) or as a
                        // user query param (untrusted). Normalize then SSRF-guard the composed URL so we
                        // never issue a Playwright Goto into an internal address.
                        string pageUri = $"{init.host}/{href.TrimStart('/')}";
                        if (!SsrfGuard.IsAllowedPublicUriBasic(pageUri))
                            return e.Fail("href-ssrf");

                        string html = null;

                        if (page != null && init.imitationHuman)
                        {
                            if (await GotoLinkAsync(page, href))
                                html = await page.ContentAsync();
                        }

                        if (html == null || !html.Contains("b-sidecover"))
                        {
                            if (page == null)
                            {
                                page = await browser.NewPageAsync(init.plugin, init.headers, proxy: proxy_data, imitationHuman: init.imitationHuman).ConfigureAwait(false);
                                if (page == null)
                                    return e.Fail("page");

                                await AdsBlockRouteAsync(page);
                            }

                            var result = await page.GotoAsync(pageUri, new PageGotoOptions()
                            {
                                WaitUntil = WaitUntilState.DOMContentLoaded,
                                Timeout = 10_000
                            });

                            if (result == null)
                                return e.Fail("page-load", refresh_proxy: true);

                            html = await result.TextAsync();
                        }

                        if (string.IsNullOrEmpty(html))
                            return e.Fail("page-content");

                        var content = oninvk.Embed(href, html);
                        if (content == null)
                            return e.Fail("embed-parse");

                        return e.Success(content);
                    }
                    catch
                    {
                        return e.Fail("catch");
                    }
                });
                #endregion

                if (cache.Value?.IsEmpty == true)
                    return ShowError(cache.Value.content);

                return await ContentTpl(cache,
                    () => oninvk.Tpl(cache.Value, accsArgs(string.Empty), title, original_title, href, t, s, rjson)
                );
            }
        }

        #region Movie
        [HttpGet]
        [Route("lite/pizdatoehd/movie")]
        [Route("lite/pizdatoehd/movie.m3u8")]
        async public Task<ActionResult> Movie(string title, string original_title, string href, string voice, int t, int s = -1, int e = -1, bool play = false)
        {
            if (PlaywrightBrowser.Status == PlaywrightStatus.disabled && !(init.rhub || init.priorityBrowser == "http"))
                return OnError();

            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            if (string.IsNullOrWhiteSpace(init.host) || !SsrfGuard.IsAllowedPublicUriBasic(init.host))
                return OnError();

            var cache = await InvokeCacheResult<PizdatoeMovieModel>(ipkey($"pizdatoehd:movie:{voice}:{href}:{t}:{s}:{e}"), 20, async result =>
            {
                using (var browser = new PlaywrightBrowser(init.priorityBrowser))
                {
                    try
                    {
                        var page = await browser.NewPageAsync(init.plugin, init.headers, proxy: proxy_data, imitationHuman: init.imitationHuman).ConfigureAwait(false);
                        if (page == null)
                            return result.Fail("page");

                        await AdsBlockRouteAsync(page);

                        #region auth cookies
                        if (!string.IsNullOrEmpty(init.cookie))
                        {
                            var excookie = DateTimeOffset.UtcNow.AddYears(1).ToUnixTimeSeconds();

                            var cookies = new List<BrowserCookie>();
                            foreach (string line in init.cookie.Split(";"))
                            {
                                if (line.Contains("dle_user_id") || line.Contains("dle_password"))
                                {
                                    var parts = line.Split("=");
                                    if (parts.Length != 2)
                                        continue;

                                    cookies.Add(new BrowserCookie()
                                    {
                                        Domain = "." + Regex.Replace(init.host, "^https?://", ""),
                                        Expires = excookie,
                                        Path = "/",
                                        HttpOnly = true,
                                        Name = parts[0].Trim(),
                                        Value = parts[1].Trim()
                                    });
                                }
                            }

                            if (cookies.Count > 0)
                                await page.Context.AddCookiesAsync(cookies);
                        }
                        #endregion

                        if (string.IsNullOrEmpty(voice))
                        {
                            #region AJAX path (serial) — capture /get_cdn_series/ response
                            page.Response += async (sender, resp) =>
                            {
                                try
                                {
                                    if (resp.Request.Method == "POST" && resp.Request.Url.Contains("/get_cdn_series/"))
                                    {
                                        string json = await resp.TextAsync();
                                        browser.SetPageResult(json);
                                    }
                                }
                                catch { }
                            };

                            // href is arbitrary user-ish state from the player (season/episode selection).
                            // SsrfGuard the composed URL before navigation.
                            string ajaxUri = $"{init.host}/{(href ?? string.Empty).TrimStart('/')}#t:{t}-s:{s}-e:{e}";
                            if (!SsrfGuard.IsAllowedPublicUriBasic(ajaxUri))
                                return result.Fail("ajax-ssrf");

                            PlaywrightBase.GotoAsync(page, ajaxUri);

                            string json = await browser.WaitPageResult(10);
                            if (string.IsNullOrEmpty(json))
                                return result.Fail("page-content");

                            var content = oninvk.AjaxMovie(json);
                            if (content == null)
                                return result.Fail("ajax-parse");

                            return result.Success(content);
                            #endregion
                        }
                        else
                        {
                            #region Voice page (single movie)
                            string voiceUri = $"{init.host}/{voice.TrimStart('/')}";
                            if (!SsrfGuard.IsAllowedPublicUriBasic(voiceUri))
                                return result.Fail("voice-ssrf");

                            var page_result = await page.GotoAsync(voiceUri, new PageGotoOptions()
                            {
                                WaitUntil = WaitUntilState.DOMContentLoaded,
                                Timeout = 10_000
                            });

                            if (page_result == null)
                                return result.Fail("page-load", refresh_proxy: true);

                            string html = await page_result.TextAsync();
                            if (string.IsNullOrEmpty(html))
                                return result.Fail("page-content");

                            var content = oninvk.Movie(html);
                            if (content == null)
                                return result.Fail("movie-parse");

                            return result.Success(content);
                            #endregion
                        }
                    }
                    catch
                    {
                        return result.Fail("catch");
                    }
                }
            });

            if (cache.Value?.links == null || cache.Value.links.Count == 0)
                return OnError();

            string payload = oninvk.Movie(cache.Value, title, original_title, play, vast: init.vast);
            if (string.IsNullOrEmpty(payload))
                return OnError();

            if (play)
                return RedirectToPlay(payload);

            return ContentTo(payload);
        }
        #endregion

        #region GotoLinkAsync
        // Why: nextgen's imitationHuman flow clicks through the search-results card instead of
        // directly navigating, which looks more natural to rezka's bot-detection heuristics.
        // Ported verbatim; returns false on any failure so the caller falls back to direct Goto.
        async Task<bool> GotoLinkAsync(IPage page, string href)
        {
            try
            {
                var container = page.Locator("div.b-content__inline_item-link").Filter(new()
                {
                    Has = page.Locator($"a[href*='{href}']")
                });

                if (container == null || await container.CountAsync() != 1)
                    return false;

                var link = container.Locator("a");
                if (link == null)
                    return false;

                await link.ClickAsync();

                await page.WaitForURLAsync($"**/{href}", new PageWaitForURLOptions()
                {
                    WaitUntil = WaitUntilState.DOMContentLoaded,
                    Timeout = 8_000
                });

                return true;
            }
            catch
            {
                return false;
            }
        }
        #endregion

        #region AdsBlockRouteAsync
        // Ported from lampac-nextgen 94f7b8b. Blocks ad/tracker requests at the
        // Playwright route layer so they never hit the network. Pattern is
        // upstream-curated; no SSRF concern (we abort, not redirect).
        async Task AdsBlockRouteAsync(IPage page)
        {
            const string adspattern = "(vk.com|ad2the.net|schulist.link|clarity.ms|frane[a-z]ki.net|cdn.jsdelivr.net/npm/yandex-metrica-watch/tag.js)";

            await page.RouteAsync("**/*", async route =>
            {
                try
                {
                    if (Regex.IsMatch(route.Request.Url, adspattern, RegexOptions.IgnoreCase))
                        await route.AbortAsync();
                    else
                        await route.ContinueAsync();
                }
                catch { }
            });
        }
        #endregion
    }
}
