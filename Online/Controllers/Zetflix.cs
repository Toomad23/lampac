using Microsoft.AspNetCore.Mvc;
using Microsoft.Playwright;
using Shared.Models.Online.Settings;
using Shared.PlaywrightCore;

namespace Online.Controllers
{
    public class Zetflix : BaseOnlineController<ZetflixSettings>
    {
        public Zetflix() : base(AppInit.conf.Zetflix) { }

        // Why: M-14 — replace naked static session field with a per-proxy-IP concurrent dictionary so
        // simultaneous requests can safely share sessions that belong to the same proxy identity
        // without reading torn values or leaking another user's cookie.
        static readonly ConcurrentDictionary<string, string> _phpSessions = new ConcurrentDictionary<string, string>();

        [HttpGet]
        [Route("lite/zetflix")]
        async public Task<ActionResult> Index(long id, int serial, long kinopoisk_id, string title, string original_title, string t, int s = -1, bool orightml = false, bool origsource = false, bool rjson = false)
        {
            if (kinopoisk_id == 0)
                return OnError();

            if (PlaywrightBrowser.Status == PlaywrightStatus.disabled)
                return OnError();

            if (await IsRequestBlocked(rch: false))
                return badInitMsg;

            string ztfhost = await goHost(init.host);
            string log = $"{HttpContext.Request.Path.Value}\n\nstart init\n";

            var oninvk = new ZetflixInvoke
            (
               host,
               ztfhost,
               init.hls,
               (url, head) => httpHydra.Get(url, addheaders: head),
               onstreamtofile => HostStreamProxy(onstreamtofile)
               //AppInit.log
            );

            int rs = serial == 1 ? (s == -1 ? 1 : s) : s;

            string html = await InvokeCache($"zetfix:view:{kinopoisk_id}:{rs}:{proxyManager?.CurrentProxyIp}", 20, async () =>
            {
                string uri = $"{ztfhost}/iplayer/videodb.php?kp={kinopoisk_id}" + (rs > 0 ? $"&season={rs}" : "");

                var headers = HeadersModel.Init(Chromium.baseContextOptions.ExtraHTTPHeaders.ToDictionary(), ("Referer", "https://www.google.com/"));

                // Why: M-14 — snapshot the per-proxy PHPSESSID under a stable key and read/write through
                // ConcurrentDictionary so another request flipping the cookie cannot produce a torn read here.
                string sessionKey = proxyManager?.CurrentProxyIp ?? "default";
                string phpSessId = _phpSessions.TryGetValue(sessionKey, out var existing) ? existing : null;
                string result = string.IsNullOrEmpty(phpSessId) ? null : await Http.Get(uri, proxy: proxy, cookie: $"PHPSESSID={phpSessId}", headers: headers);
                if (result != null && !result.StartsWith("<script>(function"))
                {
                    if (!result.Contains("new Playerjs"))
                        return null;

                    proxyManager?.Success();
                    return result;
                }

                try
                {
                    using (var browser = new PlaywrightBrowser(init.priorityBrowser))
                    {
                        log += "browser init\n";

                        var page = await browser.NewPageAsync(init.plugin, new Dictionary<string, string>()
                        {
                            ["Referer"] = "https://www.google.com/"

                        }, proxy: proxy_data, keepopen: init.browser_keepopen).ConfigureAwait(false);

                        if (page == null)
                            return null;

                        if (init.browser_keepopen)
                        {
                            await page.Context.ClearCookiesAsync(new BrowserContextClearCookiesOptions
                            {
                                Domain = Regex.Replace(ztfhost, "^https?://", ""),
                                Name = "PHPSESSID"

                            }).ConfigureAwait(false);
                        }

                        log += "page init\n";

                        await page.RouteAsync("**/*", async route =>
                        {
                            try
                            {
                                if (await PlaywrightBase.AbortOrCache(page, route, abortMedia: true, fullCacheJS: true))
                                    return;

                                await route.ContinueAsync();
                            }
                            catch { }
                        });

                        await page.GotoAsync(uri, new PageGotoOptions() 
                        {
                            Timeout = 15_000,
                            WaitUntil = WaitUntilState.NetworkIdle 
                        }).ConfigureAwait(false);

                        result = await page.ContentAsync().ConfigureAwait(false);

                        log += $"{result}\n\n";

                        if (result == null || result.StartsWith("<script>(function"))
                        {
                            proxyManager?.Refresh();
                            return null;
                        }

                        var cook = await page.Context.CookiesAsync().ConfigureAwait(false);
                        // Why: M-14 — publish the freshly-acquired cookie under the same per-proxy key so
                        // subsequent requests on this proxy reuse it, and do not race against another proxy's cookie.
                        string freshPhpSessId = cook?.FirstOrDefault(i => i.Name == "PHPSESSID")?.Value;
                        if (!string.IsNullOrEmpty(freshPhpSessId))
                            _phpSessions[sessionKey] = freshPhpSessId;

                        if (!result.Contains("new Playerjs"))
                            return null;

                        return result;
                    }
                }
                catch (Exception ex) 
                {
                    log += $"\nex: {ex}\n";
                    return null; 
                }
            });

            if (html == null)
                return OnError();

            if (orightml)
                return Content(html, "text/plain; charset=utf-8");

            var content = oninvk.Embed(html);
            if (content.pl == null)
                return OnError();

            if (origsource)
                return Json(content);

            int number_of_seasons = 1;
            if (!content.movie && s == -1 && id > 0)
                number_of_seasons = await InvokeCache($"zetfix:number_of_seasons:{kinopoisk_id}", 120, () => oninvk.number_of_seasons(id));

            OnLog(log + "\nStart OnResult");

            return await ContentTpl(oninvk.Tpl(content, number_of_seasons, kinopoisk_id, title, original_title, t, s, vast: init.vast));
        }


        async ValueTask<string> goHost(string host)
        {
            if (!Regex.IsMatch(host, "^https?://go\\."))
                return host;

            string backhost = CrypTo.DecodeBase64("aHR0cHM6Ly96ZXQtZmxpeC5vbmxpbmU=");

            string memkey = $"zeflix:gohost:{host}";
            if (hybridCache.TryGetValue(memkey, out string ztfhost))
            {
                if (string.IsNullOrEmpty(ztfhost))
                    return backhost;

                return ztfhost;
            }

            string html = await httpHydra.Get(host);
            if (html != null)
            {
                ztfhost = Regex.Match(html, "\"([^\"]+)\"\\);</script>").Groups[1].Value;
                if (!string.IsNullOrEmpty(ztfhost))
                {
                    ztfhost = $"https://{ztfhost}";
                    hybridCache.Set(memkey, ztfhost, DateTime.Now.AddMinutes(20));
                    return ztfhost;
                }
            }
            else
            {
                hybridCache.Set(memkey, string.Empty, DateTime.Now.AddMinutes(1));
            }

            return backhost;
        }
    }
}
