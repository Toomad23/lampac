using Microsoft.AspNetCore.Mvc;
using Shared.Engine.RxEnumerate;
using Shared.Engine.Utilities;
using Shared.Models.Online.FlixCDN;
using Shared.Models.Online.Settings;

namespace Online.Controllers
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/FlixCDN).
    //
    // FlixCDN exposes a JSON catalogue at {apihost}/search?token=...&title=|&kinopoisk_id=|&imdb_id=
    // then serves playback via an embed URL passed through as /lite/flixcdn/stream.
    //
    // Adaptation notes:
    //   * Upstream used [Staticache] + EncryptQuery. We do not have either:
    //     - replaced Staticache with InvokeCacheResult (4h) which gives equivalent caching.
    //     - replaced EncryptQuery with plain UrlEncode. Iframe URLs pointing outside init.host
    //       are rejected by SsrfGuard on the stream endpoint, so obfuscation buys nothing.
    //   * token + apihost are pulled from init (BaseSettings) — both are operator-configured.
    //   * stream URLs are sanitised via SsrfGuard before being embedded into the player JSON.
    public class FlixCDN : BaseOnlineController
    {
        FlixCDNInvoke oninvk;

        public FlixCDN() : base(AppInit.conf.FlixCDN)
        {
            requestInitialization = () =>
            {
                oninvk = new FlixCDNInvoke
                (
                   init.hls,
                   streamfile => HostStreamProxy(streamfile)
                );
            };
        }


        [HttpGet]
        [Route("lite/flixcdn")]
        async public Task<ActionResult> Index(string imdb_id, long kinopoisk_id, string title, string original_title, int year, int t = -1, int s = -1, bool similar = false)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            if (string.IsNullOrEmpty(init?.token))
                return OnError();

            rhubFallback:
            var cache = await InvokeCacheResult<SearchItem>($"flixcdn:search:{imdb_id}:{kinopoisk_id}:{title}:{similar}", TimeSpan.FromHours(4), async e =>
            {
                if (similar || (kinopoisk_id == 0 && string.IsNullOrEmpty(imdb_id)))
                {
                    var search = await SearchByTitle(imdb_id, kinopoisk_id, title, original_title, similar);
                    if (search == null)
                        return e.Fail("SearchByTitle", refresh_proxy: true);

                    return e.Success(search);
                }
                else
                {
                    var item = await SearchById(imdb_id, kinopoisk_id);
                    if (item != null)
                        return e.Success(item);

                    var search = await SearchByTitle(imdb_id, kinopoisk_id, title, original_title, false);
                    if (search == null)
                        return e.Fail("SearchById", refresh_proxy: true);

                    return e.Success(search);
                }
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            return await ContentTpl(cache, () =>
            {
                var result = cache.Value;

                if (result.similar != null)
                    return result.similar;

                if (result.translations == null || result.translations.Count == 0)
                    return default;

                if (result.type is "movie" or "cartoon")
                {
                    var mtpl = new MovieTpl(title, original_title, result.translations.Count);

                    foreach (var voice in result.translations)
                    {
                        string link = $"{host}/lite/flixcdn/stream?iframe={HttpUtility.UrlEncode(result.iframe_url)}&t={voice.id}";
                        mtpl.Append(voice.title, link, "call", vast: init.vast);
                    }

                    return mtpl;
                }
                else
                {
                    #region Сериал
                    string enc_title = HttpUtility.UrlEncode(title);
                    string enc_original_title = HttpUtility.UrlEncode(original_title);

                    if (s == -1)
                    {
                        var tpl = new SeasonTpl();
                        var hash = new HashSet<int>();

                        foreach (var voice in result.translations.OrderBy(s => s.season))
                        {
                            if (hash.Add(voice.season))
                            {
                                string link = $"{host}/lite/flixcdn?similar={similar}&kinopoisk_id={kinopoisk_id}&imdb_id={imdb_id}&title={enc_title}&original_title={enc_original_title}&t={t}&s={voice.season}";
                                tpl.Append($"{voice.season} сезон", link, voice.season);
                            }
                        }

                        return tpl;
                    }
                    else
                    {
                        #region Перевод
                        var vtpl = new VoiceTpl();
                        var tmpVoice = new HashSet<int>(20);

                        foreach (var voice in result.translations.Where(i => i.season == s))
                        {
                            if (tmpVoice.Add(voice.id))
                            {
                                if (t == -1)
                                    t = voice.id;

                                vtpl.Append(voice.title, t == voice.id, $"{host}/lite/flixcdn?similar={similar}&kinopoisk_id={kinopoisk_id}&imdb_id={imdb_id}&title={enc_title}&original_title={enc_original_title}&t={voice.id}&s={s}");
                            }
                        }
                        #endregion

                        var etpl = new EpisodeTpl(vtpl);
                        string sArhc = s.ToString();

                        var targetVoice = result.translations.FirstOrDefault(i => i.season == s && i.id == t);
                        if (targetVoice == null)
                            return default;

                        for (int ep = 1; ep <= targetVoice.episode; ep++)
                        {
                            string link = $"{host}/lite/flixcdn/stream?iframe={HttpUtility.UrlEncode(result.iframe_url)}&t={t}&s={s}&e={ep}";
                            etpl.Append($"Серия {ep}", title ?? original_title, sArhc, ep.ToString(), link, "call", streamlink: $"{link}&play=true", vast: init.vast);
                        }

                        return etpl;
                    }
                    #endregion
                }
            });
        }


        [HttpGet]
        [Route("lite/flixcdn/stream")]
        async public Task<ActionResult> Stream(string iframe, int t, int s = 0, int e = 0, bool play = false)
        {
            if (string.IsNullOrEmpty(iframe))
                return OnError();

            // Why: iframe arrives as a user-controllable query parameter. Upstream lampac-nextgen
            // used EncryptQuery to wrap it, which we do not have — so we must SSRF-check the raw
            // URL fail-closed before letting httpHydra dereference it.
            if (!SsrfGuard.IsAllowedPublicUriBasic(iframe))
                return OnError();

            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            if (rch != null)
            {
                if (rch.IsNotConnected())
                {
                    if (init.rhub_fallback && play)
                        rch.Disabled();
                    else
                        return ContentTo(rch.connectionMsg);
                }

                if (!play && rch.IsRequiredConnected())
                    return ContentTo(rch.connectionMsg);

                if (rch.IsNotSupport(out string rch_error))
                    return ShowError(rch_error);
            }

        rhubFallback:
            var cache = await InvokeCacheResult<string>(ipkey($"flixcdn:stream:{iframe}:{t}:{s}:{e}"), 10, async result =>
            {
                string file = null;
                string iframeUrl = oninvk.BuildIframeUrl(iframe, t, s, e);

                // Why: BuildIframeUrl may append new query args but should never change host.
                // Re-validate just in case, and to make the guard invariant visible at callsite.
                if (!SsrfGuard.IsAllowedPublicUriBasic(iframeUrl))
                    return result.Fail("iframe-ssrf");

                await httpHydra.GetSpan(iframeUrl, spanAction: html =>
                {
                    file = Rx.Match(html, "file'?:\\s*'([^']+)'");
                });

                if (string.IsNullOrWhiteSpace(file))
                    return result.Fail("embed", refresh_proxy: true);

                return result.Success(file);
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            if (!cache.IsSuccess)
                return OnError(cache.ErrorMsg);

            var streamquality = oninvk.GetStreamQualityTpl(cache.Value);

            var first = streamquality.Firts();
            if (string.IsNullOrEmpty(first.link))
                return OnError();

            if (play)
                return RedirectToPlay(first.link);

            return ContentTo(VideoTpl.ToJson("play", first.link, "auto",
                streamquality: streamquality,
                vast: init.vast,
                hls_manifest_timeout: (int)TimeSpan.FromSeconds(20).TotalMilliseconds
            ));
        }


        #region search
        async Task<SearchItem> SearchByTitle(string imdb_id, long kinopoisk_id, string title, string original_title, bool forceSimilar)
        {
            if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(original_title))
                return null;

            var root = await ApiSearch($"title={HttpUtility.UrlEncode(title ?? original_title)}");
            if (root == null || root.Length == 0)
                return null;

            var stpl = new SimilarTpl(root.Length);
            string enc_title = HttpUtility.UrlEncode(title);
            string enc_original_title = HttpUtility.UrlEncode(original_title);

            string stitle = StringConvert.SearchName(title);
            string sorig = StringConvert.SearchName(original_title);

            SearchItem exact = null;

            foreach (var item in root)
            {
                string name = item.title_rus ?? item.title_orig;
                string details = item.year > 0 ? item.year.ToString() : string.Empty;
                string link = $"{host}/lite/flixcdn?kinopoisk_id={kinopoisk_id}&imdb_id={imdb_id}&title={HttpUtility.UrlEncode(item.title_rus)}&original_title={HttpUtility.UrlEncode(item.title_orig)}&year={item.year}";

                stpl.Append(name, details, string.Empty, link, PosterApi.Size(item.poster));

                if (exact == null && !string.IsNullOrEmpty(name))
                {
                    string sname = StringConvert.SearchName(name);
                    if (!string.IsNullOrEmpty(stitle) && sname.Contains(stitle))
                        exact = item;
                    else if (!string.IsNullOrEmpty(sorig) && sname.Contains(sorig))
                        exact = item;
                }
            }

            if (forceSimilar)
                return new SearchItem() { similar = stpl };

            if (exact != null)
                return exact;

            if (root.Length == 1)
                return root[0];

            if (stpl.Length > 0)
                return new SearchItem() { similar = stpl };

            return null;
        }

        async Task<SearchItem> SearchById(string imdb_id, long kinopoisk_id)
        {
            var args = new List<string>(3);

            if (kinopoisk_id > 0)
                args.Add($"kinopoisk_id={kinopoisk_id}");

            if (!string.IsNullOrEmpty(imdb_id))
                args.Add($"imdb_id={imdb_id}");

            var root = await ApiSearch(string.Join("&", args));
            if (root != null && root.Length > 0)
                return root[0];

            return null;
        }

        async Task<SearchItem[]> ApiSearch(string query)
        {
            string uri = $"{init.apihost}/search?token={init.token}&{query}";
            var root = await httpHydra.Get<SearchRoot>(uri, safety: true);

            return root?.result;
        }
        #endregion
    }
}
