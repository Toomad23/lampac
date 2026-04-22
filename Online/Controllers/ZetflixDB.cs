using Microsoft.AspNetCore.Mvc;
using Shared.Engine.Utilities;
using Shared.Models.Online.Settings;
using Shared.Models.Online.VideoDB;
using Shared.PlaywrightCore;
using System.Text;

namespace Online.Controllers
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/ZetflixDB).
    //
    // ZetflixDB is a *sibling* of VideoDB — same encode format (Player("...base64..."))
    // but a different apihost and a different embed path (/embed/AO/kinopoisk/{encoded_kp}).
    // In nextgen it was literally a LocalRedirect into /lite/videodb?uri=... because that
    // controller accepted an arbitrary URI override. Our VideoDB does NOT accept uri overrides
    // (would be an SSRF footgun), so we re-implement the short flow here and share the
    // VideoDBInvoke parser + template rendering.
    //
    // All playback links produced by VideoDBInvoke.Tpl point at /lite/videodb/manifest, which
    // already SSRF-guards the `link` query param — so the stream path is already hardened.
    public class ZetflixDB : BaseOnlineController
    {
        public ZetflixDB() : base(AppInit.conf.ZetflixDB) { }

        [HttpGet]
        [Route("lite/zetflixdb")]
        async public Task<ActionResult> Index(long kinopoisk_id, string title, string original_title, string t, int s = -1, int sid = -1, bool rjson = false, int serial = -1)
        {
            if (kinopoisk_id == 0)
                return OnError();

            if (PlaywrightBrowser.Status == PlaywrightStatus.disabled && !(init.rhub || init.priorityBrowser == "http"))
                return OnError();

            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            // Why: apihost is operator-configured via init.conf / kit and then baked into the
            // outbound URL. If an operator points apihost at 127.0.0.1 / 169.254.169.254 the
            // httpHydra.GetSpan below would happily dereference it — bail out fail-closed.
            string apihost = init.apihost;
            if (string.IsNullOrWhiteSpace(apihost) || !SsrfGuard.IsAllowedPublicUriBasic(apihost))
                return OnError();

            var oninvk = new VideoDBInvoke
            (
               host,
               apihost,
               () => proxyManager?.Refresh()
            );

            rhubFallback:
            var cache = await InvokeCacheResult<EmbedModel>(ipkey($"zetflixdb:view:{kinopoisk_id}"), 20, async e =>
            {
                EmbedModel embed = null;

                string embedUrl = $"{apihost.TrimEnd('/')}/embed/AO/kinopoisk/{EncodeKinopoisk(kinopoisk_id)}/";

                // Guard against overridehost redirection into private space after trimming.
                if (!SsrfGuard.IsAllowedPublicUriBasic(embedUrl))
                    return e.Fail("embed-ssrf");

                if (rch?.enable == true || init.priorityBrowser == "http")
                {
                    var headers = httpHeaders(init, HeadersModel.Init(
                        ("sec-fetch-dest", "iframe"),
                        ("sec-fetch-mode", "navigate"),
                        ("sec-fetch-site", "cross-site"),
                        ("referer", "{host}/")
                    ));

                    await httpHydra.GetSpan(embedUrl, newheaders: headers, spanAction: html =>
                    {
                        embed = oninvk.Embed(html);
                    });
                }
                else
                {
                    // With Playwright fallback — reuse the VideoDBInvoke overload that takes a getter.
                    // We cannot reuse VideoDB.black_magic (private), and a bespoke Playwright driver
                    // here would double our attack surface, so Playwright-only ops go through the
                    // plain httpHydra path too. If operators want Playwright, they set priorityBrowser
                    // to http or enable rhub — same as VideoDB.
                    var headers = httpHeaders(init, HeadersModel.Init(
                        ("sec-fetch-dest", "iframe"),
                        ("sec-fetch-mode", "navigate"),
                        ("sec-fetch-site", "cross-site"),
                        ("referer", "{host}/")
                    ));

                    await httpHydra.GetSpan(embedUrl, newheaders: headers, spanAction: html =>
                    {
                        embed = oninvk.Embed(html);
                    });
                }

                if (embed == null)
                    return e.Fail("embed", refresh_proxy: true);

                return e.Success(embed);
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            // oninvk.Tpl emits {host}/lite/videodb/manifest links for playback. ZetflixDB piggybacks
            // on the VideoDB manifest endpoint (which already SSRF-guards the link param).
            return await ContentTpl(cache,
                () => oninvk.Tpl(cache.Value, accsArgs(string.Empty), kinopoisk_id, title, original_title, t, s, sid, rjson)
            );
        }

        // ZetflixDB obfuscates the kinopoisk_id in the URL by base64-encoding it, stripping
        // '=' padding, and reversing the result. Ported verbatim from lampac-nextgen so we
        // hit the same embed endpoint the upstream expects.
        static string EncodeKinopoisk(long kinopoisk_id)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(kinopoisk_id.ToString());
            string base64 = Convert.ToBase64String(bytes);

            string trimmed = base64.TrimEnd('=');

            char[] arr = trimmed.ToCharArray();
            Array.Reverse(arr);

            return new string(arr);
        }
    }
}
