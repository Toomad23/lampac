using Microsoft.AspNetCore.Mvc;

namespace SISI.Controllers.Xhamster
{
    public class ViewController : BaseSisiController
    {
        public ViewController() : base(AppInit.conf.Xhamster) { }

        [HttpGet]
        [Route("xmr/vidosik")]
        async public Task<ActionResult> Index(string uri, bool related)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            rhubFallback:
            // Why: M-24 — cap unbounded user input in the cache key; fingerprint long uris via md5 so
            // an attacker cannot spray the in-memory cache with megabyte-sized keys.
            string uriKey = !string.IsNullOrEmpty(uri) && uri.Length > 256 ? CrypTo.md5(uri) : uri;
            var cache = await InvokeCacheResult<StreamItem>($"xhamster:view:{uriKey}", 20, async e =>
            {
                string targetHost = init.corsHost();
                string url = XhamsterTo.StreamLinksUri(targetHost, uri);

                if (url == null)
                    return e.Fail("uri");

                StreamItem stream_links = null;

                await httpHydra.GetSpan(url, span =>
                {
                    stream_links = XhamsterTo.StreamLinks(targetHost, "xmr/vidosik", span);
                });

                if (stream_links?.qualitys == null || stream_links.qualitys.Count == 0)
                    return e.Fail("stream_links", refresh_proxy: true);

                return e.Success(stream_links);
            });

            if (IsRhubFallback(cache))
                goto rhubFallback;

            if (related)
                return await PlaylistResult(cache.Value?.recomends, cache.ISingleCache, null, total_pages: 1);

            return OnResult(cache);
        }
    }
}
