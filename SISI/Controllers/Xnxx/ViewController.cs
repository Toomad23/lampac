using Microsoft.AspNetCore.Mvc;

namespace SISI.Controllers.Xnxx
{
    public class ViewController : BaseSisiController
    {
        public ViewController() : base(AppInit.conf.Xnxx) { }

        [HttpGet]
        [Route("xnx/vidosik")]
        async public Task<ActionResult> Index(string uri, bool related)
        {
            if (await IsRequestBlocked(rch: true))
                return badInitMsg;

            rhubFallback:
            // Why: M-24 — fingerprint oversized uris so unbounded user input cannot bloat the cache key.
            string uriKey = !string.IsNullOrEmpty(uri) && uri.Length > 256 ? CrypTo.md5(uri) : uri;
            var cache = await InvokeCacheResult<StreamItem>($"xnxx:view:{uriKey}", 20, async e =>
            {
                string url = XnxxTo.StreamLinksUri(init.corsHost(), uri);
                if (url == null)
                    return e.Fail("uri");

                StreamItem stream_links = null;

                await httpHydra.GetSpan(url, span =>
                {
                    stream_links = XnxxTo.StreamLinks(span, "xnx/vidosik");
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
