using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Shared.Engine
{
    public static class FrendlyHttp
    {
        #region static
        static ConcurrentDictionary<string, (DateTime lifetime, HttpClient http)> _clients = new ConcurrentDictionary<string, (DateTime, HttpClient)>();

        static FrendlyHttp()
        {
            ThreadPool.QueueUserWorkItem(async _ =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5));

                    try
                    {
                        var now = DateTime.UtcNow;

                        foreach (var client in _clients)
                        {
                            try
                            {
                                if (DateTime.UtcNow > client.Value.lifetime &&
                                    _clients.TryRemove(client.Key, out var _c))
                                {
                                    _= Task.Delay(TimeSpan.FromSeconds(20))
                                        .ContinueWith(e => _c.http.Dispose())
                                        .ConfigureAwait(false);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            });
        }
        #endregion

        #region MessageClient
        // Why (H-17): Callers of MessageClient never dispose the returned HttpClient — they treat it like a
        // pooled instance from IHttpClientFactory. Previously the "cookie-bearing" branch returned `new HttpClient(handler)`
        // unconditionally, which leaked the socket handler on every request. The proxy branch used a cache key
        // that ignored cookie identity and redirect/buffer knobs, which meant a later request with different
        // handler state could get a stale client. Fix: unify both branches into the same pool, and include
        // every handler knob that affects behaviour (proxy identity, cookie container identity, AllowAutoRedirect,
        // UseProxy, AutomaticDecompression, MaxResponseContentBufferSize) in the key. Tradeoff: if each caller
        // hands in a fresh CookieContainer per request, each gets its own pool entry — this is bounded because
        // the background sweeper disposes entries 30 minutes after creation (see static ctor above). The prior
        // unbounded-leak behaviour is replaced by a time-bounded pool. An alternative (SocketsHttpHandler with
        // PooledConnectionLifetime) would require rewriting Handler() and touching every caller, so we stay
        // within the two-file scope dictated by this change.
        public static HttpClient MessageClient
        (
            string factoryClient,
            HttpClientHandler handler,
            long MaxResponseContentBufferSize = -1
        )
        {
            // 10MB
            long maxBufferSize = 10_000_000;
            if (MaxResponseContentBufferSize > 0)
                maxBufferSize = MaxResponseContentBufferSize;

            bool hasCookies = handler != null && handler.CookieContainer != null && handler.CookieContainer.Count > 0;

            if (!hasCookies && Http.httpClientFactory != null)
            {
                var webProxyNoCookie = handler?.Proxy != null ? handler.Proxy as WebProxy : null;

                if (webProxyNoCookie == null)
                {
                    if (handler != null && handler.AllowAutoRedirect == false)
                    {
                        if (factoryClient is "base" or "http2")
                            factoryClient += "NoRedirect";
                    }

                    var factory = Http.httpClientFactory.CreateClient(factoryClient);

                    if (maxBufferSize > factory.MaxResponseContentBufferSize)
                        factory.MaxResponseContentBufferSize = maxBufferSize;

                    return factory;
                }
            }

            // Fallback path: pooled HttpClient owning its own handler. Used when either cookies are present
            // (IHttpClientFactory clients can't accept an ad-hoc CookieContainer) or a per-request WebProxy
            // is set, or httpClientFactory is not yet initialised.
            string ip = null, username = null, password = null;
            int port = 0;

            var webProxy = handler?.Proxy != null ? handler.Proxy as WebProxy : null;
            if (webProxy != null)
            {
                ip = webProxy.Address?.Host;
                port = webProxy.Address?.Port ?? 0;

                if (webProxy.Credentials is NetworkCredential credentials)
                {
                    username = credentials.UserName;
                    password = credentials.Password;
                }
            }

            // Why: CookieContainer identity must be part of the key so two callers with different cookie jars
            // don't share a client (that was the stale-cache bug). Reference-hash is fine — callers reuse their
            // own container instance, and ephemeral containers age out via the 30-minute sweeper.
            int cookieId = hasCookies ? RuntimeHelpers.GetHashCode(handler.CookieContainer) : 0;
            bool useProxy = handler?.UseProxy ?? false;
            var decompression = handler?.AutomaticDecompression ?? System.Net.DecompressionMethods.None;
            bool redirect = handler?.AllowAutoRedirect ?? true;

            string key = $"{factoryClient}:{ip}:{port}:{username}:{password}:{maxBufferSize}:{redirect}:{useProxy}:{(int)decompression}:{cookieId}";

            return _clients.GetOrAdd(key, k =>
            {
                var client = new HttpClient(handler, disposeHandler: true);
                client.MaxResponseContentBufferSize = maxBufferSize;

                return (DateTime.UtcNow.AddMinutes(30), client);

            }).http;
        }
        #endregion
    }
}
