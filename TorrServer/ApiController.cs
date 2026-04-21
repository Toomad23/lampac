using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using Shared;
using Shared.Engine;
using Shared.Models.Base;
using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace TorrServer.Controllers
{
    public class TorrServerController : BaseController
    {
        // Why: one-shot warning per process when defaultPasswd is unset/weak so logs aren't spammed.
        static bool _warnedNoPasswd;

        #region ts.js
        [HttpGet]
        [AllowAnonymous]
        [Route("ts.js")]
        [Route("ts/js/{token}")]
        public ActionResult Plugin(string token)
        {
            string file = FileCache.ReadAllText("plugins/ts.js").Replace("{localhost}", Regex.Replace(host, "^https?://", ""));

            // Why (round5): upstream ts.js hardcodes `Lampa.Storage.set('torrserver_password','ts')`,
            // which clobbers any user-saved TS password on every plugin reload. After PR #42 made
            // the legacy 'ts' default fail-closed on the server side, this bricked the Lampa Android
            // client — auth kept reverting to 'ts' on every app start and 401'd. Inject the real
            // defaultPasswd only when the request identifies a valid accsdb user (via RequestInfo
            // middleware, or a base64-decoded `email=` query the upstream Android client sends but
            // the middleware does not recognise). Anonymous callers still see the inert 'ts'
            // literal, so the shared secret is not harvestable without knowledge of a whitelisted
            // email. On installs with accsdb.enable=false, behaviour is unchanged.
            AccsUser user = requestInfo.user;
            if (user == null && AppInit.conf.accsdb.enable)
            {
                string emailB64 = HttpContext.Request.Query["email"].ToString();
                if (!string.IsNullOrEmpty(emailB64))
                {
                    try
                    {
                        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(emailB64));
                        user = AppInit.conf.accsdb.findUser(decoded);
                    }
                    catch { /* malformed base64 — treat as anonymous */ }
                }
            }

            bool isAuthed = user != null && !user.ban && user.expires > DateTime.UtcNow;
            string tsPasswd = ModInit.conf?.defaultPasswd;

            if (isAuthed && !string.IsNullOrEmpty(tsPasswd) && tsPasswd.Length >= 8)
            {
                file = Regex.Replace(file, "Lampa.Storage.set\\('torrserver_password'[^\n\r]+",
                    $"Lampa.Storage.set('torrserver_password','{HttpUtility.JavaScriptStringEncode(tsPasswd)}');");

                string login = !string.IsNullOrEmpty(token) ? token : user.id;
                file = Regex.Replace(file, "Lampa.Storage.set\\('torrserver_login'[^\n\r]+",
                    $"Lampa.Storage.set('torrserver_login','{HttpUtility.JavaScriptStringEncode(login)}');");
            }
            else if (!string.IsNullOrEmpty(token))
            {
                // Legacy back-compat path: admin-provided token on the route.
                file = Regex.Replace(file, "Lampa.Storage.set\\('torrserver_login'[^\n\r]+",
                    $"Lampa.Storage.set('torrserver_login','{HttpUtility.UrlEncode(token)}');");
            }

            return Content(file, "application/javascript; charset=utf-8");
        }
        #endregion

        #region HttpClient
        private static readonly HttpClient httpClient = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.None,
            SslOptions = { RemoteCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true },
            MaxConnectionsPerServer = 100
        })
        {
            BaseAddress = new Uri($"http://{AppInit.conf.listen.localhost}:{ModInit.tsport}"),
            DefaultRequestHeaders =
            {
                Authorization = new AuthenticationHeaderValue("Basic", CrypTo.Base64($"ts:{ModInit.tspass}")),
            },
            Timeout = TimeSpan.FromSeconds(30)
        };
        #endregion


        #region Main
        [HttpGet]
        [Route("ts")]
        [Route("ts/static/js/{suffix}")]
        async public Task<ActionResult> Main()
        {
            string pathRequest = Regex.Replace(HttpContext.Request.Path.Value, "^/ts", "");

            // Why (round5 HIGH-4): the TorrServer admin UI and its JS bundle used to
            // be proxied anonymously. An unauthenticated caller could load /ts and
            // /ts/static/js/* without any auth — defeating the PR #44 /ts/settings
            // lockdown because the UI itself was still reachable for reconnaissance.
            // Gate on admin cookie OR strict loopback OR signed HMAC.  Return 404
            // (not 401) when unauthenticated so the existence of the TorrServer
            // proxy cannot be probed by unauthenticated clients.
            if (AppInit.conf.accsdb.enable && !await IsAdminOrLoopbackAsync().ConfigureAwait(false))
            {
                HttpContext.Response.StatusCode = 404;
                return new EmptyResult();
            }

            string html = null;

            try
            {
                var responseMessage = await httpClient.GetAsync(pathRequest + HttpContext.Request.QueryString.Value).ConfigureAwait(false);
                html = await responseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch { }

            if (html == null)
                return StatusCode(500);

            if (pathRequest.Contains(".js"))
            {
                string key = Regex.Match(html, "\\.concat\\(([^,]+),\"/echo\"").Groups[1].Value;
                html = html.Replace($".concat({key},\"/", $".concat({key},\"/ts/");
                return Content(html, "application/javascript; charset=utf-8");
            }
            else
            {
                html = html.Replace("href=\"/", "href=\"/ts/").Replace("src=\"/", "src=\"/ts/");
                html = html.Replace("src=\"./", "src=\"/ts/");
                return Content(html, "text/html; charset=utf-8");
            }
        }
        #endregion

        #region TorAPI
        [HttpGet]
        [HttpPost]
        [Route("ts/{*suffix}")]
        async public Task Index()
        {
            string pathSuffix = Regex.Replace(HttpContext.Request.Path.Value, "^/ts", "");

            // Block dangerous management endpoints unless from a local/loopback address
            if (pathSuffix.StartsWith("/shutdown") ||
                pathSuffix.StartsWith("/exit") ||
                pathSuffix.StartsWith("/restart") ||
                pathSuffix.StartsWith("/log") ||
                pathSuffix.StartsWith("/debug/pprof"))
            {
                if (!Shared.Engine.Utilities.IPNetwork.IsLocalIp(requestInfo.IP))
                {
                    HttpContext.Response.StatusCode = 404;
                    return;
                }
            }

            if (AppInit.conf.accsdb.enable)
            {
                // Why: fail-closed when no/weak defaultPasswd is configured. Without this check, a
                // fresh install with the former "ts" default (or any empty/short password) accepted
                // Basic auth from anyone who could enumerate users. Gated behind accsdb.enable since
                // unauthenticated deployments intentionally bypass /ts auth below.
                string tsPasswd = ModInit.conf?.defaultPasswd;
                bool tsAuthDisabled = string.IsNullOrEmpty(tsPasswd) || tsPasswd.Length < 8;
                if (tsAuthDisabled && !_warnedNoPasswd)
                {
                    _warnedNoPasswd = true;
                    Console.WriteLine("[TorrServer] defaultPasswd is not set or shorter than 8 chars — /ts auth disabled. Set TorrServerConf.defaultPasswd in init.conf.");
                }

                #region Access-Control-Request-Headers
                if (HttpContext.Request.Method == "OPTIONS" && HttpContext.Request.Headers.TryGetValue("Access-Control-Request-Headers", out var AccessControl) && AccessControl == "authorization")
                {
                    HttpContext.Response.StatusCode = 204;
                    return;
                }
                #endregion

                // Why (round5 HIGH-3): the GET /ts/stream and /ts/play branch used to
                // return upstream bytes *before* the auth gate below was evaluated —
                // any unauthenticated caller could pull media directly from the
                // TorrServer proxy. The gate is now applied up-front: accsdb user
                // (Basic auth), admin cookie, strict loopback, or signed HMAC. Matches
                // the treatment /ts/torrents already receives.
                bool isStreamPath = HttpContext.Request.Method == "GET" &&
                                    Regex.IsMatch(HttpContext.Request.Path.Value, "^/ts/(stream|play)");

                if (isStreamPath)
                {
                    if (await IsAdminOrLoopbackAsync().ConfigureAwait(false))
                    {
                        await TorAPI().ConfigureAwait(false);
                        return;
                    }
                    // fall through into Basic-auth accsdb check below; if that also
                    // fails, the 401 at the end of this block is returned.
                }

                if (HttpContext.Request.Headers.TryGetValue("Authorization", out var Authorization))
                {
                    // Why: L-10 — malformed Authorization headers used to throw FormatException /
                    // IndexOutOfRangeException out of FromBase64String / decodedString[1] and
                    // bubble up as a 500. Wrap the parse, and reject cleanly with 401 on any
                    // decoding / splitting error so an attacker cannot probe the server with
                    // junk headers.
                    string login = null, passwd = null;
                    try
                    {
                        string authHeader = Authorization.ToString();
                        if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                        {
                            byte[] data = Convert.FromBase64String(authHeader.Substring("Basic ".Length).Trim());
                            string[] decodedString = Encoding.UTF8.GetString(data).Split(':', 2);

                            if (decodedString.Length == 2)
                            {
                                login = decodedString[0].ToLowerAndTrim();
                                passwd = decodedString[1];
                            }
                        }
                    }
                    catch
                    {
                        login = null;
                        passwd = null;
                    }

                    if (login != null && passwd != null && !tsAuthDisabled &&
                        AppInit.conf.accsdb.findUser(login) is AccsUser user && !user.ban && user.expires > DateTime.UtcNow && CrypTo.FixedTimeEquals(passwd, tsPasswd))
                    {
                        if (ModInit.conf.group > user.group)
                        {
                            await HttpContext.Response.WriteAsync("NoAccessGroup", HttpContext.RequestAborted).ConfigureAwait(false);
                            return;
                        }

                        await TorAPI(user).ConfigureAwait(false);
                        return;
                    }
                }

                if (HttpContext.Request.Path.Value.StartsWith("/ts/echo"))
                {
                    await HttpContext.Response.WriteAsync("MatriX.API", HttpContext.RequestAborted).ConfigureAwait(false);
                    return;
                }

                HttpContext.Response.StatusCode = 401;
                HttpContext.Response.Headers["Www-Authenticate"] = "Basic realm=Authorization Required";
                return;
            }
            else
            {
                await TorAPI().ConfigureAwait(false);
                return;
            }
        }

        // Why (round5): shared admin gate reused by Main() and the /ts/stream|/ts/play
        // branch of Index(). Accepts strict loopback, admin cookie (rootPasswd), or a
        // valid X-Signature/X-Timestamp HMAC (signs body). Deliberately does NOT accept
        // accsdb Basic auth — those credentials are validated separately in Index().
        async Task<bool> IsAdminOrLoopbackAsync()
        {
            var connFeat = HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpConnectionFeature>();
            string remoteIp = connFeat?.RemoteIpAddress?.ToString()
                              ?? HttpContext.Connection.RemoteIpAddress?.ToString();

            if (Shared.Engine.Utilities.IPNetwork.IsStrictLoopback(remoteIp))
                return true;

            if (HttpContext.Request.Cookies.TryGetValue("passwd", out string cookiePasswd)
                && !string.IsNullOrEmpty(AppInit.rootPasswd)
                && Shared.Engine.CrypTo.FixedTimeEquals(cookiePasswd, AppInit.rootPasswd))
            {
                return true;
            }

            if (await Shared.Engine.HmacAuth.ValidateAsync(HttpContext.Request).ConfigureAwait(false))
                return true;

            return false;
        }

        async public Task TorAPI(AccsUser user = null)
        {
            string pathRequest = Regex.Replace(HttpContext.Request.Path.Value, "^/ts", "");
            string servUri = $"http://{AppInit.conf.listen.localhost}:{ModInit.tsport}{pathRequest + HttpContext.Request.QueryString.Value}";

            #region settings
            if (pathRequest.StartsWith("/settings"))
            {
                if (HttpContext.Request.Method != "POST")
                {
                    HttpContext.Response.StatusCode = 404;
                    await HttpContext.Response.WriteAsync("404 page not found", HttpContext.RequestAborted).ConfigureAwait(false);
                    return;
                }

                using (var reader = new StreamReader(HttpContext.Request.Body, Encoding.UTF8, bufferSize: PoolInvk.bufferSize, leaveOpen: true))
                {
                    string requestJson = await reader.ReadToEndAsync().ConfigureAwait(false);

                    if (requestJson.Contains("\"get\""))
                    {
                        var rs = await httpClient.PostAsync("/settings", new StringContent("{\"action\":\"get\"}", Encoding.UTF8, "application/json")).ConfigureAwait(false);
                        await rs.Content.CopyToAsync(HttpContext.Response.Body, HttpContext.RequestAborted).ConfigureAwait(false);
                        return;
                    }
                    else
                    {
                        // Why (auth-gate): previously, `rdb=false` (default) allowed any
                        // authenticated user to rewrite TorrServer settings via the /ts/settings
                        // proxy — TS has no ACL between upstream and the proxy. When
                        // `rdb=true` the settings are treated as read-only unless the caller is
                        // strictly loopback (operator on the host). Keep that behaviour, and
                        // additionally require admin proof (loopback OR rootPasswd cookie OR
                        // X-Signature/X-Timestamp HMAC) for mutating requests when rdb=false.
                        var connFeat = HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpConnectionFeature>();
                        string remoteIp = connFeat?.RemoteIpAddress?.ToString()
                                          ?? HttpContext.Connection.RemoteIpAddress?.ToString();

                        bool isStrictLoopback = Shared.Engine.Utilities.IPNetwork.IsStrictLoopback(remoteIp);
                        bool isAdminCookie =
                            HttpContext.Request.Cookies.TryGetValue("passwd", out string cookiePasswd)
                            && !string.IsNullOrEmpty(AppInit.rootPasswd)
                            && Shared.Engine.CrypTo.FixedTimeEquals(cookiePasswd, AppInit.rootPasswd);
                        bool isHmac = await Shared.Engine.HmacAuth.ValidateAsync(HttpContext.Request).ConfigureAwait(false);

                        bool allowMutation;
                        if (ModInit.conf.rdb)
                            allowMutation = isStrictLoopback;
                        else
                            allowMutation = isStrictLoopback || isAdminCookie || isHmac;

                        if (allowMutation)
                        {
                            await httpClient.PostAsync("/settings", new StringContent(requestJson, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                        }
                        else
                        {
                            HttpContext.Response.StatusCode = 403;
                            await HttpContext.Response.WriteAsync("admin required for TorrServer settings mutation", HttpContext.RequestAborted).ConfigureAwait(false);
                            return;
                        }
                    }

                    await HttpContext.Response.WriteAsync(string.Empty, HttpContext.RequestAborted).ConfigureAwait(false);
                    return;
                }
            }
            #endregion

            #region playlist
            if (pathRequest.StartsWith("/stream/") && HttpContext.Request.QueryString.Value.Contains("&m3u"))
            {
                string m3u = await httpClient.GetStringAsync(servUri).ConfigureAwait(false);
                HttpContext.Response.ContentType = "audio/x-mpegurl; charset=utf-8";
                await HttpContext.Response.WriteAsync((m3u ?? string.Empty).Replace("/stream/", "/ts/stream/"), HttpContext.RequestAborted).ConfigureAwait(false);
                return;
            }
            #endregion

            #region multiaccess
            if (ModInit.conf.multiaccess == "full" || (ModInit.conf.multiaccess == "auth" && user != null))
            {
                if (HttpContext.Request.Method == "POST" && pathRequest == "/torrents" && user?.group != 666)
                {
                    HttpContext.Request.EnableBuffering();
                    using (var readerBody = new StreamReader(HttpContext.Request.Body, Encoding.UTF8, bufferSize: PoolInvk.bufferSize, leaveOpen: true)) // Оставляем поток открытым
                    {
                        string requestJson = await readerBody.ReadToEndAsync().ConfigureAwait(false);

                        if (requestJson.Contains("\"action\":\"add\"") || requestJson.Contains("\"action\":\"list\""))
                        {
                            try
                            {
                                var rs = await httpClient.PostAsync(pathRequest, new StringContent(requestJson, Encoding.UTF8, "application/json")).ConfigureAwait(false);
                                string json = await rs.Content.ReadAsStringAsync().ConfigureAwait(false);

                                string uid = user?.id ?? user?.ids?.FirstOrDefault();
                                HttpContext.Response.ContentType = "application/json; charset=utf-8";

                                if (requestJson.Contains("\"action\":\"add\""))
                                {
                                    #region add
                                    string hash = Regex.Match(json, "\"hash\":\"([^\"]+)\"").Groups[1].Value;
                                    if (!string.IsNullOrEmpty(hash))
                                    {
                                        var doc = ModInit.whosehash.FindById(hash);

                                        if (doc != null)
                                        {
                                            // Why: M-17 — do not let user B hijack user A's torrent by
                                            // re-adding an existing hash. Owner is identified by uid
                                            // when available, otherwise by source IP. If neither matches
                                            // the stored record, reject the add-as-owner attempt with 403
                                            // (the torrent itself was already added on the TS side, but
                                            // we refuse to rewrite ownership metadata).
                                            bool ownerMatches =
                                                (!string.IsNullOrEmpty(uid) && !string.IsNullOrEmpty(doc.uid) && doc.uid == uid) ||
                                                (string.IsNullOrEmpty(doc.uid) && doc.ip == requestInfo.IP);

                                            if (!ownerMatches)
                                            {
                                                HttpContext.Response.StatusCode = 403;
                                                await HttpContext.Response.WriteAsync(string.Empty, HttpContext.RequestAborted).ConfigureAwait(false);
                                                return;
                                            }

                                            // Same owner re-adding — refresh the last-seen IP but keep uid stable.
                                            doc.ip = requestInfo.IP;
                                            if (string.IsNullOrEmpty(doc.uid))
                                                doc.uid = uid;
                                            ModInit.whosehash.Update(doc);
                                        }
                                        else
                                        {
                                            ModInit.whosehash.Insert(new WhoseHashModel
                                            {
                                                id = hash,
                                                ip = requestInfo.IP,
                                                uid = uid
                                            });
                                        }
                                    }

                                    await HttpContext.Response.WriteAsync(json, HttpContext.RequestAborted).ConfigureAwait(false);
                                    return;
                                    #endregion
                                }
                                else
                                {
                                    #region list
                                    var torrents = JArray.Parse(json);

                                    for (int i = torrents.Count - 1; i >= 0; i--)
                                    {
                                        var hash = torrents[i]["hash"]?.ToString();

                                        if (!string.IsNullOrEmpty(hash))
                                        {
                                            var doc = ModInit.whosehash.FindById(hash);

                                            if (doc != null)
                                            {
                                                if (doc.ip == requestInfo.IP || (doc.uid != null && doc.uid == uid)) { }
                                                else
                                                    torrents.RemoveAt(i);
                                            }
                                        }
                                    }

                                    await HttpContext.Response.WriteAsync(torrents.ToString(), HttpContext.RequestAborted).ConfigureAwait(false);
                                    return;
                                    #endregion
                                }
                            }
                            catch { }

                            HttpContext.Response.StatusCode = 503;
                            await HttpContext.Response.WriteAsync(string.Empty, HttpContext.RequestAborted).ConfigureAwait(false);
                            return;
                        }
                    }

                    // Сбрасываем позицию
                    HttpContext.Request.Body.Position = 0;
                }
            }
            #endregion

            var request = CreateProxyHttpRequest(HttpContext, new Uri(servUri));

            var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            await CopyProxyHttpResponse(HttpContext, response).ConfigureAwait(false);
        }
        #endregion


        #region CreateProxyHttpRequest
        HttpRequestMessage CreateProxyHttpRequest(HttpContext context, Uri uri)
        {
            var request = context.Request;

            var requestMessage = new HttpRequestMessage();
            var requestMethod = request.Method;

            // Attach body for any method that may carry one (not GET/HEAD/OPTIONS/CONNECT/TRACE)
            bool methodAllowsBody = !HttpMethods.IsGet(requestMethod)
                                    && !HttpMethods.IsHead(requestMethod)
                                    && !HttpMethods.IsOptions(requestMethod)
                                    && !string.Equals(requestMethod, "CONNECT", StringComparison.OrdinalIgnoreCase)
                                    && !string.Equals(requestMethod, "TRACE", StringComparison.OrdinalIgnoreCase);

            bool hasBody = request.ContentLength > 0
                           || request.Headers.ContainsKey("Transfer-Encoding");

            if (methodAllowsBody && hasBody)
            {
                var streamContent = new StreamContent(request.Body);
                requestMessage.Content = streamContent;
            }

            foreach (var header in request.Headers)
            {
                if (header.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()) && requestMessage.Content != null)
                    requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }

            requestMessage.Headers.Host = string.IsNullOrEmpty(AppInit.conf.listen.host) ? context.Request.Host.Value : AppInit.conf.listen.host;
            requestMessage.RequestUri = uri;
            requestMessage.Method = new HttpMethod(request.Method);

            return requestMessage;
        }
        #endregion

        #region CopyProxyHttpResponse
        async Task CopyProxyHttpResponse(HttpContext context, HttpResponseMessage responseMessage)
        {
            var response = context.Response;
            response.StatusCode = (int)responseMessage.StatusCode;

            #region UpdateHeaders
            void UpdateHeaders(HttpHeaders headers)
            {
                foreach (var header in headers)
                {
                    if (header.Key.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase) ||
                        header.Key.Equals("etag", StringComparison.OrdinalIgnoreCase) ||
                        header.Key.Equals("connection", StringComparison.OrdinalIgnoreCase) ||
                        header.Key.Equals("content-security-policy", StringComparison.OrdinalIgnoreCase) ||
                        header.Key.Equals("content-disposition", StringComparison.OrdinalIgnoreCase))
                        continue;

                    response.Headers[header.Key] = header.Value.ToArray();
                }
            }
            #endregion

            UpdateHeaders(responseMessage.Headers);
            UpdateHeaders(responseMessage.Content.Headers);

            var responseStream = await responseMessage.Content.ReadAsStreamAsync().ConfigureAwait(false);

            if (response.Body == null)
                throw new ArgumentNullException("destination");

            if (!responseStream.CanRead && !responseStream.CanWrite)
                throw new ObjectDisposedException("ObjectDisposed_StreamClosed");

            if (!response.Body.CanRead && !response.Body.CanWrite)
                throw new ObjectDisposedException("ObjectDisposed_StreamClosed");

            if (!responseStream.CanRead || !response.Body.CanWrite)
                throw new NotSupportedException("NotSupported_UnreadableStream");

            byte[] buffer = ArrayPool<byte>.Shared.Rent(PoolInvk.rentChunk);

            try
            {
                int bytesRead;

                while ((bytesRead = await responseStream.ReadAsync(buffer, context.RequestAborted).ConfigureAwait(false)) != 0)
                    await response.Body.WriteAsync(buffer, 0, bytesRead, context.RequestAborted).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        #endregion
    }
}
