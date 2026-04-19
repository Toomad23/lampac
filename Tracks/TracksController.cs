using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shared;
using Shared.Engine;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace Tracks.Controllers
{
    public class TracksController : BaseController
    {
        [HttpGet]
        [AllowAnonymous]
        [Route("tracks.js")]
        [Route("tracks/js/{token}")]
        public ActionResult Tracks(string token)
        {
            if (!AppInit.conf.ffprobe.enable)
                return Content(string.Empty);

            var sb = new StringBuilder(FileCache.ReadAllText("plugins/tracks.js"));

            sb.Replace("{localhost}", host)
              .Replace("{token}", HttpUtility.UrlEncode(token));

            return Content(sb.ToString(), "application/javascript; charset=utf-8");
        }


        [HttpGet]
        [Route("ffprobe")]
        async public Task<ActionResult> Ffprobe(string media, bool showerror)
        {
            if (!AppInit.conf.ffprobe.enable || string.IsNullOrWhiteSpace(media) || !media.StartsWith("http") || media.Contains("/transcoding/"))
                return ContentTo("{}");

            return ContentTo(await FfprobeJson(host, HttpContext, hybridCache, media));
        }


        public static async Task<string> FfprobeJson(string host, HttpContext httpContext, IHybridCache hybridCache, string media, bool showerror = false)
        {
            string magnethash = null;

            if (media.Contains("/dlna/stream"))
            {
                string path = Regex.Match(media, "\\?path=([^&]+)").Groups[1].Value;

                // Why: M-21 — without canonicalisation "?path=..%2F..%2Fetc%2Fpasswd" probes
                // arbitrary filesystem locations via the "path" vs "{}" response, giving the
                // caller a filesystem-enumeration oracle. Canonicalise both the base dir and
                // the resolved candidate and require the candidate to live under the base.
                bool insideDlna = false;
                try
                {
                    string decoded = HttpUtility.UrlDecode(path) ?? string.Empty;
                    string dlnaRoot = System.IO.Path.GetFullPath("dlna") + System.IO.Path.DirectorySeparatorChar;
                    string candidate = System.IO.Path.GetFullPath(System.IO.Path.Combine("dlna", decoded));

                    insideDlna = candidate.StartsWith(dlnaRoot, StringComparison.Ordinal) &&
                                 System.IO.File.Exists(candidate);
                }
                catch
                {
                    insideDlna = false;
                }

                if (!insideDlna)
                    return showerror ? "path" : "{}";

                magnethash = path;
            }
            else if (media.Contains("/stream/") || media.Contains("/lite/pidtor/"))
            {
                media = Regex.Replace(media, "[^a-z0-9_:\\-\\/\\.\\=\\?\\&\\%\\@]+", "", RegexOptions.IgnoreCase);

                if (media.Contains("/stream/") && !string.IsNullOrWhiteSpace(AppInit.conf.ffprobe.tsuri))
                    media = Regex.Replace(media, "^https?://[^/]+", AppInit.conf.ffprobe.tsuri, RegexOptions.IgnoreCase);
            }
            else if (media.Contains("/proxy/") && media.Contains(".mkv"))
            {
                string hash = Regex.Match(media, "/proxy/([^\n\r]+\\.mkv)").Groups[1].Value;
                media = ProxyLink.Decrypt(hash, null)?.uri;
                if (string.IsNullOrWhiteSpace(media))
                    return showerror ? "media" : "{}";
            }

            string argumentList = string.Empty;

            string memKey = $"tracks:ffprobe:{media}";
            if (!hybridCache.TryGetValue(memKey, out string outPut, inmemory: false))
            {
                #region getFolder
                static string getFolder(string magnethash)
                {
                    return $"database/tracks/{magnethash}";
                }
                #endregion

                if (media.Contains("/stream/"))
                {
                    magnethash = Regex.Match(media, "link=([a-z0-9]+)").Groups[1].Value;
                    string index = Regex.Match(media, @"index=([0-9]+)", RegexOptions.IgnoreCase).Groups[1].Value;

                    if (!string.IsNullOrWhiteSpace(magnethash))
                        magnethash = $"{magnethash}_{index}";
                }
                else if (media.Contains("/lite/pidtor/"))
                {
                    magnethash = Regex.Match(media, "/lite/pidtor/s([a-z0-9]+)").Groups[1].Value;
                    string index = Regex.Match(media, @"tsid=([0-9]+)", RegexOptions.IgnoreCase).Groups[1].Value;

                    if (!string.IsNullOrWhiteSpace(magnethash))
                        magnethash = $"{magnethash}_{index}";
                }

                if (string.IsNullOrEmpty(magnethash))
                    magnethash = CrypTo.md5(media);

                if (System.IO.File.Exists(getFolder(magnethash)))
                    outPut = await BrotliTo.DecompressAsync(getFolder(magnethash));

                if (string.IsNullOrWhiteSpace(outPut))
                {
                    if (!Uri.TryCreate(media, UriKind.Absolute, out var uri) ||
                        (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                        return showerror ? "uri" : "{}";

                    // SSRF guard: without a host allow-list /ffprobe would happily
                    // hand an arbitrary http(s) URL (including 169.254.169.254,
                    // intranet admin UIs, etc.) to the ffprobe subprocess.
                    // Reject private/loopback/link-local unconditionally, and if
                    // ffprobe.allowHosts is configured, require the host to match.
                    if (!Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriBasic(uri.AbsoluteUri))
                        return showerror ? "uri" : "{}";

                    var ffconf = AppInit.conf.ffprobe;
                    if (ffconf.allowHosts != null && ffconf.allowHosts.Length > 0 &&
                        !ffconf.allowHosts.Contains(uri.Host, System.StringComparer.OrdinalIgnoreCase))
                        return showerror ? "host" : "{}";

                    // HIGH-5: ffprobe follows 3xx by default, so even when the initial host passes
                    // SsrfGuard an attacker-controlled public endpoint can 302 to
                    // http://169.254.169.254 / http://127.0.0.1 / internal services. Resolve the
                    // final URL via HttpClient with AllowAutoRedirect=false, revalidating every
                    // hop with SsrfGuard before handing the URL to the ffprobe subprocess.
                    string resolvedUri = await ResolveSafeRedirectsAsync(uri.AbsoluteUri, ffconf.allowHosts);
                    if (string.IsNullOrEmpty(resolvedUri))
                        return showerror ? "redirect" : "{}";

                    var process = new System.Diagnostics.Process();
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.StandardOutputEncoding = Encoding.UTF8;
                    process.StartInfo.FileName = AppInit.Win32NT ? "data/ffprobe.exe" : System.IO.File.Exists("data/ffprobe") ? "data/ffprobe" : "ffprobe";

                    process.StartInfo.ArgumentList.Add("-v");
                    process.StartInfo.ArgumentList.Add("quiet");
                    process.StartInfo.ArgumentList.Add("-print_format");
                    process.StartInfo.ArgumentList.Add("json");
                    process.StartInfo.ArgumentList.Add("-show_format");
                    process.StartInfo.ArgumentList.Add("-show_streams");
                    // HIGH-5: harden protocols and disable reconnect/seek behaviour that could
                    // otherwise be steered onto internal services via side channels.
                    process.StartInfo.ArgumentList.Add("-protocol_whitelist");
                    process.StartInfo.ArgumentList.Add("http,https,tls,tcp");
                    process.StartInfo.ArgumentList.Add("-reconnect");
                    process.StartInfo.ArgumentList.Add("0");
                    process.StartInfo.ArgumentList.Add("-reconnect_streamed");
                    process.StartInfo.ArgumentList.Add("0");
                    process.StartInfo.ArgumentList.Add("-seekable");
                    process.StartInfo.ArgumentList.Add("0");
                    process.StartInfo.ArgumentList.Add(AccsDbInvk.Args(resolvedUri, httpContext));

                    argumentList = process.StartInfo.FileName + " " + string.Join(" ", process.StartInfo.ArgumentList);

                    process.Start();

                    outPut = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();

                    if (outPut == null)
                        outPut = string.Empty;

                    if (Regex.Replace(outPut, "[\n\r\t ]+", "") == "{}")
                        outPut = string.Empty;

                    if (!string.IsNullOrWhiteSpace(outPut) && !string.IsNullOrWhiteSpace(magnethash))
                    {
                        await BrotliTo.CompressAsync(getFolder(magnethash), outPut);
                    }
                    else
                    {
                        // заглушка
                        hybridCache.Set(memKey, outPut, DateTime.Now.AddMinutes(AppInit.conf.multiaccess ? 20 : 1), inmemory: false);
                    }
                }
            }

            return string.IsNullOrEmpty(outPut) ? (showerror ? argumentList : "{}") : outPut;
        }


        // HIGH-5: manually resolve HTTP redirects BEFORE invoking ffprobe. Every hop (including
        // the initial URL) must pass SsrfGuard so an attacker cannot redirect ffprobe onto
        // loopback/metadata/internal services, and the optional ffprobe.allowHosts list is
        // re-applied at each hop. Returns null if any hop is unsafe or the chain is too long.
        private static readonly HttpClient _redirectProbeClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None
        })
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        static async Task<string> ResolveSafeRedirectsAsync(string startUri, string[] allowHosts)
        {
            const int maxHops = 3;
            string current = startUri;

            for (int hop = 0; hop <= maxHops; hop++)
            {
                if (!Shared.Engine.Utilities.SsrfGuard.IsAllowedPublicUriBasic(current))
                    return null;

                if (allowHosts != null && allowHosts.Length > 0)
                {
                    if (!Uri.TryCreate(current, UriKind.Absolute, out var parsed))
                        return null;
                    if (!allowHosts.Contains(parsed.Host, StringComparer.OrdinalIgnoreCase))
                        return null;
                }

                HttpResponseMessage resp;
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Head, current);
                    resp = await _redirectProbeClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                }
                catch
                {
                    // Upstream may reject HEAD; accept the URL as-is (ffprobe itself will fail
                    // cleanly on unreachable targets — important: do NOT follow an unknown
                    // redirect we couldn't verify).
                    return current;
                }

                try
                {
                    int code = (int)resp.StatusCode;
                    if (code < 300 || code >= 400 || resp.Headers.Location == null)
                        return current;

                    Uri next = resp.Headers.Location.IsAbsoluteUri
                        ? resp.Headers.Location
                        : new Uri(new Uri(current), resp.Headers.Location);

                    if (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps)
                        return null;

                    current = next.AbsoluteUri;
                }
                finally
                {
                    resp.Dispose();
                }
            }

            // Too many hops — treat as unsafe.
            return null;
        }
    }
}
