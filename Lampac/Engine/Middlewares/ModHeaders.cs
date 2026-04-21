using Microsoft.AspNetCore.Http;
using Shared;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Lampac.Engine.Middlewares
{
    public class ModHeaders
    {
        private readonly RequestDelegate _next;
        public ModHeaders(RequestDelegate next)
        {
            _next = next;
        }

        public Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Path.Value.StartsWith("/cors/check", StringComparison.OrdinalIgnoreCase))
                return Task.CompletedTask;

            httpContext.Response.Headers["Access-Control-Allow-Private-Network"] = "true";
            httpContext.Response.Headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS";

            if (GetAllowHeaders(httpContext, out HashSet<string> allowHeadersSet))
                httpContext.Response.Headers["Access-Control-Allow-Headers"] = string.Join(", ", allowHeadersSet);
            else
                httpContext.Response.Headers["Access-Control-Allow-Headers"] = stringAllowHeaders;

            // Previously the middleware reflected the caller's Origin and
            // emitted Access-Control-Allow-Credentials: true unconditionally,
            // allowing any site on the internet to read authenticated JSON
            // responses from this server. The new policy reflects Origin and
            // adds Credentials only when the Origin matches a configured
            // allow-list; everything else gets a credentials-less "*" so the
            // browser refuses to expose cookies cross-origin per CORS spec.
            string reqOrigin = null;
            if (httpContext.Request.Headers.TryGetValue("origin", out var origin) && !string.IsNullOrEmpty(origin))
                reqOrigin = GetOrigin(origin);
            else if (httpContext.Request.Headers.TryGetValue("referer", out var referer) && !string.IsNullOrEmpty(referer))
                reqOrigin = GetOrigin(referer);

            if (!string.IsNullOrEmpty(reqOrigin) && IsAllowedOrigin(reqOrigin))
            {
                httpContext.Response.Headers["Access-Control-Allow-Origin"] = reqOrigin;
                httpContext.Response.Headers["Access-Control-Allow-Credentials"] = "true";
                httpContext.Response.Headers["Vary"] = "Origin";
            }
            else
            {
                httpContext.Response.Headers["Access-Control-Allow-Origin"] = "*";
                // Do not set Allow-Credentials with "*" — browsers reject it.
            }

            if (Regex.IsMatch(httpContext.Request.Path.Value, "^/(lampainit|sisi|lite|online|tmdbproxy|cubproxy|tracks|transcoding|dlna|timecode|bookmark|catalog|sync|backup|ts|invc-ws)\\.js", RegexOptions.IgnoreCase) ||
                Regex.IsMatch(httpContext.Request.Path.Value, "^/(on/|(lite|online|sisi|timecode|bookmark|sync|tmdbproxy|dlna|ts|tracks|transcoding|backup|catalog|invc-ws)/js/)", RegexOptions.IgnoreCase))
            {
                httpContext.Response.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate"; // HTTP 1.1.
                httpContext.Response.Headers["Pragma"] = "no-cache"; // HTTP 1.0.
                httpContext.Response.Headers["Expires"] = "0"; // Proxies.
            }

            if (HttpMethods.IsOptions(httpContext.Request.Method))
                return Task.CompletedTask;

            return _next(httpContext);
        }


        static readonly string stringAllowHeaders = "Authorization, Token, Profile, X-Kit-AesGcm, Content-Type, X-Signalr-User-Agent, X-Requested-With";

        static readonly HashSet<string> hashAllowHeaders = new HashSet<string>(
        [
            "Authorization", "Token", "Profile", "X-Kit-AesGcm",
            "Content-Type", "X-Signalr-User-Agent", "X-Requested-With"
        ], StringComparer.OrdinalIgnoreCase);


        static bool GetAllowHeaders(HttpContext httpContext, out HashSet<string> headersSet)
        {
            if (httpContext.Request.Headers.TryGetValue("Access-Control-Request-Headers", out var requestedHeaders))
            {
                headersSet = [.. hashAllowHeaders];

                foreach (string header in requestedHeaders.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!string.IsNullOrWhiteSpace(header))
                        headersSet.Add(header.Trim());
                }

                return true;
            }

            headersSet = null;
            return false;
        }

        static string GetOrigin(string url)
        {
            if (string.IsNullOrEmpty(url))
                return string.Empty;

            int scheme = url.IndexOf("://", StringComparison.Ordinal);
            if (scheme <= 0)
                return url;

            int start = scheme + 3;
            int slash = url.IndexOf('/', start);
            if (slash < 0)
                return url; // уже origin

            return url.Substring(0, slash);
        }

        static bool IsAllowedOrigin(string origin)
        {
            var allow = AppInit.conf?.cors?.allowOrigins;
            if (allow == null || allow.Length == 0)
                return false;

            foreach (string entry in allow)
            {
                if (string.IsNullOrEmpty(entry))
                    continue;

                if (string.Equals(origin, entry, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}
