using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Shared.Engine
{
    /// <summary>
    /// HMAC-SHA256 request authentication for admin endpoints (M-27 fix).
    /// Clients send X-Signature and X-Timestamp headers; signature is computed over
    /// a canonical string: METHOD|path|sorted-query|unix-timestamp. Server validates
    /// within a ±60s skew window. Key derives lazily from AppInit.rootPasswd.
    /// </summary>
    public static class HmacAuth
    {
        public const string TimestampHeader = "X-Timestamp";
        public const string SignatureHeader = "X-Signature";
        const int MaxSkewSeconds = 60;

        // Why: rootPasswd is set in Program.Run() after static constructors, so derive lazily.
        // Pattern mirrors Shared/Engine/ProxyLink.cs:20-31.
        static volatile byte[] _key;
        static byte[] Key
        {
            get
            {
                if (_key == null)
                    _key = SHA256.HashData(Encoding.UTF8.GetBytes((AppInit.rootPasswd ?? "fallback") + "|hmacauth"));
                return _key;
            }
        }

        public static bool Validate(HttpRequest req)
        {
            if (req == null)
                return false;

            if (!req.Headers.TryGetValue(SignatureHeader, out var sigValues) || sigValues.Count == 0)
                return false;
            if (!req.Headers.TryGetValue(TimestampHeader, out var tsValues) || tsValues.Count == 0)
                return false;

            if (!long.TryParse(tsValues[0], out long unix))
                return false;

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(now - unix) > MaxSkewSeconds)
                return false;

            byte[] provided;
            try { provided = Convert.FromHexString(sigValues[0]); }
            catch { return false; }

            string canonical = $"{req.Method}|{req.Path.Value}|{CanonicalQuery(req.Query)}|{unix}";

            using var h = new HMACSHA256(Key);
            byte[] expected = h.ComputeHash(Encoding.UTF8.GetBytes(canonical));

            return CryptographicOperations.FixedTimeEquals(expected, provided);
        }

        // Why: ordinal-sorted keys + URL-encoded key/value so client and server agree
        // on a single canonical form regardless of how the HTTP transport reordered them.
        static string CanonicalQuery(IQueryCollection q)
        {
            if (q == null || q.Count == 0)
                return string.Empty;

            var sb = new StringBuilder();
            bool first = true;
            foreach (var kv in q.OrderBy(x => x.Key, StringComparer.Ordinal))
            {
                foreach (var val in kv.Value)
                {
                    if (!first) sb.Append('&');
                    first = false;
                    sb.Append(HttpUtility.UrlEncode(kv.Key));
                    sb.Append('=');
                    sb.Append(HttpUtility.UrlEncode(val));
                }
            }
            return sb.ToString();
        }
    }
}
