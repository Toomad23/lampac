using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace Shared.Engine
{
    /// <summary>
    /// HMAC-SHA256 request authentication for admin endpoints (M-27 fix, round5 hardening).
    ///
    /// Clients send X-Signature and X-Timestamp headers. The server validates within a
    /// ±60s skew window. The signing key is derived from AppInit.rootPasswd — if
    /// rootPasswd is null/empty/whitespace the module is fail-closed (Validate returns
    /// false, Key throws).
    ///
    /// Canonical string format (UTF-8):
    ///     METHOD|path|sorted-query|unix-timestamp|hex(sha256(body))
    ///
    ///   METHOD          — HTTP method, verbatim ("GET", "POST", ...)
    ///   path            — HttpRequest.Path.Value (no scheme/host, no query)
    ///   sorted-query    — query keys sorted Ordinal; each "key=value" URL-encoded;
    ///                     joined with '&'. Empty string if no query.
    ///   unix-timestamp  — same integer sent in X-Timestamp
    ///   hex(sha256(body)) — lowercase hex SHA-256 of the raw request body bytes.
    ///                     Empty string when there is no body (e.g. GET, HEAD).
    ///
    /// Signature: HMAC-SHA256(key, canonical) encoded as lowercase hex, placed in X-Signature.
    ///
    /// IMPORTANT for callers: ValidateAsync buffers the request body via
    /// HttpRequest.EnableBuffering() before reading so MVC model binding downstream
    /// still works. Validate(HttpRequest) remains for backward compat but skips the
    /// body hash (treats body as empty) — only use it on methods without a body.
    /// </summary>
    public static class HmacAuth
    {
        public const string TimestampHeader = "X-Timestamp";
        public const string SignatureHeader = "X-Signature";
        const int MaxSkewSeconds = 60;

        // Why: rootPasswd is set in Program.Run() after static constructors, so derive lazily.
        // Pattern mirrors Shared/Engine/ProxyLink.cs:20-31.
        // Fail-closed: if rootPasswd is null/empty, the property throws so callers that
        // reach HMAC code on a misconfigured install cannot accidentally use the old
        // deterministic "fallback|hmacauth" key that anyone could forge.
        static volatile byte[] _key;
        static byte[] Key
        {
            get
            {
                if (_key == null)
                {
                    string p = AppInit.rootPasswd;
                    if (string.IsNullOrWhiteSpace(p))
                        throw new InvalidOperationException("HmacAuth: AppInit.rootPasswd is not set; refusing to derive a deterministic fallback key.");

                    _key = SHA256.HashData(Encoding.UTF8.GetBytes(p + "|hmacauth"));
                }
                return _key;
            }
        }

        /// <summary>
        /// True when rootPasswd is configured and HMAC validation can be performed.
        /// Callers can use this at startup to emit a one-shot warning.
        /// </summary>
        public static bool IsConfigured => !string.IsNullOrWhiteSpace(AppInit.rootPasswd);

        /// <summary>
        /// Preferred entry point — buffers the body, computes sha256 over it, then
        /// verifies the signature. Safe to call before MVC model binding reads the body.
        /// </summary>
        public static async Task<bool> ValidateAsync(HttpRequest req)
        {
            if (req == null)
                return false;

            if (!TryReadHeaders(req, out long unix, out byte[] provided))
                return false;

            string bodyHashHex = await ComputeBodyHashHexAsync(req).ConfigureAwait(false);

            return Verify(req, unix, provided, bodyHashHex);
        }

        /// <summary>
        /// Legacy/body-less entry point. Does NOT hash the request body — treats it
        /// as empty. Safe only for methods that carry no body (GET/HEAD/OPTIONS with
        /// no payload). Prefer ValidateAsync for anything that may have a body.
        /// </summary>
        public static bool Validate(HttpRequest req)
        {
            if (req == null)
                return false;

            if (!TryReadHeaders(req, out long unix, out byte[] provided))
                return false;

            // Empty body hash — canonical string uses "" in that slot.
            return Verify(req, unix, provided, string.Empty);
        }

        static bool TryReadHeaders(HttpRequest req, out long unix, out byte[] provided)
        {
            unix = 0;
            provided = null;

            if (!IsConfigured)
                return false;

            if (!req.Headers.TryGetValue(SignatureHeader, out var sigValues) || sigValues.Count == 0)
                return false;
            if (!req.Headers.TryGetValue(TimestampHeader, out var tsValues) || tsValues.Count == 0)
                return false;

            if (!long.TryParse(tsValues[0], out unix))
                return false;

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(now - unix) > MaxSkewSeconds)
                return false;

            try { provided = Convert.FromHexString(sigValues[0]); }
            catch { return false; }

            return true;
        }

        static bool Verify(HttpRequest req, long unix, byte[] provided, string bodyHashHex)
        {
            byte[] key;
            try { key = Key; }
            catch { return false; } // fail-closed if rootPasswd missing

            string canonical = $"{req.Method}|{req.Path.Value}|{CanonicalQuery(req.Query)}|{unix}|{bodyHashHex}";

            using var h = new HMACSHA256(key);
            byte[] expected = h.ComputeHash(Encoding.UTF8.GetBytes(canonical));

            return CryptographicOperations.FixedTimeEquals(expected, provided);
        }

        static async Task<string> ComputeBodyHashHexAsync(HttpRequest req)
        {
            // No body at all (GET / HEAD / OPTIONS without payload) → empty hash slot.
            if (req.ContentLength == 0 ||
                (req.ContentLength == null && !req.Headers.ContainsKey("Transfer-Encoding")))
            {
                return string.Empty;
            }

            // Buffer so MVC can re-read the body after we consume it.
            req.EnableBuffering();

            if (req.Body.CanSeek)
                req.Body.Position = 0;

            using (var sha = SHA256.Create())
            {
                byte[] buf = new byte[8192];
                int read;
                while ((read = await req.Body.ReadAsync(buf.AsMemory(0, buf.Length)).ConfigureAwait(false)) > 0)
                    sha.TransformBlock(buf, 0, read, null, 0);
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                if (req.Body.CanSeek)
                    req.Body.Position = 0;

                return Convert.ToHexString(sha.Hash).ToLowerInvariant();
            }
        }

        // Why: reusable HMAC-SHA256 compute for non-request payloads (e.g. KurwaCron
        // script integrity). Returns the raw MAC; callers compare with
        // CryptographicOperations.FixedTimeEquals against an expected hex / base64
        // sidecar. Decoupled from the request-signature path so we don't leak the
        // AppInit.rootPasswd-derived key into arbitrary verification contexts.
        public static byte[] HmacCompute(byte[] key, byte[] body)
        {
            if (key == null || body == null)
                return null;

            using var h = new HMACSHA256(key);
            return h.ComputeHash(body);
        }

        public static bool HmacVerify(byte[] key, byte[] body, byte[] expected)
        {
            if (key == null || body == null || expected == null)
                return false;

            byte[] computed = HmacCompute(key, body);
            if (computed == null || computed.Length != expected.Length)
                return false;

            return CryptographicOperations.FixedTimeEquals(computed, expected);
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
