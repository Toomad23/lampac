using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared;
using Shared.Engine;
using Shared.Models;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IO = System.IO.File;

namespace Merchant.Controllers
{
    /// <summary>
    /// https://app.cryptocloud.plus/integration/api
    /// </summary>
    public class CryptoCloud : MerchantController
    {
        static CryptoCloud() { Directory.CreateDirectory("merchant/invoice/cryptocloud"); }

        // Why: fields dropped from postback log to avoid leaking the JWT token (forgery-enabler),
        // HMAC signatures, and user PII (email). Matches L-17 audit finding.
        static readonly HashSet<string> _sensitiveLogKeys = new(StringComparer.OrdinalIgnoreCase)
        {
            "token", "signature", "sign", "hmac", "email"
        };


        [HttpGet]
        [AllowAnonymous]
        [Route("cryptocloud/invoice/create")]
        async public Task<ActionResult> Index(string email)
        {
            if (!AppInit.conf.Merchant.CryptoCloud.enable || string.IsNullOrWhiteSpace(email))
                return Content(string.Empty);

            email = decodeEmail(email);

            Dictionary<string, string> postParams = new Dictionary<string, string>()
            {
                ["amount"] = AppInit.conf.Merchant.accessCost.ToString(),
                ["shop_id"] = AppInit.conf.Merchant.CryptoCloud.SHOPID,
                //["currency"] = "USD",
                //["order_id"] = CrypTo.md5(DateTime.Now.ToBinary().ToString()),
                ["email"] = email
            };

            if (memoryCache.TryGetValue($"cryptocloud:{email}", out string pay_url))
            {
                // HIGH-8: re-verify cached pay_url host before redirect — a cache entry poisoned
                // (or left over from a compromised PSP response) must not silently send users
                // to a phishing domain.
                if (!IsAllowedCryptoCloudRedirect(pay_url))
                    return Content("pay_url host not allowed");
                return Redirect(pay_url);
            }

            // Why: L-16 — PSP outbound must go through StrictHttpClient (default TLS validation),
            // not Shared.Engine.Http (which disables certificate validation globally).
            JObject root = null;
            try
            {
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, "https://api.cryptocloud.plus/v1/invoice/create")
                {
                    Content = new System.Net.Http.FormUrlEncodedContent(postParams)
                };
                req.Headers.TryAddWithoutValidation("Authorization", $"Token {AppInit.conf.Merchant.CryptoCloud.APIKEY}");
                using var resp = await StrictHttpClient.SendAsync(req);
                if (resp.IsSuccessStatusCode)
                {
                    string body = await resp.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body))
                        root = JsonConvert.DeserializeObject<JObject>(body);
                }
            }
            catch { }

            if (root == null || !root.ContainsKey("pay_url"))
                return Content("root == null");

            pay_url = root.Value<string>("pay_url");
            if (string.IsNullOrWhiteSpace(pay_url))
                return Content("pay_url == null");

            // HIGH-8: verify the pay_url host matches a CryptoCloud-owned domain before 302-ing
            // users. A MitM'd or compromised PSP response could otherwise walk the user onto
            // a phishing page "attached" to the legitimate checkout flow.
            if (!IsAllowedCryptoCloudRedirect(pay_url))
                return Content("pay_url host not allowed");

            memoryCache.Set($"cryptocloud:{email}", pay_url, DateTime.Now.AddHours(2));

            string invoicePath = $"merchant/invoice/cryptocloud/{root.Value<string>("invoice_id")}";
            IO.WriteAllText(invoicePath, JsonConvert.SerializeObject(postParams));

            // Why: the invoice file stores the buyer email; restrict to 0600 on Unix so other local
            // users cannot harvest it. Windows permissions left to the host admin (parity with Scraping.cs).
            TryRestrictToOwner(invoicePath);

            return Redirect(pay_url);
        }


        // HIGH-8: host allow-list for CryptoCloud redirects. CryptoCloud production checkout lives
        // on pay.cryptocloud.plus; api/app subdomains are included in case they are returned for
        // legacy flows. Subdomain match is enforced via case-insensitive suffix check.
        static readonly string[] _cryptoCloudHosts = new[]
        {
            "cryptocloud.plus",
            "pay.cryptocloud.plus",
            "app.cryptocloud.plus"
        };

        static bool IsAllowedCryptoCloudRedirect(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed))
                return false;
            if (parsed.Scheme != Uri.UriSchemeHttps)
                return false;
            string host = parsed.Host;
            foreach (string allowed in _cryptoCloudHosts)
            {
                if (host.Equals(allowed, StringComparison.OrdinalIgnoreCase))
                    return true;
                if (host.EndsWith("." + allowed, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }


        [HttpPost]
        [AllowAnonymous]
        [Route("cryptocloud/callback")]
        async public Task<ActionResult> Callback(string invoice_id)
        {
            if (!AppInit.conf.Merchant.CryptoCloud.enable || string.IsNullOrWhiteSpace(invoice_id) || !IO.Exists($"merchant/invoice/cryptocloud/{invoice_id}"))
                return StatusCode(403);

            var form = HttpContext.Request.Form;

            // Why: H-21. Log BEFORE verification so suspicious traffic is still recorded, but redact
            // token/signature/email so a stolen log file cannot be replayed against this endpoint.
            WriteLog("cryptocloud", RedactForLog(form));

            // Why: H-21. Require the `token` JWT signed with SECRETKEY (HS256 per CryptoCloud docs).
            // Without this, any attacker who learns an invoice_id can drive PayConfirm.
            string token = form["token"].ToString();
            string secretKey = AppInit.conf.Merchant.CryptoCloud.SECRETKEY;
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(secretKey))
                return StatusCode(403);

            JObject jwtPayload = VerifyAndDecodeJwt(token, secretKey);
            if (jwtPayload == null)
                return StatusCode(403);

            // Why: bind the JWT to THIS request's invoice_id. CryptoCloud tokens carry the invoice id
            // in `id` as "INV-<uuid>". Without this check a token for one invoice could be replayed
            // against another (known-invoice-id confused-deputy).
            string jwtInvoiceId = jwtPayload.Value<string>("id") ?? string.Empty;
            string expectedInvoiceId = invoice_id.StartsWith("INV-", StringComparison.OrdinalIgnoreCase)
                ? invoice_id
                : "INV-" + invoice_id;
            if (!CrypTo.FixedTimeEquals(jwtInvoiceId, expectedInvoiceId))
                return StatusCode(403);

            // Why: L-16 — PSP outbound must go through StrictHttpClient so the
            // api.cryptocloud.plus certificate is actually validated. Using Shared.Engine.Http
            // here would accept a MitM cert and let an attacker forge a "paid" invoice lookup.
            JObject root = null;
            try
            {
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, "https://api.cryptocloud.plus/v1/invoice/info?uuid=INV-" + invoice_id);
                req.Headers.TryAddWithoutValidation("Authorization", $"Token {AppInit.conf.Merchant.CryptoCloud.APIKEY}");
                using var resp = await StrictHttpClient.SendAsync(req);
                if (resp.IsSuccessStatusCode)
                {
                    string body = await resp.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body))
                        root = JsonConvert.DeserializeObject<JObject>(body);
                }
            }
            catch { }

            if (root == null || root.Value<string>("status") != "success")
                return StatusCode(403);

            if (root.Value<string>("status_invoice") is not ("paid" or "overpaid"))
                return StatusCode(403);

            // Why: H-22. Verify the buyer actually paid at least accessCost (USD). Prefer the
            // authoritative fiat amount from invoice/info; fall back to the postback fields
            // (amount / amount_crypto) if the server-side response schema has changed.
            double paidUsd = ExtractFiatAmount(root, form);
            int expected = AppInit.conf.Merchant.accessCost;
            int tolerance = AppInit.conf.Merchant.allowedDifference;
            double minAccepted = tolerance > 0 ? (expected - tolerance) : expected;
            if (paidUsd <= 0 || paidUsd < minAccepted)
                return StatusCode(403);

            var invoice = JsonConvert.DeserializeObject<Dictionary<string, string>>(IO.ReadAllText($"merchant/invoice/cryptocloud/{invoice_id}"));
            PayConfirm(invoice["email"], "cryptocloud", invoice_id);

            return StatusCode(200);
        }


        #region helpers

        // Why: redact sensitive fields (token, signature, email) before writing to the append-only log.
        static string RedactForLog(Microsoft.AspNetCore.Http.IFormCollection form)
        {
            var redacted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in form)
            {
                if (_sensitiveLogKeys.Contains(kv.Key))
                    redacted[kv.Key] = "[REDACTED]";
                else
                    redacted[kv.Key] = kv.Value.ToString();
            }
            return JsonConvert.SerializeObject(redacted);
        }

        // Why: minimal HS256 JWT verifier (the project has no JWT library referenced here, so decoding
        // by hand avoids pulling in a new dep). Returns the decoded payload JObject on success, null
        // on any failure (bad shape, wrong alg, bad base64, bad signature, bad JSON).
        static JObject VerifyAndDecodeJwt(string token, string secretKey)
        {
            try
            {
                string[] parts = token.Split('.');
                if (parts.Length != 3)
                    return null;

                string headerJson = Base64UrlDecodeToString(parts[0]);
                string payloadJson = Base64UrlDecodeToString(parts[1]);
                byte[] providedSig = Base64UrlDecodeToBytes(parts[2]);
                if (headerJson == null || payloadJson == null || providedSig == null)
                    return null;

                var header = JsonConvert.DeserializeObject<JObject>(headerJson);
                if (header == null)
                    return null;

                // Accept only HS256 — reject "none", RS*, ES*, etc. to avoid alg-confusion.
                string alg = header.Value<string>("alg");
                if (!string.Equals(alg, "HS256", StringComparison.Ordinal))
                    return null;

                byte[] signingInput = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
                byte[] expectedSig = hmac.ComputeHash(signingInput);

                if (!CryptographicOperations.FixedTimeEquals(expectedSig, providedSig))
                    return null;

                return JsonConvert.DeserializeObject<JObject>(payloadJson);
            }
            catch
            {
                return null;
            }
        }

        static string Base64UrlDecodeToString(string value)
        {
            byte[] bytes = Base64UrlDecodeToBytes(value);
            return bytes == null ? null : Encoding.UTF8.GetString(bytes);
        }

        static byte[] Base64UrlDecodeToBytes(string value)
        {
            if (string.IsNullOrEmpty(value))
                return null;
            try
            {
                string padded = value.Replace('-', '+').Replace('_', '/');
                switch (padded.Length % 4)
                {
                    case 1: return null;
                    case 2: padded += "=="; break;
                    case 3: padded += "="; break;
                }
                return Convert.FromBase64String(padded);
            }
            catch
            {
                return null;
            }
        }

        // Why: invoice/info response has varied across CryptoCloud API revisions. Try the documented
        // fiat fields first (amount_in_fiat / order_amount / amount), and fall back to the postback's
        // `amount` / `amount_crypto` only if the lookup didn't return a USD figure.
        static double ExtractFiatAmount(JObject info, Microsoft.AspNetCore.Http.IFormCollection form)
        {
            foreach (string key in new[] { "amount_in_fiat", "order_amount", "amount", "amount_usd" })
            {
                if (info.TryGetValue(key, out var t) && TryParseInvariant(t?.ToString(), out double v) && v > 0)
                    return v;
            }

            foreach (string key in new[] { "amount", "amount_crypto" })
            {
                if (form.TryGetValue(key, out var fv) && TryParseInvariant(fv.ToString(), out double v) && v > 0)
                    return v;
            }

            return 0;
        }

        static bool TryParseInvariant(string s, out double v)
        {
            if (string.IsNullOrWhiteSpace(s))
            {
                v = 0;
                return false;
            }
            return double.TryParse(s.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out v);
        }

        // Why: best-effort 0600 on Unix; mirrors Shared/PlaywrightCore/Scraping.cs.TryRestrictToOwner.
        static void TryRestrictToOwner(string path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;
            try
            {
                IO.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { }
        }

        #endregion
    }
}
