using Chaos.NaCl;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json.Linq;
using Shared;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using IO = System.IO.File;

namespace Merchant.Controllers
{
    public class Streampay : MerchantController
    {
        static Streampay() { Directory.CreateDirectory("merchant/invoice/streampay"); }

        // Why: M-29 — gate external_id so it matches what /streampay/new produces (Guid "N" = 32 hex chars);
        // 20..64 keeps a small tolerance without allowing path separators or traversal tokens.
        static readonly Regex transidRegex = new Regex("^[0-9a-fA-F]{20,64}$", RegexOptions.Compiled);


        [HttpGet]
        [AllowAnonymous]
        [Route("streampay/new")]
        async public Task<ActionResult> Index(string email)
        {
            var init = AppInit.conf.Merchant.Streampay;
            if (!init.enable || string.IsNullOrWhiteSpace(email))
                return Content(string.Empty);

            email = decodeEmail(email);

            // Why: M-28 — replace predictable DateTime.ToBinary() transid with a cryptographically
            // random 32-hex-char id so an attacker can't guess/race invoice filenames.
            string transid = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

            if (memoryCache.TryGetValue($"streampay:{transid}", out string pay_link))
                return Redirect(pay_link);

            IO.WriteAllText($"merchant/invoice/streampay/{transid}", email);

            var body = new
            {
                init.store_id,
                customer = email,
                external_id = transid,
                description = $"Подписка на {AppInit.conf.Merchant.accessForMonths} {EndOfText("месяц", "месяца", "месяцев", AppInit.conf.Merchant.accessForMonths)}",
                system_currency = "USDT",
                payment_type = 2,
                amount = AppInit.conf.Merchant.accessCost
            };

            var jsonBody = JsonSerializer.Serialize(body);
            string signature = Sign(Encoding.UTF8.GetBytes(jsonBody + DateTime.UtcNow.ToString("yyyyMMdd:HHmm")), init.private_key);

            // Why: L-16 — previously this created a fresh `new HttpClient()` per request, which
            // was TLS-safe (default validation) but leaked sockets under load. Switch to the
            // static MerchantController.StrictHttpClient so pooling is reused, and explicitly
            // dispose the request (not the shared client).
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.streampay.org/api/payment/create")
                {
                    Content = new StringContent(jsonBody, Encoding.UTF8, "application/json")
                };

                request.Headers.Add("signature", signature);

                using var response = await StrictHttpClient.SendAsync(request);
                if (response.IsSuccessStatusCode)
                {
                    string respData = await response.Content.ReadAsStringAsync();
                    string pay_url = Regex.Match(respData, "\"pay_url\":\"([^\"]+)\"").Groups[1].Value;

                    if (!string.IsNullOrEmpty(pay_url))
                    {
                        memoryCache.Set($"streampay:{transid}", pay_url, DateTime.Now.AddHours(2));
                        return Redirect(pay_url);
                    }

                    return Content(respData);
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    // Why: previously this surfaced PSP errors as HTTP 200 with a plain-text body,
                    // which misleads callers (and automated monitors) into treating an auth / policy
                    // rejection as success. Propagate a matching status code with the reason as body.
                    return StatusCode(401, "Invalid signature");
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotAcceptable)
                {
                    return StatusCode(400, "Invalid request data");
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.InternalServerError)
                {
                    return StatusCode(502, "Internal server error");
                }
            }

            return Content("error");
        }


        [HttpGet]
        [AllowAnonymous]
        [Route("streampay/callback")]
        public ActionResult Callback()
        {
            var merchant = AppInit.conf.Merchant;
            if (!merchant.Streampay.enable)
                return Ok();

            string transid = Request.Query["external_id"].ToString();

            // Why: M-29 — validate external_id BEFORE any filesystem access to kill the
            // path-traversal / FS-existence oracle. Reject anything that isn't plain hex.
            if (string.IsNullOrEmpty(transid) || !transidRegex.IsMatch(transid))
            {
                WriteRedactedLog("rejected: bad external_id");
                return Ok();
            }

            if (Request.Query["status"] != "awaiting_payment")
                memoryCache.Remove($"streampay:{transid}");

            if (Request.Query["status"] != "success")
                return Ok();

            var now = DateTime.UtcNow;
            var queryParams = Request.Query.OrderBy(x => x.Key).Select(x => $"{x.Key}={x.Value}").ToList();
            string paramsStr = string.Join('&', queryParams);
            byte[] paramsBuf = Encoding.UTF8.GetBytes(paramsStr);

            // Why: L-17 — logs previously included the raw Signature header, email and account_email;
            // route everything through WriteRedactedLog which strips known secrets/PII and chmods 600.
            string log = BuildRedactedSummary(paramsStr, Request.Headers);

            for (int i = 0; i < 2; i++)
            {
                string tm = now.ToString("yyyyMMdd:HHmm");
                var bufToSign = paramsBuf.Concat(Encoding.UTF8.GetBytes(tm)).ToArray();

                bool verify = Verify(Request.Headers["Signature"], bufToSign, merchant.Streampay.public_key);
                log += $"\nverify: {verify} | {tm}";

                if (verify)
                {
                    // Why: M-29 — signature is valid, only NOW is it safe to touch the filesystem.
                    string invoicePath = $"merchant/invoice/streampay/{transid}";
                    if (!IO.Exists(invoicePath))
                    {
                        WriteRedactedLog(log + "\nForbid: invoice missing");
                        return Forbid();
                    }

                    // Why: H-22 — enforce the paid amount against accessCost with the configured
                    // allowedDifference tolerance (and reject non-USDT) so a spoofed "amount=1" can't
                    // mint a subscription even with a valid vendor signature on a different invoice.
                    if (!AmountIsAcceptable(Request.Query["amount"], Request.Query["system_currency"], out string amountReason))
                    {
                        WriteRedactedLog(log + $"\nForbid: {amountReason}");
                        return StatusCode(403);
                    }

                    PayConfirm(IO.ReadAllText(invoicePath), "streampay", transid);

                    WriteRedactedLog(log + "\nOK");
                    return Ok();
                }

                now = now.AddMinutes(-1);
            }

            WriteRedactedLog(log + "\nForbid: bad signature");
            return Forbid();
        }


        // Why: H-22 — centralised numeric compare so both the tolerance window and the currency check
        // live in one place and fail-closed on parse errors.
        static bool AmountIsAcceptable(string rawAmount, string currency, out string reason)
        {
            reason = null;

            if (!string.IsNullOrEmpty(currency) && !string.Equals(currency, "USDT", StringComparison.OrdinalIgnoreCase))
            {
                reason = $"currency mismatch ({currency})";
                return false;
            }

            if (!decimal.TryParse(rawAmount, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal paid))
            {
                reason = "amount unparseable";
                return false;
            }

            decimal expected = AppInit.conf.Merchant.accessCost;
            decimal tolerance = AppInit.conf.Merchant.allowedDifference;

            if (paid + tolerance < expected)
            {
                reason = $"amount too low ({paid} < {expected} - {tolerance})";
                return false;
            }

            return true;
        }


        // Why: L-17 — redact signature/email/token-like fields from the query string and drop Signature/
        // Authorization headers entirely before writing to disk.
        static readonly HashSet<string> redactKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "signature", "sign", "email", "account_email", "customer", "token"
        };

        static readonly HashSet<string> dropHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Signature", "signature", "Authorization", "Cookie", "Set-Cookie"
        };

        static string BuildRedactedSummary(string paramsStr, Microsoft.AspNetCore.Http.IHeaderDictionary headers)
        {
            var sb = new StringBuilder();

            if (!string.IsNullOrEmpty(paramsStr))
            {
                var redactedPairs = paramsStr.Split('&').Select(p =>
                {
                    int eq = p.IndexOf('=');
                    if (eq <= 0)
                        return p;
                    string key = p.Substring(0, eq);
                    return redactKeys.Contains(key) ? $"{key}=[REDACTED]" : p;
                });
                sb.Append(string.Join('&', redactedPairs));
            }

            sb.Append('\n');

            var safeHeaders = new JObject();
            foreach (var h in headers)
            {
                if (dropHeaders.Contains(h.Key))
                {
                    safeHeaders[h.Key] = "[REDACTED]";
                    continue;
                }
                safeHeaders[h.Key] = h.Value.ToString();
            }
            sb.Append(safeHeaders.ToString(Newtonsoft.Json.Formatting.None));

            return sb.ToString();
        }

        static void WriteRedactedLog(string content)
        {
            try
            {
                Directory.CreateDirectory("merchant/log");
                string path = "merchant/log/streampay.txt";
                bool firstWrite = !IO.Exists(path);
                IO.AppendAllText(path, content + "\n\n\n");

                // Why: L-17 — tighten permissions on first write so the log isn't world-readable on Unix hosts.
                if (firstWrite && (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                {
                    try { IO.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
                }
            }
            catch { }
        }


        static string Sign(byte[] message, string privateKey)
        {
            var bytes = Ed25519.Sign(message, HexToBytes(privateKey));

            StringBuilder hex = new StringBuilder(bytes.Length * 2);

            foreach (byte b in bytes)
                hex.AppendFormat("{0:x2}", b);

            return hex.ToString();
        }

        static bool Verify(string signature, byte[] message, string publicKey)
        {
            try
            {
                return Ed25519.Verify(HexToBytes(signature), message, HexToBytes(publicKey));
            }
            catch { return false; }
        }

        static byte[] HexToBytes(string key)
        {
            if (key.Length % 2 != 0)
                return null;

            int byteCount = key.Length / 2;
            byte[] hexKey = new byte[byteCount];

            for (int i = 0; i < byteCount; i++)
            {
                string byteString = key.Substring(i * 2, 2);
                byte keyValue = Convert.ToByte(byteString, 16);
                hexKey[i] = keyValue;
            }

            return hexKey;
        }

        static string EndOfText(string s1, string s2, string s3, int x)
        {
            int n = x % 100;
            if ((n > 10) && (n < 20))
                return s3;

            switch (x % 10)
            {
                case 4: return s2;
                case 0:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9: return s3;
                default: return s1;
            }
        }
    }
}
