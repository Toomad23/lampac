using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared;
using Shared.Engine;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IO = System.IO.File;

namespace Merchant.Controllers
{
    /// <summary>
    /// https://pay.b2pay.io/merchant/api.php
    /// </summary>
    public class B2PAY : MerchantController
    {
        static B2PAY() { Directory.CreateDirectory("merchant/invoice/b2pay"); }


        [HttpGet]
        [AllowAnonymous]
        [Route("b2pay/new")]
        async public Task<ActionResult> Index(string email)
        {
            if (!AppInit.conf.Merchant.B2PAY.enable || string.IsNullOrWhiteSpace(email))
                return Content(string.Empty);

            Dictionary<string, dynamic> payment = new Dictionary<string, dynamic>() 
            {
                ["amount"] = AppInit.conf.Merchant.accessCost,
                ["currency"] = "USD",
                ["description"] = "Buy Premium",
                // Why: M-28 — replaced predictable md5(DateTime.ToBinary()) with a CSPRNG-derived id so order_number can't be guessed from wall-clock.
                ["order_number"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
                ["type_payment"] = "merchant",
                ["usr"] = "new",
                ["custom_field"] = decodeEmail(email),
                ["callback_url"] = CrypTo.Base64($"{AppInit.Host(HttpContext)}/b2pay/callback"),
                ["success_url"] = CrypTo.Base64($"{AppInit.Host(HttpContext)}/buy/success.html"),
                ["error_url"] = CrypTo.Base64($"{AppInit.Host(HttpContext)}/buy/error.html")
            };

            payment.Add("signature", CrypTo.Base64(CrypTo.md5binary($"{AppInit.conf.Merchant.accessCost}:{payment["callback_url"]}:{payment["currency"]}:{payment["custom_field"]}:{payment["description"]}:{payment["error_url"]}:{payment["order_number"]}:{payment["success_url"]}:merchant:new:{AppInit.conf.Merchant.B2PAY.encryption_password}")));

            string data = $"payment={CrypTo.Base64(CrypTo.AES256(JsonConvert.SerializeObject(payment), AppInit.conf.Merchant.B2PAY.encryption_password, AppInit.conf.Merchant.B2PAY.encryption_iv))}&id={AppInit.conf.Merchant.B2PAY.username_id}";

            // Why: L-16 — use the strict (default-validation) HttpClient instead of Shared.Engine.Http,
            // whose handler installs a permissive ServerCertificateCustomValidationCallback. For PSP
            // outbound the TLS identity of api.b2pay.io must be authenticated.
            JObject root = null;
            try
            {
                string url = AppInit.conf.Merchant.B2PAY.sandbox ? "https://pay.b2pay.io/api_sandbox/merchantpayments.php" : "https://pay.b2pay.io/api/merchantpayments.php";
                using var req = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(data, Encoding.UTF8, "application/x-www-form-urlencoded")
                };
                using var resp = await StrictHttpClient.SendAsync(req);
                if (resp.IsSuccessStatusCode)
                {
                    string body = await resp.Content.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body))
                        root = JsonConvert.DeserializeObject<JObject>(body);
                }
            }
            catch { }

            if (root == null || !root.ContainsKey("data"))
                return Content("data == null");

            string invoiceurl = root.Value<JObject>("data")?.Value<string>("url");
            if (string.IsNullOrWhiteSpace(invoiceurl))
                return Content("invoiceurl == null");

            // HIGH-8: verify invoiceurl points at a b2pay.io host before 302-ing users. A MitM'd
            // or compromised PSP response could redirect the buyer onto a phishing domain that
            // inherits the trust of the legitimate checkout flow.
            if (!IsAllowedB2payRedirect(invoiceurl))
                return Content("invoiceurl host not allowed");

            IO.WriteAllText($"merchant/invoice/b2pay/{payment["order_number"]}", JsonConvert.SerializeObject(payment));

            return Redirect(invoiceurl);
        }


        // HIGH-8: allow-list for B2PAY redirects. Production checkout is pay.b2pay.io; the root
        // apex + *.b2pay.io covers api/sandbox/alt subdomains without opening the gate to arbitrary
        // third-party hosts the PSP may return.
        static readonly string[] _b2payHosts = new[] { "b2pay.io" };

        static bool IsAllowedB2payRedirect(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed))
                return false;
            if (parsed.Scheme != Uri.UriSchemeHttps)
                return false;
            string host = parsed.Host;
            foreach (string allowed in _b2payHosts)
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
        [Route("b2pay/callback")]
        async public Task<ActionResult> Callback()
        {
            if (!AppInit.conf.Merchant.B2PAY.enable || HttpContext.Request.Method != HttpMethods.Post || HttpContext.Request.ContentLength == 0)
                return StatusCode(404);

            var buffer = new byte[Convert.ToInt32(HttpContext.Request.ContentLength)];
            await HttpContext.Request.Body.ReadAsync(buffer, 0, buffer.Length);

            var requestContent = Encoding.UTF8.GetString(buffer);
            // Why: L-17 — redact sign/signature/token/sanitizedMask (MD5 auth material and partial PAN masks) before persisting webhook body to disk.
            WriteRedactedLog(requestContent);

            JObject result = JsonConvert.DeserializeObject<JObject>(requestContent);
            string signature = CrypTo.Base64(CrypTo.md5binary($"{result.Value<string>("amount")}:{result.Value<string>("currency")}:{result.Value<string>("gatewayAmount")}:{result.Value<string>("gatewayCurrency")}:{result.Value<string>("gatewayRate")}:{result.Value<string>("orderNumber")}:{result.Value<string>("pay_id")}:{result.Value<string>("sanitizedMask")}:{result.Value<string>("status")}:{result.Value<string>("token")}:pay:{AppInit.conf.Merchant.B2PAY.encryption_password}"));

            if (!CrypTo.FixedTimeEquals(result.Value<string>("sign"), signature))
                return StatusCode(401);

            string orderNumber = result.Value<string>("orderNumber");
            if (result.Value<string>("status") != "approved" || string.IsNullOrWhiteSpace(orderNumber) || !IO.Exists($"merchant/invoice/b2pay/{orderNumber}"))
                return StatusCode(403);

            // Why: H-22 — a valid signature on {status=approved} alone is not enough; a crafted/replayed callback could forward a cheaper invoice. Enforce paid amount >= accessCost (minus allowedDifference tolerance) and currency == USD to match /b2pay/new.
            decimal accessCost = AppInit.conf.Merchant.accessCost;
            decimal allowedDifference = AppInit.conf.Merchant.allowedDifference;
            if (!decimal.TryParse(result.Value<string>("amount"), NumberStyles.Number, CultureInfo.InvariantCulture, out decimal paidAmount) || paidAmount < accessCost - allowedDifference)
                return StatusCode(403);

            if (!string.Equals(result.Value<string>("currency"), "USD", StringComparison.OrdinalIgnoreCase))
                return StatusCode(403);

            var invoice = JsonConvert.DeserializeObject<Dictionary<string, string>>(IO.ReadAllText($"merchant/invoice/b2pay/{orderNumber}"));
            PayConfirm(invoice["custom_field"], "b2pay", orderNumber);

            return Content("ok");
        }


        // Why: L-17 — strip secrets/PAN-mask from JSON body before WriteLog; also chmod 600 on first write (Unix) so the log isn't world-readable.
        static readonly string[] redactKeys = new[] { "sign", "signature", "sanitizedMask", "token" };

        static void WriteRedactedLog(string requestContent)
        {
            string sanitized;
            try
            {
                var parsed = JsonConvert.DeserializeObject<JObject>(requestContent);
                if (parsed != null)
                {
                    foreach (var key in redactKeys)
                    {
                        if (parsed[key] != null)
                            parsed[key] = "[REDACTED]";
                    }
                    sanitized = parsed.ToString(Formatting.None);
                }
                else
                {
                    sanitized = "[unparseable-body]";
                }
            }
            catch
            {
                sanitized = "[unparseable-body]";
            }

            string path = "merchant/log/b2pay.txt";
            try
            {
                Directory.CreateDirectory("merchant/log");
                bool firstWrite = !IO.Exists(path);
                IO.AppendAllText(path, sanitized + "\n\n\n");

                if (firstWrite && (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                {
                    try { IO.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
                }
            }
            catch { }
        }
    }
}
