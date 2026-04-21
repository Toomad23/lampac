using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Shared;
using Shared.Engine;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using IO = System.IO.File;

namespace Merchant.Controllers
{
    /// <summary>
    /// https://docs.freekassa.ru/
    /// </summary>
    public class FreeKassa : MerchantController
    {
        static FreeKassa() { Directory.CreateDirectory("merchant/invoice/freekassa"); }


        [HttpGet]
        [AllowAnonymous]
        [Route("freekassa/new")]
        public ActionResult Index(string email)
        {
            if (!AppInit.conf.Merchant.FreeKassa.enable || string.IsNullOrWhiteSpace(email))
                return Content(string.Empty);

            // Why (M-28): DateTime.ToBinary() is predictable/enumerable — an attacker can guess nearby
            // transids and hit /freekassa/callback with brute-forced signatures against existing invoices.
            // Guid.NewGuid("N") gives 32 hex chars backed by a CSPRNG, keeping the FreeKassa `o` param format intact.
            string transid = Guid.NewGuid().ToString("N");

            IO.WriteAllText($"merchant/invoice/freekassa/{transid}", decodeEmail(email));

            string hash = CrypTo.md5($"{AppInit.conf.Merchant.FreeKassa.shop_id}:{AppInit.conf.Merchant.accessCost}:{AppInit.conf.Merchant.FreeKassa.secret}:USD:{transid}");
            return Redirect("https://pay.freekassa.ru/" + $"?m={AppInit.conf.Merchant.FreeKassa.shop_id}&oa={AppInit.conf.Merchant.accessCost}&o={transid}&s={hash}&currency=USD");
        }


        [HttpPost]
        [AllowAnonymous]
        [Route("freekassa/callback")]
        public ActionResult Callback(string AMOUNT, long MERCHANT_ORDER_ID, string SIGN)
        {
            if (!AppInit.conf.Merchant.FreeKassa.enable)
                return StatusCode(403);

            // Why (M-28): Consolidated early return — previously a missing invoice file returned 403 immediately
            // while a present-but-bad-signature path ran MD5 + FixedTimeEquals. That timing delta leaks whether
            // a given MERCHANT_ORDER_ID exists (invoice enumeration). Now every failure mode runs MD5 first and
            // returns via the same Content() path with comparable latency.
            string invoicePath = $"merchant/invoice/freekassa/{MERCHANT_ORDER_ID}";
            bool invoiceExists = IO.Exists(invoicePath);

            string expectedSign = CrypTo.md5($"{AppInit.conf.Merchant.FreeKassa.shop_id}:{AMOUNT}:{AppInit.conf.Merchant.FreeKassa.secret}:{MERCHANT_ORDER_ID}");
            bool signOk = CrypTo.FixedTimeEquals(expectedSign, SIGN);

            // Why (L-17): Dumping the raw form body leaks the MD5 `SIGN` (plus P_EMAIL/P_PHONE PII).
            // A leaked SIGN + known message lets an attacker offline-brute-force the FreeKassa shop secret.
            // Redact sensitive fields before persisting, then lock the log file to the owner on Unix.
            WriteRedactedCallbackLog();

            if (!invoiceExists || !signOk)
                return Content("SIGN != hash");

            // Why (H-22): The MD5 signature only proves FreeKassa sent the callback — it does not bind the
            // paid amount to our price. If the shop is misconfigured (wrong oa) or FreeKassa partial-pays,
            // an under-paid order would still land full subscription credit. Enforce AMOUNT >= accessCost
            // with the admin-configured allowedDifference tolerance; parse with InvariantCulture because
            // FreeKassa sends `AMOUNT` as a dot-decimal string.
            if (!decimal.TryParse(AMOUNT, NumberStyles.Number, CultureInfo.InvariantCulture, out decimal paid))
                return StatusCode(403);

            decimal expected = AppInit.conf.Merchant.accessCost;
            decimal tolerance = AppInit.conf.Merchant.allowedDifference; // int, defaults to 0 → exact ≥ required
            if (paid + tolerance < expected)
                return StatusCode(403);

            string email = IO.ReadAllText(invoicePath);
            PayConfirm(email, "freekassa", MERCHANT_ORDER_ID.ToString());

            return Content("YES");
        }


        // Why (L-17): Centralized redaction + 0600 hardening for the freekassa callback log.
        void WriteRedactedCallbackLog()
        {
            try
            {
                var redacted = new Dictionary<string, string>();
                foreach (var kv in HttpContext.Request.Form)
                {
                    string key = kv.Key ?? string.Empty;
                    string keyUpper = key.ToUpperInvariant();
                    if (keyUpper == "SIGN" || keyUpper == "P_EMAIL" || keyUpper == "P_PHONE")
                        redacted[key] = "[REDACTED]";
                    else
                        redacted[key] = kv.Value.ToString();
                }

                string path = "merchant/log/freekassa.txt";
                bool firstWrite = !IO.Exists(path);

                WriteLog("freekassa", JsonConvert.SerializeObject(redacted));

                if (firstWrite && !RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    try { IO.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                    catch { }
                }
            }
            catch { }
        }
    }
}
