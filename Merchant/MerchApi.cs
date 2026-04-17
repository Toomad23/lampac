using System;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Shared;
using Shared.Engine;

namespace Merchant.Controllers
{
    public class MerchApi : MerchantController
    {
        // Why (M-27): rate-limited deprecation log for query-string passwd auth. Emit at most
        // once per minute per endpoint so an attacker cannot flood the log with spoofed probes.
        static readonly ConcurrentDictionary<string, DateTime> _deprecationLog = new();

        [HttpGet]
        [AllowAnonymous]
        [Route("merchant/user")]
        public ActionResult Index(string account_email, string passwd)
        {
            // Previously [AllowAnonymous] with no passwd check — anyone could
            // enumerate subscribers by email and read expiry/group/ban fields.
            // Require the same rootPasswd as /merchant/payconfirm.
            if (!IsAuthorized(Request, passwd, "/merchant/user"))
                return Content("incorrect passwd");

            string email = decodeEmail(account_email);
            if (email == null)
                return Json(new { error = true, msg = "email null" });

            var user = AppInit.conf.accsdb.findUser(email);
            if (user == null)
                return Json(new { error = true, msg = "user not found" });

            return Json(new
            {
                user.id,
                user.ids,
                user.ban,
                user.ban_msg,
                user.expires,
                user.group
            });
        }

        [HttpGet]
        [HttpPost]
        [AllowAnonymous]
        [Route("merchant/payconfirm")]
        public ActionResult ConfirmPay(string passwd, string account_email, string merch, string order, int days = 0)
        {
            if (!IsAuthorized(Request, passwd, "/merchant/payconfirm"))
                return Content("incorrect passwd");

            string email = decodeEmail(account_email);
            if (email == null)
                return Json(new { error = true, msg = "email null" });

            PayConfirm(email, merch, order, days);

            var user = AppInit.conf.accsdb.findUser(email);
            if (user == null)
                return Json(new { error = true, msg = "user not found" });

            return Json(user);
        }

        // Why (M-27): accept X-Signature/X-Timestamp HMAC headers (preferred) or
        // fall back to query-string passwd (deprecated). Query-string credentials leak
        // into access logs, referer headers, and proxy caches; the HMAC layer removes
        // the plaintext from the URL. Fallback kept for one release to give existing
        // operators time to update their automation. After that, remove the fallback.
        static bool IsAuthorized(HttpRequest req, string passwd, string endpoint)
        {
            if (HmacAuth.Validate(req))
                return true;

            if (!string.IsNullOrEmpty(passwd) && CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
            {
                LogDeprecatedPasswdAuth(endpoint);
                return true;
            }

            return false;
        }

        static void LogDeprecatedPasswdAuth(string endpoint)
        {
            var now = DateTime.UtcNow;
            if (_deprecationLog.TryGetValue(endpoint, out var last) && (now - last).TotalSeconds < 60)
                return;
            _deprecationLog[endpoint] = now;
            Console.Error.WriteLine($"[deprecation] {endpoint}: query-string passwd auth is deprecated, switch to X-Signature/X-Timestamp HMAC headers (HmacAuth.cs).");
        }
    }
}
