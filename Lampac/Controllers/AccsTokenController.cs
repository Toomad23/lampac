using Microsoft.AspNetCore.Mvc;
using Shared;
using Shared.Engine;
using Shared.Models;
using System;

namespace Lampac.Controllers
{
    public class AccsTokenController : BaseController
    {
        [HttpGet]
        [Route("/admin/accsdb/token")]
        public ActionResult GenerateToken(string uid, int? days = null)
        {
            if (!HttpContext.Request.Cookies.TryGetValue("passwd", out string passwd) || !CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
                return Redirect("/admin/auth");

            if (!AccsToken.IsEnabled)
                return Json(new { error = "hmac_secret not configured in accsdb" });

            if (string.IsNullOrEmpty(uid))
                return Json(new { error = "uid parameter required" });

            var user = AppInit.conf.accsdb.findUser(uid);
            if (user == null)
                return Json(new { error = $"user '{uid}' not found" });

            // HIGH-3: default to 30 days rather than 365. The 365-day ceiling remains available
            // only if the admin explicitly provides `?days=…`. A stolen admin cookie previously
            // minted year-long tokens by default.
            int requestedDays = days ?? 30;
            requestedDays = Math.Clamp(requestedDays, 1, 365);
            var expiresAt = DateTime.UtcNow.AddDays(requestedDays);
            string token = AccsToken.Generate(user.id, expiresAt);

            // HIGH-3: audit every token issuance so post-incident we can enumerate which UIDs
            // were handed out from which admin IP over which validity window.
            var requestInfo = HttpContext.Features.Get<RequestModel>();
            string adminIp = requestInfo?.IP ?? HttpContext.Connection.RemoteIpAddress?.ToString() ?? "?";
            AccsToken.Audit("issue", user.id, $"days={requestedDays}\texpires={expiresAt:yyyy-MM-ddTHH:mm:ssZ}", adminIp);

            return Json(new { token, uid = user.id, expires = expiresAt.ToString("yyyy-MM-dd HH:mm:ss UTC") });
        }


        // HIGH-3: admin-driven revocation endpoint. Appends to database/admin-revoked-tokens.txt;
        // validation consults that list so a previously-issued token can be killed without rotating
        // hmac_secret (which would nuke every valid token at once).
        [HttpGet]
        [Route("/admin/accsdb/revoke")]
        public ActionResult RevokeToken(string uid)
        {
            if (!HttpContext.Request.Cookies.TryGetValue("passwd", out string passwd) || !CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
                return Redirect("/admin/auth");

            if (string.IsNullOrEmpty(uid))
                return Json(new { error = "uid parameter required" });

            AccsToken.Revoke(uid);

            var requestInfo = HttpContext.Features.Get<RequestModel>();
            string adminIp = requestInfo?.IP ?? HttpContext.Connection.RemoteIpAddress?.ToString() ?? "?";
            AccsToken.Audit("revoke", uid, "scope=all", adminIp);

            return Json(new { revoked = true, uid });
        }
    }
}
