using Microsoft.AspNetCore.Mvc;
using Shared;
using Shared.Engine;
using System;

namespace Lampac.Controllers
{
    public class AccsTokenController : BaseController
    {
        [HttpGet]
        [Route("/admin/accsdb/token")]
        public ActionResult GenerateToken(string uid, int days = 30)
        {
            if (!HttpContext.Request.Cookies.TryGetValue("passwd", out string passwd) || passwd != AppInit.rootPasswd)
                return Redirect("/admin/auth");

            if (!AccsToken.IsEnabled)
                return Json(new { error = "hmac_secret not configured in accsdb" });

            if (string.IsNullOrEmpty(uid))
                return Json(new { error = "uid parameter required" });

            var user = AppInit.conf.accsdb.findUser(uid);
            if (user == null)
                return Json(new { error = $"user '{uid}' not found" });

            days = Math.Clamp(days, 1, 365);
            var expiresAt = DateTime.UtcNow.AddDays(days);
            string token = AccsToken.Generate(user.id, expiresAt);
            return Json(new { token, uid = user.id, expires = expiresAt.ToString("yyyy-MM-dd HH:mm:ss UTC") });
        }
    }
}
