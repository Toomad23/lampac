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
                return Content("hmac_secret not configured in accsdb", "text/plain");

            if (string.IsNullOrEmpty(uid))
                return Content("uid parameter required", "text/plain");

            var user = AppInit.conf.accsdb.findUser(uid);
            if (user == null)
                return Content($"user '{uid}' not found", "text/plain");

            string token = AccsToken.Generate(user.id, DateTime.UtcNow.AddDays(days));
            return Json(new { token, uid = user.id, expires = DateTime.UtcNow.AddDays(days).ToString("yyyy-MM-dd HH:mm:ss UTC") });
        }
    }
}
