using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shared;
using Shared.Engine;

namespace Merchant.Controllers
{
    public class MerchApi : MerchantController
    {
        [HttpGet]
        [AllowAnonymous]
        [Route("merchant/user")]
        public ActionResult Index(string account_email, string passwd)
        {
            // Previously [AllowAnonymous] with no passwd check — anyone could
            // enumerate subscribers by email and read expiry/group/ban fields.
            // Require the same rootPasswd as /merchant/payconfirm.
            if (!CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
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
            if (!CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
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
    }
}
