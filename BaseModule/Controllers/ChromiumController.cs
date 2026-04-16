using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shared;
using System.Web;

namespace Lampac.Controllers
{
    public class ChromiumController : BaseController
    {
        [HttpGet]
        [AllowAnonymous]
        [Route("/api/chromium/ping")]
        public string Ping() => "pong";


        [HttpGet]
        [AllowAnonymous]
        [Route("/api/chromium/iframe")]
        public ActionResult RenderIframe(string src)
        {
            string safeSrc = HttpUtility.HtmlAttributeEncode(src ?? "");
            return ContentTo($@"<html lang=""ru"">
                <head>
                    <meta charset=""UTF-8"">
                    <meta http-equiv=""X-UA-Compatible"" content=""IE=edge"">
                    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"">
                    <title>chromium iframe</title>
                </head>
                <body>
                    <iframe width=""560"" height=""400"" src=""{safeSrc}"" frameborder=""0"" allow=""*"" allowfullscreen></iframe>
                </body>
            </html>");
        }
    }
}