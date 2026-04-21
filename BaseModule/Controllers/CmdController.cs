using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Scripting;
using Shared;
using Shared.Engine;
using Shared.Models.CSharpGlobals;
using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace Lampac.Controllers
{
    public class CmdController : BaseController
    {
        [HttpGet]
        [Route("cmd/{key}/{*comand}")]
        async public Task CMD(string key, string comand)
        {
            // /cmd/{key} executes operator-configured shell commands or arbitrary
            // Roslyn C# scripts. This is effectively RCE-over-HTTP and must be
            // gated: loopback OR the caller must present the admin passwd cookie.
            string clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            bool isLocal = clientIp != null && Shared.Engine.Utilities.IPNetwork.IsLocalIp(clientIp);
            bool isAdmin = HttpContext.Request.Cookies.TryGetValue("passwd", out string cookiePasswd)
                           && CrypTo.FixedTimeEquals(cookiePasswd, AppInit.rootPasswd);

            if (!isLocal && !isAdmin)
            {
                HttpContext.Response.StatusCode = 403;
                return;
            }

            if (!AppInit.conf.cmd.TryGetValue(key, out var cmd))
                return;

            if (!string.IsNullOrEmpty(cmd.eval))
            {
                var options = ScriptOptions.Default
                    .AddReferences(typeof(HttpRequest).Assembly).AddImports("Microsoft.AspNetCore.Http")
                    .AddReferences(typeof(Task).Assembly).AddImports("System.Threading.Tasks")
                    .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                    .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Engine").AddImports("Shared.Models")
                    .AddReferences(typeof(System.IO.File).Assembly).AddImports("System.IO")
                    .AddReferences(typeof(Process).Assembly).AddImports("System.Diagnostics");

                var model = new CmdEvalModel(key, comand, requestInfo, HttpContext.Request, hybridCache, memoryCache);

                await CSharpEval.ExecuteAsync(cmd.eval, model, options);
            }
            else
            {
                if (cmd.arguments.Length == 0)
                    return;

                var _info = new ProcessStartInfo()
                {
                    FileName = cmd.path
                };

                foreach (string a in cmd.arguments)
                {
                    _info.ArgumentList.Add(a.Contains("{value}")
                        ? a.Replace("{value}", comand + HttpContext.Request.QueryString.Value)
                        : a
                    );
                }

                Process.Start(_info);
            }
        }
    }
}