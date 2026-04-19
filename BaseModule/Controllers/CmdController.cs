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
            // Roslyn C# scripts. This is effectively RCE-over-HTTP, so the gate
            // is now ALWAYS the admin passwd cookie — proximity ("on the LAN" or
            // "on loopback") is no longer sufficient on its own.
            //
            // Why not "loopback OR admin"?
            //  * `IPNetwork.IsLocalIp` previously accepted the entire RFC1918/
            //    ULA space — any 192.168.x.x peer satisfied it.
            //  * Even tightening to `IsStrictLoopback` is insufficient under
            //    Docker `network: host` (and similar shared-loopback setups):
            //    every sibling container appears as 127.0.0.1 to Lampac, so a
            //    compromise of any other container would yield RCE here.
            //  * UseForwardedHeaders runs before MVC and may have rewritten
            //    HttpContext.Connection.RemoteIpAddress from an X-Forwarded-For
            //    header sent by a loopback reverse proxy / Tor hidden service /
            //    local unix socket — meaning a "trust loopback" branch could be
            //    spoofed by any caller able to reach the listener through such
            //    a proxy. Dropping the IP gate altogether eliminates that risk.
            //
            // The cookie path itself defends against:
            //  * `rootPasswd` empty/null (fresh install) — short-circuit the
            //    FixedTimeEquals so an attacker can't authenticate by sending
            //    an empty cookie before the operator has set a password;
            //  * timing oracles — FixedTimeEquals is constant-time.
            bool isAdmin = HttpContext.Request.Cookies.TryGetValue("passwd", out string cookiePasswd)
                           && !string.IsNullOrEmpty(AppInit.rootPasswd)
                           && CrypTo.FixedTimeEquals(cookiePasswd, AppInit.rootPasswd);

            if (!isAdmin)
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