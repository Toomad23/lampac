using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared;
using Shared.Engine;
using Shared.Models.Module;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using IO = System.IO;

namespace Lampac.Controllers
{
    public class AdminController : BaseController
    {
        #region TryAuthorizeAdmin
        bool TryAuthorizeAdmin(string passwd, out ActionResult result)
        {
            result = null;

            if (AppInit.rootPasswd == "termux")
            {
                HttpContext.Response.Cookies.Append("passwd", "termux");
                return true;
            }

            if (string.IsNullOrWhiteSpace(passwd))
                HttpContext.Request.Cookies.TryGetValue("passwd", out passwd);

            if (string.IsNullOrWhiteSpace(passwd))
            {
                result = Redirect("/admin/auth");
                return false;
            }

            // Why: check the password BEFORE incrementing the brute-force counter so that
            // a legitimate admin's own AJAX traffic (10+ requests per page) doesn't lock
            // them out. Only failed attempts should count towards the cap. Mirrors the
            // pattern in Lampac/Engine/Middlewares/Accsdb.cs.
            if (CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
                return true;

            // Wrong password — increment brute force counter and apply backoff
            int attempts = AdminBruteGuard.Increment(memoryCache, requestInfo.IP);

            if (attempts > 10)
            {
                result = Content("Too many attempts, try again tomorrow.");
                return false;
            }

            AdminBruteGuard.BackoffAsync(attempts).GetAwaiter().GetResult();

            HttpContext.Response.Cookies.Delete("passwd");
            result = Redirect("/admin/auth");
            return false;
        }
        #endregion

        #region admin / auth
        [HttpGet]
        [HttpPost]
        [Route("/admin")]
        [Route("/admin/auth")]
        public ActionResult Authorization([FromForm]string parol)
        {
            string passwd = parol?.Trim();

            if (string.IsNullOrWhiteSpace(passwd)) 
                HttpContext.Request.Cookies.TryGetValue("passwd", out passwd);

            if (string.IsNullOrWhiteSpace(passwd))
            {
                string html = @"
<!DOCTYPE html>
<html>
<head>
	<title>Authorization</title>
</head>
<body>

<style type=""text/css"">
	* {
	    box-sizing: border-box;
	    outline: none;
	}
	body{
		padding: 40px;
		font-family: sans-serif;
	}
	label{
		display: block;
		font-weight: 700;
		margin-bottom: 8px;
	}
	input,
	textarea,
	select{
		width: 340px;
		padding: 8px;
	}
	button{
		padding: 10px;
	}
	form > * + *{
		margin-top: 20px;
	}
</style>

<form method=""post"" action=""/admin/auth"" id=""form"">
	<div>
		<input type=""text"" name=""parol"" placeholder=""пароль из файла passwd""></input>
	</div>
	
	<button type=""submit"">войти</button>
	
</form>

<div style=""margin-top: 4em;""><b style=""color: cadetblue;"">Выполните одну из команд через ssh</b><br><br>
	cat /home/lampac/passwd<br><br>
	docker exec -it lampac cat passwd
</div>

</body>
</html>
";

                return Content(html, "text/html; charset=utf-8");
            }
            else
            {
                if (!TryAuthorizeAdmin(passwd, out ActionResult badresult))
                    return badresult;

                HttpContext.Response.Cookies.Append("passwd", passwd, new Microsoft.AspNetCore.Http.CookieOptions
                {
                    HttpOnly = true,
                    SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict,
                    Path = "/admin"
                });
                return renderAdmin();
            }
        }

        ActionResult renderAdmin()
		{
            string adminHtml = IO.File.Exists("wwwroot/mycontrol/index.html") ? IO.File.ReadAllText("wwwroot/mycontrol/index.html") : IO.File.ReadAllText("wwwroot/control/index.html");
            return Content(adminHtml, contentType: "text/html; charset=utf-8");
		}
        #endregion


        #region init
        [HttpPost]
        [Route("/admin/init/save")]
        public ActionResult InitSave([FromForm]string json)
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            try
            {
                JsonConvert.DeserializeObject<AppInit>(json);
            }
			catch (Exception ex) { return Json(new { error = true, ex = ex.Message }); }

            JObject jo;
            try
            {
                jo = JsonConvert.DeserializeObject<JObject>(json);
            }
            catch (Exception ex) { return Json(new { error = true, ex = ex.Message }); }

			JToken users = null;
            var accsdbNode = jo["accsdb"] as JObject;
            if (accsdbNode != null)
            {
                var usersNode = accsdbNode["users"];
                if (usersNode != null)
				{
					users = usersNode.DeepClone();
                    accsdbNode.Remove("users");

                    WriteAtomic("users.json", JsonConvert.SerializeObject(users, Formatting.Indented), backup: false);
                }
            }

            WriteAtomic("init.conf", JsonConvert.SerializeObject(jo, Formatting.Indented), backup: true);

            return Json(new { success = true });
        }

        // Why: WriteAllText non-atomically truncates+writes, so a crash mid-write
        // leaves a corrupted init.conf that the next boot fails to parse. Rename
        // via a sibling .tmp (atomic on POSIX/rename, atomic on Windows via
        // MoveFileEx+REPLACE_EXISTING) and snapshot the previous content to .bak.
        static void WriteAtomic(string path, string content, bool backup)
        {
            string tmp = path + ".tmp-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
            IO.File.WriteAllText(tmp, content);

            if (backup && IO.File.Exists(path))
            {
                try { IO.File.Copy(path, path + ".bak", overwrite: true); } catch { }
            }

            try
            {
                IO.File.Move(tmp, path, overwrite: true);
            }
            catch
            {
                try { if (IO.File.Exists(tmp)) IO.File.Delete(tmp); } catch { }
                throw;
            }
        }

        [HttpGet]
        [Route("/admin/init/custom")]
        public ActionResult InitCustom()
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            string json = IO.File.Exists("init.conf") ? IO.File.ReadAllText("init.conf") : null;
			if (json != null && !json.Trim().StartsWith("{"))
				json = "{" + json + "}";

            var ob = json != null ? JsonConvert.DeserializeObject<JObject>(json) : new JObject { };
            return ContentTo(JsonConvert.SerializeObject(ob));
        }

        [HttpGet]
        [Route("/admin/init/current")]
        public ActionResult InitCurrent()
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            return Content(JsonConvert.SerializeObject(AppInit.conf), contentType: "application/json; charset=utf-8");
        }

        [HttpGet]
        [Route("/admin/init/default")]
        public ActionResult InitDefault()
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            return Content(JsonConvert.SerializeObject(new AppInit()), contentType: "application/json; charset=utf-8");
        }

        [HttpGet]
        [Route("/admin/init/example")]
        public ActionResult InitExample()
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            return Content(IO.File.Exists("example.conf") ? IO.File.ReadAllText("example.conf") : string.Empty);
        }
        #endregion

        #region sync/init
        [HttpGet]
        [Route("/admin/sync/init")]
        public ActionResult Synchtml()
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            string html = @"
<!DOCTYPE html>
<html>
<head>
	<title>Редактор sync.conf</title>
</head>
<body>

<style type=""text/css"">
	* {
	    box-sizing: border-box;
	    outline: none;
	}
	body{
		padding: 40px;
		font-family: sans-serif;
	}
	label{
		display: block;
		font-weight: 700;
		margin-bottom: 8px;
	}
	input,
	textarea,
	select{
		width: 100%;
		padding: 10px;
	}
	button{
		padding: 10px;
	}
	form > * + *{
		margin-top: 30px;
	}
</style>

<form method=""post"" action="""" id=""form"">
	<div>
		<label>Ваш sync.conf
		<textarea id=""value"" name=""value"" rows=""30"">{conf}</textarea>
	</div>
	
	<button type=""submit"">Сохранить</button>
	
</form>

<script type=""text/javascript"">
	document.getElementById('form').addEventListener(""submit"", (e) => {
		let json = document.getElementById('value').value

		e.preventDefault()

		try{
			let formData = new FormData()
				formData.append('json', json)

			fetch('/admin/sync/init/save',{
			    method: ""POST"",
			    body: formData
			})
			.then((response)=>{
				if (!response.ok) {
					return response.json().then(err => {
						throw new Error(err.ex || 'Не удалось сохранить настройки');
					});
				}
				return response.json();
			 })  
			.then((data)=>{
				if (data.success) {
					alert('Сохранено');
				} else if (data.error) {
					throw new Error(data.ex); 
				} else {
					throw new Error('Не удалось сохранить настройки'); 
				}
			})
			.catch((e)=>{
				alert(e.message)
			})
		}
		catch(e){
			alert('Ошибка: ' + e.message)
		}
	})
</script>

</body>
</html>
";

            string conf = IO.File.Exists("sync.conf") ? IO.File.ReadAllText("sync.conf") : string.Empty;
            string confEncoded = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(conf);
            return Content(html.Replace("{conf}", confEncoded), contentType: "text/html; charset=utf-8");
        }


        [HttpPost]
        [Route("/admin/sync/init/save")]
        public ActionResult SyncSave([FromForm] string json)
        {
            if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                return badresult;

            try
            {
                string testjson = json.Trim();
                if (!testjson.StartsWith("{"))
                    testjson = "{" + testjson + "}";

                JsonConvert.DeserializeObject<AppInit>(testjson);

            }
            catch (Exception ex) { return Json(new { error = true, ex = ex.Message }); }

            WriteAtomic("sync.conf", json, backup: true);
            return Json(new { success = true });
        }
        #endregion

        #region manifest
        [HttpGet]
        [HttpPost]
        [Route("/admin/manifest/install")]
        public Task ManifestInstallHtml(string online, string sisi, string jac, string dlna, string tracks, string ts, string catalog, string merch, string eng)
        {
            if (IO.File.Exists("module/manifest.json"))
            {
                if (!TryAuthorizeAdmin(null, out ActionResult badresult))
                {
                    HttpContext.Response.Redirect("/admin/auth");
                    return Task.CompletedTask;
                }
            }
            else
            {
                // Fresh install: Accsdb middleware lets /admin/manifest/install
                // through without auth so the operator can bootstrap the box.
                // Before this gate, an external attacker who noticed an
                // unconfigured instance could drive the POST and read the
                // root passwd back from the success HTML. Require proof of
                // locality — the operator must SSH in and drive the install
                // from loopback (`curl 127.0.0.1/admin/manifest/install …`).
                //
                // Why (FC-1): use IsStrictLoopback — IsLocalIp also accepts
                // RFC1918 peers (10/8, 192.168/16, 172.16/12, fc00::/7), so
                // any LAN attacker would satisfy it. Fresh install must only
                // be driven from the host itself (127.0.0.0/8 or ::1).
                //
                // Why (FC-2): UseForwardedHeaders runs before MVC with an
                // unbounded ForwardLimit and the default KnownProxies/
                // KnownNetworks (loopback is trusted). So HttpContext.
                // Connection.RemoteIpAddress may already have been overwritten
                // by X-Forwarded-For sent from a loopback reverse proxy / Tor
                // hidden service / local unix socket / anything peering over
                // lo. Read the true socket peer via IHttpConnectionFeature,
                // which is populated by Kestrel before any middleware runs.
                var connFeat = HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpConnectionFeature>();
                string remoteIp = connFeat?.RemoteIpAddress?.ToString()
                                  ?? HttpContext.Connection.RemoteIpAddress?.ToString();
                if (!Shared.Engine.Utilities.IPNetwork.IsStrictLoopback(remoteIp))
                {
                    HttpContext.Response.StatusCode = 403;
                    HttpContext.Response.ContentType = "text/plain; charset=utf-8";
                    return HttpContext.Response.WriteAsync(
                        "First-time install must be driven from a loopback peer.\n" +
                        "SSH into the host and run the request against 127.0.0.1 (or `docker exec … curl localhost/admin/manifest/install`).",
                        HttpContext.RequestAborted);
                }
            }

            HttpContext.Response.ContentType = "text/html; charset=utf-8";

            if (AppInit.rootPasswd == "termux")
                return HttpContext.Response.WriteAsync("В termux операция недоступна");

            bool isEditManifest = false;

			if (IO.File.Exists("module/manifest.json"))
			{
                if (HttpContext.Request.Cookies.TryGetValue("passwd", out string passwd) && CrypTo.FixedTimeEquals(passwd, AppInit.rootPasswd))
                {
                    isEditManifest = true;
                }
                else
                {
                    HttpContext.Response.Redirect("/admin");
                    return Task.CompletedTask;
                }
            }

			if (HttpContext.Request.Method == "POST")
			{
				var modules = new List<string>(10);

				if (online == "on")
					modules.Add("{\"enable\":true,\"dll\":\"Online.dll\"}");

                if (sisi == "on")
                    modules.Add("{\"enable\":true,\"dll\":\"SISI.dll\"}");

                if (!string.IsNullOrEmpty(jac))
                {
                    modules.Add("{\"enable\":true,\"initspace\":\"Jackett.ModInit\",\"dll\":\"JacRed.dll\"}");

                    #region JacRed.conf
                    if (jac == "fdb")
                    {
                        var jacPath = "module/JacRed.conf";

                        JObject jj;
                        if (IO.File.Exists(jacPath))
                        {
                            string txt = IO.File.ReadAllText(jacPath).Trim();
                            if (string.IsNullOrEmpty(txt))
                                jj = new JObject();
                            else
                            {
                                if (!txt.StartsWith("{"))
                                    txt = "{" + txt + "}";

                                try
                                {
                                    jj = JsonConvert.DeserializeObject<JObject>(txt) ?? new JObject();
                                }
                                catch
                                {
                                    jj = new JObject();
                                }
                            }
                        }
                        else
                        {
                            jj = new JObject();
                        }

                        jj["typesearch"] = "red";
                        IO.File.WriteAllText(jacPath, JsonConvert.SerializeObject(jj, Formatting.Indented));
                    }
                    #endregion
                }

                if (dlna == "on")
                    modules.Add("{\"enable\":true,\"dll\":\"DLNA.dll\"}");

                if (tracks == "on")
                    modules.Add("{\"enable\":true,\"initspace\":\"Tracks.ModInit\",\"dll\":\"Tracks.dll\"}");

                if (ts == "on")
                    modules.Add("{\"enable\":true,\"initspace\":\"TorrServer.ModInit\",\"dll\":\"TorrServer.dll\"}");

                if (catalog == "on")
                    modules.Add("{\"enable\":true,\"initspace\":\"Catalog.ModInit\",\"dll\":\"Catalog.dll\"}");

                if (merch == "on")
                    modules.Add("{\"enable\":false,\"dll\":\"Merchant.dll\"}");

                IO.File.WriteAllText("module/manifest.json", $"[{string.Join(",", modules)}]");

                if (eng != "on")
                    UpdateInitConf(j => j["disableEng"] = true);

                if (isEditManifest)
                {
                    return HttpContext.Response.WriteAsync("Перезагрузите lampac для изменения настроек");
                }
                else
                {
                    #region frontend cloudflare
                    if (HttpContext.Request.Headers.TryGetValue("CF-Connecting-IP", out var xip) && !string.IsNullOrEmpty(xip))
                    {
                        UpdateInitConf(j =>
                        {
                            var listen = j["listen"] as JObject;
                            if (listen == null)
                            {
                                listen = new JObject();
                                j["listen"] = listen;
                            }

                            listen["frontend"] = "cloudflare";
                        });
                    }
                    #endregion

                    #region htmlSuccess

                    #region shared_passwd
                    byte[] _buf = new byte[32];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(_buf);
                    string shared_passwd = Convert.ToHexString(_buf).ToLower();

                    UpdateInitConf(j =>
                    {
                        var accsdb = j["accsdb"] as JObject;
                        if (accsdb == null)
                        {
                            accsdb = new JObject();
                            j["accsdb"] = accsdb;
                        }

                        accsdb["enable"] = true;
                        accsdb["shared_passwd"] = shared_passwd;
                    });

                    string sharedBlock = $@"<div class=""block""><b>Авторизация в Lampa</b><br /><br />
                            Пароль: {shared_passwd}
                        </div><hr />";
                    #endregion

                    string htmlSuccesds = $@"<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"" />
    <title>Настройка завершена</title>
</head>
<body>

<style type=""text/css"">
    * {{ box-sizing: border-box; outline: none; }}
    body {{ padding: 40px; font-family: sans-serif; }}
    h1 {{ color: #2b7a78; margin-bottom: 1em; text-align: center; }}
    hr {{ margin-top: 1em; margin-bottom: 2em; }}
    .block {{ margin-top: 20px; }}
    pre {{ background: #f5f5f5; padding: 12px; border-radius: 6px; white-space: pre-wrap; word-break: break-all; }}
</style>

<h1>Настройка завершена</h1>

{sharedBlock}

<div class=""block"">
    <b>Админ панель</b><br /><br />
    Aдрес: {host}/admin<br />
    Пароль: смотри файл <code>passwd</code> на хосте (<code>cat passwd</code> или <code>docker exec -it lampac cat passwd</code>)
</div>

<hr />

<div class=""block"">
    <div style=""margin-top:10px""> 
        <b>Media Station X</b><br /><br />
        Settings -> Start Parameter -> Setup<br />
        Enter current ip address and port: {HttpContext.Request.Host.Value}<br /><br />
        Убрать/Добавить адреса можно в /home/lampac/msx.json
    </div>
</div>

<hr />

<div class=""block"">
    <b>Виджет для Samsung</b><br /><br />
    {host}/samsung.wgt
</div>

<hr />

<div class=""block"">
    <b>Для android apk</b><br /><br />
    Зажмите кнопку назад и введите новый адрес: {host}
</div>

<hr />

<div class=""block"">
    <b>Плагины для Lampa</b><br /><br />
    Заходим в настройки - расширения, жмем на кнопку ""добавить плагин"". В окне ввода вписываем адрес плагина {host}/on.js и перезагружаем виджет удерживая кнопку ""назад"" пока виджет не закроется.
</div>

<hr />

<div class=""block"">
    <b>TorrServer (если установлен)</b><br /><br />
    {host}/ts
</div>

</body>
</html>";

                    return HttpContext.Response.WriteAsync(htmlSuccesds).ContinueWith(t => Shared.Startup.appReload.Reload());
                    #endregion
                }
            }

            #region renderHtml
            string renderHtml()
			{
				var modules = IO.File.Exists("module/manifest.json") ? JsonConvert.DeserializeObject<List<RootModule>>(IO.File.ReadAllText("module/manifest.json")) : null;

				string IsChecked(string name, string def)
				{
					if (modules == null)
						return def;

                    bool res = modules.FirstOrDefault(m => m.dll == name)?.enable ?? false;
                    return res ? "checked" : string.Empty;
                }

                return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"" />
	<title>Модули</title>
</head>
<body>

<style type='text/css'>
	* {{
	    box-sizing: border-box;
	    outline: none;
	}}
	body{{
		padding: 40px;
		font-family: sans-serif;
	}}
	label{{
		display: block;
		font-weight: 700;
		margin-bottom: 8px;
	}}
	input,
	select{{
		margin: 10px;
		margin-left: 0px;
	}}
	button{{
		padding: 10px;
	}}
	form > * + *{{
		margin-top: 30px;
	}}
	.flex{{
		display: flex;
		align-items: center;
	}}
</style>

<form method='post' action='/admin/manifest/install' id='form'>
	<div>
		<label>Установка модулей</label>
		<div class='flex'>
			<input name='online' type='checkbox' {IsChecked("Online.dll", "checked")} /> Онлайн балансеры Rezka, Filmix, etc
		</div>
		<div class='flex'>
			&nbsp; &nbsp; &nbsp; <input name='eng' type='checkbox' checked /> ENG балансеры
		</div>
		<div class='flex'>
			<input name='sisi' type='checkbox' {IsChecked("SISI.dll", "checked")} /> Клубничка 18+, PornHub, Xhamster, etc
		</div>
		<div class='flex'>
			<input name='catalog' type='checkbox' {IsChecked("Catalog.dll", "checked")} /> Альтернативные источники каталога cub и tmdb
		</div>
		<div class='flex'>
			<input name='dlna' type='checkbox' {IsChecked("DLNA.dll", "checked")} /> DLNA - Загрузка торрентов и просмотр медиа файлов с локального устройства 
		</div>
		<div class='flex'>
			<input name='ts' type='checkbox' {IsChecked("TorrServer.dll", "checked")} /> TorrServer - возможность просматривать торренты в онлайн 
		</div>
		<div class='flex'>
			<input name='tracks' type='checkbox' {IsChecked("Tracks.dll", "checked")} /> Tracks - транскодинг видео и замена названий аудиодорожек с rus1, rus2 на читаемые LostFilm, HDRezka, etc
		</div>
		<div class='flex'>
			<input name='merch' type='checkbox' {IsChecked("Merchant.dll", "")} /> Автоматизация оплаты FreeKassa, Streampay, Litecoin, CryptoCloud
		</div>

		<br><br>
		<label>Поиск торрентов</label>
		<div class='flex'>
			<input name='jac' type='radio' value='webapi' checked /> Быстрый поиск по внешним базам JacRed, Rutor, Kinozal, NNM-Club, Rutracker, etc
		</div>
		<div class='flex'>
			<input name='jac' type='radio' value='fdb' /> Локальный jacred.xyz (не рекомендуется ставить на домашние устройства) - 2GB HDD
		</div>
	</div>
	
	<button type='submit'>{(isEditManifest ? "Изменить настройки" : "Завершить настройку")}</button></form></body></html>";
            }
            #endregion

            return HttpContext.Response.WriteAsync(renderHtml());
        }
        #endregion


        #region UpdateInitConf
        void UpdateInitConf(Action<JObject> modify)
        {
            JObject jo;

            if (IO.File.Exists("init.conf"))
            {
                string initconf = IO.File.ReadAllText("init.conf").Trim();
                if (string.IsNullOrEmpty(initconf))
                    jo = new JObject();

                else
                {
                    if (!initconf.StartsWith("{"))
                        initconf = "{" + initconf + "}";

                    try
                    {
                        jo = JsonConvert.DeserializeObject<JObject>(initconf) ?? new JObject();
                    }
                    catch
                    {
                        jo = new JObject();
                    }
                }
            }
            else
            {
                jo = new JObject();
            }

            modify?.Invoke(jo);

            WriteAtomic("init.conf", JsonConvert.SerializeObject(jo, Formatting.Indented), backup: true);
        }
        #endregion
    }
}