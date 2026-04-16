using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Online.Controllers
{
    public class Jackett : BaseController
    {
        [HttpGet]
        [Route("lite/jac")]
        async public ValueTask<ActionResult> Index(string title, string original_title, string original_language, int year, int serial, int quality = -1)
        {
            if (!AppInit.conf.litejac)
                return Content(string.Empty);

            #region Кеш запроса
            string localhost = $"http://{AppInit.conf.listen.localhost}:{AppInit.conf.listen.port}";

            string memkey = $"lite/jac:{title}:{original_title}:{year}";
            if (!hybridCache.TryGetValue(memkey, out JArray results, inmemory: false) || quality == -1)
            {
                var root = await Http.Get<JObject>($"{localhost}/api/v2.0/indexers/all/results?apikey={AppInit.conf.apikey}&title={HttpUtility.UrlEncode(title)}&title_original={HttpUtility.UrlEncode(original_title)}&year={year}&is_serial={(original_language == "ja" ? 5 : (serial + 1))}", timeoutSeconds: 11, headers: HeadersModel.Init("localrequest", AppInit.rootPasswd));
                if (root == null)
                    return Content(string.Empty, "text/html; charset=utf-8");

                results = root.GetValue("Results")?.ToObject<JArray>();
                if (results == null || results.Count == 0)
                    return Content(string.Empty, "text/html; charset=utf-8");

                hybridCache.Set(memkey, results, DateTime.Now.AddMinutes(5), inmemory: false);
            }
            #endregion

            bool firstjson = true;
            string html = string.Empty;

            #region Меню качества
            HashSet<int> qualitys = new HashSet<int>();

            foreach (var item in results)
            {
                var info = item.Value<JObject>("Info");
                if (info != null)
                    qualitys.Add(info.Value<int>("quality"));
            }

            html = "<div class=\"videos__line\">";

            foreach (int q in qualitys.OrderByDescending(i => i))
            {
                string link = $"{host}/lite/jac?year={year}&serial={serial}&title={HttpUtility.UrlEncode(title)}&original_title={HttpUtility.UrlEncode(original_title)}&quality={q}";

                string active = q == quality ? "active" : "";

                // Why (FM-6): build the data-json payload via JsonConvert then HtmlEncode so
                // neither JSON nor HTML metacharacters from user-influenced fields can break
                // out of the attribute (stored XSS). Visible text goes through HtmlEncode too.
                string qjson = HttpUtility.HtmlEncode(JsonConvert.SerializeObject(new { method = "link", url = link }));
                html += "<div class=\"videos__button selector " + active + "\" data-json='" + qjson + "'>" + HttpUtility.HtmlEncode($"{q}p") + "</div>";
                firstjson = false;
            }

            firstjson = true;
            html += "</div>";
            #endregion

            foreach (var item in results)
            {
                int sid = item.Value<int>("Seeders"), pir = item.Value<int>("Peers"), q = 0;
                string magnet = item.Value<string>("MagnetUri");
                string tracker = item.Value<string>("Tracker");
                string sizeName = null;

                if (string.IsNullOrWhiteSpace(magnet))
                    magnet = item.Value<string>("Link").Replace(localhost, host);

                var info = item.Value<JObject>("Info");
                if (info != null)
                {
                    q = info.Value<int>("quality");
                    sizeName = info.Value<string>("sizeName");

                    if (quality != -1 && quality != q)
                        continue;
                }

                // Why (FM-6): Title/tracker/magnet are attacker-controllable data coming from
                // indexers. Build JSON via serializer, HtmlEncode the attribute value, and
                // HtmlEncode each visible text fragment so a crafted torrent title cannot
                // inject <script> or close the data-json='…' attribute.
                string itemJson = HttpUtility.HtmlEncode(JsonConvert.SerializeObject(new
                {
                    method = "torrent",
                    Link = magnet,
                    title = title ?? original_title
                }));
                string itemTitle = HttpUtility.HtmlEncode(item.Value<string>("Title") ?? string.Empty);
                string itemMeta = HttpUtility.HtmlEncode($"Размер {sizeName} / Раздают {sid} / Качают {pir} / {q}p / {tracker}");

                html += "<div class=\"videos__item videos__torrent selector " + (firstjson ? "focused" : "") + "\" media=\"\" data-json='" + itemJson + "'><div class=\"videos__torrent-title\">" + itemTitle + "</div><div class=\"videos__item-title\">" + itemMeta + "</div></div>";
                firstjson = false;
            }

            return ContentTo(html);
        }
    }
}
