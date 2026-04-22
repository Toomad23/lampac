using Shared.Engine.RxEnumerate;
using Shared.Engine.Utilities;
using Shared.Models;
using Shared.Models.Base;
using Shared.Models.Online.PizdatoeHD;
using Shared.Models.Online.Settings;
using Shared.Models.Templates;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace Shared.Engine.Online
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/PizdatoeHD/Services/PizdaInvoke.cs).
    //
    // Text-shaping helpers for the rezka.ag ("PizdatoeHD") HTML. No HTTP / browser is
    // performed here — the controller drives Playwright, then hands raw HTML / JSON to
    // these parsers. Kept as a class (not a struct) because the upstream instance holds
    // Func<string, string> for streamfile rewriting, which a struct would box anyway.
    public class PizdatoeHDInvoke
    {
        PizdatoeHDSettings init;
        string host, route;
        Func<string, string> onstreamfile;

        public PizdatoeHDInvoke(string host, string route, PizdatoeHDSettings init, Func<string, string> onstreamfile)
        {
            this.host = host != null ? $"{host}/" : null;
            this.route = route;
            this.init = init;
            this.onstreamfile = onstreamfile;
        }

        #region Search
        public PizdatoeSearchModel Search(string html, string title, string original_title, int year)
        {
            var result = new PizdatoeSearchModel();

            string reservedlink = null;

            if (html.Contains("class=\"error-code\"", StringComparison.OrdinalIgnoreCase) && html.Contains("ошибка доступа", StringComparison.OrdinalIgnoreCase))
            {
                if (html.Contains("(105)") || html.Contains(">105<") ||
                    html.Contains("(403)") || html.Contains(">403<"))
                {
                    return new PizdatoeSearchModel() { IsEmpty = true, content = "Ошибка доступа (105)<br>IP-адрес заблокирован<br><br>" };
                }

                if (html.Contains("(101)") || html.Contains(">101<"))
                    return new PizdatoeSearchModel() { IsEmpty = true, content = "Ошибка доступа (101)<br>Аккаунт заблокирован<br><br>" };

                var accessError = Regex.Match(html, "Ошибка доступа[ \t]+\\(([0-9]+)\\)", RegexOptions.IgnoreCase);
                return new PizdatoeSearchModel() { IsEmpty = true, content = $"Ошибка доступа ({(accessError.Success ? accessError.Groups[1].Value : "?")})" };
            }

            string stitle = StringConvert.SearchName(title);
            string sorigtitle = StringConvert.SearchName(original_title);

            var rx = Rx.Split("\"b-content__inline_item\"", html, 1);
            if (rx.Count == 0)
            {
                result.IsError = true;
                return result;
            }

            foreach (var row in rx.Rows())
            {
                var g = row.Groups("href=\"https?://[^/]+/([^\"]+)\">([^<]+)</a> ?<div>([0-9]{4})");

                if (string.IsNullOrEmpty(g[1].Value))
                    continue;

                string name = g[2].Value.Trim();
                if (string.IsNullOrEmpty(name))
                    continue;

                if (result.similar == null)
                    result.similar = new List<PizdatoeSimilarModel>(rx.Count);

                string img = row.Match("<img src=\"([^\"]+)\"");
                result.similar.Add(new PizdatoeSimilarModel(name, g[3].Value, g[1].Value, img));

                string _sname = StringConvert.SearchName(name);

                if ((stitle != null && (name.Contains(" / ") && _sname.Contains(stitle) || _sname == stitle)) ||
                    (sorigtitle != null && (name.Contains(" / ") && _sname.Contains(sorigtitle) || _sname == sorigtitle)))
                {
                    reservedlink = g[1].Value;

                    if (string.IsNullOrEmpty(result.href) && year > 0 && g[3].Value == year.ToString())
                        result.href = reservedlink;
                }
            }

            if (string.IsNullOrEmpty(result.href))
            {
                if (string.IsNullOrEmpty(reservedlink))
                {
                    if (result.similar != null && result.similar.Count > 0)
                        return result;

                    if (html.Contains("Результаты поиска"))
                        return new PizdatoeSearchModel() { IsEmpty = true };

                    result.IsError = true;
                    return result;
                }

                result.href = reservedlink;
            }

            return result;
        }
        #endregion

        #region Embed
        public PizdatoeRootObject Embed(string href, string html)
        {
            var result = new PizdatoeRootObject();

            bool IsTrailer = html.Contains("Ожидаем фильм в хорошем качестве", StringComparison.OrdinalIgnoreCase);

            if (!html.Contains("data-season_id="))
            {
                var rx = Rx.Split("ctrl_token_id", html);
                if (rx.Count > 0)
                {
                    var row = Rx.Split("translators-list", rx[0].Span);
                    if (row.Count > 1)
                        result.content = row[1].ToString();
                    else
                        result.content = rx[1].Span.ToString();
                }
            }
            else
            {
                string trs = Rx.Match(html, "\\.initCDNSeriesEvents\\([0-9]+, ([0-9]+),");
                if (string.IsNullOrEmpty(trs))
                    return null;

                result.trs = trs;

                var rx = Rx.Split("user-network-issues", html);
                if (rx.Count > 0)
                {
                    var row = Rx.Split("b-post__lastepisodeout", rx[0].Span);
                    if (row.Count > 1)
                        result.content = row[1].ToString();
                    else if (!IsTrailer)
                        result.content = rx[0].Span.ToString();
                }
            }

            if (string.IsNullOrEmpty(result.content))
            {
                return IsTrailer
                    ? new PizdatoeRootObject() { IsEmpty = true, content = "Ожидаем фильм в хорошем качестве..." }
                    : null;
            }

            return result;
        }
        #endregion

        #region Movie
        public PizdatoeMovieModel AjaxMovie(string json)
        {
            Dictionary<string, object> root;
            try
            {
                root = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
            }
            catch { return null; }

            if (root == null)
                return null;

            string url = root.ContainsKey("url") ? root["url"]?.ToString() : null;
            if (string.IsNullOrEmpty(url) || url.Contains("false", StringComparison.OrdinalIgnoreCase))
                return null;

            var links = getStreamLink(url);
            if (links.Count == 0)
                return null;

            string subtitlehtml = null;
            try { subtitlehtml = root.TryGetValue("subtitle", out var sub) ? sub?.ToString() : null; } catch { }

            return new PizdatoeMovieModel() { links = links, subtitlehtml = subtitlehtml };
        }

        public PizdatoeMovieModel Movie(string html)
        {
            string url = Rx.Match(html, "\"streams\"\\s*:\\s*\"(.*?)\"\\s*,");
            if (string.IsNullOrEmpty(url) || url.Contains("false", StringComparison.OrdinalIgnoreCase))
                return null;

            var links = getStreamLink(url.Replace("\\", ""));
            if (links.Count == 0)
                return null;

            string subtitlehtml = Rx.Match(html, "\"subtitle\":\"([^\"]+)\"");

            return new PizdatoeMovieModel() { links = links, subtitlehtml = subtitlehtml };
        }

        public string Movie(PizdatoeMovieModel md, string title, string original_title, bool play, VastConf vast = null)
        {
            if (play)
                return onstreamfile(md.links[0].stream_url);

            var subtitles = new SubtitleTpl();

            try
            {
                if (!string.IsNullOrWhiteSpace(md.subtitlehtml))
                {
                    var m = Regex.Match(md.subtitlehtml, "\\[([^\\]]+)\\](https?://[^\n\r,']+\\.vtt)");
                    while (m.Success)
                    {
                        if (!string.IsNullOrEmpty(m.Groups[1].Value) && !string.IsNullOrEmpty(m.Groups[2].Value))
                        {
                            string vtt = m.Groups[2].Value;
                            // Why: subtitle URLs are scraped — SSRF-guard before we serve them back.
                            if (SsrfGuard.IsAllowedPublicUriBasic(vtt))
                                subtitles.Append(m.Groups[1].Value, onstreamfile(vtt));
                        }
                        m = m.NextMatch();
                    }
                }
            }
            catch { }

            var streamquality = new StreamQualityTpl();
            foreach (var l in md.links)
                streamquality.Append(onstreamfile(l.stream_url), l.title);

            return VideoTpl.ToJson("play", onstreamfile(md.links[0].stream_url), (title ?? original_title ?? "auto"),
                streamquality: streamquality,
                subtitles: subtitles,
                vast: vast,
                hls_manifest_timeout: (int)TimeSpan.FromSeconds(20).TotalMilliseconds
            );
        }
        #endregion


        #region Tpl
        public ITplResult Tpl(PizdatoeRootObject result, string args, string title, string original_title, string href, string t, int s, bool rjson = false)
        {
            if (result == null || result.IsEmpty || result.content == null)
                return default;

            if (!string.IsNullOrEmpty(args))
                args = $"&{args.Remove(0, 1)}";

            string enc_title = HttpUtility.UrlEncode(title);
            string enc_original_title = HttpUtility.UrlEncode(original_title);
            string enc_href = HttpUtility.UrlEncode(href);

            if (!result.content.Contains("data-season_id="))
            {
                #region Фильм
                var match = new Regex("<[^>]+ data-translator_id=\"([0-9]+)\"([^>]+)?>(?<voice>[^<]+)(<img title=\"(?<imgname>[^\"]+)\" [^>]+/>)?").Match(result.content);

                var mtpl = new MovieTpl(title, original_title, match.Length);

                if (match.Success)
                {
                    while (match.Success)
                    {
                        if (!string.IsNullOrEmpty(match.Groups[1].Value) && !string.IsNullOrEmpty(match.Groups["voice"].Value))
                        {
                            if (match.Groups[0].Value.Contains("prem_translator"))
                            {
                                match = match.NextMatch();
                                continue;
                            }

                            string link = host + $"{route}/movie?title={enc_title}&original_title={enc_original_title}&t={match.Groups[1].Value}";

                            string voice_href = Regex.Match(match.Groups[0].Value, "href=\"(https?://[^/]+)?/([^\"]+)\"").Groups[2].Value;
                            if (string.IsNullOrEmpty(voice_href))
                            {
                                match = match.NextMatch();
                                continue;
                            }

                            link += $"&voice={HttpUtility.UrlEncode(voice_href)}";

                            string voice = match.Groups["voice"].Value.Trim();

                            if (!string.IsNullOrEmpty(match.Groups["imgname"].Value) && !voice.ToLower().Contains(match.Groups["imgname"].Value.ToLower().Trim()))
                                voice += $" ({match.Groups["imgname"].Value.Trim()})";

                            if (voice == "-" || string.IsNullOrEmpty(voice))
                                voice = "Оригинал";

                            string stream = init.hls ? $"{link.Replace("/movie", "/movie.m3u8")}&play=true" : $"{link}&play=true";
                            stream += args;

                            mtpl.Append(voice, link, "call", stream);
                        }

                        match = match.NextMatch();
                    }
                }

                if (mtpl.Length == 0)
                {
                    var links = getStreamLink(Regex.Match(result.content, "\"id\":\"cdnplayer\",\"streams\":\"([^\"]+)\"").Groups[1].Value.Replace("\\", ""));
                    if (links.Count == 0)
                        return default;

                    var streamquality = new StreamQualityTpl();
                    foreach (var l in links)
                        streamquality.Append(onstreamfile(l.stream_url), l.title);

                    var first = streamquality.Firts();
                    if (first != null)
                        mtpl.Append(first.quality, onstreamfile(links[0].stream_url), streamquality: streamquality);
                }

                return mtpl;
                #endregion
            }
            else
            {
                string selectVoice = string.IsNullOrEmpty(t) ? result.trs : t;

                #region Перевод
                var vtpl = new VoiceTpl();

                if (result.content.Contains("data-translator_id="))
                {
                    var match = new Regex("<[a-z]+ [^>]+ data-translator_id=\"(?<translator>[0-9]+)\"([^>]+)?>(?<name>[^<]+)(<img title=\"(?<imgname>[^\"]+)\" [^>]+/>)?").Match(result.content);
                    while (match.Success)
                    {
                        if (!init.premium && match.Groups[0].Value.Contains("prem_translator"))
                        {
                            match = match.NextMatch();
                            continue;
                        }

                        string name = match.Groups["name"].Value.Trim();
                        if (!string.IsNullOrEmpty(match.Groups["imgname"].Value) && !name.ToLower().Contains(match.Groups["imgname"].Value.ToLower().Trim()))
                            name += $" ({match.Groups["imgname"].Value})";

                        string voice_href = Regex.Match(match.Groups[0].Value, "href=\"(https?://[^/]+)?/([^\"]+)\"").Groups[2].Value;
                        string voice = HttpUtility.UrlEncode(voice_href);
                        if (string.IsNullOrEmpty(voice))
                            voice = enc_href;

                        string link = host + $"{route}?rjson={rjson}&title={enc_title}&original_title={enc_original_title}&href={voice}&t={match.Groups["translator"].Value}";

                        vtpl.Append(name, match.Groups["translator"].Value == selectVoice, link);

                        match = match.NextMatch();
                    }
                }
                #endregion

                #region Сериал
                var tpl = new SeasonTpl(vtpl);
                var etpl = new EpisodeTpl(vtpl);
                HashSet<string> eshash = new HashSet<string>();

                string sArhc = s.ToString();

                var m = Regex.Match(result.content, "data-cdn_url=\"(?<cdn>[^\"]+)\" [^>]+ data-season_id=\"(?<season>[0-9]+)\" data-episode_id=\"(?<episode>[0-9]+)\"([^>]+)?>(?<name>[^>]+)</[a-z]+>");
                while (m.Success)
                {
                    if (s == -1)
                    {
                        string sname = $"{m.Groups["season"].Value} сезон";
                        if (!string.IsNullOrEmpty(m.Groups["season"].Value) && !eshash.Contains(sname))
                        {
                            eshash.Add(sname);
                            string link = host + $"{route}?rjson={rjson}&title={enc_title}&original_title={enc_original_title}&href={enc_href}&t={selectVoice}&s={m.Groups["season"].Value}";
                            tpl.Append(sname, link, m.Groups["season"].Value);
                        }
                    }
                    else
                    {
                        if (m.Groups["season"].Value == sArhc && !eshash.Contains(m.Groups["name"].Value))
                        {
                            eshash.Add(m.Groups["name"].Value);

                            string voice_href = Regex.Match(m.Groups[0].Value, "href=\"(https?://[^/]+)?/([^\"]+)\"").Groups[2].Value;

                            string link = host + $"{route}/movie?title={enc_title}&original_title={enc_original_title}&href={enc_href}&voice={HttpUtility.UrlEncode(voice_href)}&t={selectVoice}&s={s}&e={m.Groups["episode"].Value}";

                            string stream = init.hls ? $"{link.Replace("/movie", "/movie.m3u8")}&play=true" : $"{link}&play=true";
                            stream += args;

                            etpl.Append(m.Groups["name"].Value, title ?? original_title, sArhc, m.Groups["episode"].Value, link, "call", streamlink: stream);
                        }
                    }

                    m = m.NextMatch();
                }

                if (s == -1)
                    return tpl;

                return etpl;
                #endregion
            }
        }
        #endregion


        #region decodeBase64
        static readonly string[] trashListBase = { "JCQhIUAkJEBeIUAjJCRA", "QEBAQEAhIyMhXl5e", "IyMjI14hISMjIUBA", "Xl5eIUAjIyEhIyM=", "JCQjISFAIyFAIyM=" };
        static readonly string[] trashListOld = {
            "QEA=","QCM=","QCE=","QF4=","QCQ=","I0A=","IyM=","IyE=","I14=","IyQ=","IUA=","ISM=","ISE=","IV4=","ISQ=","XkA=","XiM=","XiE=","Xl4=","XiQ=","JEA=","JCM=","JCE=","JF4=","JCQ=",
            "QEBA","QEAj","QEAh","QEBe","QEAk","QCNA","QCMj","QCMh","QCNe","QCMk","QCFA","QCEj","QCEh","QCFe","QCEk","QF5A","QF4j","QF4h","QF5e","QF4k","QCRA","QCQj","QCQh","QCRe","QCQk",
            "I0BA","I0Aj","I0Ah","I0Be","I0Ak","IyNA","IyMj","IyMh","IyNe","IyMk","IyFA","IyEj","IyEh","IyFe","IyEk","I15A","I14j","I14h","I15e","I14k","IyRA","IyQj","IyQh","IyRe","IyQk",
            "IUBA","IUAj","IUAh","IUBe","IUAk","ISNA","ISMj","ISMh","ISNe","ISMk","ISFA","ISEj","ISEh","ISFe","ISEk","IV5A","IV4j","IV4h","IV5e","IV4k","ISRA","ISQj","ISQh","ISRe","ISQk",
            "XkBA","XkAj","XkAh","XkBe","XkAk","XiNA","XiMj","XiMh","XiNe","XiMk","XiFA","XiEj","XiEh","XiFe","XiEk","Xl5A","Xl4j","Xl4h","Xl5e","Xl4k","XiRA","XiQj","XiQh","XiRe","XiQk",
            "JEBA","JEAj","JEAh","JEBe","JEAk","JCNA","JCMj","JCMh","JCNe","JCMk","JCFA","JCEj","JCEh","JCFe","JCEk","JF5A","JF4j","JF4h","JF5e","JF4k","JCRA","JCQj","JCQh","JCRe","JCQk"
        };

        static string decodeBase64(string data)
        {
            if (!data.StartsWith("#"))
                return data;

            try
            {
                string _data = data.Remove(0, 2);

                foreach (string trash in trashListBase)
                {
                    if (_data.Contains($"//_//{trash}"))
                        _data = _data.Replace($"//_//{trash}", "");
                }

                byte[] buffer = new byte[Encoding.UTF8.GetMaxByteCount(data.Length)];
                if (Convert.TryFromBase64String(_data, buffer, out int bytesWritten))
                    return Encoding.UTF8.GetString(buffer, 0, bytesWritten);

                string stripped = Regex.Replace(_data, "//[^/]+_//", "").Replace("//_//", "");
                if (Convert.TryFromBase64String(stripped, buffer, out bytesWritten))
                    return Encoding.UTF8.GetString(buffer, 0, bytesWritten);

                _data = data.Remove(0, 2).Replace("//_//", "");
                foreach (string trash in trashListOld)
                {
                    if (_data.Contains(trash))
                        _data = _data.Replace(trash, "");
                }

                _data = Regex.Replace(_data, "//[^/]+_//", "").Replace("//_//", "");
                if (Convert.TryFromBase64String(_data, buffer, out bytesWritten))
                    return Encoding.UTF8.GetString(buffer, 0, bytesWritten);
            }
            catch { }

            return data;
        }
        #endregion

        #region getStreamLink
        List<PizdatoeApiModel> getStreamLink(string _data)
        {
            string data = decodeBase64(_data);
            var links = new List<PizdatoeApiModel>(6);

            string getLink(string _q)
            {
                string qline = Regex.Match(data, $"\\[({_q}|[^\\]]+{_q}[^\\]]+)\\]([^,\\[]+)").Groups[2].Value;
                if (!qline.Contains(".mp4") && !qline.Contains(".m3u8"))
                    return null;

                string link = Regex.Match(qline, "(https?://[^\\[\n\r, ]+)").Groups[1].Value;
                if (string.IsNullOrEmpty(link))
                    return null;

                // Why: all stream URLs come from scraped upstream HTML; reject private targets.
                if (!SsrfGuard.IsAllowedPublicUriBasic(link))
                    return null;

                if (init.hls)
                {
                    if (link.EndsWith(".m3u8"))
                        return link;
                    return link + ":hls:manifest.m3u8";
                }

                return link.Replace(":hls:manifest.m3u8", "");
            }

            var qualities = init.premium
                ? new List<string> { "2160p", "1440p", "1080p Ultra", "1080p", "720p", "480p" }
                : new List<string> { "1080p", "720p", "480p" };

            foreach (string q in qualities)
            {
                string link = q switch
                {
                    "2160p" => getLink("4K") ?? getLink(q),
                    "1440p" => getLink("2K") ?? getLink(q),
                    "1080p" => init.premium ? (getLink(q) ?? getLink("1080p Ultra")) : getLink(q),
                    _ => getLink(q)
                };

                if (string.IsNullOrEmpty(link))
                    continue;

                if (init.scheme == "http")
                    link = link.Replace("https:", "http:");

                string realq = q switch
                {
                    "1080p Ultra" => "1080p",
                    "1080p" => "720p",
                    "720p" => "480p",
                    "480p" => "360p",
                    _ => q
                };

                links.Add(new PizdatoeApiModel()
                {
                    title = realq,
                    stream_url = link
                });
            }

            return links;
        }
        #endregion
    }
}
