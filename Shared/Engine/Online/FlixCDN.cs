using Shared.Models.Templates;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Shared.Engine.Online
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/FlixCDN/Service.cs).
    //
    // Small helper struct that:
    //  * turns the `file` string scraped from the embed page into a StreamQualityTpl
    //    (supporting either [1080]https://... entries or a single bare stream URL)
    //  * composes the iframe URL with translation/season/episode query args
    //
    // No HTTP, no state — pure text shaping.
    public struct FlixCDNInvoke
    {
        bool usehls;
        Func<string, string> onstreamfile;

        public FlixCDNInvoke(bool hls, Func<string, string> onstreamfile)
        {
            this.onstreamfile = onstreamfile;
            usehls = hls;
        }

        #region StreamQuality
        public StreamQualityTpl GetStreamQualityTpl(string file)
        {
            var streamquality = new StreamQualityTpl();

            var map = new Dictionary<string, string>(8);

            foreach (Match m in Regex.Matches(file, "\\[(?<q>\\d{3,4})\\](?<url>https?://[^,\\s]+)"))
            {
                string q = m.Groups["q"].Value;
                string link = m.Groups["url"].Value;

                if (string.IsNullOrEmpty(link) || string.IsNullOrEmpty(q))
                    continue;

                if (!usehls)
                    link = link.Replace(":hls:manifest.m3u8", "");

                map[q] = onstreamfile.Invoke(link);
            }

            if (map.Count == 0)
            {
                foreach (Match m in Regex.Matches(file, "(https?://[^,\\s]+\\.(m3u8|mp4)(:hls:manifest\\.m3u8)?)"))
                {
                    string link = m.Groups[1].Value;
                    if (string.IsNullOrEmpty(link))
                        continue;

                    if (!usehls)
                        link = link.Replace(":hls:manifest.m3u8", "");

                    streamquality.Append(onstreamfile.Invoke(link), "auto");
                    break;
                }

                return streamquality;
            }

            foreach (string q in new string[] { "2160", "1440", "1080", "720", "480", "360", "240" })
            {
                if (map.TryGetValue(q, out string link))
                    streamquality.Append(link, $"{q}p");
            }

            return streamquality;
        }
        #endregion

        #region BuildIframeUrl
        public string BuildIframeUrl(string iframe, int t, int s, int e)
        {
            var args = new List<string>(3);

            if (t > 0)
                args.Add("translation=" + t);

            if (s > 0)
                args.Add("season=" + s);

            if (e > 0)
                args.Add("episode=" + e);

            if (args.Count == 0)
                return iframe;

            return iframe + (iframe.Contains("?") ? "&" : "?") + string.Join("&", args);
        }
        #endregion
    }
}
