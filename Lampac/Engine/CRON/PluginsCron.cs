using Shared;
using Shared.Engine;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Lampac.Engine.CRON
{
    public static class PluginsCron
    {
        public static void Run()
        {
            _cronTimer = new Timer(cron, null, TimeSpan.FromMinutes(2), TimeSpan.FromHours(1));
        }

        static Timer _cronTimer;

        static bool _cronWork = false;

        async static void cron(object state)
        {
            if (_cronWork)
                return;

            _cronWork = true;

            try
            {
                if (!AppInit.conf.pirate_store)
                    return;

                // Why: M-1 — all HTTPS origins are preferred. For each origin we probed above we
                // switched http:// -> https:// where the origin actually serves TLS, and left
                // http:// only for endpoints that cannot (IP-only hosts with no valid cert).
                await update("https://immisterio.github.io/bwa/fx.js");
                await update("https://adultjs.onrender.com", path: "adult.js");
                await update("https://nb557.github.io/plugins/online_mod.js");
                await update("https://github.freebie.tom.ru/want.js"); // Why: M-1 — switched to HTTPS (origin serves valid TLS).
                await update("https://nb557.github.io/plugins/reset_subs.js");
                // Why: M-1 — 193.233.134.21 is an IP-only host without a valid HTTPS cert; kept HTTP but payload is validated by update() below.
                await update("http://193.233.134.21/plugins/mult.js");
                await update("https://nemiroff.github.io/lampa/select_weapon.js");
                await update("https://nb557.github.io/plugins/not_mobile.js");
                await update("https://cub.red/plugin/etor", path: "etor.js"); // Why: M-1 — switched to HTTPS (origin serves valid TLS).
                // Why: M-1 — same IP-only origin as mult.js; kept HTTP, relies on content validation in update().
                await update("http://193.233.134.21/plugins/checker.js");
                await update("https://plugin.rootu.top/ts-preload.js");
                await update("https://lampame.github.io/main/pubtorr/pubtorr.js");
                await update("https://lampame.github.io/main/nc/nc.js");
                await update("https://nb557.github.io/plugins/rating.js");
                await update("https://github.freebie.tom.ru/torrents.js");
                await update("https://nnmdd.github.io/lampa_hotkeys/hotkeys.js");
                await update("https://bazzzilius.github.io/scripts/gold_theme.js");
                await update("https://bdvburik.github.io/rezkacomment.js");
                await update("https://lampame.github.io/main/Shikimori/Shikimori.js");
            }
            catch { }
            finally
            {
                _cronWork = false;
            }
        }


        async static Task update(string url, string checkcode = "Lampa.", string path = null)
        {
            try
            {
                await Http.GetSpan(js =>
                {
                    // Why: M-1 — strict validation before overwriting wwwroot/plugins/*.js.
                    // Rejects MITM-injected HTML (redirect/captcha pages), empty stubs, and
                    // oversized payloads on top of the original Lampa. marker check.
                    if (!IsValidPluginPayload(js, checkcode))
                        return;

                    if (path == null)
                        path = Path.GetFileName(url);

                    string destination = $"wwwroot/plugins/{path}";

                    // Why: M-1 — atomic replace. Write to a temp sibling first so a partial/bad
                    // write cannot corrupt the live file; if verification/write fails we keep
                    // the previous version intact.
                    string tempPath = destination + ".tmp";
                    try
                    {
                        File.WriteAllText(tempPath, js.ToString(), Encoding.UTF8);

                        // Double-check on-disk size after write.
                        var fi = new FileInfo(tempPath);
                        if (fi.Length < 1024 || fi.Length > 5 * 1024 * 1024)
                        {
                            File.Delete(tempPath);
                            return;
                        }

                        // Atomic move (overwrites existing).
                        File.Move(tempPath, destination, overwrite: true);
                    }
                    catch
                    {
                        try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                    }

                }, url, Encoding.UTF8, weblog: false);
            }
            catch { }
        }

        // Why: M-1 — central validator. Refuses payload if it is too small, too large,
        // looks like HTML (redirect / captcha wall / error page), or is missing the
        // expected Lampa. marker. TODO: pin per-plugin SHA-256 hashes when upstreams
        // publish stable releases — that would give real integrity instead of heuristics.
        static bool IsValidPluginPayload(ReadOnlySpan<char> js, string checkcode)
        {
            if (js.Length < 1024 || js.Length > 5 * 1024 * 1024)
                return false;

            if (!js.Contains(checkcode.AsSpan(), StringComparison.Ordinal))
                return false;

            // Cheap HTML sniff: reject obvious HTML/redirect/captcha responses.
            // We only look at the first 512 chars — real JS plugins don't start with a DOCTYPE or <html>.
            int peekLen = Math.Min(js.Length, 512);
            ReadOnlySpan<char> head = js.Slice(0, peekLen);
            if (head.Contains("<!doctype".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
                head.Contains("<html".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
                head.Contains("<head".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
                head.Contains("<body".AsSpan(), StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }
    }
}
