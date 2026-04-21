using Shared;
using Shared.Engine;
using System;
using System.IO;
using System.Security.Cryptography;
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

                // Why: M-1 — all HTTPS origins are preferred. HTTP-only origins are now rejected
                // inside update() so a MITM on those two endpoints cannot inject JS into wwwroot.
                await update("https://immisterio.github.io/bwa/fx.js");
                await update("https://adultjs.onrender.com", path: "adult.js");
                await update("https://nb557.github.io/plugins/online_mod.js");
                await update("https://github.freebie.tom.ru/want.js");
                await update("https://nb557.github.io/plugins/reset_subs.js");
                // TODO: 193.233.134.21 is an IP-only origin without a valid TLS cert; skipped fail-closed
                // until the upstream supports HTTPS or publishes a pinnable sha256. Safer to miss an
                // update than to run attacker-controlled JS in the Lampa UI.
                await update("http://193.233.134.21/plugins/mult.js");
                await update("https://nemiroff.github.io/lampa/select_weapon.js");
                await update("https://nb557.github.io/plugins/not_mobile.js");
                await update("https://cub.red/plugin/etor", path: "etor.js");
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


        async static Task update(string url, string checkcode = "Lampa.", string path = null, string sha256 = null)
        {
            try
            {
                // Why: fail-closed for HTTP origins. A MITM on the operator's uplink could swap the
                // fetched JS for arbitrary code that executes in every user's Lampa UI. Unless the
                // caller provides an out-of-band sha256 pin (which we verify below), skip the fetch
                // entirely rather than overwrite wwwroot/plugins/*.js from a plaintext channel.
                if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(sha256))
                {
                    Console.WriteLine($"PluginsCron: skipped insecure HTTP source without sha256 pin: {url}");
                    return;
                }

                await Http.GetSpan(js =>
                {
                    // Why: M-1 — strict validation before overwriting wwwroot/plugins/*.js.
                    // Rejects MITM-injected HTML (redirect/captcha pages), empty stubs, and
                    // oversized payloads on top of the original Lampa. marker check.
                    if (!IsValidPluginPayload(js, checkcode))
                        return;

                    // Why: optional content pinning. When the caller supplies an expected sha256,
                    // refuse to write the file on mismatch — this protects HTTP origins and also
                    // catches a compromised HTTPS CDN.
                    if (!string.IsNullOrEmpty(sha256))
                    {
                        byte[] bodyBytes = Encoding.UTF8.GetBytes(js.ToString());
                        byte[] hash = SHA256.HashData(bodyBytes);
                        string actual = Convert.ToHexString(hash);
                        if (!string.Equals(actual, sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"PluginsCron: sha256 mismatch for {url} (expected {sha256}, got {actual})");
                            return;
                        }
                    }
                    else if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    {
                        // Defence in depth: we already rejected the HTTP path above, but if somebody
                        // bypasses it in the future, log rather than silently accept.
                        Console.WriteLine($"PluginsCron: refusing unpinned HTTP payload from {url}");
                        return;
                    }

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
