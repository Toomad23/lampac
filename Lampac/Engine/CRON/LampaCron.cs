using Shared;
using Shared.Engine;
using Shared.Engine.Utilities;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Lampac.Engine.CRON
{
    public static class LampaCron
    {
        static string currentapp;
        static bool unpinnedWarned;

        public static void Run()
        {
            var init = AppInit.conf.LampaWeb;
            _cronTimer = new Timer(cron, null, TimeSpan.FromSeconds(20), TimeSpan.FromMinutes(Math.Max(init.intervalupdate, 5)));
        }

        static Timer _cronTimer;

        static int _updatingDb = 0;

        async static void cron(object state)
        {
            if (Interlocked.Exchange(ref _updatingDb, 1) == 1)
                return;

            try
            {
                var init = AppInit.conf.LampaWeb;
                bool istree = !string.IsNullOrEmpty(init.tree);

                async ValueTask<bool> update()
                {
                    if (!init.autoupdate)
                        return false;

                    if (!File.Exists("wwwroot/lampa-main/app.min.js"))
                        return true;

                    if (istree && File.Exists("wwwroot/lampa-main/tree") && init.tree == File.ReadAllText("wwwroot/lampa-main/tree"))
                        return false;

                    bool changeversion = false;

                    await Http.GetSpan(gitapp => 
                    {
                        if (!gitapp.Contains("author: 'Yumata'", StringComparison.Ordinal))
                            return;

                        if (currentapp == null)
                            currentapp = CrypTo.md5File("wwwroot/lampa-main/app.min.js");

                        if (!string.IsNullOrEmpty(currentapp) && CrypTo.md5(gitapp) != currentapp)
                            changeversion = true;

                    }, $"https://raw.githubusercontent.com/{init.git}/{(istree ? init.tree : "main")}/app.min.js", weblog: false);

                    if (istree)
                        File.WriteAllText("wwwroot/lampa-main/tree", init.tree);

                    return changeversion;
                }

                if (await update())
                {
                    string uri = istree ?
                        $"https://github.com/{init.git}/archive/{init.tree}.zip" :
                        $"https://github.com/{init.git}/archive/refs/heads/main.zip";

                    byte[] array = await Http.Download(uri);
                    if (array != null)
                    {
                        // Why (supply-chain): the Lampa zip comes from a third-party
                        // host. If operator pinned init.sha256 we verify before
                        // extracting; mismatch keeps the previously-installed copy.
                        string actualSha = ZipSafe.ComputeSha256Hex(array);
                        if (!string.IsNullOrWhiteSpace(init.sha256))
                        {
                            if (!string.Equals(actualSha, init.sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                            {
                                Console.WriteLine($"LampaCron: ERROR sha256 mismatch for {uri} (expected {init.sha256}, got {actualSha}); keeping existing install");
                                return;
                            }
                        }
                        else if (!unpinnedWarned)
                        {
                            unpinnedWarned = true;
                            Console.WriteLine($"LampaCron: LampaWeb.sha256 not set; downloaded Lampa zip is unverified (actual sha256={actualSha}). Add 'sha256' to lock. (warning shown once per process)");
                        }

                        currentapp = null;

                        await File.WriteAllBytesAsync("wwwroot/lampa.zip", array);
                        ZipSafe.ExtractToDirectory("wwwroot/lampa.zip", "wwwroot/", overwriteFiles: true);

                        if (istree)
                        {
                            foreach (string infilePath in Directory.GetFiles($"wwwroot/lampa-{init.tree}", "*", SearchOption.AllDirectories))
                            {
                                string outfile = infilePath.Replace($"lampa-{init.tree}", "lampa-main");
                                Directory.CreateDirectory(Path.GetDirectoryName(outfile));
                                File.Copy(infilePath, outfile, true);
                            }

                            File.WriteAllText("wwwroot/lampa-main/tree", init.tree);
                        }

                        string html = File.ReadAllText("wwwroot/lampa-main/index.html");
                        html = html.Replace("</body>", "<script src=\"/lampainit.js\"></script></body>");

                        File.WriteAllText("wwwroot/lampa-main/index.html", html);
                        File.CreateText("wwwroot/lampa-main/personal.lampa");

                        if (!File.Exists("wwwroot/lampa-main/plugins_black_list.json"))
                            File.WriteAllText("wwwroot/lampa-main/plugins_black_list.json", "[]");

                        if (!File.Exists("wwwroot/lampa-main/plugins/modification.js"))
                        {
                            Directory.CreateDirectory("wwwroot/lampa-main/plugins");
                            File.WriteAllText("wwwroot/lampa-main/plugins/modification.js", string.Empty);
                        }

                        File.Delete("wwwroot/lampa.zip");

                        if (istree)
                            Directory.Delete($"wwwroot/lampa-{init.tree}", true);
                    }
                }
            }
            catch { }
            finally
            {
                Volatile.Write(ref _updatingDb, 0);
            }
        }
    }
}
