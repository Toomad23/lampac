using LiteDB;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Shared.Engine;
using Shared.Models.Module;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace TorrServer
{
    [ModuleEntry]
    public class ModInit
    {
        #region static
        static bool IsShutdown;

        public static int tsport = 9080;

        public static string tspass = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        static string TryReadExistingTsPass(string accsDbPath)
        {
            try
            {
                if (!File.Exists(accsDbPath))
                    return null;

                string raw = File.ReadAllText(accsDbPath);
                if (string.IsNullOrWhiteSpace(raw))
                    return null;

                var obj = JObject.Parse(raw);
                string existing = obj.Value<string>("ts");
                return string.IsNullOrEmpty(existing) ? null : existing;
            }
            catch { return null; }
        }

        public static string homedir;

        public static string tspath;

        public static Process tsprocess;
        #endregion

        #region dataDb
        static LiteDatabase dataDb;

        public static ILiteCollection<WhoseHashModel> whosehash { get; set; }
        #endregion

        #region ModInit
        public string releases { get; set; } = "MatriX.135";

        public bool rdb { get; set; }

        public string defaultPasswd { get; set; } = "ts";

        public int group { get; set; }

        /// <summary>
        /// auth
        /// full
        /// null - desable
        /// </summary>
        public string multiaccess { get; set; } = "auth";

        public bool checkfile { get; set; } = true;


        static (ModInit, DateTime) cacheconf = default;

        public static ModInit conf => cacheconf.Item1;
        #endregion

        #region cron_UpdateSettings
        static Timer _cronTimer;

        static int _cronWork = 0;

        static void cron_UpdateSettings(object state)
        {
            if (Interlocked.Exchange(ref _cronWork, 1) == 1)
                return;

            try
            {
                string path = "module/TorrServer.conf";

                if (!File.Exists(path))
                {
                    if (cacheconf.Item1 == null)
                        cacheconf.Item1 = new ModInit();

                    return;
                }

                var lastWriteTime = File.GetLastWriteTime(path);

                if (cacheconf.Item2 != lastWriteTime)
                {
                    cacheconf.Item1 = JsonConvert.DeserializeObject<ModInit>(File.ReadAllText(path));
                    cacheconf.Item2 = lastWriteTime;
                }
            }
            catch { }
            finally
            {
                Volatile.Write(ref _cronWork, 0);
            }
        }
        #endregion

        #region loaded
        public static void loaded(InitspaceModel initspace)
        {
            RegisterShutdown(initspace);

            _cronTimer = new Timer(cron_UpdateSettings, null, TimeSpan.Zero, TimeSpan.FromSeconds(1));

            dataDb = new LiteDatabase("cache/ts.db");
            whosehash = dataDb.GetCollection<WhoseHashModel>("whosehash");

            #region homedir
            homedir = Directory.GetCurrentDirectory();
            if (string.IsNullOrWhiteSpace(homedir) || homedir == "/")
                homedir = string.Empty;

            homedir = Path.Combine(homedir, "torrserver");
            Directory.CreateDirectory(homedir);
            #endregion

            #region tspath
            tspath = Path.Combine(homedir, "TorrServer-linux");

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                tspath = Path.Combine(homedir, "TorrServer-windows-amd64.exe");
            #endregion

            #region tspass: reuse across Lampac-only restarts
            string accsDbPath = Path.Combine(homedir, "accs.db");
            string existingPass = TryReadExistingTsPass(accsDbPath);
            if (!string.IsNullOrEmpty(existingPass))
                tspass = existingPass;
            else
                File.WriteAllText(accsDbPath, $"{{\"ts\":\"{tspass}\"}}");
            #endregion

            ThreadPool.QueueUserWorkItem(async _ =>
            {
                #region downloadUrl
                string downloadUrl;
                if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                {
                    downloadUrl = "https://github.com/YouROK/TorrServer/releases/latest/download/TorrServer-windows-amd64.exe";
                    if (conf.releases != "latest")
                        downloadUrl = $"https://github.com/YouROK/TorrServer/releases/download/{conf.releases}/TorrServer-windows-amd64.exe";
                }
                else
                {
                    string uname = (await Bash.Run("uname -m")) ?? string.Empty;
                    string arch = uname.Contains("x86_64") ? "amd64" : (uname.Contains("i386") || uname.Contains("i686")) ? "386" : uname.Contains("aarch64") ? "arm64" : uname.Contains("armv7") ? "arm7" : uname.Contains("armv6") ? "arm5" : "amd64";

                    downloadUrl = "https://github.com/YouROK/TorrServer/releases/latest/download/TorrServer-linux-" + arch;
                    if (conf.releases != "latest")
                        downloadUrl = $"https://github.com/YouROK/TorrServer/releases/download/{conf.releases}/TorrServer-linux-" + arch;
                }
                #endregion

                #region updatet/install
                async Task install()
                {
                    try
                    {
                        if (conf.releases == "latest")
                        {
                            var root = await Http.Get<JObject>("https://api.github.com/repos/YouROK/TorrServer/releases/latest");
                            if (root != null && root.ContainsKey("tag_name"))
                            {
                                string tagname = root.Value<string>("tag_name");
                                if (!string.IsNullOrEmpty(tagname))
                                {
                                    if (!File.Exists($"{homedir}/tagname") || tagname != File.ReadAllText($"{homedir}/tagname"))
                                    {
                                        if (File.Exists(tspath))
                                            File.Delete(tspath);

                                        File.WriteAllText($"{homedir}/tagname", tagname);
                                    }
                                }
                            }
                        }

                        if (!File.Exists(tspath))
                        {
                            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
                            {
                                tsprocess?.Dispose();
                                bool success = await Http.DownloadFile(downloadUrl, tspath, timeoutSeconds: 200);
                                if (!success)
                                    File.Delete(tspath);
                            }
                            else
                            {
                                tsprocess?.Dispose();
                                bool success = await Http.DownloadFile(downloadUrl, tspath, timeoutSeconds: 200);
                                if (success)
                                    Bash.Invoke($"chmod +x {tspath}");
                                else
                                    Bash.Invoke($"rm -f {tspath}");
                            }
                        }
                    }
                    catch { }
                }

                await install();

                if (!File.Exists(tspath))
                {
                    await Task.Delay(10_000);
                    await install();
                }

                if (!File.Exists("isdocker") && conf.checkfile)
                {
                    var response = await Http.ResponseHeaders(downloadUrl, timeoutSeconds: 10, allowAutoRedirect: true);
                    if (response != null && response.Content.Headers.ContentLength.HasValue && new FileInfo(tspath).Length != response.Content.Headers.ContentLength.Value)
                    {
                        File.Delete(tspath);
                        await Task.Delay(10_000);
                        await install();
                    }
                }
                #endregion

                int _restartFailures = 0;
                DateTime _failWindowStart = DateTime.UtcNow;
                int _backoffMs = 5_000;

                while (!IsShutdown && File.Exists(tspath))
                {
                    // Give up after 10 failures within 1 hour
                    if (DateTime.UtcNow - _failWindowStart > TimeSpan.FromHours(1))
                    {
                        _restartFailures = 0;
                        _failWindowStart = DateTime.UtcNow;
                    }
                    if (_restartFailures >= 10)
                    {
                        Console.WriteLine("TorrServer: too many restarts, giving up");
                        break;
                    }

                    var startedAt = DateTime.UtcNow;
                    try
                    {
                        // Why: each restart created a new Process without disposing the
                        // previous one → handle + pipe FD leak accumulates per restart.
                        // Dispose after WaitForExit (or in catch) before the next iteration.
                        var previous = tsprocess;
                        tsprocess = new Process();
                        try { previous?.Dispose(); } catch { }

                        tsprocess.StartInfo.UseShellExecute = false;
                        tsprocess.StartInfo.RedirectStandardOutput = true;
                        tsprocess.StartInfo.RedirectStandardError = true;
                        tsprocess.StartInfo.FileName = tspath;
                        tsprocess.StartInfo.Arguments = $"--httpauth -p {tsport} -d \"{homedir}\"";

                        tsprocess.Start();

                        tsprocess.OutputDataReceived += (sender, e) => { if (e.Data != null) Console.WriteLine($"TorrServer: {e.Data}"); };
                        tsprocess.ErrorDataReceived += (sender, e) => { if (e.Data != null) Console.WriteLine($"TorrServer: {e.Data}"); };
                        tsprocess.BeginOutputReadLine();
                        tsprocess.BeginErrorReadLine();

                        await tsprocess.WaitForExitAsync();
                    }
                    catch { }

                    if ((DateTime.UtcNow - startedAt).TotalSeconds >= 60)
                    {
                        // Healthy run — reset backoff
                        _restartFailures = 0;
                        _failWindowStart = DateTime.UtcNow;
                        _backoffMs = 5_000;
                    }
                    else
                    {
                        _restartFailures++;
                        Console.WriteLine($"TorrServer: restart #{_restartFailures}, backoff {_backoffMs / 1000}s");
                        await Task.Delay(_backoffMs);
                        _backoffMs = Math.Min(_backoffMs * 2, 300_000); // cap at 5 min
                        continue;
                    }

                    await Task.Delay(5_000);
                }
            });
        }
        #endregion


        #region Shutdown
        static void RegisterShutdown(InitspaceModel initspace)
        {
            if (initspace?.app?.ApplicationServices != null)
            {
                var lifetime = initspace.app.ApplicationServices.GetService<IHostApplicationLifetime>();
                lifetime?.ApplicationStopping.Register(StopTranscoding);
            }

            AppDomain.CurrentDomain.ProcessExit += (_, _) => StopTranscoding();
        }

        static void StopTranscoding()
        {
            try
            {
                IsShutdown = true;
                tsprocess?.Kill(true);
                _cronTimer.Dispose();
            }
            catch { }
        }
        #endregion
    }
}
