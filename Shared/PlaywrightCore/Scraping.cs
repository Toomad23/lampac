using Shared.Engine;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;

namespace Shared.PlaywrightCore
{
    public class Scraping : IDisposable
    {
        Process process;

        ExplicitProxyEndPoint explicitEndPoint;
        ProxyServer proxyServer;

        string patternUrl, headerKey;

        public bool IsCompleted { get; set; }

        public Action<SessionEventArgs> OnRequest { get; set; }

        public Action<SessionEventArgs> OnResponse { get; set; }


        public Scraping(string targetUrl, string patternUrl, string headerKey, string proxyBypassList = "*.example.com")
        {
            try
            {
                this.patternUrl = patternUrl;
                this.headerKey = headerKey;

                if (Chromium.Status != PlaywrightStatus.disabled)
                {
                    proxyServer = new ProxyServer();
                    proxyServer.BeforeRequest += Request;
                    proxyServer.BeforeResponse += Response;

                    // A pfx without a side-car key file means it was generated with the old
                    // hardcoded password shared across every Lampac install — regenerate to
                    // limit cross-install blast radius if one .pfx ever leaks.
                    bool needGenerate = !File.Exists("cache/titanium.pfx") || !File.Exists("cache/titanium.pfx.key");

                    if (needGenerate)
                    {
                        byte[] passBytes = new byte[24];
                        System.Security.Cryptography.RandomNumberGenerator.Fill(passBytes);
                        string pfxPassword = Convert.ToBase64String(passBytes);

                        Directory.CreateDirectory("cache");
                        File.WriteAllText("cache/titanium.pfx.key", pfxPassword);
                        TryRestrictToOwner("cache/titanium.pfx.key");

                        if (proxyServer.CertificateManager.RootCertificate == null)
                            proxyServer.CertificateManager.CreateRootCertificate();

                        X509Certificate2 rootCert = proxyServer.CertificateManager.RootCertificate;

                        byte[] certBytes = rootCert.Export(X509ContentType.Pkcs12, pfxPassword);
                        File.WriteAllBytes("cache/titanium.pfx", certBytes);
                        TryRestrictToOwner("cache/titanium.pfx");

                        certBytes = proxyServer.CertificateManager.RootCertificate.Export(X509ContentType.Cert);
                        File.WriteAllBytes("cache/titanium.crt", certBytes);
                    }

                    string loadPassword = File.ReadAllText("cache/titanium.pfx.key").Trim();

                    // NOTE: installing this CA into the system trust store gives any process
                    // that reads cache/titanium.pfx the ability to MITM every HTTPS request on
                    // the host. The per-install random password above keeps the blast radius
                    // to a single host; the .pfx and .pfx.key files should be backed up like
                    // any other secret material.
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && !File.Exists("/usr/local/share/ca-certificates/lampac_titanium.crt"))
                    {
                        File.Copy("cache/titanium.crt", "/usr/local/share/ca-certificates/lampac_titanium.crt", true);
                        _ = Bash.Run("update-ca-certificates");
                    }

                    proxyServer.CertificateManager.LoadRootCertificate("cache/titanium.pfx", loadPassword);
                    proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;

                    explicitEndPoint = new ExplicitProxyEndPoint(System.Net.IPAddress.Loopback, 0, true);
                    proxyServer.AddEndPoint(explicitEndPoint);
                    proxyServer.Start();

                    #region executablePath
                    string executablePath = AppInit.conf.chromium.executablePath;

                    if (string.IsNullOrEmpty(executablePath))
                    {
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        {
                            if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                                executablePath = ".playwright\\chrome-win32\\chrome.exe";
                            else
                                executablePath = ".playwright\\chrome-win\\chrome.exe";
                        }
                        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                        {
                            executablePath = ".playwright/chrome-mac/Chromium.app/Contents/MacOS/Chromium";
                        }
                        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                        {
                            executablePath = ".playwright/chrome-linux/chrome";
                        }
                    }

                    if (string.IsNullOrEmpty(executablePath) || !File.Exists(executablePath))
                        return;
                    #endregion

                    int proxyPort = explicitEndPoint.Port;

                    var startInfo = new ProcessStartInfo
                    {
                        FileName = executablePath,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = false
                    };

                    startInfo.ArgumentList.Add($"--proxy-server=127.0.0.1:{proxyPort}");
                    startInfo.ArgumentList.Add($"--proxy-bypass-list=localhost;127.0.0.1;*.microsoft.com;{proxyBypassList}");
                    startInfo.ArgumentList.Add("--incognito");
                    startInfo.ArgumentList.Add("--ignore-certificate-errors");
                    startInfo.ArgumentList.Add("--ignore-ssl-errors");
                    startInfo.ArgumentList.Add("--disable-web-security");
                    startInfo.ArgumentList.Add("--no-first-run");
                    startInfo.ArgumentList.Add("--no-default-browser-check");
                    startInfo.ArgumentList.Add("--disable-background-mode");
                    startInfo.ArgumentList.Add("--no-sandbox");

                    if (AppInit.conf.chromium.Headless)
                    {
                        startInfo.ArgumentList.Add("--headless");
                        startInfo.ArgumentList.Add($"--user-agent=\"{Http.UserAgent}\"");
                    }

                    startInfo.ArgumentList.Add(targetUrl);

                    process = Process.Start(startInfo);
                    if (process == null)
                        return;
                }
            }
            catch { Dispose(); }
        }


        private Task Request(object sender, SessionEventArgs e)
        {
            try
            {
                var session = e.HttpClient.Request;

                if (IsCompleted)
                {
                    e.Ok(string.Empty);
                    return Task.CompletedTask;
                }

                if (session.Method == "GET" && !string.IsNullOrEmpty(patternUrl) && Regex.IsMatch(session.Url, patternUrl))
                {
                    IsCompleted = true;
                    completionSource.TrySetResult(session);
                    e.Ok(string.Empty);
                    return Task.CompletedTask;
                }

                if (!string.IsNullOrEmpty(headerKey))
                {
                    foreach (var header in session.Headers)
                    {
                        if (header.Name == headerKey)
                        {
                            IsCompleted = true;
                            completionSource.TrySetResult(session);
                            e.Ok(string.Empty);
                            return Task.CompletedTask;
                        }
                    }
                }

                if (AppInit.conf.chromium.consoleLog)
                {
                    Console.WriteLine("=== HTTP ЗАПРОС ===");
                    Console.WriteLine($"URL: {session.Url}");
                    Console.WriteLine($"Метод: {session.Method}");
                    Console.WriteLine("Заголовки:");
                    foreach (var header in session.Headers)
                        Console.WriteLine($"  {header.Name}: {header.Value}");
                    Console.WriteLine();
                }
            }
            catch { }

            OnRequest?.Invoke(e);
            return Task.CompletedTask;
        }

        private Task Response(object sender, SessionEventArgs e)
        {
            try
            {
                if (AppInit.conf.chromium.consoleLog)
                {
                    var session = e.HttpClient.Response;
                    Console.WriteLine("=== HTTP ОТВЕТ ===");
                    Console.WriteLine($"URL: {e.HttpClient.Request.Url}");
                    Console.WriteLine($"Статус: {session.StatusCode} {session.StatusDescription}");
                    Console.WriteLine("Заголовки:");
                    foreach (var header in session.Headers)
                        Console.WriteLine($"  {header.Name}: {header.Value}");
                    Console.WriteLine();
                }

                OnResponse?.Invoke(e);
            }
            catch { }

            return Task.CompletedTask;
        }


        #region WaitPageResult
        TaskCompletionSource<Request> completionSource { get; set; } = new TaskCompletionSource<Request>();

        async public Task<Request> WaitPageResult(int seconds = 10)
        {
            try
            {
                if (proxyServer == null)
                    return null;

                var completionTask = completionSource.Task;
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(seconds));

                var completedTask = await Task.WhenAny(completionTask, timeoutTask).ConfigureAwait(false);

                if (completedTask == completionTask)
                    return await completionTask;

                return null;
            }
            catch { return null; }
        }
        #endregion

        #region Dispose
        public void Dispose()
        {
            if (AppInit.conf.chromium.DEV)
                return;

            try
            {
                if (proxyServer != null)
                {
                    proxyServer.BeforeRequest -= Request;
                    proxyServer.BeforeResponse -= Response;
                    proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;

                    Task.Run(() =>
                    {
                        try
                        {
                            proxyServer.Stop();
                            proxyServer.Dispose();
                        }
                        catch { }
                        finally
                        {
                            proxyServer = null;
                        }
                    });
                }
            }
            catch { }

            try
            {
                if (process != null)
                {
                    Task.Run(() =>
                    {
                        try
                        {
                            process.Kill(true);
                            process.Close();
                            process.Dispose();
                        }
                        catch { }
                        finally
                        {
                            process = null;
                        }
                    });
                }
            }
            catch { }

            completionSource = null;
        }
        #endregion



        private Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            e.IsValid = true;
            return Task.CompletedTask;
        }

        // Best-effort 0600 on Unix-like hosts. Windows NTFS ACLs are left to the admin.
        private static void TryRestrictToOwner(string path)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return;

            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch { }
        }
    }
}
