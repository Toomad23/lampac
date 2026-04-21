using Lampac.Engine;
using Lampac.Engine.Middlewares;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;
using Newtonsoft.Json;
using Shared;
using Shared.Engine;
using Shared.Models.Module;
using Shared.Models.Module.Entrys;
using Shared.Models.SQL;
using Shared.PlaywrightCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Lampac
{
    public class Startup
    {
        #region Startup
        static IApplicationBuilder _app = null;

        public static bool IsShutdown { get; private set; }

        public IConfiguration Configuration { get; }

        public static IServiceCollection serviceCollection { get; private set; }

        public static IMemoryCache memoryCache { get; private set; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        #endregion

        #region ConfigureServices
        public void ConfigureServices(IServiceCollection services)
        {
            var init = AppInit.conf;
            var mods = init.BaseModule;

            serviceCollection = services;

            #region IHttpClientFactory
            // Why (security): previously every registered SocketsHttpHandler installed
            // `RemoteCertificateValidationCallback = (..) => true`, permanently disabling
            // chain verification for both trusted-origin clients ("base", "http2", etc.)
            // and the proxy-family clients. Gate the skip per-family:
            //   * "base", "baseNoRedirect", "http2", "http2NoRedirect", "http3"
            //     → honour AppInit.insecureSkipVerify (default false → full verify).
            //   * "proxy", "proxyRedirect", "proxyimg", "http2proxyimg"
            //     → honour AppInit.proxyInsecureSkipVerify (default true for back-compat
            //       with untrusted tracker/CDN origins; a warning is emitted below).
            bool proxySkip = init.proxyInsecureSkipVerify;
            bool baseSkip = init.insecureSkipVerify;

            static void ApplySslSkip(System.Net.Security.SslClientAuthenticationOptions opt, bool skip)
            {
                if (skip)
                    opt.RemoteCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            }

            if (proxySkip)
                Console.WriteLine("[security] AppInit.proxyInsecureSkipVerify=true — proxy/proxyimg HTTP clients will NOT validate upstream TLS certificates. Set to false once proxy targets have healthy TLS.");

            if (baseSkip)
                Console.WriteLine("[security] AppInit.insecureSkipVerify=true — base/http2/http3 HTTP clients will NOT validate upstream TLS certificates. This disables MITM protection for trusted upstreams.");

            services.AddHttpClient("proxy").ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.None,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, proxySkip);
                return h;
            });

            services.AddHttpClient("proxyRedirect").ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.None,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, proxySkip);
                return h;
            });

            services.AddHttpClient("proxyimg").ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.None,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, proxySkip);
                return h;
            });

            services.AddHttpClient("base").ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, baseSkip);
                return h;
            });

            services.AddHttpClient("baseNoRedirect").ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, baseSkip);
                return h;
            });

            services.AddHttpClient("http2", client =>
            {
                client.DefaultRequestVersion = HttpVersion.Version20;
                client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    EnableMultipleHttp2Connections = true,
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, baseSkip);
                return h;
            });

            services.AddHttpClient("http2proxyimg", client =>
            {
                client.DefaultRequestVersion = HttpVersion.Version20;
                client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.None,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    EnableMultipleHttp2Connections = true,
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, proxySkip);
                return h;
            });

            services.AddHttpClient("http2NoRedirect", client =>
            {
                client.DefaultRequestVersion = HttpVersion.Version20;
                client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    EnableMultipleHttp2Connections = true,
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, baseSkip);
                return h;
            });

            services.AddHttpClient("http3", client =>
            {
                client.DefaultRequestVersion = HttpVersion.Version30;
                client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            })
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var h = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    AutomaticDecompression = DecompressionMethods.Brotli | DecompressionMethods.GZip | DecompressionMethods.Deflate,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(30),
                    EnableMultipleHttp2Connections = true,
                    UseCookies = false
                };
                ApplySslSkip(h.SslOptions, baseSkip);
                return h;
            });

            services.RemoveAll<IHttpMessageHandlerBuilderFilter>();
            #endregion

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            if (init.listen.compression)
            {
                services.AddResponseCompression(options =>
                {
                    options.MimeTypes = AppInit.CompressionMimeTypes;
                });
            }

            services.AddMemoryCache(o =>
            {
                o.TrackStatistics = AppInit.conf.openstat.enable;
            });

            if (mods.ws)
            {
                services.AddSignalR(o =>
                {
                    o.EnableDetailedErrors = true;
                    o.MaximumParallelInvocationsPerClient = 2;
                    o.MaximumReceiveMessageSize = 1024 * 1024 * 10; // 10MB
                    o.StreamBufferCapacity = 1024 * 1024;           // 1MB
                });
            }

            services.AddSingleton<IActionDescriptorChangeProvider>(DynamicActionDescriptorChangeProvider.Instance);
            services.AddSingleton(DynamicActionDescriptorChangeProvider.Instance);

            services.AddDbContextFactory<HybridCacheContext>(HybridCacheContext.ConfiguringDbBuilder);
            services.AddDbContextFactory<ProxyLinkContext>(ProxyLinkContext.ConfiguringDbBuilder);

            if (mods.Sql.syncUser)
                services.AddDbContextFactory<SyncUserContext>(SyncUserContext.ConfiguringDbBuilder);

            if (mods.Sql.sisi)
                services.AddDbContextFactory<SisiContext>(SisiContext.ConfiguringDbBuilder);

            if (mods.Sql.externalids)
                services.AddDbContextFactory<ExternalidsContext>(ExternalidsContext.ConfiguringDbBuilder);

            IMvcBuilder mvcBuilder = services.AddControllersWithViews();

            mvcBuilder.AddJsonOptions(options => {
                //options.JsonSerializerOptions.IgnoreNullValues = true;
                options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault;
            });

            #region module references
            string referencesPath = Path.Combine(Environment.CurrentDirectory, "module", "references");

            if (Directory.Exists(referencesPath))
            {
                var current = AppDomain.CurrentDomain.GetAssemblies();
                foreach (string dllFile in Directory.GetFiles(referencesPath, "*.dll", SearchOption.AllDirectories))
                {
                    try
                    {
                        string loadedName = Path.GetFileNameWithoutExtension(dllFile);
                        if (current.Any(a => string.Equals(a.GetName().Name, loadedName, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        Assembly loadedAssembly = Assembly.LoadFrom(dllFile);
                        mvcBuilder.AddApplicationPart(loadedAssembly);
                        Program.assemblieReferences.Add(MetadataReference.CreateFromFile(loadedAssembly.Location));

                        Console.WriteLine($"load reference: {Path.GetFileName(dllFile)}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to load reference {dllFile}: {ex.Message}");
                    }
                }
            }
            #endregion

            ModuleRepository.Configuration(mvcBuilder);

            Shared.Startup.Configure(Program.appReload, new NativeWebSocket(), new soks());
            BaseModControllers(mvcBuilder);

            #region compilation modules
            if (AppInit.modules != null)
            {
                // mod.dll
                foreach (var mod in AppInit.modules)
                {
                    try
                    {
                        Console.WriteLine("load module: " + mod.dll);
                        mvcBuilder.AddApplicationPart(mod.assembly);
                    }
                    catch (Exception ex) { Console.WriteLine(ex.Message + "\n"); }
                }
            }

            //  dll  source
            if (File.Exists("module/manifest.json"))
            {
                var jss = new JsonSerializerSettings
                {
                    Error = (se, ev) =>
                    {
                        ev.ErrorContext.Handled = true;
                        Console.WriteLine("module/manifest.json - " + ev.ErrorContext.Error + "\n\n");
                    }
                };

                var modules = JsonConvert.DeserializeObject<List<RootModule>>(File.ReadAllText("module/manifest.json"), jss);
                if (modules == null)
                    return;

                #region CompilationMod
                void CompilationMod(RootModule mod)
                {
                    if (!mod.enable || AppInit.modules.FirstOrDefault(i => i.dll == mod.dll) != null)
                        return;

                    if (mod.dll.EndsWith(".dll"))
                    {
                        // Why (FH-1): mod.dll may be (a) a bare filename
                        // ("Foo.dll"), (b) a combined "module/folder/foo.dll"
                        // produced by the nested-manifest scan below, or
                        // (c) a relative "folder/foo.dll". Reject rooted paths
                        // and ".." anywhere, and verify the resolved absolute
                        // path stays strictly under module/.
                        if (Path.IsPathRooted(mod.dll) || mod.dll.Contains("..", StringComparison.Ordinal))
                        {
                            Console.WriteLine($"CompilationMod: rejected mod.dll '{mod.dll}' (rooted or traversal)");
                            return;
                        }

                        // Normalise separators, then decide which base to join
                        // against: if it already begins with "module/" treat the
                        // value as relative to CWD (matches the legacy
                        // Assembly.LoadFrom(mod.dll) behaviour), otherwise join
                        // onto ModuleRoot.
                        string normalizedDll = mod.dll.Replace('\\', '/');
                        string dllFullPath = normalizedDll.StartsWith("module/", StringComparison.OrdinalIgnoreCase)
                            ? Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, normalizedDll))
                            : Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "module", normalizedDll));

                        if (!ModulePaths.IsContainedIn(dllFullPath, ModulePaths.ModuleRoot))
                        {
                            Console.WriteLine($"CompilationMod: rejected mod.dll '{mod.dll}' (escapes module root)");
                            return;
                        }

                        if (!File.Exists(dllFullPath))
                        {
                            Console.WriteLine($"CompilationMod: mod.dll '{mod.dll}' not found at {dllFullPath}");
                            return;
                        }

                        // Why (FH-4): optional sha256 check, non-breaking when absent.
                        if (!ModulePaths.VerifyDllIntegrity(dllFullPath, mod.sha256, mod.dll))
                            return;

                        try
                        {
                            // Why (FH-3): collectible ALC so this assembly can be
                            // unloaded on rebuild. Trade-off: collectible contexts
                            // cannot host Reflection.Emit of dynamic modules that
                            // require collectible=false (e.g. some JIT/IL-heavy
                            // libraries). See LoadedModule fallback.
                            var alc = new AssemblyLoadContext($"lampac-mod:{Path.GetFileName(dllFullPath)}", isCollectible: true);
                            mod.loadHandle = new ModuleLoadHandle(alc, collectible: true);
                            mod.assembly = alc.LoadFromAssemblyPath(dllFullPath);

                            AppInit.modules.Add(mod);
                            mvcBuilder.AddApplicationPart(mod.assembly);
                            Console.WriteLine($"load module: {Path.GetFileName(mod.dll)}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Failed to load reference {mod.dll}: {ex.Message}");
                        }

                        return;
                    }

                    string path = Directory.Exists(mod.dll) ? mod.dll : $"{Environment.CurrentDirectory}/module/{mod.dll}";
                    if (Directory.Exists(path))
                    {
                        var syntaxTree = new List<SyntaxTree>();

                        // Why (FL-2): prefer an explicit sources array from the
                        // manifest to avoid compiling arbitrary .cs files that land
                        // in the module directory. When sources is absent we keep
                        // the legacy glob for back-compat but warn and limit to the
                        // top level (no recursion).
                        IEnumerable<string> sourceFiles;
                        if (mod.sources != null && mod.sources.Length > 0)
                        {
                            var list = new List<string>();
                            string pathRoot = ModulePaths.NormalizeDirectory(Path.GetFullPath(path));
                            foreach (string rel in mod.sources)
                            {
                                if (string.IsNullOrWhiteSpace(rel) || Path.IsPathRooted(rel) || rel.Contains("..", StringComparison.Ordinal))
                                {
                                    Console.WriteLine($"CompilationMod: rejected sources entry '{rel}' for {mod.dll}");
                                    continue;
                                }
                                string full = Path.GetFullPath(Path.Combine(path, rel));
                                if (!ModulePaths.IsContainedIn(full, pathRoot) || !File.Exists(full))
                                {
                                    Console.WriteLine($"CompilationMod: sources entry '{rel}' missing or escapes module dir");
                                    continue;
                                }
                                list.Add(full);
                            }
                            sourceFiles = list;
                        }
                        else
                        {
                            Console.WriteLine($"CompilationMod: module '{mod.dll}' has no 'sources' array; falling back to top-level *.cs glob (deprecated)");
                            sourceFiles = Directory.GetFiles(path, "*.cs", SearchOption.TopDirectoryOnly);
                        }

                        foreach (string file in sourceFiles)
                        {
                            string _file = file.Replace("\\", "/").Replace(path.Replace("\\", "/"), "").Replace(Environment.CurrentDirectory.Replace("\\", "/"), "");
                            if (Regex.IsMatch(_file, "(\\.vs|bin|obj|Properties)/", RegexOptions.IgnoreCase))
                                continue;

                            syntaxTree.Add(CSharpSyntaxTree.ParseText(File.ReadAllText(file)));
                        }

                        if (mod.references != null)
                        {
                            foreach (string refns in mod.references)
                            {
                                // Why (FM-2): reject rooted / traversal reference
                                // names and verify the resolved path stays inside
                                // module/references/ or module/{mod.dll}/.
                                if (!ModulePaths.TryResolveReference(refns, mod.dll, out string dlrns, out string refReason))
                                {
                                    Console.WriteLine($"CompilationMod: skipping reference for {mod.dll} ({refReason})");
                                    continue;
                                }

                                if (Program.assemblieReferences.FirstOrDefault(a => Path.GetFileName(a.FilePath) == refns) == null)
                                {
                                    // References are shared across modules; keep in Default ALC.
                                    var assembly = Assembly.LoadFrom(dlrns);
                                    Program.assemblieReferences.Add(MetadataReference.CreateFromFile(assembly.Location));
                                }
                            }
                        }

                        CSharpCompilation compilation = CSharpCompilation.Create(Path.GetFileName(mod.dll), syntaxTree, references: Program.assemblieReferences, options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

                        using (var ms = new MemoryStream())
                        {
                            var result = compilation.Emit(ms);

                            if (!result.Success)
                            {
                                Console.WriteLine($"\ncompilation error: {mod.dll}");
                                foreach (var diagnostic in result.Diagnostics)
                                {
                                    if (diagnostic.Severity == DiagnosticSeverity.Error)
                                        Console.WriteLine(diagnostic);
                                }
                                Console.WriteLine();
                            }
                            else
                            {
                                ms.Seek(0, SeekOrigin.Begin);

                                // Why (FH-3): compiled-from-source modules go into a
                                // dedicated collectible ALC so rebuilds unload the
                                // previous version. The byte[] is loaded via the ALC
                                // rather than Assembly.Load(byte[]) to pin the lifetime
                                // to our handle.
                                var alc = new AssemblyLoadContext($"lampac-mod-src:{Path.GetFileName(mod.dll)}", isCollectible: true);
                                mod.loadHandle = new ModuleLoadHandle(alc, collectible: true);
                                ms.Seek(0, SeekOrigin.Begin);
                                mod.assembly = alc.LoadFromStream(ms);

                                Console.WriteLine("compilation module: " + mod.dll);
                                mod.index = mod.index != 0 ? mod.index : (100 + AppInit.modules.Count);
                                AppInit.modules.Add(mod);
                                mvcBuilder.AddApplicationPart(mod.assembly);
                                WatchersDynamicModule(null, mvcBuilder, mod, path);
                            }
                        }
                    }
                }
                #endregion

                foreach (var mod in modules)
                    CompilationMod(mod);

                foreach (string folderMod in Directory.GetDirectories("module/"))
                {
                    string manifest = $"{Environment.CurrentDirectory}/{folderMod}/manifest.json";
                    if (!File.Exists(manifest))
                        continue;

                    var mod = JsonConvert.DeserializeObject<RootModule>(File.ReadAllText(manifest), jss);
                    if (mod != null)
                    {
                        if (mod.dll == null)
                            mod.dll = folderMod.Split("/")[1];
                        else if (mod.dll.EndsWith(".dll"))
                        {
                            // Why (FH-2): if manifest.dll is rooted, Path.Combine
                            // discards folderMod and returns the absolute path verbatim
                            // (/etc/evil.dll). Validate separately and verify the
                            // final full path stays inside this module's folder.
                            if (!ModulePaths.TryResolveNestedModuleDll(folderMod, mod.dll, out _, out string nestedReason))
                            {
                                Console.WriteLine($"CompilationMod: rejected nested mod.dll '{mod.dll}' from {folderMod} ({nestedReason})");
                                continue;
                            }
                            // Store a relative form so downstream path-joins still work,
                            // but CompilationMod's .dll branch re-resolves + re-verifies.
                            mod.dll = Path.Combine(folderMod, mod.dll);
                        }

                        CompilationMod(mod);
                    }
                }

                if (Program.assemblieReferences != null)
                    CSharpEval.appReferences = Program.assemblieReferences;
            }

            if (AppInit.modules != null)
                AppInit.modules = AppInit.modules.OrderBy(i => i.index).ToList();

            Console.WriteLine();
            #endregion
        }
        #endregion


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IMemoryCache memory, IHttpClientFactory httpClientFactory, IHostApplicationLifetime applicationLifetime)
        {
            _app = app;
            memoryCache = memory;
            var init = AppInit.conf;
            var mods = init.BaseModule;
            var midd = mods.Middlewares;

            #region IDbContextFactory
            HybridCacheContext.Factory = app.ApplicationServices.GetService<IDbContextFactory<HybridCacheContext>>();
            ProxyLinkContext.Factory = app.ApplicationServices.GetService<IDbContextFactory<ProxyLinkContext>>();

            if (mods.Sql.externalids)
                ExternalidsContext.Factory = app.ApplicationServices.GetService<IDbContextFactory<ExternalidsContext>>();

            if (mods.Sql.sisi)
                SisiContext.Factory = app.ApplicationServices.GetService<IDbContextFactory<SisiContext>>();

            if (mods.Sql.syncUser)
                SyncUserContext.Factory = app.ApplicationServices.GetService<IDbContextFactory<SyncUserContext>>();
            #endregion

            Shared.Startup.Configure(app, memory);
            HybridCache.Configure(memory);
            HybridFileCache.Configure(memory);
            ProxyManager.Configure(memory);

            // Why (round5 HIGH-6): HMAC-signed admin endpoints require rootPasswd.
            // Program.cs generates one if the `passwd` file is missing, but a
            // deployment that explicitly wiped it (or mapped an empty volume over
            // it) would silently fall back to the deterministic "fallback|hmacauth"
            // key in previous versions. HmacAuth.cs now fail-closes, so log a
            // single error here so the misconfiguration is loud rather than
            // manifesting as mysterious 401s from /merchant, /nws, and /ts.
            if (!Shared.Engine.HmacAuth.IsConfigured)
                Console.Error.WriteLine("[security] HMAC-signed admin endpoints are DISABLED: AppInit.rootPasswd is empty. Set it via the `passwd` file or environment.");

            Http.httpClientFactory = httpClientFactory;

            if (mods.nws)
            {
                NativeWebSocket.memoryCache = memoryCache;
                Http.nws = new NativeWebSocket();
            }

            if (mods.ws)
                Http.ws = new soks();

            #region modules loaded
            if (AppInit.modules != null)
            {
                foreach (var mod in AppInit.modules)
                {
                    try
                    {
                        if (mod.dll == "DLNA.dll")
                            mod.initspace = "DLNA.ModInit";

                        if (mod.dll == "SISI.dll")
                            mod.initspace = "SISI.ModInit";

                        if (mod.dll == "Tracks.dll" || mod.dll == "TorrServer.dll")
                            mod.version = 2;

                        LoadedModule(app, mod);
                    }
                    catch (Exception ex) { Console.WriteLine($"Module {mod.NamespacePath(mod.initspace)}: {ex.Message}\n\n"); }
                }
            }
            #endregion

            app.UseBaseMod();

            // Why (security): previously the gate was `!init.multiaccess || init.useDeveloperExceptionPage`,
            // and the default multiaccess=false meant fresh installs (including production deployments)
            // rendered full stack traces with source snippets on any unhandled exception. Require BOTH
            // an explicit opt-in AND the ASP.NET Core "Development" environment before exposing the dev
            // page. Production traffic routes to the generic /error handler (500, no body detail).
            if (init.useDeveloperExceptionPage && env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/error");
            }

            applicationLifetime.ApplicationStopping.Register(OnShutdown);

            applicationLifetime.ApplicationStarted.Register(() =>
            {
                if (!string.IsNullOrEmpty(init.listen.sock))
                    _ = Bash.Run($"while [ ! -S /var/run/{init.listen.sock}.sock ]; do sleep 1; done && chmod 666 /var/run/{init.listen.sock}.sock").ConfigureAwait(false);
            });

            #region UseForwardedHeaders
            // Why (FC-2): previously ForwardLimit = null combined with the
            // default KnownProxies/KnownNetworks (127.0.0.1/8 + ::1) let ANY
            // loopback peer (reverse proxy, local Tor hidden service, unix
            // socket peer, a local process) spoof X-Forwarded-For and have
            // HttpContext.Connection.RemoteIpAddress rewritten to whatever
            // they sent. That breaks the FC-1 loopback gates (without the
            // FC-2 raw-IP read) and per-IP rate limiting / audit logs.
            //
            // Defence in depth:
            //  * ForwardLimit = 1 — only trust the first hop's header chain.
            //  * KnownNetworks.Clear() + KnownProxies.Clear() — drop the
            //    "loopback is trusted" default. A trusted forwarder must be
            //    declared explicitly via init.KnownProxies.
            //  * real_ip_cf / listen.frontend=cloudflare users already handle
            //    the CF-Connecting-IP rewrite themselves in RequestInfo.cs,
            //    so we do not need to (and must not) trust XFF for them.
            var forwarded = new ForwardedHeadersOptions
            {
                ForwardLimit = 1,
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };

            forwarded.KnownNetworks.Clear();
            forwarded.KnownProxies.Clear();

            if (init.KnownProxies != null && init.KnownProxies.Count > 0)
            {
                foreach (var k in init.KnownProxies)
                    forwarded.KnownNetworks.Add(new Microsoft.AspNetCore.HttpOverrides.IPNetwork(IPAddress.Parse(k.ip), k.prefixLength));
            }

            app.UseForwardedHeaders(forwarded);
            #endregion

            app.UseModHeaders();
            app.UseRequestInfo();

            if (mods.nws)
            {
                app.Map("/nws", nwsApp =>
                {
                    nwsApp.UseWAF();
                    nwsApp.UseWebSockets();
                    nwsApp.Run(NativeWebSocket.HandleWebSocketAsync);
                });
            }

            if (mods.ws)
            {
                app.Map("/ws", wsApp =>
                {
                    wsApp.UseWAF();
                    wsApp.UseRouting();
                    wsApp.UseEndpoints(endpoints =>
                    {
                        endpoints.MapHub<soks>("");
                    });
                });
            }

            if (midd.staticache)
                app.UseStaticache();

            app.UseRouting();

            if (init.listen.compression)
                app.UseResponseCompression();

            if (midd.statistics)
                app.UseRequestStatistics();

            app.UseAnonymousRequest();

            app.UseAlwaysRjson();

            if (midd.module)
                app.UseModule(first: true);

            app.UseOverrideResponse(first: true);

            #region UseStaticFiles
            if (midd.staticFiles)
            {
                var contentTypeProvider = new FileExtensionContentTypeProvider();

                if (midd.staticFilesMappings != null)
                {
                    foreach (var mapping in midd.staticFilesMappings)
                        contentTypeProvider.Mappings[mapping.Key] = mapping.Value;
                }

                app.UseStaticFiles(new StaticFileOptions
                {
                    ServeUnknownFileTypes = midd.unknownStaticFiles,
                    DefaultContentType = "application/octet-stream",
                    ContentTypeProvider = contentTypeProvider
                });
            }
            #endregion

            app.UseWAF();
            app.UseAccsdb();

            if (midd.proxy)
            {
                app.MapWhen(context => context.Request.Path.Value.StartsWith("/proxy/") || context.Request.Path.Value.StartsWith("/proxy-dash/"), proxyApp =>
                {
                    proxyApp.UseProxyAPI();
                });
            }

            if (midd.proxyimg)
            {
                app.MapWhen(context => context.Request.Path.Value.StartsWith("/proxyimg"), proxyApp =>
                {
                    proxyApp.UseProxyIMG();
                });
            }

            if (midd.proxycub)
            {
                app.MapWhen(context => context.Request.Path.Value.StartsWith("/cub/"), proxyApp =>
                {
                    proxyApp.UseProxyCub();
                });
            }

            if (midd.proxytmdb)
            {
                app.MapWhen(context => context.Request.Path.Value.StartsWith("/tmdb/"), proxyApp =>
                {
                    proxyApp.UseProxyTmdb();
                });
            }

            if (midd.module)
                app.UseModule(first: false);

            app.UseOverrideResponse(first: false);

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }


        #region OnShutdown
        void OnShutdown()
        {
            if (Program._reload)
                return;

            IsShutdown = true;
            Shared.Startup.IsShutdown = true;

            Chromium.FullDispose();
            Firefox.FullDispose();
            NativeWebSocket.FullDispose();
            soks.FullDispose();

            DisposeModule(null);
        }
        #endregion

        #region BaseModControllers
        public static bool WebLogEnableController { get; private set; }

        public void BaseModControllers(IMvcBuilder mvcBuilder)
        {
            if (AppInit.conf?.BaseModule?.EnableControllers == null || 
                AppInit.conf.BaseModule.EnableControllers.Length == 0)
                return;

            WebLogEnableController = AppInit.conf.BaseModule.EnableControllers.Contains("WebLog");

            var syntaxTree = new List<SyntaxTree>();

            string patchcontrol = Path.Combine("basemod", "Controllers");
            if (!Directory.Exists(patchcontrol))
                patchcontrol = "../../../../../BaseModule/Controllers";

            foreach (string file in Directory.GetFiles(patchcontrol, "*.cs", SearchOption.AllDirectories))
            {
                string name = Path.GetFileName(file).Replace("Controller.cs", "");

                if (name.Equals("Cmd", StringComparison.OrdinalIgnoreCase) && AppInit.conf.cmd.Count == 0)
                    continue;

                if (name.Equals("SyncApi", StringComparison.OrdinalIgnoreCase) && !AppInit.conf.sync.enable)
                    continue;

                if (AppInit.conf.BaseModule.EnableControllers.Contains(name, StringComparer.OrdinalIgnoreCase))
                    syntaxTree.Add(CSharpSyntaxTree.ParseText(File.ReadAllText(file)));
            }

            CSharpCompilation compilation = CSharpCompilation.Create("basemod", syntaxTree, references: Program.assemblieReferences, options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

            using (var ms = new MemoryStream())
            {
                var result = compilation.Emit(ms);

                if (result.Success)
                {
                    ms.Seek(0, SeekOrigin.Begin);
                    // Why (FH-3): basemod is first-party shipped code (BaseModule/
                    // Controllers). Per the module-loader hardening policy,
                    // first-party DLLs remain in AssemblyLoadContext.Default so
                    // they are not subject to collectible-ALC limitations and
                    // compose correctly with the host's controller caches.
                    var assembly = Assembly.Load(ms.ToArray());
                    mvcBuilder.AddApplicationPart(assembly);
                }
                else
                {
                    Console.WriteLine($"\ncompilation error: basemod");
                    foreach (var diagnostic in result.Diagnostics)
                    {
                        if (diagnostic.Severity == DiagnosticSeverity.Error)
                            Console.WriteLine(diagnostic);
                    }
                    Console.WriteLine();
                }
            }
        }
        #endregion

        #region WatchRebuildModule
        static readonly Dictionary<string, FileSystemWatcher> moduleWatchers = new();

        static readonly object moduleWatcherLock = new object();

        // Why (FM-1): previously the FileSystemWatcher callback performed a
        // DisposeModule → remove ApplicationPart → AddApplicationPart →
        // NotifyChanges → EnsureCache(forced:true) sequence without any lock.
        // Two overlapping .cs saves (common with editors) could run the sequence
        // concurrently, leaving the PartManager with dangling/duplicated parts.
        // All mutating operations on the part list or the module entry caches
        // must be serialised through this lock.
        static readonly object _moduleRebuildLock = new object();

        void WatchersDynamicModule(IApplicationBuilder app, IMvcBuilder mvcBuilder, RootModule mod, string path)
        {
            if (!mod.dynamic)
                return;

            path = Path.GetFullPath(path);

            lock (moduleWatcherLock)
            {
                if (moduleWatchers.ContainsKey(path))
                    return;

                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
                };

                watcher.Filters.Add("*.cs");
                watcher.Filters.Add("manifest.json");

                CancellationTokenSource debounceCts = null;
                object debounceLock = new object();

                void Recompile(object sender, FileSystemEventArgs e)
                {
                    string _file = e.FullPath.Replace("\\", "/").Replace(path.Replace("\\", "/"), "").Replace(Environment.CurrentDirectory.Replace("\\", "/"), "");
                    if (Regex.IsMatch(_file, "(\\.vs|bin|obj|Properties)/", RegexOptions.IgnoreCase))
                        return;

                    CancellationTokenSource cts;

                    lock (debounceLock)
                    {
                        debounceCts?.Cancel();
                        debounceCts = new CancellationTokenSource();
                        cts = debounceCts;
                    }

                    _ = Task.Run(async () =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(2), cts.Token);

                        if (cts.IsCancellationRequested)
                            return;

                        watcher.EnableRaisingEvents = false;

                        // Why (FM-1): serialise the whole DisposeModule →
                        // AddApplicationPart → NotifyChanges → EnsureCache sequence;
                        // concurrent edits would otherwise race the PartManager.
                        lock (_moduleRebuildLock)
                        {
                            try
                            {
                                var parts = mvcBuilder.PartManager.ApplicationParts
                                    .OfType<AssemblyPart>()
                                    .Where(p => p.Assembly == mod.assembly)
                                    .ToList();

                                #region update manifest.json
                                string manifestPath = Path.Combine(path, "manifest.json");
                                RootModule manifestMod = null;

                                if (File.Exists(manifestPath))
                                {
                                    try
                                    {
                                        manifestMod = JsonConvert.DeserializeObject<RootModule>(File.ReadAllText(manifestPath));

                                        var excludedProperties = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                                        {
                                            nameof(RootModule.dynamic),
                                            nameof(RootModule.index),
                                            nameof(RootModule.dll),
                                            nameof(RootModule.assembly),
                                            nameof(RootModule.initspace),
                                            nameof(RootModule.loadHandle)
                                        };

                                        foreach (var property in typeof(RootModule).GetProperties(BindingFlags.Public | BindingFlags.Instance))
                                        {
                                            if (!property.CanRead || !property.CanWrite || excludedProperties.Contains(property.Name))
                                                continue;

                                            property.SetValue(mod, property.GetValue(manifestMod));
                                        }
                                    }
                                    catch (Exception manifestEx)
                                    {
                                        Console.WriteLine($"Failed to update manifest for {mod.dll}: {manifestEx.Message}");
                                    }
                                }
                                #endregion

                                var assembly = CSharpEval.Compilation(mod);
                                if (assembly != null)
                                {
                                    DisposeModule(mod);

                                    foreach (var part in parts)
                                        mvcBuilder.PartManager.ApplicationParts.Remove(part);

                                    if (manifestMod != null)
                                        mod.initspace = manifestMod.initspace;

                                    mod.assembly = assembly;
                                    LoadedModule(app, mod);

                                    mvcBuilder.PartManager.ApplicationParts.Add(new AssemblyPart(mod.assembly));
                                    DynamicActionDescriptorChangeProvider.Instance.NotifyChanges();

                                    // Why (FM-1): these cache refreshes must also be
                                    // inside the lock so readers can't observe a half
                                    // swapped module list.
                                    MiddlewaresModuleEntry.EnsureCache(forced: true);
                                    OnlineModuleEntry.EnsureCache(forced: true);
                                    SisiModuleEntry.EnsureCache(forced: true);

                                    Console.WriteLine("rebuild module: " + mod.dll);
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"Failed to rebuild module {mod.dll}: {ex.Message}");
                            }
                            finally
                            {
                                watcher.EnableRaisingEvents = true;
                            }
                        }
                    });
                }

                watcher.Changed += Recompile;
                watcher.Created += Recompile;
                watcher.Deleted += Recompile;
                watcher.Renamed += Recompile;

                watcher.EnableRaisingEvents = true;
                moduleWatchers[path] = watcher;
            }
        }
        #endregion

        #region LoadedModule
        // Why (FM-3): refuse to invoke "loaded" / "Dispose" on an arbitrary type.
        // The type must either implement IModuleEntry or wear [ModuleEntry] -
        // otherwise a hostile manifest could point initspace at any static class
        // that happens to expose a loaded() method (e.g. System.IO.File).
        static bool IsTrustedEntry(Type t)
        {
            if (t == null) return false;

            if (typeof(IModuleEntry).IsAssignableFrom(t))
                return true;

            // Check via attribute name (avoids a hard reference from older
            // first-party modules that haven't been recompiled yet).
            foreach (var attr in t.GetCustomAttributes(inherit: false))
            {
                string n = attr.GetType().FullName;
                if (n == typeof(ModuleEntryAttribute).FullName || n.EndsWith(".ModuleEntryAttribute", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        void LoadedModule(IApplicationBuilder app, RootModule mod)
        {
            if (mod == null)
                return;

            if (mod.initspace == null || mod.assembly == null)
                return;

            Type t = mod.assembly.GetType(mod.NamespacePath(mod.initspace));
            if (t == null)
                return;

            if (!IsTrustedEntry(t))
            {
                Console.WriteLine($"LoadedModule: '{mod.NamespacePath(mod.initspace)}' does not implement IModuleEntry / [ModuleEntry]; not invoking loaded()");
                return;
            }

            if (t.GetMethod("loaded") is MethodInfo m)
            {
                if (mod.version >= 2)
                {
                    m.Invoke(null, [
                        new InitspaceModel()
                        {
                            path = $"module/{mod.dll}",
                            soks = new soks(),
                            nws = new NativeWebSocket(),
                            memoryCache = memoryCache,
                            configuration = Configuration,
                            services = serviceCollection,
                            app = app ?? _app
                        }
                    ]);
                }
                else
                    m.Invoke(null, []);
            }
        }
        #endregion

        #region DisposeModule
        void DisposeModule(RootModule module)
        {
            if (AppInit.modules == null)
                return;

            if (module != null)
            {
                DisposeOne(module);
            }
            else
            {
                foreach (var mod in AppInit.modules)
                    DisposeOne(mod);
            }
        }

        static void DisposeOne(RootModule mod)
        {
            // Why (FM-3): same trust gate as LoadedModule for the Dispose call.
            try
            {
                if (mod.initspace != null && mod.assembly?.GetType(mod.NamespacePath(mod.initspace)) is Type t && IsTrustedEntry(t) && t.GetMethod("Dispose") is MethodInfo m)
                    m.Invoke(null, []);
            }
            catch { }

            // Why (FH-3): after the module disposes, unload its collectible
            // context and keep the weak reference so a follow-up GC pass can
            // confirm the assemblies were actually released. Root leaks (event
            // handlers, static caches, timers) show up here as a live target
            // after multiple GCs.
            var handle = mod.loadHandle;
            if (handle != null && handle.IsCollectible)
            {
                try
                {
                    handle.Context.Unload();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"DisposeModule: Unload failed for {mod.dll}: {ex.Message}");
                }

                _ = Task.Run(() =>
                {
                    for (int i = 0; i < 10 && handle.Tracker != null && handle.Tracker.IsAlive; i++)
                    {
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                    }

                    if (handle.Tracker != null && handle.Tracker.IsAlive)
                        Console.WriteLine($"DisposeModule: module '{mod.dll}' AssemblyLoadContext is still alive after Unload; likely a root leak (event handler / static reference).");
                });
            }
        }
        #endregion
    }
}
