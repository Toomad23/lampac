using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.Playwright;
using Shared.Engine;
using Shared.Models;
using Shared.Models.Base;
using Shared.Models.Events;
using Shared.Models.Proxy;
using Shared.Models.Templates;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using YamlDotNet.Serialization;

namespace Shared
{
    public static class InvkEvent
    {
        #region static
        static InvkEvent()
        {
            updateConf();

            var eventsDir = Path.Combine(AppContext.BaseDirectory, "events");
            var lastWriteTimes = new Dictionary<string, DateTime>();
            var lastCsWriteTimes = new Dictionary<string, DateTime>();

            // Инициализация дат
            foreach (var file in Directory.Exists(eventsDir) ? Directory.GetFiles(eventsDir, "*.yaml") : Array.Empty<string>())
                lastWriteTimes[file] = File.GetLastWriteTimeUtc(file);

            // Why (FL-6): also track .cs files so when an operator edits an event script the
            // compiled-delegate cache in CSharpEval is purged immediately (otherwise the stale
            // compiled code runs until the 10-minute TTL or cache bound evicts it).
            foreach (var file in Directory.Exists(eventsDir) ? Directory.GetFiles(eventsDir, "*.cs") : Array.Empty<string>())
                lastCsWriteTimes[file] = File.GetLastWriteTimeUtc(file);

            ThreadPool.QueueUserWorkItem(async _ =>
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1));

                    if (!Directory.Exists(eventsDir))
                        continue;

                    bool changed = false;
                    bool csChanged = false;
                    var files = Directory.GetFiles(eventsDir, "*.yaml");
                    var csFiles = Directory.GetFiles(eventsDir, "*.cs");

                    // Проверка новых и изменённых файлов
                    foreach (var file in files)
                    {
                        var writeTime = File.GetLastWriteTimeUtc(file);
                        if (!lastWriteTimes.TryGetValue(file, out var lastTime) || writeTime != lastTime)
                        {
                            changed = true;
                            lastWriteTimes[file] = writeTime;
                        }
                    }

                    // Проверка удалённых файлов
                    foreach (var file in lastWriteTimes.Keys.ToList())
                    {
                        if (!files.Contains(file))
                        {
                            changed = true;
                            lastWriteTimes.Remove(file);
                        }
                    }

                    // Why (FL-6): detect .cs edits so the compiled-delegate cache is flushed.
                    foreach (var file in csFiles)
                    {
                        var writeTime = File.GetLastWriteTimeUtc(file);
                        if (!lastCsWriteTimes.TryGetValue(file, out var lastTime) || writeTime != lastTime)
                        {
                            csChanged = true;
                            lastCsWriteTimes[file] = writeTime;
                        }
                    }

                    foreach (var file in lastCsWriteTimes.Keys.ToList())
                    {
                        if (!csFiles.Contains(file))
                        {
                            csChanged = true;
                            lastCsWriteTimes.Remove(file);
                        }
                    }

                    if (changed)
                        updateConf();

                    if (changed || csChanged)
                        CSharpEval.InvalidateAll();
                }
            });
        }
        #endregion

        #region conf
        public static EventsModel conf = new EventsModel();

        static void updateConf()
        {
            var eventsDir = Path.Combine(AppContext.BaseDirectory, "events");
            if (!Directory.Exists(eventsDir))
                return;

            var deserializer = new DeserializerBuilder().Build();
            var serializer = new SerializerBuilder().Build();

            // Итоговый словарь для объединения всех файлов
            var merged = new Dictionary<object, object>();

            foreach (string file in Directory.GetFiles(eventsDir, "*.yaml"))
            {
                try
                {
                    if (Path.GetFileName(file) is "example.yaml" or "interceptors.yaml")
                        continue;

                    var yaml = File.ReadAllText(file);
                    var dict = deserializer.Deserialize<Dictionary<object, object>>(yaml);

                    foreach (var property in dict)
                    {
                        if (!merged.ContainsKey(property.Key))
                        {
                            merged[property.Key] = property.Value;
                            continue;
                        }

                        if (property.Value is IDictionary<object, object> sourceDict &&
                            merged[property.Key] is IDictionary<object, object> targetDict)
                        {
                            foreach (var item in sourceDict)
                                targetDict[item.Key] = item.Value;
                        }
                        else
                        {
                            merged[property.Key] = property.Value;
                        }
                    }
                }
                catch (Exception ex) { Console.WriteLine(ex); }
            }

            // Преобразуем объединённый словарь обратно в YAML, затем десериализуем в EventsModel
            var yamlResult = serializer.Serialize(merged);
            conf = deserializer.Deserialize<EventsModel>(yamlResult);
        }
        #endregion

        #region FileOrCode
        static string FileOrCode(string _val)
        {
            if (!_val.EndsWith(".cs"))
                return _val;

            // Why (FL-5): _val is a YAML-supplied value. Previously we combined it with
            // "events/" and handed it to FileCache. If an operator (or anyone who can edit
            // the YAML) wrote `../foo.cs` or `..\..\etc\passwd.cs`, the combined path would
            // escape the events/ directory. Reject separators and relative traversals, then
            // confirm the resolved absolute path still lives under events/.
            if (_val.IndexOfAny(new[] { '/', '\\' }) >= 0 || _val.Contains(".."))
            {
                Console.Error.WriteLine($"InvkEvent FileOrCode: rejected path-like value '{_val}'");
                return string.Empty;
            }

            var eventsDir = Path.Combine(AppContext.BaseDirectory, "events");
            string combined = Path.Combine(eventsDir, Path.GetFileName(_val));

            string fullEvents;
            string fullCombined;
            try
            {
                fullEvents = Path.GetFullPath(eventsDir);
                fullCombined = Path.GetFullPath(combined);
            }
            catch
            {
                return string.Empty;
            }

            if (!fullCombined.StartsWith(fullEvents + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                && !string.Equals(fullCombined, fullEvents, StringComparison.Ordinal))
            {
                Console.Error.WriteLine($"InvkEvent FileOrCode: path escapes events dir '{_val}'");
                return string.Empty;
            }

            // Why (FL-4): FileCache.ReadAllText silently prefers a sibling `.my.cs` shadow file
            // (intended for config overrides), which means an attacker or misconfigured operator
            // could hide a second code path behind every event handler without the reviewer
            // seeing it. For executable code we read the canonical file directly and skip the
            // override machinery. Config files keep the .my override behavior — only scripts
            // are tightened here.
            if (!File.Exists(fullCombined))
                return string.Empty;

            try
            {
                return File.ReadAllText(fullCombined);
            }
            catch
            {
                return string.Empty;
            }
        }
        #endregion


        #region exception logging
        // Why (FL-7): previously the Invoke helpers swallowed every exception with `catch { }`.
        // Operators had no visibility into scripts that silently failed. We now rate-limit the
        // log line to one message per minute per (handler, exception-type) pair — enough to
        // surface repeated failures without spamming stderr. The exception detail is NOT
        // returned to HTTP responses; we only write to stderr.
        static readonly ConcurrentDictionary<string, long> _lastLogTicks = new();
        static readonly TimeSpan _logInterval = TimeSpan.FromMinutes(1);

        static void LogInvokeException(Exception ex, [CallerMemberName] string handler = null)
        {
            if (ex == null)
                return;

            string key = (handler ?? "?") + "|" + ex.GetType().Name;
            long now = DateTime.UtcNow.Ticks;
            long last = _lastLogTicks.GetOrAdd(key, 0);

            if (now - last < _logInterval.Ticks)
                return;

            if (!_lastLogTicks.TryUpdate(key, now, last))
                return; // another thread logged this same handler/type in the meantime

            Console.Error.WriteLine($"InvkEvent {handler} failed: {ex.GetType().Name}: {ex.Message}");
        }
        #endregion


        #region Invoke<T>
        static T Invoke<T>(string cs, object model, ScriptOptions options = null, [CallerMemberName] string handler = null)
        {
            try
            {
                if (cs != null)
                    return CSharpEval.Execute<T>(FileOrCode(cs), model, options);
            }
            catch (Exception ex) { LogInvokeException(ex, handler); }

            return default;
        }
        #endregion

        #region InvokeAsync<T>
        static async Task<T> InvokeAsync<T>(string cs, object model, ScriptOptions options = null, [CallerMemberName] string handler = null)
        {
            try
            {
                if (cs != null)
                    return await CSharpEval.ExecuteAsync<T>(FileOrCode(cs), model, options).ConfigureAwait(false);
            }
            catch (Exception ex) { LogInvokeException(ex, handler); }

            return default;
        }
        #endregion

        #region Invoke
        static void Invoke(string cs, object model, ScriptOptions options = null, [CallerMemberName] string handler = null)
        {
            try
            {
                if (cs != null)
                    CSharpEval.Execute(FileOrCode(cs), model, options);
            }
            catch (Exception ex) { LogInvokeException(ex, handler); }
        }
        #endregion

        #region InvokeAsync
        static async Task InvokeAsync(string cs, object model, ScriptOptions options = null, [CallerMemberName] string handler = null)
        {
            try
            {
                if (cs != null)
                    await CSharpEval.ExecuteAsync(FileOrCode(cs), model, options).ConfigureAwait(false);
            }
            catch (Exception ex) { LogInvokeException(ex, handler); }
        }
        #endregion


        #region LoadKitInit
        public static bool IsLoadKitInit()
            => EventListener.LoadKitInit != null || conf?.LoadKitInit != null;

        public static void LoadKitInit(EventLoadKit model)
        {
            EventListener.LoadKitInit?.Invoke(model);

            if (conf?.LoadKitInit == null)
                return;

            Invoke(conf?.LoadKitInit, model, ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models.Base")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO"));
        }
        #endregion

        #region LoadKit
        public static bool IsLoadKit()
            => EventListener.LoadKit != null || conf?.LoadKit != null;

        public static void LoadKit(EventLoadKit model)
        {
            EventListener.LoadKit?.Invoke(model);

            if (conf?.LoadKit == null)
                return;

            Invoke(conf?.LoadKit, model, ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Engine").AddImports("Shared.Models")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO"));
        }
        #endregion

        #region ProxyApi
        public static bool IsProxyApiCacheStream()
            => EventListener.ProxyApiCacheStream != null || conf?.ProxyApi?.CacheStream != null;

        public static (string uriKey, string contentType) ProxyApiCacheStream(HttpContext httpContext, ProxyLinkModel decryptLink)
        {
            var cacheStreamModel = new EventProxyApiCacheStream(httpContext, decryptLink);

            if (EventListener.ProxyApiCacheStream != null)
                return EventListener.ProxyApiCacheStream.Invoke(cacheStreamModel);

            string code = conf?.ProxyApi?.CacheStream;

            if (string.IsNullOrEmpty(code))
                return (null, null);

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpRequest).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(typeof(Task).Assembly).AddImports("System.Threading.Tasks");

            return Invoke<(string uriKey, string contentType)>(code, cacheStreamModel, option);
        }

        public static bool IsProxyApiCreateHttpRequest()
            => EventListener.ProxyApiCreateHttpRequest != null || conf?.ProxyApi?.CreateHttpRequest != null;

        async public static Task ProxyApiCreateHttpRequest(string plugin, HttpRequest request, List<HeadersModel> headers, Uri uri, bool ismedia, HttpRequestMessage requestMessage)
        {
            var httpRequestModel = new EventProxyApiCreateHttpRequest(plugin, request, headers, uri, ismedia, requestMessage);

            if (EventListener.ProxyApiCreateHttpRequest != null)
                await EventListener.ProxyApiCreateHttpRequest.Invoke(httpRequestModel);

            string code = conf?.ProxyApi?.CreateHttpRequest;

            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpRequest).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(typeof(Task).Assembly).AddImports("System.Threading.Tasks")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine")
                .AddReferences(typeof(HttpRequestMessage).Assembly).AddImports("System.Net.Http")
                .AddReferences(typeof(System.Net.Cookie).Assembly).AddImports("System.Net")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            await InvokeAsync(code, httpRequestModel, option);
        }
        #endregion

        #region ProxyImg
        public static bool IsProxyImgMd5key()
            => EventListener.ProxyImgMd5key != null || conf?.ProxyImg?.Md5Key != null;

        public static void ProxyImgMd5key(ref string md5key, HttpContext httpContext, RequestModel requestInfo, ProxyLinkModel decryptLink, string href, int width, int height)
        {
            var model = new EventProxyImgMd5key(httpContext, requestInfo, decryptLink, href, width, height);

            if (EventListener.ProxyImgMd5key != null)
            {
                string newKey = EventListener.ProxyImgMd5key.Invoke(model);
                if (!string.IsNullOrEmpty(newKey))
                    md5key = CrypTo.md5(newKey);
            }

            string code = conf?.ProxyImg?.Md5Key;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpRequest).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Models.Proxy").AddImports("Shared.Models.Events");

            string eventKey = Invoke<string>(code, model, option);
            if (!string.IsNullOrEmpty(eventKey))
                md5key = CrypTo.md5(eventKey);
        }
        #endregion

        #region BadInitialization
        public static bool IsBadInitialization()
            => conf?.Controller?.BadInitialization != null || EventListener.BadInitialization != null;

        public static Task<ActionResult> BadInitialization(EventBadInitialization model)
        {
            if (conf?.Controller?.BadInitialization == null)
            {
                if (EventListener.BadInitialization != null)
                    return EventListener.BadInitialization.Invoke(model);

                return Task.FromResult(default(ActionResult));
            }

            var option = ScriptOptions.Default
                .AddReferences(typeof(ActionResult).Assembly).AddImports("Microsoft.AspNetCore.Mvc")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models.Base").AddImports("Shared.Engine")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            return InvokeAsync<ActionResult>(conf?.Controller?.BadInitialization, model, option);
        }
        #endregion

        #region HostStreamProxy
        public static bool IsHostStreamProxy()
            => conf?.Controller?.HostStreamProxy != null || EventListener.HostStreamProxy != null;

        public static string HostStreamProxy(EventHostStreamProxy model)
        {
            if (conf?.Controller?.HostStreamProxy == null)
                return EventListener.HostStreamProxy?.Invoke(model);

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Engine").AddImports("Shared.Models.Base").AddImports("Shared.Models")
                .AddReferences(typeof(WebProxy).Assembly).AddImports("System.Net")
                .AddReferences(typeof(MD5).Assembly).AddImports("System.Security.Cryptography")
                .AddImports("System.Collections.Generic");

            return Invoke<string>(conf.Controller.HostStreamProxy, model, option);
        }
        #endregion

        #region HostImgProxy
        public static bool IsHostImgProxy()
            => conf?.Controller?.HostImgProxy != null || EventListener.HostImgProxy != null;

        public static string HostImgProxy(RequestModel requestInfo, HttpContext httpContext, string uri, int height, List<HeadersModel> headers, string plugin)
        {
            var model = new EventHostImgProxy(requestInfo, httpContext, uri, height, headers, plugin);

            if (conf?.Controller?.HostImgProxy == null)
                return EventListener.HostImgProxy?.Invoke(model);

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models").AddImports("Shared.Models.Base").AddImports("Shared.Engine")
                .AddImports("System.Collections.Generic");

            return Invoke<string>(conf.Controller.HostImgProxy, model, option);
        }
        #endregion

        #region MyLocalIp
        public static bool IsMyLocalIp()
            => conf?.Controller?.MyLocalIp != null || EventListener.MyLocalIp != null;

        public static Task<string> MyLocalIp(EventMyLocalIp model)
        {
            if (string.IsNullOrEmpty(conf?.Controller?.MyLocalIp))
            {
                if (EventListener.MyLocalIp != null)
                    return EventListener.MyLocalIp.Invoke(model);

                return Task.FromResult(default(string));
            }

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Engine").AddImports("Shared.Models.Base")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            return InvokeAsync<string>(conf.Controller.MyLocalIp, model, option);
        }
        #endregion

        #region HttpHeaders
        public static bool IsHttpHeaders()
            => conf?.Controller?.HttpHeaders != null || EventListener.HttpHeaders != null;

        public static Dictionary<string, string> HttpHeaders(EventControllerHttpHeaders model)
        {
            if (string.IsNullOrEmpty(conf?.Controller?.HttpHeaders))
                return EventListener.HttpHeaders?.Invoke(model);

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models.Base").AddImports("Shared.Models")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO")
                .AddImports("System.Collections.Generic");

            return Invoke<Dictionary<string, string>>(conf.Controller.HttpHeaders, model, option);
        }
        #endregion

        #region Staticache
        public static bool IsStaticache()
            => conf?.Staticache != null || EventListener.Staticache != null;

        public static bool Staticache(EventStaticache model)
        {
            if (string.IsNullOrEmpty(conf?.Staticache))
                return EventListener.Staticache?.Invoke(model) ?? default;

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            return Invoke<bool>(conf.Staticache, model, option);
        }
        #endregion

        #region Middleware
        public static bool IsMiddleware(bool first)
            => (first ? conf?.Middleware?.first : conf?.Middleware?.end) != null || EventListener.Middleware != null;

        public static Task<bool> Middleware(bool first, EventMiddleware model)
        {
            if ((first ? conf?.Middleware?.first : conf?.Middleware?.end) == null)
            {
                if (EventListener.Middleware != null)
                    return EventListener.Middleware.Invoke(first, model);

                return Task.FromResult(default(bool));
            }

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpContext).Assembly).AddImports("Microsoft.AspNetCore.Http")
                .AddReferences(typeof(Task).Assembly).AddImports("System.Threading.Tasks")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine")
                .AddReferences(typeof(HttpRequestMessage).Assembly).AddImports("System.Net.Http")
                .AddReferences(typeof(System.Net.Cookie).Assembly).AddImports("System.Net")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            return InvokeAsync<bool>(first ? conf?.Middleware?.first : conf?.Middleware?.end, model, option);
        }
        #endregion

        #region AppReplace
        public static string AppReplace(string e, EventAppReplace model)
        {
            string code = null;

            switch (e)
            {
                case "online":
                    code = conf?.Controller?.AppReplace?.online?.eval;
                    break;

                case "sisi":
                    code = conf?.Controller?.AppReplace?.sisi?.eval;
                    break;

                case "appjs":
                    code = conf?.Controller?.AppReplace?.appjs?.eval;
                    break;

                case "appcss":
                    code = conf?.Controller?.AppReplace?.appcss?.eval;
                    break;
            }

            if (string.IsNullOrEmpty(code))
                return EventListener.AppReplace?.Invoke(e, model);

            return Invoke<string>(code, model, ScriptOptions.Default.AddReferences(typeof(File).Assembly).AddImports("System.IO"));
        }
        #endregion

        #region Http
        public static bool IsHttpClientHandler()
            => conf?.Http?.Handler != null || EventListener.HttpHandler != null;

        public static void HttpClientHandler(EventHttpHandler model)
        {
            string code = conf?.Http?.Handler;
            EventListener.HttpHandler?.Invoke(model);

            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(WebProxy).Assembly).AddImports("System.Net")
                .AddReferences(typeof(HttpClientHandler).Assembly).AddImports("System.Net.Http")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            Invoke(code, model, option);
        }

        public static bool IsHttpClientHeaders()
            => conf?.Http?.Headers != null || EventListener.HttpRequestHeaders != null;

        public static void HttpClientHeaders(EventHttpHeaders model)
        {
            string code = code = conf?.Http?.Headers;
            EventListener.HttpRequestHeaders?.Invoke(model);

            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(WebProxy).Assembly).AddImports("System.Net")
                .AddReferences(typeof(HttpClientHandler).Assembly).AddImports("System.Net.Http")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            Invoke(code, model, option);
        }

        public static bool IsHttpAsync()
            => conf?.Http?.Response != null || EventListener.HttpResponse != null;

        public static Task HttpAsync(EventHttpResponse model)
        {
            string code = code = conf?.Http?.Response;

            if (string.IsNullOrEmpty(code) && EventListener.HttpResponse != null)
                return EventListener.HttpResponse.Invoke(model);

            if (string.IsNullOrEmpty(code))
                return Task.CompletedTask;

            var option = ScriptOptions.Default
                .AddReferences(typeof(WebProxy).Assembly).AddImports("System.Net")
                .AddReferences(typeof(HttpClientHandler).Assembly).AddImports("System.Net.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine")
                .AddReferences(typeof(File).Assembly).AddImports("System.IO");

            return InvokeAsync(code, model, option);
        }
        #endregion

        #region Corseu
        public static void CorseuRequest(CorseuRequest request)
        {
            var model = new EventCorseuRequest(request);

            EventListener.CorseuRequest?.Invoke(model);

            string code = conf?.Corseu?.Execute;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models.Events").AddImports("Shared.Models.Base");

            Invoke(code, model, option);
        }

        public static bool IsCorseuHttpRequest()
            => conf?.Corseu?.HttpRequest != null || EventListener.CorseuHttpRequest != null;

        public static void CorseuHttpRequest(string method, string url, HttpRequestMessage request)
        {
            var model = new EventCorseuHttpRequest(method, url, request);

            EventListener.CorseuHttpRequest?.Invoke(model);

            string code = conf?.Corseu?.HttpRequest;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(HttpRequestMessage).Assembly).AddImports("System.Net.Http")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models.Events");

            Invoke(code, model, option);
        }

        public static bool IsCorseuPlaywrightRequest()
            => conf?.Corseu?.PlaywrightRequest != null || EventListener.CorseuPlaywrightRequest != null;

        public static void CorseuPlaywrightRequest(string method, string url, APIRequestNewContextOptions contextOptions, APIRequestContextOptions requestOptions)
        {
            var model = new EventCorseuPlaywrightRequest(method, url, contextOptions, requestOptions);

            EventListener.CorseuPlaywrightRequest?.Invoke(model);

            string code = conf?.Corseu?.PlaywrightRequest;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(APIRequestNewContextOptions).Assembly).AddImports("Microsoft.Playwright")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models.Events");

            Invoke(code, model, option);
        }
        #endregion

        #region RedApi
        public static bool RedApi(string e, object model)
        {
            string code = null;

            switch (e)
            {
                case "addtorrent":
                    code = conf?.RedApi?.AddTorrents;
                    break;
            }

            return Invoke<bool>(code, model);
        }
        #endregion

        #region Externalids
        public static bool IsExternalids()
            => conf?.Controller?.Externalids != null || EventListener.Externalids != null;

        public static void Externalids(string id, ref string imdb_id, ref string kinopoisk_id, int serial)
        {
            (string imdb_id, string kinopoisk_id) result = default;

            var md = new EventExternalids(id, imdb_id, kinopoisk_id, serial);

            if (EventListener.Externalids != null)
                result = EventListener.Externalids.Invoke(md);

            if (!string.IsNullOrEmpty(conf?.Controller?.Externalids))
                result = Invoke<(string imdb_id, string kinopoisk_id)>(conf.Controller.Externalids, md);

            if (result == default || (result.imdb_id == null && result.kinopoisk_id == null))
                return;

            imdb_id = result.imdb_id;
            kinopoisk_id = result.kinopoisk_id;
        }
        #endregion

        #region StreamQualityTpl
        public static bool IsStreamQuality()
            => conf?.StreamQualityTpl != null || EventListener.StreamQuality != null;

        public static (bool? next, string link) StreamQuality(EventStreamQuality model)
        {
            if (string.IsNullOrEmpty(conf?.StreamQualityTpl))
                return EventListener.StreamQuality?.Invoke(model) ?? default;

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models.Events").AddImports("Shared.Models.Templates");

            return Invoke<(bool? next, string link)>(conf.StreamQualityTpl, model, option);
        }

        public static bool IsStreamQualityFirts()
            => conf?.StreamQualityFirts != null || EventListener.StreamQualityFirts != null;

        public static StreamQualityDto? StreamQualityFirts(EventStreamQualityFirts model)
        {
            if (string.IsNullOrEmpty(conf?.StreamQualityFirts))
                return EventListener.StreamQualityFirts?.Invoke(model);

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Models.Events").AddImports("Shared.Models.Templates");

            return Invoke<StreamQualityDto?>(conf.StreamQualityFirts, model, option);
        }
        #endregion

        #region Transcoding
        public static void Transcoding(EventTranscoding model)
        {
            EventListener.TranscodingCreateProcess?.Invoke(model);

            var code = conf?.Transcoding?.CreateProcess;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(Collection<string>).Assembly).AddImports("System.Collections.ObjectModel")
                .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine").AddImports("Shared.Models.AppConf");

            Invoke(code, model, option);
        }
        #endregion

        #region Rch
        public static bool IsRchRegistry()
            => conf?.Rch?.Registry != null || EventListener.RchRegistry != null;

        public static void RchRegistry(EventRchRegistry model)
        {
            EventListener.RchRegistry?.Invoke(model);

            var code = conf?.Rch?.Registry;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll"))
                .AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine");

            Invoke(code, model, option);
        }

        public static bool IsRchDisconnected()
            => conf?.Rch?.Disconnected != null || EventListener.RchDisconnected != null;

        public static void RchDisconnected(EventRchDisconnected model)
        {
            EventListener.RchDisconnected?.Invoke(model.connectionId);

            var code = conf?.Rch?.Disconnected;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll"))
                .AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine");

            Invoke(code, model, option);
        }
        #endregion

        #region Nws
        public static bool IsNwsConnected()
            => conf?.Nws?.Connected != null || EventListener.NwsConnected != null;

        public static void NwsConnected(EventNwsConnected model)
        {
            EventListener.NwsConnected?.Invoke(model);

            var code = conf?.Nws?.Connected;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(CancellationToken).Assembly).AddImports("System.Threading")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine");

            Invoke(code, model, option);
        }

        public static bool IsNwsMessage()
            => conf?.Nws?.Message != null || EventListener.NwsMessage != null;

        public static void NwsMessage(EventNwsMessage model)
        {
            EventListener.NwsMessage?.Invoke(model);

            var code = conf?.Nws?.Message;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(typeof(JsonElement).Assembly).AddImports("System.Text.Json")
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine");

            Invoke(code, model, option);
        }

        public static bool IsNwsDisconnected()
            => conf?.Nws?.Disconnected != null || EventListener.NwsDisconnected != null;

        public static void NwsDisconnected(EventNwsDisconnected model)
        {
            EventListener.NwsDisconnected?.Invoke(model.connectionId);

            var code = conf?.Nws?.Disconnected;
            if (string.IsNullOrEmpty(code))
                return;

            var option = ScriptOptions.Default
                .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared").AddImports("Shared.Models").AddImports("Shared.Engine");

            Invoke(code, model, option);
        }
        #endregion

        #region HybridCache
        //public static (DateTimeOffset ex, string value) HybridCache(string e, string key, string value, DateTimeOffset ex)
        //{
        //    string code = null;

        //    var model = new EventHybridCache(key, value, ex);

        //    switch (e)
        //    {
        //        case "read":
        //            code = conf?.HybridCache?.Read;
        //            break;

        //        case "write":
        //            code = conf?.HybridCache?.Write;
        //            break;
        //    }

        //    if (string.IsNullOrEmpty(code))
        //        return EventListener.HybridCache?.Invoke(e, model) ?? default;

        //    var option = ScriptOptions.Default
        //        .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll")).AddImports("Shared.Engine")
        //        .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll")).AddImports("Newtonsoft.Json").AddImports("Newtonsoft.Json.Linq")
        //        .AddReferences(typeof(File).Assembly).AddImports("System.IO");

        //    return Invoke<(DateTimeOffset ex, string value)>(code, model, option);
        //}
        #endregion

        public static void PidTor(EventPidTor model) => Invoke(conf?.PidTor, model);
    }
}
