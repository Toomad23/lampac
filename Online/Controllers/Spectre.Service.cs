using Newtonsoft.Json;
using Shared.Models.Events;
using Shared.Models.Online.Spectre;
using System.Net.WebSockets;
using System.Text;
using System.Threading;

namespace Online.Controllers
{
    // Spectre playback service — multi-viewer rework ported from lampac-nextgen
    // (commit 480ba7c, "Spectre mux"). One WatchMux per active streamId; all
    // segment-fetch interception, WS keep-alive and edge_hash injection happen
    // on a per-WatchMux basis instead of the old single-global state machine.
    //
    // Adaptations vs. nextgen:
    //   * Our EventProxyApiCreateHttpRequest record does NOT carry a `userdata`
    //     channel. Upstream keys WatchMux lookups off `e.decryptLink.userdata
    //     as StreamData`. We can't recover that key from the segment URL alone,
    //     so we dispatch by the requesting viewer's remote IP instead. With
    //     mux=false we collapse to a single shared key ("muxoff") to preserve
    //     the pre-mux behaviour byte-for-byte for single-viewer setups.
    //   * Resolution-change handover (sendResolution -> playback_start) is
    //     dropped — without userdata we can't tell from a segment fetch what
    //     quality the viewer is on. Initial resolution is captured once in
    //     goMovie and never re-emitted. See PR #60 / Spectre.cs comment.
    //   * Every external host crossed before HTTP is SsrfGuard'd at the call
    //     site (linkhost / wsUri / per-quality stream link). Those checks live
    //     on the controller, not here.
    public static class Service
    {
        static Timer timer;
        static readonly ConcurrentDictionary<string, WatchMux> watchs = new();

        // Upstream-constant bearer token kept verbatim from nextgen. NOT a user
        // secret and NOT user-derived — the upstream service requires this exact
        // value as its bot-gate. Intentionally never logged.
        const string AuthorizationsBearer = "Bearer pXzvbyDGLYyB6VkwsWZDv3iMKZtsXNzpzRyxZUcsKHXxsSeaYakbo3hw9mBFRc5VQTpqAX6BW8aDEqyLaHYcXSQiV6KHYTVTK6MYRphNAy5sBjtrevqkDzKmLqNdfMZGEU9NELjmtKfZy3RNGzCd767sNh1mXEj4tCcvqndHtzmwAbZNkhm4ghDEasodotMBewypNQ56uotJAQGX11csfeRfBAPk8DcUWWkkqzxca8vbnEw12vUFbBzT6hz8ZB3F3dzUhUXoL2cr1WM1bXQArRCS1MUNMz3X5WDMMQoZKxj2AMTRqp7QQX4dDB9B7VzEZTmyFULhm1AcHHMkoMvSVvKYoBoAKLycYAgMHeD4ECJcGEAGpnkJhrV57zQ7";

        public static void Start()
        {
            // One-shot start guard — Spectre's static ctor is the single caller,
            // but the timer field is non-null after first init; subsequent
            // entry would silently leak. Kept idempotent.
            if (timer != null)
                return;

            timer = new Timer(_ =>
            {
                foreach (var kvp in watchs)
                {
                    var watch = kvp.Value;
                    if (watch == null)
                        continue;

                    if (watch.lastreq != default && DateTime.Now.AddMinutes(-15) > watch.lastreq)
                    {
                        if (watchs.TryRemove(kvp.Key, out WatchMux removed))
                            removed?.Dispose();
                    }
                }
            }, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(1));
        }


        #region ProxyApiCreateHttpRequest
        async public static Task ProxyApiCreateHttpRequest(EventProxyApiCreateHttpRequest e)
        {
            if (e.plugin == null || !e.plugin.Equals("Spectre", StringComparison.OrdinalIgnoreCase))
                return;

            var conf = AppInit.conf.Spectre;

            // Dispatch by viewer IP (or "muxoff" when mux is disabled). Upstream
            // uses e.decryptLink.userdata as StreamData; our record has no such
            // channel — see file header.
            string streamId = ResolveStreamId(e, conf);
            if (string.IsNullOrEmpty(streamId))
                return;

            if (!watchs.TryGetValue(streamId, out WatchMux watch) || watch?.ws == null)
            {
                if (conf.debug)
                    Console.WriteLine($"[Spectre] watch null (streamId={streamId})");

                // Fail-closed: if we don't know this viewer, don't strip /
                // forge headers from an unrelated request that happened to
                // share the plugin tag. Just leave the message alone.
                return;
            }

            // Wait briefly for the WS handshake to deliver edge_hash.
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (watch.edge_hash == null && sw.Elapsed < TimeSpan.FromSeconds(20))
                await Task.Delay(25);

            if (watch.edge_hash == null)
            {
                if (conf.debug)
                    Console.WriteLine($"[Spectre] edge_hash null (streamId={streamId})");
                return;
            }

            watch.lastreq = DateTime.Now;

            #region current_time (inferred from segment index in URL)
            // Upstream keyed this off decryptLink.userdata; we parse the segment
            // index from the proxied URL and derive elapsed seconds.
            string reqUri = e.requestMessage?.RequestUri?.ToString() ?? string.Empty;
            string segId = Regex.Match(reqUri, "/seg-([0-9]+)-").Groups[1].Value;
            int seg = int.TryParse(segId, out int s) ? s : 0;

            bool sendSeeked = false;

            if (25 >= seg)
            {
                lock (watch.stateLock)
                {
                    watch.current_time = 0;
                    watch.last_time = 0;
                }
            }
            else
            {
                lock (watch.stateLock)
                {
                    watch.current_time = (seg - 25) * 6;
                    if (watch.last_time == 0)
                        watch.last_time = watch.current_time;

                    if ((watch.current_time - watch.last_time) > 90)
                        sendSeeked = true;

                    watch.last_time = watch.current_time;
                }

                if (sendSeeked)
                {
                    if (conf.debug)
                        Console.WriteLine($"[Spectre] seeked: {watch.current_time} (streamId={streamId})");

                    await WsSendAsync(watch, "seeked");
                    await Task.Delay(1000);
                }
            }
            #endregion

            #region requestMessage headers (Spectre anti-bot shape)
            e.requestMessage.Headers.Clear();

            e.requestMessage.Headers.TryAddWithoutValidation("Connection", "keep-alive");
            e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua", Http.defaultUaHeaders["sec-ch-ua"]);
            e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua-mobile", "?0");
            e.requestMessage.Headers.TryAddWithoutValidation("sec-ch-ua-platform", "\"Windows\"");
            e.requestMessage.Headers.TryAddWithoutValidation("User-Agent", Http.UserAgent);
            e.requestMessage.Headers.TryAddWithoutValidation("Accept", "*/*");
            e.requestMessage.Headers.TryAddWithoutValidation("Accept-Language", "ru-RU,ru;q=0.9,uk-UA;q=0.8,uk;q=0.7,en-US;q=0.6,en;q=0.5");
            e.requestMessage.Headers.TryAddWithoutValidation("Accepts-Controls", watch.edge_hash);
            // Upstream-constant bearer; do not log.
            e.requestMessage.Headers.TryAddWithoutValidation("Authorizations", AuthorizationsBearer);
            if (!string.IsNullOrEmpty(watch.requestOrigin))
                e.requestMessage.Headers.TryAddWithoutValidation("Origin", watch.requestOrigin);
            e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "cross-site");
            e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Mode", "cors");
            e.requestMessage.Headers.TryAddWithoutValidation("Sec-Fetch-Dest", "empty");
            if (!string.IsNullOrEmpty(watch.requestReferer))
                e.requestMessage.Headers.TryAddWithoutValidation("Referer", watch.requestReferer);
            e.requestMessage.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip, deflate, br, zstd");

            if (e.requestMessage.Content?.Headers != null)
                e.requestMessage.Content.Headers.Clear();
            #endregion
        }
        #endregion


        #region ResolveStreamId
        // Centralised so /Video and the proxy hook agree on the key. With
        // mux=false everyone collapses onto "muxoff" (pre-mux behaviour). With
        // mux=true we use the viewer's remote IP — the only viewer signal we
        // can read from both code paths in our fork. Falls back to "unknown"
        // if the IP can't be determined; matches Video()'s logic exactly.
        static string ResolveStreamId(EventProxyApiCreateHttpRequest e, Shared.Models.Online.Settings.SpectreSettings conf)
        {
            if (conf == null || !conf.mux)
                return "muxoff";

            string ip = e.request?.HttpContext?.Connection?.RemoteIpAddress?.ToString();
            return string.IsNullOrEmpty(ip) ? "unknown" : ip;
        }
        #endregion


        #region AddOrUpdate
        async public static Task<bool> AddOrUpdate(string streamId, string wsUri, WatchMux watch)
        {
            if (string.IsNullOrEmpty(streamId) || watch == null)
                return false;

            // Replace any prior watch for this streamId; this is what the old
            // ClearConnect() did globally, scoped per viewer now.
            if (watchs.TryRemove(streamId, out WatchMux prev))
                prev?.Dispose();

            bool connected = await WebSocket(wsUri, watch);
            if (!connected)
                return false;

            return watchs.TryAdd(streamId, watch);
        }
        #endregion


        #region WebSocket
        async static Task<bool> WebSocket(string wsUri, WatchMux watch)
        {
            try
            {
                watch.ws = new ClientWebSocket();
                watch.ws.Options.SetRequestHeader("User-Agent", Http.UserAgent);

                watch.wscts = new CancellationTokenSource();

                await watch.ws.ConnectAsync(new Uri(wsUri), watch.wscts.Token);

                var receiveBuffer = new byte[16 * 1024];

                _ = Task.Factory.StartNew(async () =>
                {
                    try
                    {
                        while (!watch.wscts.Token.IsCancellationRequested && watch.ws.State == WebSocketState.Open)
                        {
                            var result = await watch.ws.ReceiveAsync(new ArraySegment<byte>(receiveBuffer), watch.wscts.Token);
                            if (watch.wscts.Token.IsCancellationRequested)
                                return;

                            if (result.MessageType == WebSocketMessageType.Close)
                            {
                                if (AppInit.conf.Spectre.debug)
                                    Console.WriteLine("[Spectre] WS closed by server");
                                return;
                            }

                            string message = Encoding.UTF8.GetString(receiveBuffer, 0, result.Count);

                            string hash = Regex.Match(message ?? string.Empty, "\"edge_hash\":\"([^\"]+)\"").Groups[1].Value;
                            if (!string.IsNullOrEmpty(hash))
                            {
                                watch.edge_hash = hash;

                                if (AppInit.conf.Spectre.debug)
                                    Console.WriteLine("[Spectre] edge_hash arrived");
                            }
                        }
                    }
                    catch { }
                }, watch.wscts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

                _ = Task.Factory.StartNew(async () =>
                {
                    while (!watch.wscts.Token.IsCancellationRequested && watch.ws.State == WebSocketState.Open)
                    {
                        try
                        {
                            await Task.Delay(TimeSpan.FromSeconds(30), watch.wscts.Token);
                            if (watch.wscts.Token.IsCancellationRequested)
                                return;

                            await WsSendAsync(watch, "playing");
                        }
                        catch { }
                    }
                }, watch.wscts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);

                long unixtime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                await WsSendAsync(watch, "playback_start", unixtime);
                await WsSendAsync(watch, "init", unixtime);

                return true;
            }
            catch
            {
                // Cleanup on failed handshake; the caller will not Add the watch.
                try { watch.Dispose(); } catch { }
                return false;
            }
        }
        #endregion


        #region WsSendAsync
        public static Task WsSendAsync(WatchMux watch, string type, long unixtime = 0)
        {
            if (watch?.ws == null || watch.ws.State != WebSocketState.Open)
                return Task.CompletedTask;

            if (unixtime == 0)
                unixtime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            string payload = JsonConvert.SerializeObject(new
            {
                type,
                current_time = watch.current_time,
                resolution = watch.resolution,
                track_id = "1",
                speed = 1,
                subtitle = -1,
                ts = unixtime
            });

            try
            {
                return watch.ws.SendAsync(
                    new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
                    WebSocketMessageType.Text,
                    true,
                    watch.wscts?.Token ?? CancellationToken.None
                );
            }
            catch
            {
                return Task.CompletedTask;
            }
        }
        #endregion
    }
}
