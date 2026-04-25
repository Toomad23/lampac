using System;
using System.Net.WebSockets;
using System.Threading;

namespace Shared.Models.Online.Spectre
{
    // Per-viewer playback state for the Spectre balancer.
    //
    // Replaces the static fields that used to live on the Spectre controller.
    // One WatchMux per active streamId (in our fork, the streamId is the viewer's
    // remote IP, or the literal "muxoff" when mux=false). Owned by the static
    // ConcurrentDictionary in Online.Controllers.Service; disposed by the
    // idle-sweep timer or replaced on a fresh /lite/spectre/video request.
    public class WatchMux : IDisposable
    {
        public ClientWebSocket ws { get; set; }

        public CancellationTokenSource wscts { get; set; }

        public DateTime lastreq { get; set; }

        public string edge_hash { get; set; }

        public string resolution { get; set; }

        public string requestOrigin { get; set; }

        public string requestReferer { get; set; }

        public int current_time { get; set; }

        public int last_time { get; set; }

        // Per-instance lock for current_time / last_time / resolution mutations.
        // Upstream uses two static locks shared across all viewers; in the muxed
        // model that's a global throttle. Keep the mutation lock per-instance so
        // segment-fetch handlers for different viewers don't serialise on it.
        public readonly object stateLock = new();

        public void Dispose()
        {
            edge_hash = null;
            resolution = null;
            lastreq = default;

            try
            {
                wscts?.Cancel();
            }
            catch { }

            try
            {
                if (ws != null)
                    _ = ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
            }
            catch { }

            try
            {
                ws?.Dispose();
            }
            catch { }

            try
            {
                wscts?.Dispose();
            }
            catch { }

            ws = null;
            wscts = null;
        }
    }
}
