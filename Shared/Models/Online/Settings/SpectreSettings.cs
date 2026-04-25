using Shared.Models.Base;

namespace Shared.Models.Online.Settings
{
    // Ported from lampac-nextgen Modules/OnlineRUS/Spectre/ModuleConf.cs.
    //
    // Spectre is a Russian streaming source that relies on a short-lived
    // `edge_hash` obtained from a WebSocket handshake to authorise each
    // segment fetch (anti-bot gate). The balancer therefore needs:
    //   - apihost   : search / metadata endpoint (e.g. api.apbugall.org)
    //   - linkhost  : iframe / playlist endpoint (e.g. aport-as.allarknow.online)
    //   - token     : long-term API token
    //   - secret_token : reserved for future use (kept for parity with AllohaSettings family)
    //   - m4s       : enable 2160p / 1440p (dash-like) streams
    //   - mux       : multi-viewer dispatch — when true, each viewer gets its own
    //                 WatchMux (keyed by remote IP); when false, all viewers
    //                 share a single WatchMux under the literal key "muxoff",
    //                 which matches the pre-mux behaviour. Default: true.
    //   - debug     : verbose Console logging from the Spectre Service path
    //                 (edge_hash arrival, watch lifecycle, seeked / playing
    //                 events). Default: false.
    //
    // Keeping this as its own type (rather than reusing AllohaSettings like Mirage does)
    // means future Spectre-specific flags can be added without polluting the Alloha shape
    // and without affecting other balancers that share AllohaSettings.
    public class SpectreSettings : BaseSettings, ICloneable
    {
        public SpectreSettings(string plugin, string apihost, string linkhost, string token, string secret_token, bool m4s)
        {
            this.plugin = plugin;
            this.token = token;
            this.secret_token = secret_token;
            this.m4s = m4s;

            this.linkhost = linkhost == null ? string.Empty : (linkhost.StartsWith("http") ? linkhost : Decrypt(linkhost)!);
            this.apihost = apihost == null ? string.Empty : (apihost.StartsWith("http") ? apihost : Decrypt(apihost));
        }


        public string secret_token { get; set; }

        public string linkhost { get; set; }

        public bool m4s { get; set; }

        public bool mux { get; set; }

        public bool debug { get; set; }


        public SpectreSettings Clone()
        {
            return (SpectreSettings)MemberwiseClone();
        }

        object ICloneable.Clone()
        {
            return MemberwiseClone();
        }
    }
}
