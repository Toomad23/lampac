using Shared.Models.Base;

namespace Shared.Models.Online.Settings
{
    // Why: PizdatoeHD is a Playwright-driven rezka.ag variant ported from lampac-nextgen. It
    // needs a couple of extra knobs beyond the common OnlinesSettings (premium tier toggles
    // quality ladder; cdn rewrites the stream host; imitationHuman controls WaitUntil behaviour).
    public class PizdatoeHDSettings : BaseSettings, ICloneable
    {
        public PizdatoeHDSettings(string plugin, string host, bool enable = true, bool streamproxy = false)
        {
            this.enable = enable;
            this.plugin = plugin;
            this.streamproxy = streamproxy;

            if (host != null)
                this.host = host.StartsWith("http") ? host : Decrypt(host);
        }

        public bool premium { get; set; }

        public bool imitationHuman { get; set; }

        // CDN rewrite target (e.g. a cdn-routed mirror of rezka's stream servers). Validated via
        // SsrfGuard before use so operator cannot accidentally point this at an internal host.
        public string cdn { get; set; }

        public PizdatoeHDSettings Clone() => (PizdatoeHDSettings)MemberwiseClone();

        object ICloneable.Clone() => MemberwiseClone();
    }
}
