using Shared.Models.Base;

namespace Shared.Models.Online.Settings
{
    public class KinoPubSettings : BaseSettings, ICloneable
    {
        public KinoPubSettings(string plugin, string host = null)
        {
            this.plugin = plugin;

            if (host != null)
                this.host = host.StartsWith("http") ? host : Decrypt(host);
        }

        public string[] tokens { get; set; }

        public string filetype { get; set; }

        // Why: allow operators to override the compiled-in XBMC client_secret (L-8).
        // Null means "use the built-in default" so out-of-the-box behaviour is preserved.
        public string client_secret { get; set; } = null;


        public KinoPubSettings Clone()
        {
            return (KinoPubSettings)MemberwiseClone();
        }

        object ICloneable.Clone()
        {
            return MemberwiseClone();
        }
    }
}
