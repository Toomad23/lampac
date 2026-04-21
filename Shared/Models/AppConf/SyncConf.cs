namespace Shared.Models.AppConf
{
    public class SyncConf
    {
        public bool enable { get; set; }

        /// <summary>
        /// master
        /// slave
        /// </summary>
        public string type { get; set; }

        public string initconf { get; set; }

        public bool sync_full { get; set; } = true;

        public string api_host { get; set; }

        public string api_passwd { get; set; }

        // Why (round5.6): slave fetches AppInit wholesale from api_host and mass-assigns
        // it as the running config. Without an allowlist, anyone who can MITM / spoof
        // DNS for the master host poisons globalproxy, chromium.executablePath, and
        // other RCE-adjacent fields. Require the operator to enumerate trusted masters
        // explicitly; empty allowlist disables sync to fail-closed.
        public string[] allowHosts { get; set; } = System.Array.Empty<string>();

        public Dictionary<string, string> override_conf { get; set; }
    }
}
