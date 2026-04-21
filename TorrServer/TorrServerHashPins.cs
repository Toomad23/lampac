using System;
using System.Collections.Generic;

namespace TorrServer
{
    // Why (supply-chain, HIGH-8): we download the TorrServer binary straight
    // from https://github.com/YouROK/TorrServer/releases and execute it. Upstream
    // does not publish checksums alongside the assets, so an attacker who compromises
    // YouROK's GitHub credentials (or a release-pipeline secret) could swap the
    // binary for one that runs arbitrary code in Lampac's container / host. We
    // mitigate that by pinning the SHA-256 we expect per (tag, asset) pair. If the
    // operator points `TorrServer.conf.releases` at a tag that is not listed here
    // (or "latest"), the installer refuses to chmod+x the downloaded file and
    // deletes it — fail-closed. The map below was computed locally against the
    // upstream asset bytes; update it deliberately after reviewing each new
    // TorrServer release.
    internal static class TorrServerHashPins
    {
        private static readonly Dictionary<string, Dictionary<string, string>> _pins =
            new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
            {
                // Computed 2026-04-21 from
                // https://github.com/YouROK/TorrServer/releases/tag/MatriX.135
                ["MatriX.135"] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["TorrServer-linux-amd64"]         = "e8df23592ff44ccaf447d55adde3c625cd2d9de9b2af994aacd2e579d8ea174a",
                    ["TorrServer-linux-arm64"]         = "b583dbed25d08a2dfaf2302d4d920070ea5ec0ad7d0211cbf13ffc51110bd4c6",
                    ["TorrServer-linux-arm7"]          = "2d094631df6480253cd0b3c08c4fa7b4dcb53016192bf8b61ff7a4e5213e431a",
                    ["TorrServer-linux-arm5"]          = "dd30be5f4e1d25d1a7a74664e9a956e01ebc20939046df913bc2f015297c6842",
                    ["TorrServer-linux-386"]           = "41ec32dcd609f7ec5fabbd7ce1f4cb20a036b7069644dd607491507ec5bea1fb",
                    ["TorrServer-windows-amd64.exe"]   = "f05c13f218286866473cb4e83b081eecd4cde8dcc8faf5ede321bfeaa444b044",
                },
            };

        /// <summary>Returns the hex SHA-256 we expect, or null when the (tag, asset) pair is not pinned.</summary>
        public static string Resolve(string tag, string assetName)
        {
            if (string.IsNullOrEmpty(tag) || string.IsNullOrEmpty(assetName))
                return null;

            if (!_pins.TryGetValue(tag, out var assets))
                return null;

            return assets.TryGetValue(assetName, out var sha) ? sha : null;
        }
    }
}
