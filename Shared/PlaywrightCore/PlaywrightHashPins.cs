using System;
using System.Collections.Generic;

namespace Shared.PlaywrightCore
{
    // Why (supply-chain, HIGH-9): PlaywrightBase pulls Node binaries and
    // package.zip from the third-party lampac-talks/lampac release bucket and
    // executes them (node is the Playwright JS driver; package.zip is loaded
    // by the .NET Playwright client). Upstream publishes no checksums, so a
    // compromise of the release token would yield code execution in our
    // process. We pin a SHA-256 per exact download URL; unpinned URLs are
    // refused by DownloadFile. Hashes were computed locally on 2026-04-21
    // against the live release assets.
    internal static class PlaywrightHashPins
    {
        private static readonly Dictionary<string, string> _pins =
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                // package.zip — Playwright .NET client bundle
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/package.zip"]
                    = "3cb9bab69b35dc262f7fe78d277f544b47098fcce88409d072f7c5654fe0afd9",

                // Node binaries — Linux
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-linux-x64"]
                    = "1abce2374a485bddae3c27b17a3e3143e2780232026e627c4fe74ddde3f380a1",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-linux-x86"]
                    = "033e92a17004ab0a039cb76adbf1df909a772c204b1fc69dea3cd62ded164f27",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-linux-arm64"]
                    = "f15053488b3c49d16eb4b0da25593b459a79839248381f6aa61a876bcce54966",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-linux-armv7l"]
                    = "6bd2a0bb9f828fe503c866ced3e46425b0f03f91714859e639a2ca776513c737",

                // Node binaries — macOS
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-mac-x64"]
                    = "96df1150d8a9e72a34e7337f5032169aa7ff500c934d67bd2abcc40683fe006c",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-mac-arm64"]
                    = "e2d4915d03eda6a2f00a09920e7eeb7a04ad123f9aaad61b1481179fe1bf50e0",

                // Node binaries — Windows
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-win-x64.exe"]
                    = "33b1bc1a8aca11fd5a4f2699e51019c63c0af30cf437701d07af69be7706771b",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-win-x86.exe"]
                    = "d52f9f1b03eca305dbaa23e251fe612efbb48a99aaeab6ffa073ee1c111b28e0",
                ["https://github.com/lampac-talks/lampac/releases/download/browsers/node-win-arm64.exe"]
                    = "b37c6950508f266d066deb91abe2050fcd3f19e34c86ca89eed72efb40090b57",
            };

        /// <summary>Returns the hex SHA-256 pin for a given download URL, or null when unpinned.</summary>
        public static string Resolve(string url)
        {
            if (string.IsNullOrEmpty(url))
                return null;

            return _pins.TryGetValue(url, out var sha) ? sha : null;
        }
    }
}
