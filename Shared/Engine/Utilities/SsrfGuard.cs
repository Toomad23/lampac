using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Shared.Engine.Utilities
{
    // Shared predicate for "is this URL safe to dereference from the server?"
    //
    // Uses IPNetwork.IsLocalIp for IP-literal rejection and does an async DNS
    // lookup for hostnames so that IPs hidden behind DNS names (either
    // deliberately or via rebinding on their first resolution) are also
    // rejected if any resolved address is private/loopback/link-local.
    //
    // NOTE: there is a residual DNS-rebinding window between this check and the
    // actual HTTP request. Callers that need strict protection should pass the
    // resolved public IP as the target and set the Host header manually. For
    // most adapters the host allowlist is tighter than this denylist, so this
    // helper is a secondary defence.
    public static class SsrfGuard
    {
        public static bool IsAllowedPublicUriBasic(string uri)
        {
            if (string.IsNullOrWhiteSpace(uri))
                return false;

            if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri parsed))
                return false;

            if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
                return false;

            string host = parsed.Host;
            if (string.IsNullOrEmpty(host))
                return false;

            // IP literal → reject if private/loopback/link-local.
            if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress literal))
                return !IsBlocked(literal);

            return true;
        }

        public static async Task<bool> IsAllowedPublicUriAsync(string uri)
        {
            if (!IsAllowedPublicUriBasic(uri))
                return false;

            if (!Uri.TryCreate(uri, UriKind.Absolute, out Uri parsed))
                return false;

            string host = parsed.Host;

            if (IPAddress.TryParse(host.Trim('[', ']'), out _))
                return true; // already validated in Basic.

            IPAddress[] addresses;
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }

            if (addresses == null || addresses.Length == 0)
                return false;

            foreach (var a in addresses)
            {
                if (IsBlocked(a))
                    return false;
            }

            return true;
        }

        static bool IsBlocked(IPAddress addr)
        {
            if (IPAddress.IsLoopback(addr))
                return true;

            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] b = addr.GetAddressBytes();
                if (b[0] == 10) return true;                        // 10.0.0.0/8
                if (b[0] == 127) return true;                       // 127.0.0.0/8
                if (b[0] == 192 && b[1] == 168) return true;        // 192.168.0.0/16
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12
                if (b[0] == 169 && b[1] == 254) return true;        // 169.254.0.0/16 link-local / metadata
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true; // CGNAT 100.64.0.0/10
                if (b[0] == 0) return true;                         // 0.0.0.0/8
                if (b[0] >= 224) return true;                       // multicast/reserved 224.0.0.0+
                return false;
            }

            if (addr.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || addr.IsIPv6Multicast)
                    return true;

                byte[] b = addr.GetAddressBytes();
                // unique-local fc00::/7
                if ((b[0] & 0xfe) == 0xfc) return true;
                // ::ffff:0:0/96 → IPv4-mapped; extract and recheck.
                if (addr.IsIPv4MappedToIPv6)
                {
                    IPAddress v4 = addr.MapToIPv4();
                    return IsBlocked(v4);
                }
                return false;
            }

            return true; // unknown family → fail closed
        }
    }
}
