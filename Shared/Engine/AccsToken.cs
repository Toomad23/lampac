using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Shared.Engine
{
    public static class AccsToken
    {
        const int SignatureBytes = 20; // 160 bits of HMAC-SHA256 — sufficient for MAC truncation
        const int SignatureHexLen = SignatureBytes * 2; // 40 hex chars

        static volatile byte[] _hmacKey;

        // HIGH-3: token revocation list. Entries are "uid|issuedAtUnix" OR "uid|*" (revoke-all-for-uid).
        // Loaded once from database/admin-revoked-tokens.txt on first access and append-on-revoke.
        static readonly ConcurrentDictionary<string, byte> _revoked = new(StringComparer.Ordinal);
        static volatile bool _revokedLoaded;
        static readonly object _revokedLoadLock = new();
        const string RevokedPath = "database/admin-revoked-tokens.txt";
        const string AuditPath = "database/admin-audit.log";

        public static void Init(string hmacSecret)
        {
            if (string.IsNullOrEmpty(hmacSecret))
            {
                _hmacKey = null;
                return;
            }

            _hmacKey = SHA256.HashData(Encoding.UTF8.GetBytes(hmacSecret + "|accsdb-token"));
        }

        public static bool IsEnabled => _hmacKey != null;

        static void EnsureRevokedLoaded()
        {
            if (_revokedLoaded) return;
            lock (_revokedLoadLock)
            {
                if (_revokedLoaded) return;
                try
                {
                    if (File.Exists(RevokedPath))
                    {
                        foreach (string line in File.ReadAllLines(RevokedPath))
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                                continue;
                            _revoked.TryAdd(line.Trim(), 0);
                        }
                    }
                }
                catch { }
                _revokedLoaded = true;
            }
        }

        public static void Revoke(string uid, long issuedAtUnix = -1)
        {
            if (string.IsNullOrEmpty(uid)) return;
            EnsureRevokedLoaded();
            string entry = issuedAtUnix > 0 ? $"{uid}|{issuedAtUnix}" : $"{uid}|*";
            if (_revoked.TryAdd(entry, 0))
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(RevokedPath) ?? ".");
                    File.AppendAllText(RevokedPath, entry + "\n");
                }
                catch { }
            }
        }

        public static bool IsRevoked(string uid, long issuedAtUnix)
        {
            EnsureRevokedLoaded();
            if (_revoked.ContainsKey($"{uid}|*"))
                return true;
            if (issuedAtUnix > 0 && _revoked.ContainsKey($"{uid}|{issuedAtUnix}"))
                return true;
            return false;
        }

        public static void Audit(string kind, string uid, string extra, string adminIp)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(AuditPath) ?? ".");
                string line = $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}\t{kind}\tuid={uid}\tip={adminIp}\t{extra}\n";
                File.AppendAllText(AuditPath, line);
            }
            catch { }
        }

        public static string Generate(string uid, DateTime expiresUtc)
        {
            if (_hmacKey == null || string.IsNullOrEmpty(uid))
                return null;

            string uidB64 = Base64UrlEncode(uid);
            long expiry = new DateTimeOffset(expiresUtc).ToUnixTimeSeconds();
            // HIGH-3: embed issuedAt so revocation can target a specific token issuance without
            // voiding every token ever issued for the uid.
            long issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string payload = $"{uidB64}.{expiry}.{issuedAt}";

            byte[] sig = ComputeSignature(payload);
            return $"{payload}.{Convert.ToHexString(sig, 0, SignatureBytes).ToLower()}";
        }

        // Kept for back-compat with already-issued tokens that only carry uid.expiry.sig.
        public static string GenerateLegacy(string uid, DateTime expiresUtc)
        {
            if (_hmacKey == null || string.IsNullOrEmpty(uid))
                return null;
            string uidB64 = Base64UrlEncode(uid);
            long expiry = new DateTimeOffset(expiresUtc).ToUnixTimeSeconds();
            string payload = $"{uidB64}.{expiry}";
            byte[] sig = ComputeSignature(payload);
            return $"{payload}.{Convert.ToHexString(sig, 0, SignatureBytes).ToLower()}";
        }

        public static (string uid, bool valid) Verify(string token)
        {
            if (_hmacKey == null || string.IsNullOrEmpty(token))
                return (null, false);

            // HIGH-3: support both legacy 3-segment (uid.expiry.sig) and new 4-segment
            // (uid.expiry.issuedAt.sig) token layouts. The last segment is always the signature.
            string[] parts = token.Split('.');
            if (parts.Length != 3 && parts.Length != 4)
                return (null, false);

            string uidB64 = parts[0];
            string expiryStr = parts[1];
            string issuedStr = parts.Length == 4 ? parts[2] : null;
            string sigHex = parts[^1];

            if (sigHex.Length != SignatureHexLen)
                return (null, false);

            if (!long.TryParse(expiryStr, out long expiry))
                return (null, false);

            long issuedAt = 0;
            if (issuedStr != null && !long.TryParse(issuedStr, out issuedAt))
                return (null, false);

            // Verify signature before checking expiry to avoid timing oracle
            string payload = issuedStr == null ? $"{uidB64}.{expiryStr}" : $"{uidB64}.{expiryStr}.{issuedStr}";
            byte[] expected = ComputeSignature(payload);
            byte[] actual;

            try
            {
                actual = Convert.FromHexString(sigHex);
            }
            catch
            {
                return (null, false);
            }

            if (!CryptographicOperations.FixedTimeEquals(expected.AsSpan(0, SignatureBytes), actual))
                return (null, false);

            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiry)
                return (null, false);

            string uid = Base64UrlDecode(uidB64);
            if (uid == null)
                return (null, false);

            // HIGH-3: consult revocation list — a stolen admin cookie previously granted
            // lifetime access to every user; now individual tokens can be killed without a rekey.
            if (IsRevoked(uid, issuedAt))
                return (null, false);

            return (uid, true);
        }

        public static bool IsHmacToken(string value)
        {
            // Minimum: 1-char base64url uid + '.' + 10-digit expiry + '.' + 40-char sig = 53
            // Or 4-segment form: 1-char uid + '.' + expiry + '.' + issuedAt + '.' + 40-char sig
            if (string.IsNullOrEmpty(value) || value.Length < 53)
                return false;

            int dots = 0;
            int lastDot = -1;
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] == '.')
                {
                    dots++;
                    lastDot = i;
                }
            }

            return (dots == 2 || dots == 3) && lastDot > 0 && (value.Length - lastDot - 1) == SignatureHexLen;
        }

        static byte[] ComputeSignature(string payload)
        {
            using var hmac = new HMACSHA256(_hmacKey);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
        }

        static string Base64UrlEncode(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        static string Base64UrlDecode(string value)
        {
            try
            {
                string padded = value.Replace('-', '+').Replace('_', '/');
                switch (padded.Length % 4)
                {
                    case 1: return null; // invalid base64url length
                    case 2: padded += "=="; break;
                    case 3: padded += "="; break;
                }
                return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
            }
            catch
            {
                return null;
            }
        }
    }
}
