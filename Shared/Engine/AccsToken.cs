using System;
using System.Security.Cryptography;
using System.Text;

namespace Shared.Engine
{
    public static class AccsToken
    {
        const int SignatureBytes = 20; // 160 bits of HMAC-SHA256 — sufficient for MAC truncation
        const int SignatureHexLen = SignatureBytes * 2; // 40 hex chars

        static volatile byte[] _hmacKey;

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

        public static string Generate(string uid, DateTime expiresUtc)
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

            int firstDot = token.IndexOf('.');
            if (firstDot < 0)
                return (null, false);

            int secondDot = token.IndexOf('.', firstDot + 1);
            if (secondDot < 0 || secondDot == token.Length - 1)
                return (null, false);

            string uidB64 = token.Substring(0, firstDot);
            string expiryStr = token.Substring(firstDot + 1, secondDot - firstDot - 1);
            string sigHex = token.Substring(secondDot + 1);

            if (sigHex.Length != SignatureHexLen)
                return (null, false);

            if (!long.TryParse(expiryStr, out long expiry))
                return (null, false);

            // Verify signature before checking expiry to avoid timing oracle
            string payload = $"{uidB64}.{expiryStr}";
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

            return (uid, true);
        }

        public static bool IsHmacToken(string value)
        {
            // Minimum: 1-char base64url uid + '.' + 10-digit expiry + '.' + 40-char sig = 53
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

            return dots == 2 && lastDot > 0 && (value.Length - lastDot - 1) == SignatureHexLen;
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
