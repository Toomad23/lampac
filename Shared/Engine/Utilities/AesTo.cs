using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Shared.Engine
{
    // Authenticated encryption for short-lived proxy-link payloads.
    //
    // Previous implementation used AES-CBC with a static IV and a key generated
    // via CrypTo.unic (Random.Shared, a non-crypto PRNG seeded from TickCount).
    // That was forgeable: with enough ciphertexts an attacker could recover the
    // PRNG state, and CBC without a MAC allowed bit-flipping the decoded JSON
    // (e.g. flipping verifyip=true to false or rewriting the embedded URL for
    // SSRF). Switched to AES-GCM with:
    //   * 256-bit key from RandomNumberGenerator (written once per install)
    //   * fresh 96-bit nonce per message, prepended to the ciphertext
    //   * 128-bit authentication tag verified on decrypt
    //
    // Wire format of the returned string: Base64( nonce(12) || cipher(n) || tag(16) ).
    //
    // Old ciphertexts are intentionally rejected (different format, different key)
    // — proxy links are short-lived and clients will re-request them.
    public static class AesTo
    {
        const int NonceSize = 12;
        const int TagSize = 16;

        static readonly byte[] aesKey = LoadOrCreateKey();

        static byte[] LoadOrCreateKey()
        {
            const string path = "cache/aeskey";

            if (File.Exists(path))
            {
                try
                {
                    string content = File.ReadAllText(path).Trim();
                    byte[] k = Convert.FromBase64String(content);
                    if (k.Length == 32)
                        return k;
                }
                catch { /* fall through to regeneration */ }
            }

            byte[] fresh = new byte[32];
            RandomNumberGenerator.Fill(fresh);

            Directory.CreateDirectory("cache");
            File.WriteAllText(path, Convert.ToBase64String(fresh));
            return fresh;
        }

        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrWhiteSpace(plainText))
                return plainText;

            try
            {
                int plainByteCount = Encoding.UTF8.GetMaxByteCount(plainText.Length);

                byte[] buffer = ArrayPool<byte>.Shared.Rent(NonceSize + plainByteCount + TagSize);
                byte[] plainBytes = ArrayPool<byte>.Shared.Rent(plainByteCount);
                try
                {
                    int plainLen = Encoding.UTF8.GetBytes(plainText, plainBytes);

                    Span<byte> nonce = buffer.AsSpan(0, NonceSize);
                    Span<byte> cipher = buffer.AsSpan(NonceSize, plainLen);
                    Span<byte> tag = buffer.AsSpan(NonceSize + plainLen, TagSize);

                    RandomNumberGenerator.Fill(nonce);

                    using var gcm = new AesGcm(aesKey, TagSize);
                    gcm.Encrypt(nonce, plainBytes.AsSpan(0, plainLen), cipher, tag);

                    return Convert.ToBase64String(buffer.AsSpan(0, NonceSize + plainLen + TagSize));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(plainBytes);
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch
            {
                return plainText;
            }
        }

        public static string Decrypt(ReadOnlySpan<char> cipherText)
        {
            if (cipherText.IsEmpty)
                return null;

            byte[] decoded = null;
            int decodedLen = 0;

            try
            {
                // Upper bound on decoded length for a Base64 string of length N is ~ N * 3/4.
                decoded = ArrayPool<byte>.Shared.Rent((cipherText.Length * 3 / 4) + 4);

                if (!Convert.TryFromBase64Chars(cipherText, decoded, out decodedLen))
                    return null;

                if (decodedLen < NonceSize + TagSize)
                    return null;

                int cipherLen = decodedLen - NonceSize - TagSize;

                ReadOnlySpan<byte> nonce = decoded.AsSpan(0, NonceSize);
                ReadOnlySpan<byte> cipher = decoded.AsSpan(NonceSize, cipherLen);
                ReadOnlySpan<byte> tag = decoded.AsSpan(NonceSize + cipherLen, TagSize);

                byte[] plain = ArrayPool<byte>.Shared.Rent(cipherLen);
                try
                {
                    using var gcm = new AesGcm(aesKey, TagSize);
                    gcm.Decrypt(nonce, cipher, tag, plain.AsSpan(0, cipherLen));
                    return Encoding.UTF8.GetString(plain, 0, cipherLen);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(plain);
                }
            }
            catch
            {
                // Any failure — bad Base64, wrong length, tag mismatch, key change — yields null.
                return null;
            }
            finally
            {
                if (decoded != null)
                    ArrayPool<byte>.Shared.Return(decoded);
            }
        }
    }
}
