using Shared;
using Shared.Engine;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Lampac.Engine.CRON
{
    public static class KurwaCron
    {
        public static void Run()
        {
            _cronTimer = new Timer(cron, null, TimeSpan.FromMinutes(20), TimeSpan.FromHours(5));
        }

        static Timer _cronTimer;

        static bool _cronWork = false;

        static DateTime _lastMissingKeyWarn = DateTime.MinValue;

        async static void cron(object state)
        {
            if (_cronWork)
                return;

            _cronWork = true;

            try
            {
                await DownloadBigJson("externalids");
                await DownloadBigJson("cdnmovies");
                await DownloadBigJson("lumex");
                await DownloadBigJson("veoveo");
                await DownloadBigJson("kodik");
            }
            finally
            {
                _cronWork = false;
            }
        }

        async static Task DownloadBigJson(string path)
        {
            try
            {
                // Why: M-2 + auth-gate — KurwaCron overwrites live data/*.json files that the
                // server then consumes, so a MITM-rewritten payload is effectively RCE-adjacent.
                // Gates (fail-closed):
                //   1. HTTPS only — upstream IP must serve HTTPS; plain HTTP is no longer accepted.
                //   2. HMAC-SHA256 sidecar at ${url}.sig (hex, single-line) verified with
                //      AppInit.conf.kurwa.hmacKey (hex or base64). Missing key => skip + warn.
                //   3. Existing shape / size checks kept as second-line defence.
                byte[] hmacKey = ParseHmacKey(AppInit.conf?.kurwa?.hmacKey);
                if (hmacKey == null)
                {
                    var now = DateTime.UtcNow;
                    if (now - _lastMissingKeyWarn > TimeSpan.FromHours(1))
                    {
                        _lastMissingKeyWarn = now;
                        Console.Error.WriteLine("[KurwaCron] AppInit.conf.kurwa.hmacKey is not configured (hex or base64). Skipping all updates — this cron writes data/*.json which is RCE-adjacent, so we fail closed.");
                    }
                    return;
                }

                string url = $"https://194.246.82.144/{path}.json";

                using (var ms = PoolInvk.msm.GetStream())
                {
                    bool success = await Http.DownloadToStream(ms, url);
                    if (!success)
                    {
                        Console.Error.WriteLine($"[KurwaCron] HTTPS download failed for {url}. Skipping (fail-closed, was previously plain HTTP).");
                        return;
                    }

                    // Why: M-2 — validate before overwrite. Reject if too small (truncated/empty),
                    // too large (possible DoS), or if the payload is not a JSON object/array.
                    if (!IsValidJsonPayload(ms))
                        return;

                    string sigHex = await Http.Get(url + ".sig", timeoutSeconds: 15, statusCodeOK: true, weblog: false);
                    byte[] expected = ParseSignature(sigHex);
                    if (expected == null)
                    {
                        Console.Error.WriteLine($"[KurwaCron] signature sidecar missing/malformed at {url}.sig. Aborting apply, keeping previous data/{path}.json.");
                        return;
                    }

                    byte[] computed = ComputeHmacStreaming(ms, hmacKey);
                    if (computed == null || computed.Length != expected.Length ||
                        !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(computed, expected))
                    {
                        Console.Error.WriteLine($"[KurwaCron] HMAC verify FAILED for {url}. Aborting apply, keeping previous data/{path}.json.");
                        return;
                    }

                    // Write through a temp file and atomically move, so a failed/partial write
                    // cannot leave data/<path>.json corrupted. Keeps the previous good file if
                    // anything below throws.
                    string destination = $"data/{path}.json";
                    string tempPath = destination + ".tmp";

                    ms.Position = 0;
                    try
                    {
                        using (var fileStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, PoolInvk.bufferSize))
                            await ms.CopyToAsync(fileStream, PoolInvk.bufferSize);

                        var fi = new FileInfo(tempPath);
                        if (fi.Length < 16 || fi.Length > 512L * 1024 * 1024)
                        {
                            File.Delete(tempPath);
                            return;
                        }

                        File.Move(tempPath, destination, overwrite: true);
                    }
                    catch
                    {
                        try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
                    }
                }
            }
            catch { }
        }

        // Why: M-2 — lightweight sanity check on the downloaded stream before we let it
        // replace a live data file. We require: non-trivial length, upper bound to avoid DoS,
        // and a leading byte that matches a JSON container ('{' or '['), ignoring BOM / whitespace.
        // This rejects HTML redirect/captcha pages and truncated/garbage payloads without
        // paying the cost of full JSON parsing.
        static bool IsValidJsonPayload(Stream ms)
        {
            if (ms.Length < 16 || ms.Length > 512L * 1024 * 1024)
                return false;

            long savedPos = ms.Position;
            try
            {
                ms.Position = 0;
                // Peek up to first 16 bytes to skip BOM / whitespace.
                Span<byte> buf = stackalloc byte[16];
                int read = ms.Read(buf);
                if (read <= 0)
                    return false;

                int i = 0;
                // Skip UTF-8 BOM if present.
                if (read >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF)
                    i = 3;

                // Skip ASCII whitespace.
                while (i < read && (buf[i] == (byte)' ' || buf[i] == (byte)'\t' || buf[i] == (byte)'\r' || buf[i] == (byte)'\n'))
                    i++;

                if (i >= read)
                    return false;

                return buf[i] == (byte)'{' || buf[i] == (byte)'[';
            }
            finally
            {
                ms.Position = savedPos;
            }
        }

        static byte[] ParseHmacKey(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            string trimmed = raw.Trim();

            try { return Convert.FromHexString(trimmed); } catch { }

            try
            {
                byte[] b = Convert.FromBase64String(trimmed);
                if (b.Length > 0)
                    return b;
            }
            catch { }

            return null;
        }

        static byte[] ParseSignature(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            string trimmed = raw.Trim();
            int nl = trimmed.IndexOfAny(new[] { '\r', '\n', ' ', '\t' });
            if (nl >= 0)
                trimmed = trimmed.Substring(0, nl).Trim();

            try { return Convert.FromHexString(trimmed); } catch { }

            try { return Convert.FromBase64String(trimmed); } catch { }

            return null;
        }

        static byte[] ComputeHmacStreaming(Stream ms, byte[] key)
        {
            try
            {
                ms.Position = 0;
                using (var hasher = System.Security.Cryptography.IncrementalHash.CreateHMAC(System.Security.Cryptography.HashAlgorithmName.SHA256, key))
                {
                    byte[] buf = System.Buffers.ArrayPool<byte>.Shared.Rent(64 * 1024);
                    try
                    {
                        int n;
                        while ((n = ms.Read(buf, 0, buf.Length)) > 0)
                            hasher.AppendData(buf, 0, n);

                        return hasher.GetHashAndReset();
                    }
                    finally
                    {
                        System.Buffers.ArrayPool<byte>.Shared.Return(buf);
                    }
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
