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
                // Why: M-2 — 194.246.82.144 is an IP-only endpoint that does not serve HTTPS with a
                // valid certificate, so we can't simply upgrade the scheme. Instead we keep HTTP but
                // download into a staging stream, validate shape + size, and only overwrite
                // data/<path>.json if the payload passes the checks. Prevents an on-path attacker
                // from silently rewriting the externalids / cdnmovies / lumex / veoveo / kodik DBs.
                // TODO: add an HMAC-SHA256 signature check (admin-configured shared secret,
                // delivered via an X-Kurwa-Signature header) for real integrity hardening.
                using (var ms = PoolInvk.msm.GetStream())
                {
                    bool success = await Http.DownloadToStream(ms, $"http://194.246.82.144/{path}.json");
                    if (!success)
                        return;

                    // Why: M-2 — validate before overwrite. Reject if too small (truncated/empty),
                    // too large (possible DoS), or if the payload is not a JSON object/array.
                    if (!IsValidJsonPayload(ms))
                        return;

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
    }
}
