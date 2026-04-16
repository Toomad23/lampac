using System.IO.Compression;
using System.Text;

namespace Shared.Engine
{
    public static class BrotliTo
    {
        static readonly object lockObj = new object();

        // Why (L-7): Brotli decompression into an unbounded MemoryStream lets a
        // malicious/corrupted payload inflate until the process is OOM-killed. 64 MB is well
        // above any legitimate metadata/JSON blob this project caches and keeps the decompress
        // path bounded. If a caller ever legitimately needs a bigger payload we can add a
        // per-call override; for now all callers are internal and tolerate this cap.
        const long _maxDecompressedBytes = 64L * 1024 * 1024;

        // Why (L-7): size-bounded CopyTo replacement. Reads in chunks and throws as soon as the
        // destination would exceed `maxBytes`, instead of happily growing the output buffer.
        static void BoundedCopyTo(Stream source, Stream destination, long maxBytes)
        {
            byte[] buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    throw new InvalidDataException($"Brotli payload exceeds {maxBytes} byte cap (decompression bomb guard).");
                destination.Write(buffer, 0, read);
            }
        }

        static async Task BoundedCopyToAsync(Stream source, Stream destination, long maxBytes)
        {
            byte[] buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    throw new InvalidDataException($"Brotli payload exceeds {maxBytes} byte cap (decompression bomb guard).");
                await destination.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
            }
        }


        #region Compress byte[]
        public static byte[] Compress(string value)
        {
            return Compress(Encoding.UTF8.GetBytes(value));
        }

        public static byte[] Compress(in byte[] value)
        {
            try
            {
                using (var input = new MemoryStream(value))
                {
                    using (var output = new MemoryStream())
                    {
                        try
                        {
                            using (var stream = new BrotliStream(output, CompressionLevel.Fastest))
                                input.CopyTo(stream);

                            return output.ToArray();
                        }
                        catch { return null; }
                    }
                }
            }
            catch { return null; }
        }
        #endregion

        #region Compress file
        public static void Compress(string outfile, string value)
        {
            Compress(outfile, Encoding.UTF8.GetBytes(value));
        }

        public static void Compress(string outfile, in byte[] value)
        {
            try
            {
                lock (lockObj)
                {
                    using (var input = new MemoryStream(value))
                    {
                        using (var output = new FileStream(outfile, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            try
                            {
                                using (var stream = new BrotliStream(output, CompressionLevel.Fastest))
                                    input.CopyTo(stream);
                            }
                            catch { }
                        }
                    }
                }
            }
            catch { }
        }
        #endregion

        #region CompressAsync file
        public static Task CompressAsync(string outfile, string value)
        {
            return CompressAsync(outfile, Encoding.UTF8.GetBytes(value));
        }

        async public static Task CompressAsync(string outfile, byte[] value)
        {
            try
            {
                var semaphore = new SemaphorManager(outfile, TimeSpan.FromSeconds(15));

                await semaphore.Invoke(async () =>
                {
                    using (var input = new MemoryStream(value))
                    {
                        using (var output = new FileStream(outfile, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            try
                            {
                                using (var stream = new BrotliStream(output, CompressionLevel.Fastest))
                                    await input.CopyToAsync(stream);
                            }
                            catch { }
                        }
                    }
                });
            }
            catch { }
        }

        async public static Task CompressAsync(string outfile, MemoryStream value)
        {
            try
            {
                var semaphore = new SemaphorManager(outfile, TimeSpan.FromSeconds(15));

                await semaphore.Invoke(async () =>
                {
                    using (var output = new FileStream(outfile, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        try
                        {
                            using (var stream = new BrotliStream(output, CompressionLevel.Fastest))
                                await value.CopyToAsync(stream);
                        }
                        catch { }
                    }
                });
            }
            catch { }
        }
        #endregion

        #region Decompress byte[] 
        public static string Decompress(in byte[] value)
        {
            try
            {
                using (var input = new MemoryStream(value))
                {
                    using (var output = new MemoryStream())
                    {
                        try
                        {
                            using (var stream = new BrotliStream(input, CompressionMode.Decompress))
                                stream.CopyTo(output);

                            return Encoding.UTF8.GetString(output.ToArray());
                        }
                        catch { return null; }
                    }
                }
            }
            catch { return null; }
        }
        #endregion

        #region Decompress file
        public static string Decompress(string infile)
        {
            try
            {
                byte[] array = DecompressArray(infile);
                if (array == null)
                    return null;

                return Encoding.UTF8.GetString(array);
            }
            catch { return null; }
        }

        public static byte[] DecompressArray(string infile)
        {
            try
            {
                lock (lockObj)
                {
                    using (var input = new FileStream(infile, FileMode.Open, FileAccess.Read))
                    {
                        using (var output = new MemoryStream())
                        {
                            try
                            {
                                using (var stream = new BrotliStream(input, CompressionMode.Decompress))
                                    // Why (L-7): bounded copy — previously an unbounded CopyTo
                                    // would happily inflate a malicious Brotli blob until OOM.
                                    BoundedCopyTo(stream, output, _maxDecompressedBytes);

                                return output.ToArray();
                            }
                            catch { return null; }
                        }
                    }
                }
            }
            catch { return null; }
        }
        #endregion

        #region DecompressAsync file
        async public static Task<string> DecompressAsync(string infile)
        {
            try
            {
                byte[] array = await DecompressArrayAsync(infile);
                if (array == null)
                    return null;

                return Encoding.UTF8.GetString(array);
            }
            catch { return null; }
        }

        public static Task<byte[]> DecompressArrayAsync(string infile)
        {
            try
            {
                var semaphore = new SemaphorManager(infile, TimeSpan.FromSeconds(20));

                return semaphore.Invoke(async () =>
                {
                    using (var input = new FileStream(infile, FileMode.Open, FileAccess.Read))
                    {
                        using (var output = new MemoryStream())
                        {
                            try
                            {
                                using (var stream = new BrotliStream(input, CompressionMode.Decompress))
                                    // Why (L-7): mirrors the sync path — cap decompressed size
                                    // to guard against brotli-bomb inputs.
                                    await BoundedCopyToAsync(stream, output, _maxDecompressedBytes);

                                return output.ToArray();
                            }
                            catch { return null; }
                        }
                    }
                });
            }
            catch { return null; }
        }
        #endregion
    }
}
