using DLNA.Controllers;
using Shared;
using Shared.Engine;
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DLNA
{
    public class ModInit
    {
        // Why: M-20 — ffmpeg commands are built by string-substituting {file}/{thumb}/{preview}
        // into a single Arguments string. The .NET CreateProcess path then re-parses that
        // string into argv by spaces and quotes, so a filename like "-filter_complex;drawtext=..."
        // or "; rm -rf" would be promoted to extra ffmpeg flags. We don't want to rewrite
        // FFmpeg.RunAsync (out of scope), so we refuse to feed ffmpeg any path whose basename
        // starts with '-' or whose full path contains characters we can't safely embed in
        // the space/quote-delimited Arguments string.
        static bool IsFfmpegPathSafe(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            // Reject argv-metacharacters and shell-metacharacters — the Arguments string is
            // parsed by CommandLineToArgvW (Windows) / a space-split (Linux) before exec,
            // and the output is also embedded into coverComand templates that users may have
            // wrapped with `sh -c` in their config. Backslash is intentionally NOT rejected:
            // Windows paths use it as the native separator.
            if (path.IndexOfAny(new[] { '"', '\'', '\n', '\r', '\t', '`', '$', '|', ';', '&', '>', '<' }) >= 0)
                return false;

            string basename = Path.GetFileName(path);
            if (string.IsNullOrEmpty(basename))
                return false;

            // A leading '-' in any path segment turns the filename into a flag.
            if (basename.StartsWith("-"))
                return false;

            foreach (string segment in path.Replace('\\', '/').Split('/'))
            {
                if (segment.StartsWith("-"))
                    return false;
            }

            return true;
        }

        public static void loaded()
        {
            DLNAController.Initialization();

            var init = AppInit.conf.dlna;
            var cover = init.cover;
            Directory.CreateDirectory($"{init.path}/temp/");

            ThreadPool.QueueUserWorkItem(async _ => 
            {
                bool? ffmpegInit = null;

                while (true)
                {
                    if (cover.timeout == -666)
                        await Task.Delay(TimeSpan.FromSeconds(5));
                    else
                        await Task.Delay(TimeSpan.FromMinutes(cover.timeout > 0 ? cover.timeout : 1));

                    if (!init.enable || !cover.enable)
                        continue;

                    if (ffmpegInit == null)
                    {
                        ffmpegInit = await FFmpeg.InitializationAsync();
                        if (ffmpegInit == false)
                            break;
                    }

                    try
                    {
                        #region path files
                        foreach (string file in Directory.GetFiles(init.path))
                        {
                            if (!Regex.IsMatch(Path.GetExtension(file), cover.extension))
                                continue;

                            string name = Path.GetFileName(file);
                            var fileinfo = new FileInfo(file);
                            if (fileinfo.Length == 0)
                                continue;

                            var time = fileinfo.CreationTime > fileinfo.LastWriteTime ? fileinfo.CreationTime : fileinfo.LastWriteTime;
                            if (time.AddMinutes(cover.skipModificationTime) > DateTime.Now)
                            {
                                log("skip time: " + file);
                                continue;
                            }

                            string thumb = Path.Combine(init.path, "thumbs", $"{CrypTo.md5(name)}.jpg");
                            if (File.Exists(thumb))
                            {
                                log("thumb ok: " + file);
                                continue;
                            }

                            string lockfile = Path.Combine(init.path, "temp", $"{CrypTo.md5(name)}-ffmpeg.lock");
                            if (File.Exists(lockfile))
                            {
                                log("lock: " + file);
                                continue;
                            }

                            File.WriteAllBytes(lockfile, Array.Empty<byte>());

                            try
                            {
                                // Why: M-20 — refuse to feed ffmpeg any path that would
                                // inject extra argv when the Arguments string is re-parsed.
                                if (!IsFfmpegPathSafe(file) || !IsFfmpegPathSafe(thumb))
                                {
                                    log("skip unsafe path: " + file);
                                    continue;
                                }

                                string coverComand = cover.coverComand.Replace("{file}", file).Replace("{thumb}", thumb);
                                log("\ncoverComand: " + coverComand);
                                var ffmpegLog = await FFmpeg.RunAsync(coverComand, priorityClass: cover.priorityClass);

                                log(ffmpegLog.outputData);
                                log(ffmpegLog.errorData);

                                if (cover.preview)
                                {
                                    string preview = Path.Combine(init.path, "temp", $"{CrypTo.md5(name)}.mp4");
                                    if (!IsFfmpegPathSafe(preview))
                                    {
                                        log("skip unsafe preview: " + preview);
                                    }
                                    else
                                    {
                                        string previewComand = cover.previewComand.Replace("{file}", file).Replace("{preview}", preview);

                                        log("\npreviewComand: " + previewComand);
                                        ffmpegLog = await FFmpeg.RunAsync(previewComand, priorityClass: cover.priorityClass);

                                        log(ffmpegLog.outputData);
                                        log(ffmpegLog.errorData);
                                    }
                                }
                            }
                            finally
                            {
                                try { if (File.Exists(lockfile)) File.Delete(lockfile); } catch { }
                            }
                        }
                        #endregion

                        #region path directories
                        foreach (string folder in Directory.GetDirectories(init.path))
                        {
                            string _fname = Path.GetFileName(folder);
                            if (_fname == "thumbs" || _fname == "tmdb" || _fname == "temp")
                                continue;

                            string folder_name = Path.GetFileName(folder);
                            string folder_thumb = Path.Combine(init.path, "thumbs", $"{CrypTo.md5(folder_name)}.jpg");
                            if (File.Exists(folder_thumb))
                            {
                                log("thumb ok: " + folder);
                                continue;
                            }

                            var files = Directory.GetFiles(folder);
                            if (files.Length == 0)
                                continue;

                            var folderinfo = new DirectoryInfo(folder);
                            var time = folderinfo.CreationTime > folderinfo.LastWriteTime ? folderinfo.CreationTime : folderinfo.LastWriteTime;
                            if (time.AddMinutes(cover.skipModificationTime) > DateTime.Now)
                            {
                                log("skip time: " + folder);
                                continue;
                            }

                            string lockfile = Path.Combine(init.path, "temp", $"{CrypTo.md5(folder_name)}-ffmpeg.lock");
                            if (File.Exists(lockfile))
                            {
                                log("lock: " + folder);
                                continue;
                            }

                            File.WriteAllBytes(lockfile, Array.Empty<byte>());

                            try
                            {
                                #region постер с превью на папку
                                {
                                    // Why: M-20 — see IsFfmpegPathSafe. Any untrusted path
                                    // element starting with '-' or containing argv/shell metacharacters
                                    // would be reparsed into extra ffmpeg flags.
                                    if (!IsFfmpegPathSafe(files[0]) || !IsFfmpegPathSafe(folder_thumb))
                                    {
                                        log("skip unsafe folder path: " + files[0]);
                                    }
                                    else
                                    {
                                        string coverComand = cover.coverComand.Replace("{file}", files[0]).Replace("{thumb}", folder_thumb);
                                        log("\ncoverComand: " + coverComand);
                                        var ffmpegLog = await FFmpeg.RunAsync(coverComand, priorityClass: cover.priorityClass);

                                        log(ffmpegLog.outputData);
                                        log(ffmpegLog.errorData);

                                        if (cover.preview)
                                        {
                                            string preview = Path.Combine(init.path, "temp", $"{CrypTo.md5(folder_name)}.mp4");
                                            if (!IsFfmpegPathSafe(preview))
                                            {
                                                log("skip unsafe preview: " + preview);
                                            }
                                            else
                                            {
                                                string previewComand = cover.previewComand.Replace("{file}", files[0]).Replace("{preview}", preview);

                                                log("\npreviewComand: " + previewComand);
                                                ffmpegLog = await FFmpeg.RunAsync(previewComand, priorityClass: cover.priorityClass);

                                                log(ffmpegLog.outputData);
                                                log(ffmpegLog.errorData);
                                            }
                                        }
                                    }
                                }
                                #endregion

                                #region постеры на файлы внутри папки
                                foreach (string file in files)
                                {
                                    string name = $"{Path.GetFileName(folder)}/{Path.GetFileName(file)}";
                                    string thumb = Path.Combine(init.path, "thumbs", $"{CrypTo.md5(name)}.jpg");

                                    // Why: M-20 — see IsFfmpegPathSafe.
                                    if (!IsFfmpegPathSafe(file) || !IsFfmpegPathSafe(thumb))
                                    {
                                        log("skip unsafe path: " + file);
                                        continue;
                                    }

                                    string coverComand = cover.coverComand.Replace("{file}", file).Replace("{thumb}", thumb);
                                    log("\ncoverComand: " + coverComand);
                                    var ffmpegLog = await FFmpeg.RunAsync(coverComand, priorityClass: cover.priorityClass);

                                    log(ffmpegLog.outputData);
                                    log(ffmpegLog.errorData);
                                }
                                #endregion
                            }
                            finally
                            {
                                try { if (File.Exists(lockfile)) File.Delete(lockfile); } catch { }
                            }
                        }
                        #endregion
                    }
                    catch { }
                }

            });
        }


        public static void log(string value)
        {
            if (AppInit.conf.dlna.cover.consoleLog && !string.IsNullOrEmpty(value))
                Console.WriteLine("\nFFmpeg: " + value);
        }
    }
}
