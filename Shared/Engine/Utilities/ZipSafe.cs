using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Shared.Engine.Utilities
{
    // Why (supply-chain): every site that extracts a remote zip is a zip-slip
    // candidate because ZipArchiveEntry.FullName can contain "../" or absolute
    // paths that escape the destination directory. This helper centralises the
    // path-containment check so the same rule is applied everywhere and defense
    // in depth (absolute-path reject, ".."-segment reject, post-normalize
    // prefix-match) stays in sync across callers.
    public static class ZipSafe
    {
        public static void ExtractToDirectory(string zipPath, string destinationDir, bool overwriteFiles = true)
        {
            if (string.IsNullOrWhiteSpace(zipPath))
                throw new ArgumentException("zipPath is empty", nameof(zipPath));
            if (string.IsNullOrWhiteSpace(destinationDir))
                throw new ArgumentException("destinationDir is empty", nameof(destinationDir));

            Directory.CreateDirectory(destinationDir);

            string destRoot = Path.GetFullPath(destinationDir);
            char sep = Path.DirectorySeparatorChar;
            string destRootPrefix = destRoot.EndsWith(sep) ? destRoot : destRoot + sep;

            using var archive = ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                string rawName = entry.FullName;
                if (string.IsNullOrEmpty(rawName))
                    continue;

                if (Path.IsPathRooted(rawName))
                    throw new InvalidDataException($"zip-slip: entry has absolute path '{rawName}'");

                // Reject traversal segments pre-normalization as an extra guard
                // against edge cases where Path.GetFullPath might collapse to a
                // still-contained path on some runtimes.
                string normalizedForCheck = rawName.Replace('\\', '/');
                foreach (var seg in normalizedForCheck.Split('/', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (seg == "..")
                        throw new InvalidDataException($"zip-slip: entry contains '..' segment '{rawName}'");
                }

                string targetFullPath = Path.GetFullPath(Path.Combine(destRoot, rawName));
                if (!targetFullPath.StartsWith(destRootPrefix, StringComparison.Ordinal) &&
                    !string.Equals(targetFullPath, destRoot, StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"zip-slip: entry '{rawName}' resolves outside destination ({targetFullPath})");
                }

                // Directory entry (trailing slash or empty Name)
                if (string.IsNullOrEmpty(entry.Name))
                {
                    Directory.CreateDirectory(targetFullPath);
                    continue;
                }

                string parent = Path.GetDirectoryName(targetFullPath);
                if (!string.IsNullOrEmpty(parent))
                    Directory.CreateDirectory(parent);

                entry.ExtractToFile(targetFullPath, overwriteFiles);
            }
        }

        public static string ComputeSha256Hex(byte[] data)
        {
            if (data == null)
                return null;

            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(data));
        }

        public static string ComputeSha256Hex(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return null;

            using var fs = File.OpenRead(filePath);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs));
        }
    }
}
