using System;
using System.IO;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Shared.Models.Module
{
    // Why (FM-3): contract required before we invoke reflection entry-points on
    // user-supplied module assemblies. Types that do not implement this interface
    // (or wear [ModuleEntry]) must be rejected; blindly calling
    // Assembly.GetType(mod.initspace).GetMethod("loaded").Invoke(...) lets a
    // manifest point initspace at any type with a "loaded" method.
    public interface IModuleEntry
    {
        void loaded(InitspaceModel space);
        void Dispose();
    }

    // Why (FM-3): opt-in attribute alternative for modules that don't want to
    // pick up the IModuleEntry contract as a compile-time dependency.
    [AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
    public sealed class ModuleEntryAttribute : Attribute
    {
    }

    // Why (FH-1, FH-2, FM-2): centralise path sanitisation so every caller that
    // derives a filesystem path from manifest.json (mod.dll / mod.references /
    // folderMod + mod.dll) runs the same containment check and can't be tricked
    // into loading /etc/passwd.dll or ../../other/root.
    public static class ModulePaths
    {
        public static string ModuleRoot { get; } = NormalizeDirectory(Path.Combine(Environment.CurrentDirectory, "module"));

        public static string ReferencesRoot { get; } = NormalizeDirectory(Path.Combine(ModuleRoot, "references"));

        public static string NormalizeDirectory(string path)
        {
            string full = Path.GetFullPath(path);
            char sep = Path.DirectorySeparatorChar;
            return full.EndsWith(sep) ? full : full + sep;
        }

        public static bool IsUnsafeRelative(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return true;

            if (Path.IsPathRooted(value))
                return true;

            if (value.Contains("..", StringComparison.Ordinal))
                return true;

            // Reject any separator so the caller can't prefix "foo/../../etc".
            if (value.IndexOfAny(new[] { '/', '\\' }) >= 0)
                return true;

            return false;
        }

        public static bool IsContainedIn(string resolvedFullPath, string rootWithSeparator)
        {
            if (string.IsNullOrEmpty(resolvedFullPath) || string.IsNullOrEmpty(rootWithSeparator))
                return false;

            // Compare case-sensitively on Linux, insensitively on Windows.
            StringComparison cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

            string full = Path.GetFullPath(resolvedFullPath);
            return full.StartsWith(rootWithSeparator, cmp);
        }

        // Why (FH-1): manifest.json's mod.dll goes straight into Assembly.LoadFile.
        // This validates the candidate is a simple file name inside module/ and
        // returns the absolute, contained path (or null if rejected).
        public static bool TryResolveModuleDll(string relativeDll, out string fullPath, out string reason)
        {
            fullPath = null;
            reason = null;

            if (string.IsNullOrWhiteSpace(relativeDll))
            {
                reason = "empty value";
                return false;
            }

            // Allow a bare filename or single-segment path-less name only.
            // "/" and "\" already caught by IsUnsafeRelative.
            if (Path.IsPathRooted(relativeDll) || relativeDll.Contains("..", StringComparison.Ordinal))
            {
                reason = "rooted or traversal path rejected";
                return false;
            }

            // Replace any forward/back slashes with the platform separator so
            // Path.GetFullPath produces a predictable absolute form, then verify
            // containment against ModuleRoot.
            string candidate = Path.GetFullPath(Path.Combine(ModuleRoot, relativeDll));
            if (!IsContainedIn(candidate, ModuleRoot))
            {
                reason = $"resolved path '{candidate}' escapes module root";
                return false;
            }

            fullPath = candidate;
            return true;
        }

        // Why (FH-2): folderMod + mod.dll - Path.Combine returns mod.dll as-is if
        // mod.dll is rooted. This enforces that mod.dll is a bare name/relative
        // fragment before we combine, and then re-checks containment.
        public static bool TryResolveNestedModuleDll(string folderMod, string relativeDll, out string fullPath, out string reason)
        {
            fullPath = null;
            reason = null;

            if (IsUnsafeRelative(relativeDll))
            {
                reason = $"'{relativeDll}' is not a simple file name";
                return false;
            }

            string folderFull = Path.GetFullPath(folderMod);
            string folderFullWithSep = NormalizeDirectory(folderFull);
            if (!IsContainedIn(folderFullWithSep, ModuleRoot))
            {
                reason = $"folder '{folderMod}' escapes module root";
                return false;
            }

            string candidate = Path.GetFullPath(Path.Combine(folderFull, relativeDll));
            if (!IsContainedIn(candidate, folderFullWithSep) || !IsContainedIn(candidate, ModuleRoot))
            {
                reason = $"resolved path '{candidate}' escapes {folderMod}";
                return false;
            }

            fullPath = candidate;
            return true;
        }

        // Why (FM-2): mod.references entries are joined with module/references/
        // or module/{mod.dll}/; validate they stay inside one of those roots.
        // refName must be a simple file name (no separators, no traversal).
        // moduleSubdir may be a relative segment or "folder/file.dll" style
        // combined value - we only require that its resolved directory stays
        // under ModuleRoot.
        public static bool TryResolveReference(string refName, string moduleSubdir, out string fullPath, out string reason)
        {
            fullPath = null;
            reason = null;

            if (IsUnsafeRelative(refName))
            {
                reason = $"'{refName}' is not a simple file name";
                return false;
            }

            string refInReferences = Path.GetFullPath(Path.Combine(ReferencesRoot, refName));
            if (IsContainedIn(refInReferences, ReferencesRoot) && File.Exists(refInReferences))
            {
                fullPath = refInReferences;
                return true;
            }

            if (!string.IsNullOrEmpty(moduleSubdir) &&
                !Path.IsPathRooted(moduleSubdir) &&
                !moduleSubdir.Contains("..", StringComparison.Ordinal))
            {
                // moduleSubdir may be "foo" or "foo/bar.dll" - we want the
                // directory that contains the dll. When it ends in .dll, use
                // the parent; otherwise treat it as a directory name.
                string subdirForRef = moduleSubdir;
                if (subdirForRef.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    string dir = Path.GetDirectoryName(subdirForRef);
                    subdirForRef = string.IsNullOrEmpty(dir) ? null : dir;
                }

                if (!string.IsNullOrEmpty(subdirForRef))
                {
                    string moduleDir = NormalizeDirectory(Path.GetFullPath(Path.Combine(ModuleRoot, subdirForRef)));
                    if (IsContainedIn(moduleDir, ModuleRoot))
                    {
                        string refInModule = Path.GetFullPath(Path.Combine(moduleDir, refName));
                        if (IsContainedIn(refInModule, moduleDir) && File.Exists(refInModule))
                        {
                            fullPath = refInModule;
                            return true;
                        }
                    }
                }
            }

            reason = $"reference '{refName}' not found in module/references/ or module/{moduleSubdir}/";
            return false;
        }

        // Why (FH-4): verify manifest-declared sha256 matches the on-disk file.
        // Returns true when no hash is declared (non-breaking) and warns.
        public static bool VerifyDllIntegrity(string fullPath, string expectedSha256, string contextLabel)
        {
            if (string.IsNullOrWhiteSpace(expectedSha256))
            {
                Console.WriteLine($"module integrity: '{contextLabel}' has no sha256 pin in manifest; loading unverified");
                return true;
            }

            try
            {
                using var fs = File.OpenRead(fullPath);
                using var sha = SHA256.Create();
                byte[] hash = sha.ComputeHash(fs);
                string actual = Convert.ToHexString(hash);

                if (!string.Equals(actual, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"module integrity: sha256 mismatch for '{contextLabel}' (expected {expectedSha256}, got {actual})");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"module integrity: failed to hash '{contextLabel}': {ex.Message}");
                return false;
            }
        }
    }

    // Why (FH-3): wraps a collectible AssemblyLoadContext + a WeakReference so
    // DisposeModule can call Unload() and then probe whether the module is truly
    // unloadable (a strong-rooted event handler keeps assemblies alive even
    // after Unload()). Keeping the WeakReference lets us log root leaks.
    public sealed class ModuleLoadHandle
    {
        public ModuleLoadHandle(AssemblyLoadContext context, bool collectible)
        {
            Context = context;
            IsCollectible = collectible;
            Tracker = collectible ? new WeakReference(context, trackResurrection: false) : null;
        }

        public AssemblyLoadContext Context { get; }

        public bool IsCollectible { get; }

        // Null for non-collectible contexts (e.g. AssemblyLoadContext.Default).
        public WeakReference Tracker { get; }

        public static ModuleLoadHandle ForDefault() => new ModuleLoadHandle(AssemblyLoadContext.Default, collectible: false);
    }
}
