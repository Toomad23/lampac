using Newtonsoft.Json;
using System.Reflection;

namespace Shared.Models.Module
{
    public class RootModule
    {
        public bool enable { get; set; }

        public bool dynamic { get; set; }

        public int index { get; set; }

        public int version { get; set; }

        public string dll { get; set; }

        public string[] references { get; set; }

        // Why (FH-4): optional sha256 hex digest of mod.dll; when present it is
        // verified before Assembly.Load*. Missing = non-breaking warning only.
        public string sha256 { get; set; }

        // Why (FL-2): explicit source list replaces the .cs glob. When null we
        // fall back to the legacy top-level scan with a warning.
        public string[] sources { get; set; }

        [JsonIgnore]
        public Assembly assembly { get; set; }

        // Why (FH-3): collectible AssemblyLoadContext + weak-ref tracker the
        // host uses to Unload() and detect root leaks when the module is
        // disabled or rebuilt. Null for first-party shipped DLLs that stay in
        // AssemblyLoadContext.Default. Marked [JsonIgnore] so serialising a
        // RootModule doesn't try to traverse the ALC or WeakReference.
        [JsonIgnore]
        public ModuleLoadHandle loadHandle { get; set; }


        public string @namespace { get; set; }

        public string initspace { get; set; }

        public string middlewares { get; set; }

        public string online { get; set; }

        public string sisi { get; set; }

        public string initialization { get; set; }

        public List<JacMod> jac { get; set; } = new List<JacMod>();


        public string NamespacePath(string val)
        {
            if (version >= 3 && !string.IsNullOrEmpty(@namespace))
                return $"{@namespace}.{val}";

            return val;
        }
    }
}
