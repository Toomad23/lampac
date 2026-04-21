using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using Microsoft.CodeAnalysis.Scripting.Hosting;
using Microsoft.Extensions.DependencyModel;
using Shared.Models.Module;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

namespace Shared.Engine
{
    public static class CSharpEval
    {
        // Why (FH-5): previously an unbounded ConcurrentDictionary<string, dynamic>
        // cached every compiled script keyed only by md5(cs). Long-running hosts
        // accumulated arbitrary compiled delegates, pinning metadata and causing
        // memory growth. Bounded to 512 entries with FIFO eviction. Also made
        // non-dynamic so reflection-happy callers can be inspected.
        // Why (FH-6): the key now composes md5(cs) with globalsType.FullName and
        // T.FullName so that the same source text compiled against different
        // globals / return types cannot collide in the cache (which previously
        // produced a runtime cast when a later call reused the wrong delegate).
        const int MaxCachedScripts = 512;

        static readonly ConcurrentDictionary<string, object> scripts = new ConcurrentDictionary<string, object>();
        static readonly ConcurrentQueue<string> scriptOrder = new ConcurrentQueue<string>();
        static readonly object scriptsLock = new object();

        // Why (FL-3, FM-4): compiled scripts were invoked synchronously on request/WS threads;
        // a runaway operator script (tight loop, blocking HTTP) pinned the thread forever. Wrap
        // every invocation in a CancellationTokenSource with DefaultScriptTimeout (caller may
        // override). Pure CPU scripts cannot be interrupted cooperatively — we log and rethrow
        // so InvkEvent's catch-log layer (FL-7) records which handler misbehaved.
        static readonly TimeSpan DefaultScriptTimeout = TimeSpan.FromSeconds(30);

        static async Task<T> WithTimeoutAsync<T>(Func<Task<T>> invoke, CancellationToken externalCt, string label)
        {
            using var cts = externalCt.CanBeCanceled
                ? CancellationTokenSource.CreateLinkedTokenSource(externalCt)
                : new CancellationTokenSource();
            cts.CancelAfter(DefaultScriptTimeout);
            try
            {
                return await Task.Run(invoke, cts.Token).WaitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested && !externalCt.IsCancellationRequested)
            {
                Console.Error.WriteLine($"CSharpEval timeout after {DefaultScriptTimeout.TotalSeconds:F0}s ({label}); compiled script did not complete. Thread may still be running.");
                throw;
            }
        }

        static async Task WithTimeoutAsync(Func<Task> invoke, CancellationToken externalCt, string label)
        {
            using var cts = externalCt.CanBeCanceled
                ? CancellationTokenSource.CreateLinkedTokenSource(externalCt)
                : new CancellationTokenSource();
            cts.CancelAfter(DefaultScriptTimeout);
            try
            {
                await Task.Run(invoke, cts.Token).WaitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested && !externalCt.IsCancellationRequested)
            {
                Console.Error.WriteLine($"CSharpEval timeout after {DefaultScriptTimeout.TotalSeconds:F0}s ({label}); compiled script did not complete. Thread may still be running.");
                throw;
            }
        }

        /// <summary>Why (FL-6): invalidate the whole compile cache on config reload so edits take effect without TTL wait.</summary>
        public static void InvalidateAll()
        {
            scripts.Clear();
            while (scriptOrder.TryDequeue(out _)) { }
        }

        // Why (FL-15): salt the cache key with a per-install value derived from rootPasswd.
        // Without this, an attacker who can submit script source and observe cache behavior
        // (side-channel timing) could probe for compiled delegates across installations.
        // Pattern mirrors Shared/Engine/ProxyLink.cs — lazy init because rootPasswd is set
        // during Program.Run() after static constructors.
        static volatile string _cacheSalt;
        static string CacheSalt
        {
            get
            {
                if (_cacheSalt == null)
                    _cacheSalt = CrypTo.md5((AppInit.rootPasswd ?? "fallback") + "|csharpeval");
                return _cacheSalt;
            }
        }

        static string CacheKey(string cs, Type globalsType, Type returnType)
        {
            string g = globalsType?.FullName ?? "<null>";
            string r = returnType?.FullName ?? "<null>";
            return $"{CrypTo.md5(cs)}|{g}|{r}|{CacheSalt}";
        }

        static TDelegate GetOrAdd<TDelegate>(string key, Func<TDelegate> factory) where TDelegate : class
        {
            if (scripts.TryGetValue(key, out object existing))
                return (TDelegate)existing;

            lock (scriptsLock)
            {
                if (scripts.TryGetValue(key, out existing))
                    return (TDelegate)existing;

                TDelegate produced = factory();
                scripts[key] = produced;
                scriptOrder.Enqueue(key);

                // FIFO-style bound. Simpler than real LRU and still caps memory.
                while (scripts.Count > MaxCachedScripts && scriptOrder.TryDequeue(out string evictKey))
                {
                    if (scripts.TryRemove(evictKey, out _))
                        break;
                }

                return produced;
            }
        }

        public static PortableExecutableReference ReferenceFromFile(string dll)
        {
            if (File.Exists(dll))
                return MetadataReference.CreateFromFile(Path.Combine(AppContext.BaseDirectory, dll));

            return MetadataReference.CreateFromFile(Path.Combine(AppContext.BaseDirectory, "runtimes", "references", dll));
        }


        #region Execute<T>
        public static T Execute<T>(string cs, object model, ScriptOptions options = null, CancellationToken cancellationToken = default)
        {
            return ExecuteAsync<T>(cs, model, options, cancellationToken).GetAwaiter().GetResult();
        }

        public static Task<T> ExecuteAsync<T>(string cs, object model, ScriptOptions options = null, CancellationToken cancellationToken = default)
        {
            // Why (FH-6): key includes globalsType and T.
            string key = CacheKey(cs, model?.GetType(), typeof(T));

            var entry = GetOrAdd<ScriptRunner<T>>(key, () =>
            {
                var opts = options ?? ScriptOptions.Default;

                opts = opts.AddReferences(typeof(Console).Assembly).AddImports("System")
                           .AddReferences(typeof(HttpUtility).Assembly).AddImports("System.Web")
                           .AddReferences(typeof(Enumerable).Assembly).AddImports("System.Linq")
                           .AddReferences(typeof(List<>).Assembly).AddImports("System.Collections.Generic")
                           .AddReferences(typeof(Regex).Assembly).AddImports("System.Text.RegularExpressions");

                return CSharpScript.Create<T>(
                    cs,
                    opts,
                    globalsType: model?.GetType(),
                    assemblyLoader: new InteractiveAssemblyLoader()
                ).CreateDelegate();
            });

            // Why (FL-3, FM-4): wrap in timeout so runaway scripts can't pin the thread.
            return WithTimeoutAsync<T>(() => entry(model), cancellationToken, "ExecuteAsync<T>");
        }
        #endregion

        #region BaseExecute<T>
        public static T BaseExecute<T>(string cs, object model, ScriptOptions options = null, InteractiveAssemblyLoader loader = null, CancellationToken cancellationToken = default)
        {
            return BaseExecuteAsync<T>(cs, model, options, loader, cancellationToken).GetAwaiter().GetResult();
        }

        public static Task<T> BaseExecuteAsync<T>(string cs, object model, ScriptOptions options = null, InteractiveAssemblyLoader loader = null, CancellationToken cancellationToken = default)
        {
            // Why (FH-6): key includes globalsType + T for BaseExecute too.
            string key = CacheKey(cs, model?.GetType(), typeof(T));

            var entry = GetOrAdd<ScriptRunner<T>>(key, () =>
            {
                return CSharpScript.Create<T>(
                    cs,
                    options,
                    globalsType: model?.GetType(),
                    assemblyLoader: loader
                ).CreateDelegate();
            });

            return WithTimeoutAsync<T>(() => entry(model), cancellationToken, "BaseExecuteAsync<T>");
        }
        #endregion

        #region Execute
        public static void Execute(string cs, object model, ScriptOptions options = null, CancellationToken cancellationToken = default)
        {
            ExecuteAsync(cs, model, options, cancellationToken).GetAwaiter().GetResult();
        }

        public static Task ExecuteAsync(string cs, object model, ScriptOptions options = null, CancellationToken cancellationToken = default)
        {
            // Why (FH-6): void-return overload — use typeof(object) as the "T"
            // component of the cache key since CSharpScript.Create returns a
            // non-generic script here.
            string key = CacheKey(cs, model?.GetType(), typeof(object));

            var entry = GetOrAdd<ScriptRunner<object>>(key, () =>
            {
                var opts = options ?? ScriptOptions.Default;

                opts = opts.AddReferences(typeof(Console).Assembly).AddImports("System")
                           .AddReferences(typeof(HttpUtility).Assembly).AddImports("System.Web")
                           .AddReferences(typeof(Enumerable).Assembly).AddImports("System.Linq")
                           .AddReferences(typeof(List<>).Assembly).AddImports("System.Collections.Generic")
                           .AddReferences(typeof(Regex).Assembly).AddImports("System.Text.RegularExpressions");

                return CSharpScript.Create<object>(
                    cs,
                    opts,
                    globalsType: model?.GetType(),
                    assemblyLoader: new InteractiveAssemblyLoader()
                ).CreateDelegate();
            });

            return WithTimeoutAsync(async () => { await entry(model).ConfigureAwait(false); }, cancellationToken, "ExecuteAsync");
        }
        #endregion


        #region Compilation
        public static List<PortableExecutableReference> appReferences;
        static readonly object lockCompilationObj = new();

        public static Assembly Compilation(RootModule mod)
        {
            // Why (FH-1/FM-2): resolve the source directory safely — mod.dll may
            // contain traversal from a hostile nested manifest.
            if (string.IsNullOrWhiteSpace(mod?.dll) || Path.IsPathRooted(mod.dll) || mod.dll.Contains("..", StringComparison.Ordinal))
            {
                Console.WriteLine($"CSharpEval.Compilation: rejected mod.dll '{mod?.dll}'");
                return null;
            }

            string path = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, "module", mod.dll));
            if (!ModulePaths.IsContainedIn(path, ModulePaths.ModuleRoot))
            {
                Console.WriteLine($"CSharpEval.Compilation: resolved path escapes module root: {path}");
                return null;
            }

            if (Directory.Exists(path))
            {
                var syntaxTree = new List<SyntaxTree>();

                // Why (FL-2): prefer explicit sources array; fall back to
                // top-level glob with a warning for back-compat. Deep recursion
                // removed - previously a hostile module could drop .cs files
                // inside nested subfolders (bin/, obj/) to smuggle code past
                // filters.
                IEnumerable<string> sourceFiles;
                if (mod.sources != null && mod.sources.Length > 0)
                {
                    var list = new List<string>();
                    string pathRoot = ModulePaths.NormalizeDirectory(path);
                    foreach (string rel in mod.sources)
                    {
                        if (string.IsNullOrWhiteSpace(rel) || Path.IsPathRooted(rel) || rel.Contains("..", StringComparison.Ordinal))
                        {
                            Console.WriteLine($"CSharpEval.Compilation: rejected sources entry '{rel}' for {mod.dll}");
                            continue;
                        }
                        string full = Path.GetFullPath(Path.Combine(path, rel));
                        if (!ModulePaths.IsContainedIn(full, pathRoot) || !File.Exists(full))
                        {
                            Console.WriteLine($"CSharpEval.Compilation: sources entry '{rel}' missing or escapes module dir");
                            continue;
                        }
                        list.Add(full);
                    }
                    sourceFiles = list;
                }
                else
                {
                    Console.WriteLine($"CSharpEval.Compilation: module '{mod.dll}' has no 'sources' array; falling back to top-level *.cs glob (deprecated)");
                    sourceFiles = Directory.GetFiles(path, "*.cs", SearchOption.TopDirectoryOnly);
                }

                foreach (string file in sourceFiles)
                {
                    string _file = file.Replace("\\", "/").Replace(path.Replace("\\", "/"), "").Replace(Environment.CurrentDirectory.Replace("\\", "/"), "");
                    if (Regex.IsMatch(_file, "(\\.vs|bin|obj|Properties)/", RegexOptions.IgnoreCase))
                        continue;

                    syntaxTree.Add(CSharpSyntaxTree.ParseText(File.ReadAllText(file)));
                }

                lock (lockCompilationObj)
                {
                    if (appReferences == null)
                    {
                        var dependencyContext = DependencyContext.Default;
                        var assemblies = dependencyContext.RuntimeLibraries
                            .SelectMany(library => library.GetDefaultAssemblyNames(dependencyContext))
                            .Select(Assembly.Load)
                            .ToList();

                        appReferences = assemblies.Select(assembly => MetadataReference.CreateFromFile(assembly.Location)).ToList();
                    }

                    if (mod.references != null)
                    {
                        foreach (string refns in mod.references)
                        {
                            // Why (FM-2): centralised reference resolution with
                            // containment check under module/references/ or this
                            // module's own directory.
                            if (!ModulePaths.TryResolveReference(refns, mod.dll, out string dlrns, out string refReason))
                            {
                                Console.WriteLine($"CSharpEval.Compilation: skipping reference for {mod.dll} ({refReason})");
                                continue;
                            }

                            if (appReferences.FirstOrDefault(a => Path.GetFileName(a.FilePath) == refns) == null)
                            {
                                var assembly = Assembly.LoadFrom(dlrns);
                                appReferences.Add(MetadataReference.CreateFromFile(assembly.Location));
                            }
                        }
                    }

                    CSharpCompilation compilation = CSharpCompilation.Create(Path.GetFileName(mod.dll), syntaxTree, references: appReferences, options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

                    using (var ms = new MemoryStream())
                    {
                        var result = compilation.Emit(ms);

                        if (result.Success)
                        {
                            ms.Seek(0, SeekOrigin.Begin);

                            // Why (FH-3): load the compiled byte[] into a new
                            // collectible AssemblyLoadContext so a subsequent
                            // Compilation() for the same module can Unload the
                            // previous version. Caller is responsible for
                            // tearing down mod.loadHandle (DisposeModule does so
                            // via DisposeOne). Trade-off: if a module emits IL
                            // at runtime that requires collectible=false it will
                            // fail here - we log and the operator can pin via
                            // manifest (future 'collectible: false' flag).
                            var alc = new AssemblyLoadContext($"lampac-mod-src:{Path.GetFileName(mod.dll)}:{Guid.NewGuid():N}", isCollectible: true);
                            mod.loadHandle = new ModuleLoadHandle(alc, collectible: true);
                            ms.Seek(0, SeekOrigin.Begin);
                            return alc.LoadFromStream(ms);
                        }
                        else
                        {
                            Console.WriteLine($"\ncompilation error: {mod.dll}");
                            foreach (var diagnostic in result.Diagnostics)
                            {
                                if (diagnostic.Severity == DiagnosticSeverity.Error)
                                    Console.WriteLine(diagnostic);
                            }
                            Console.WriteLine("\n");
                        }
                    }
                }
            }

            return null;
        }
        #endregion
    }
}
