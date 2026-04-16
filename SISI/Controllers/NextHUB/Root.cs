using Microsoft.CodeAnalysis.Scripting;
using YamlDotNet.Serialization;
using Shared.Models.SISI.NextHUB;

namespace SISI.Controllers.NextHUB
{
    public static class Root
    {
        #region SafeReadUnder
        // Why (FL-8): YAML-supplied relative paths (init.view.eval, init.view.routeEval,
        // list.eval, view.include: tokens) used to be concatenated straight into File.ReadAllText
        // under NextHUB/sites/ or NextHUB/utils/. A malicious or sloppy YAML with
        // `eval: ../../etc/passwd.cs` would read arbitrary files. Every NextHUB path reader now
        // funnels through this helper, which enforces containment after resolution (following
        // the Microsoft recommendation: Path.GetFullPath both sides, compare with a trailing
        // separator so sibling directories like `NextHUB/sites-backup/` don't match).
        public static string SafeReadUnder(string baseDir, string relative)
        {
            if (string.IsNullOrEmpty(relative))
                return null;

            // Cheap pre-check: reject segment separators and traversal tokens outright.
            if (relative.IndexOfAny(new[] { '\0' }) >= 0)
                return null;
            if (relative.Contains(".."))
                return null;

            try
            {
                string full = Path.GetFullPath(Path.Combine(baseDir, relative));
                string baseFull = Path.GetFullPath(baseDir);

                if (!full.StartsWith(baseFull + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                    && !string.Equals(full, baseFull, StringComparison.Ordinal))
                {
                    Console.Error.WriteLine($"NextHUB path escape blocked: base='{baseDir}' rel='{relative}'");
                    return null;
                }

                if (!File.Exists(full))
                    return null;

                return FileCache.ReadAllText(full);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"NextHUB SafeReadUnder: {ex.GetType().Name}");
                return null;
            }
        }
        #endregion

        #region evalOptionsFull
        public static ScriptOptions evalOptionsFull = ScriptOptions.Default

            .AddReferences(CSharpEval.ReferenceFromFile("Microsoft.Playwright.dll"))
            .AddImports("Microsoft.Playwright")

            .AddReferences(CSharpEval.ReferenceFromFile("Shared.dll"))
            .AddImports("Shared.PlaywrightCore")
            .AddImports("Shared.Engine")
            .AddImports("Shared.Models.SISI.Base")
            .AddImports("Shared.Models.SISI")

            .AddReferences(CSharpEval.ReferenceFromFile("Newtonsoft.Json.dll"))
            .AddImports("Newtonsoft.Json")
            .AddImports("Newtonsoft.Json.Linq");
        #endregion

        public static NxtSettings goInit(string plugin)
        {
            if (string.IsNullOrEmpty(plugin))
                return null;

            plugin = Regex.Replace(plugin, "[^a-z0-9\\-]+", "", RegexOptions.IgnoreCase);

            if (AppInit.conf.sisi.NextHUB_sites_enabled != null && !AppInit.conf.sisi.NextHUB_sites_enabled.Contains(plugin))
                return null;

            if (!File.Exists($"NextHUB/sites/{plugin}.yaml"))
                return null;

            var hybridCache = IHybridCache.Get(null);

            string memKey = $"NextHUB:goInit:{plugin}";
            if (!hybridCache.TryGetValue(memKey, out NxtSettings init))
            {
                try
                {
                    var deserializer = new DeserializerBuilder().Build();

                    // Чтение основного YAML-файла
                    string yaml = File.ReadAllText($"NextHUB/sites/{plugin}.yaml");
                    var target = deserializer.Deserialize<Dictionary<object, object>>(yaml);

                    foreach (string y in new string[] { "_", plugin })
                    {
                        if (File.Exists($"NextHUB/override/{y}.yaml"))
                        {
                            // Чтение пользовательского YAML-файла
                            string myYaml = File.ReadAllText($"NextHUB/override/{y}.yaml");
                            var mySource = deserializer.Deserialize<Dictionary<object, object>>(myYaml);

                            // Объединение словарей
                            foreach (var property in mySource)
                            {
                                if (!target.ContainsKey(property.Key))
                                {
                                    target[property.Key] = property.Value;
                                    continue;
                                }

                                if (property.Value is IDictionary<object, object> sourceDict &&
                                    target[property.Key] is IDictionary<object, object> targetDict)
                                {
                                    // Рекурсивное объединение вложенных словарей
                                    foreach (var item in sourceDict)
                                        targetDict[item.Key] = item.Value;
                                }
                                else
                                {
                                    target[property.Key] = property.Value;
                                }
                            }
                        }
                    }

                    // Преобразование словаря в объект NxtSettings
                    var serializer = new SerializerBuilder().Build();

                    var yamlResult = serializer.Serialize(target);
                    init = deserializer.Deserialize<NxtSettings>(yamlResult);

                    if (string.IsNullOrEmpty(init.plugin))
                        init.plugin = init.displayname;

                    if (!init.debug)
                    {
                        init = ModuleInvoke.Init(plugin, init);
                        hybridCache.Set(memKey, init, DateTime.Now.AddMinutes(1), inmemory: true);
                    }
                }
                catch (Exception ex)
                {
                    // Why (FL-9): previously we cached the *empty* NxtSettings for 60 seconds
                    // on any error. That turned transient parse failures (half-written YAML,
                    // race with a file save) into a full minute of silent breakage, and an
                    // attacker editing a YAML to make it invalid would lock out the plugin.
                    // Short negative cache (5s) so admins see the error immediately on the
                    // next request, plus a "broken" marker so repeated failures are obvious.
                    Console.Error.WriteLine($"NxtSettings goInit [{plugin}] broken: {ex.GetType().Name}: {ex.Message}");

                    init = new NxtSettings { plugin = plugin, displayname = "[broken]" };
                    hybridCache.Set(memKey, init, DateTime.Now.AddSeconds(5), inmemory: true);
                }
            }

            return init;
        }
    }
}
