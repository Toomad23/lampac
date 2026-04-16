using Jackett;
using JacRed.Models.Sync;

namespace JacRed.Engine
{
    public static class SyncCron
    {
        static long lastsync = -1;

        // Why: bounds applied to admin-configured Red.syncapi payloads. A compromised/misconfigured
        // mirror could otherwise poison FileDB or OOM via oversized strings/counts. Values are generous
        // relative to real-world torrent metadata.
        const int MaxTitleLength = 1024;
        const int MaxMagnetLength = 4096;
        const int MaxTorrentsPerSync = 200_000;
        static readonly Regex magnetShape = new Regex("^magnet:\\?", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));

        async public static Task Run()
        {
            bool reset = true;
            await Task.Delay(TimeSpan.FromMinutes(2));

            DateTime lastSave = DateTime.Now;

            while (true)
            {
                try
                {
                    if (File.Exists(@"C:\ProgramData\lampac\disablesync"))
                        break;

                    if (ModInit.conf.typesearch == "red" && !string.IsNullOrWhiteSpace(ModInit.conf.Red.syncapi))
                    {
                        if (lastsync == -1 && File.Exists("cache/jacred/lastsync.txt"))
                            lastsync = long.Parse(File.ReadAllText("cache/jacred/lastsync.txt"));

                        // Why: lowered from 100 MB to 32 MB — real FDB deltas are far smaller and an unbounded
                        // buffer on an admin-configured remote endpoint is an OOM vector on a compromised mirror.
                        var root = await Http.Get<RootObject>($"{ModInit.conf.Red.syncapi}/sync/fdb/torrents?time={lastsync}", timeoutSeconds: 300, MaxResponseContentBufferSize: 32_000_000, weblog: false);

                        if (root?.collections == null)
                        {
                            if (reset)
                            {
                                reset = false;
                                await Task.Delay(TimeSpan.FromMinutes(1));
                                continue;
                            }
                        }
                        else if (root.collections.Count > 0)
                        {
                            reset = true;
                            int totalImported = 0;
                            foreach (var collection in root.collections)
                            {
                                bool updateMasterDb = false;

                                using (var fdb = FileDB.Open(collection.Key, empty: true))
                                {
                                    if (collection.Value?.torrents == null)
                                        continue;

                                    foreach (var torrent in collection.Value.torrents)
                                    {
                                        if (torrent.Value == null || torrent.Value.types == null || torrent.Value.types.Contains("sport"))
                                            continue;

                                        // Why: validate each entry before it reaches FileDB. A compromised syncapi could
                                        // otherwise plant oversized/malformed records that break downstream parsing or bloat
                                        // memory. Drop invalid entries, keep the rest.
                                        var t = torrent.Value;
                                        if (string.IsNullOrWhiteSpace(t.magnet) || t.magnet.Length > MaxMagnetLength || !magnetShape.IsMatch(t.magnet))
                                            continue;
                                        if (t.title != null && t.title.Length > MaxTitleLength)
                                            continue;
                                        if (t.name != null && t.name.Length > MaxTitleLength)
                                            continue;
                                        if (t.originalname != null && t.originalname.Length > MaxTitleLength)
                                            continue;
                                        if (totalImported++ >= MaxTorrentsPerSync)
                                            break;

                                        fdb.Database.AddOrUpdate(torrent.Key, t, (k, v) => t);
                                        updateMasterDb = true;
                                    }
                                }

                                if (totalImported >= MaxTorrentsPerSync)
                                {
                                    Console.WriteLine($"JacRed/SyncCron: reached MaxTorrentsPerSync={MaxTorrentsPerSync}, truncating this batch");
                                    break;
                                }

                                if (updateMasterDb)
                                {
                                    if (FileDB.masterDb.ContainsKey(collection.Key))
                                    {
                                        FileDB.masterDb[collection.Key] = collection.Value.time;
                                    }
                                    else
                                    {
                                        FileDB.masterDb.TryAdd(collection.Key, collection.Value.time);
                                    }
                                }
                            }

                            lastsync = root.collections.Last().Value.fileTime;

                            if (root.nextread)
                            {
                                if (DateTime.Now > lastSave.AddMinutes(5))
                                {
                                    lastSave = DateTime.Now;
                                    FileDB.SaveChangesToFile();
                                    File.WriteAllText("cache/jacred/lastsync.txt", lastsync.ToString());
                                }

                                continue;
                            }
                        }

                        FileDB.SaveChangesToFile();
                        File.WriteAllText("cache/jacred/lastsync.txt", lastsync.ToString());
                    }
                    else
                    {
                        await Task.Delay(TimeSpan.FromMinutes(1));
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"JacRed/SyncCron: {ex.Message}");
                    try
                    {
                        if (lastsync > 0)
                        {
                            FileDB.SaveChangesToFile();
                            File.WriteAllText("cache/jacred/lastsync.txt", lastsync.ToString());
                        }
                    }
                    catch { /* best-effort save on error path */ }
                }

                await Task.Delay(1000 * Random.Shared.Next(60, 300));
                await Task.Delay(1000 * 60 * (20 > ModInit.conf.Red.syntime ? 20 : ModInit.conf.Red.syntime));

                reset = true;
                lastSave = DateTime.Now;
            }
        }
    }
}
