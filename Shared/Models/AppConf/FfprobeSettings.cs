namespace Shared.Models.AppConf
{
    public class FfprobeSettings
    {
        public bool enable { get; set; }

        public string tsuri { get; set; }

        // If non-empty, /ffprobe will only accept media URLs whose host matches
        // one of these values (exact match, case-insensitive). Mirrors
        // TracksTranscodingConf.allowHosts. Independent of the built-in
        // private/loopback/link-local denylist (SsrfGuard), which applies
        // unconditionally.
        public string[] allowHosts { get; set; } = System.Array.Empty<string>();
    }
}
