namespace Shared.Models.AppConf
{
    public class WsConf
    {
        public string type { get; set; }

        public int inactiveAfterMinutes { get; set; }

        public int maxPerIp { get; set; } = 4;

        public int maxTotal { get; set; } = 128;
    }
}
