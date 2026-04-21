namespace Shared.Models.SISI.Base
{
    public class SisiConf
    {
        public bool xdb { get; set; }

        public bool lgbt { get; set; }

        public bool NextHUB { get; set; }

        public string[] NextHUB_sites_enabled { get; set; }

        public bool rsize { get; set; }

        public string rsize_host { get; set; }

        public string bypass_host { get; set; }

        public string[] rsize_disable { get; set; }

        public string[] proxyimg_disable { get; set; }

        public int heightPicture { get; set; }

        public int widthPicture { get; set; }


        public bool spider { get; set; }

        public string component { get; set; }

        public string vipcontent { get; set; }

        public string iconame { get; set; }


        public bool push_all { get; set; }

        public bool forced_checkRchtype { get; set; }


        // Why (M-23): default-off gate. When true, SISI server endpoints require an
        // explicit adult=true (or =1) query parameter so clients that bootstrapped
        // via the /on/h/{token} ("no adult") manifest — which omits the SISI plugin —
        // can't bypass that by directly calling /sisi, /sisi/bookmarks, /phub/*, etc.
        // Kept default-false to avoid breaking every legit client; admins who want
        // the gate must enable it and ship a plugin variant that sets adult=true.
        public bool require_adult_flag { get; set; }


        public BookmarksConf bookmarks { get; set; }

        public HistoryConf history { get; set; }


        public Dictionary<string, string> appReplace { get; set; }
    }
}
