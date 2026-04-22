using System.Collections.Generic;

namespace Shared.Models.Online.PizdatoeHD
{
    // Ported from lampac-nextgen (Modules/OnlineRUS/PizdatoeHD/Models/RootObject.cs).
    // No DbModel / CronParse — the offline DB cache (data/PizdatoeDb.json) is not carried
    // over; the live search path covers the same lookups at a small latency cost.
    public class PizdatoeRootObject
    {
        public bool IsEmpty { get; set; }

        public string content { get; set; }

        public string trs { get; set; }
    }

    public class PizdatoeMovieModel
    {
        public List<PizdatoeApiModel> links { get; set; }

        public string subtitlehtml { get; set; }
    }

    public class PizdatoeSearchModel
    {
        public bool IsError { get; set; }

        public bool IsEmpty { get; set; }

        public string content { get; set; }

        public string href { get; set; }

        public List<PizdatoeSimilarModel> similar { get; set; }
    }

    public class PizdatoeSimilarModel
    {
        public PizdatoeSimilarModel() { }

        public PizdatoeSimilarModel(string title, string year, string href, string img)
        {
            this.title = title;
            this.year = year;
            this.href = href;
            this.img = img;
        }

        public string title { get; set; }

        public string year { get; set; }

        public string href { get; set; }

        public string img { get; set; }
    }

    public class PizdatoeApiModel
    {
        public string title { get; set; }

        public string stream_url { get; set; }
    }
}
