using Shared.Engine;
using Shared.Models.Base;

namespace Shared.Models
{
    public class RequestModel
    {
        public RequestModel()
        {
        }

        public bool IsLocalRequest { get; set; }

        public bool IsLocalIp { get; set; }

        public bool IsAnonymousRequest { get; set; }

        public string AesGcmKey { get; set; }

        public string IP { get; set; }

        public string UserAgent { get; set; }

        #region Country
        private string _countryCode = null;
        public string Country
        {
            get
            {
                if (_countryCode == string.Empty)
                    return null;

                if (_countryCode != null)
                    return _countryCode;

                _countryCode = GeoIP2.Country(IP);
                if (_countryCode == null)
                {
                    _countryCode = string.Empty;
                    return null;
                }

                return _countryCode;
            }
            set
            {
                // Why: Country is reflected into JS/HTML ({country}); enforce ISO alpha-2 at
                // the setter so any untrusted caller (e.g. spoofed CF-IPCountry) can't poison it.
                if (!string.IsNullOrEmpty(value) && value.Length == 2 &&
                    value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z')
                    _countryCode = value;
            }
        }
        #endregion

        #region ASN
        private long? _asn = null;
        public long ASN
        {
            get
            {
                if (_asn != null)
                    return _asn.Value;

                _asn = GeoIP2.ASN(IP);

                return _asn.Value;
            }
        }
        #endregion

        public AccsUser user { get; set; }

        public string user_uid { get; set; }

        public Dictionary<string, object> @params { get; set; }
    }
}
