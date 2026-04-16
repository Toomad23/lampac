using Microsoft.AspNetCore.Http;
using Shared.Engine;
using Shared.Models.Base;
using System.Collections.Concurrent;

namespace Shared.Models.AppConf
{
    public class AccsConf
    {
        public bool enable { get; set; }

        public string shared_passwd { get; set; }

        public int shared_daytime { get; set; }

        public string whitepattern { get; set; }

        public HashSet<string> white_uids { get; set; }

        public string premium_pattern { get; set; }

        public string domainId_pattern { get; set; }

        public string hmac_secret { get; set; }

        public bool require_hmac_token { get; set; }

        public int maxip_hour { get; set; }

        public int maxrequest_hour { get; set; }

        public int maxlock_day { get; set; }

        public int blocked_hour { get; set; }

        public string authMesage { get; set; }

        public string denyMesage { get; set; }

        public string denyGroupMesage { get; set; }

        public string expiresMesage { get; set; }

        public Dictionary<string, object> @params { get; set; }

        public Dictionary<string, DateTime> accounts { get; set; } = new Dictionary<string, DateTime>();

        public ConcurrentBag<AccsUser> users { get; set; } = new ConcurrentBag<AccsUser>();


        public AccsUser findUser(HttpContext httpContext, out string uid)
        {
            // 1. Try HMAC token first
            string tokenParam = httpContext.Request.Query["token"].ToString();
            if (!string.IsNullOrEmpty(tokenParam) && AccsToken.IsHmacToken(tokenParam))
            {
                var (extractedUid, valid) = AccsToken.Verify(tokenParam);
                if (valid)
                {
                    var user = findUser(extractedUid);
                    if (user != null)
                    {
                        uid = user.id;
                        return user;
                    }
                }

                uid = null;
                return null;
            }

            // 2. If HMAC required, reject bare lookups
            if (require_hmac_token && AccsToken.IsEnabled)
            {
                uid = null;
                return null;
            }

            // 3. Original bare lookup chain (backward compatible)
            var u = findUser(tokenParam) ??
                    findUser(httpContext.Request.Query["account_email"].ToString()) ??
                    findUser(httpContext.Request.Query["uid"].ToString()) ??
                    findUser(httpContext.Request.Query["box_mac"].ToString());

            if (u != null)
            {
                uid = u.id;
                return u;
            }

            uid = null;
            return null;
        }

        public AccsUser findUser(string uid)
        {
            if (string.IsNullOrEmpty(uid))
                return null;

            uid = uid.ToLowerAndTrim();
            return users.FirstOrDefault(i => (i.id != null && i.id.ToLowerAndTrim() == uid) || (i.ids != null && i.ids.FirstOrDefault(id => id.ToLowerAndTrim() == uid) != null));
        }
    }
}
