namespace Shared.Models.AppConf
{
    // Controls the Access-Control-Allow-* response headers emitted by the
    // ModHeaders middleware.
    //
    // By default the middleware reflected the caller's Origin and emitted
    // Access-Control-Allow-Credentials: true, letting any page on the
    // internet read authenticated responses from the Lampac API (user
    // tokens, bookmarks, admin data). The admin cookie is SameSite=Strict
    // and so not affected, but other cookies default to SameSite=None
    // (Startup.cs CookiePolicyOptions).
    //
    // The new behaviour:
    //   * If allowOrigins is non-empty and the request's Origin matches one
    //     of its entries (case-insensitive, exact match after scheme+host),
    //     reflect the Origin and set Allow-Credentials: true.
    //   * Otherwise the server replies Access-Control-Allow-Origin: * and
    //     never sets Allow-Credentials — per the CORS spec browsers refuse
    //     to expose credentials to a `*` origin, so cross-origin credentialed
    //     reads are blocked without breaking public-asset CORS.
    public class CorsConf
    {
        public string[] allowOrigins { get; set; } = System.Array.Empty<string>();
    }
}
