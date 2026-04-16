using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json.Linq;
using Shared;
using Shared.Engine;
using Shared.Models;
using Shared.Models.Merchant.LtcWallet;
using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IO = System.IO.File;

namespace Merchant.Controllers
{
    public class Litecoin : MerchantController
    {
        #region Litecoin
        static Litecoin()
        {
            Directory.CreateDirectory("merchant/invoice/litecoin");
            ThreadPool.QueueUserWorkItem(async _ => await ChekTransactions());
        }
        #endregion

        #region LtcKurs
        async static ValueTask<double> LtcKurs()
        {
            if (!Startup.memoryCache.TryGetValue("Litecoin:kurs:ltc", out double kurs))
            {
                var exmo = await Http.Get<JObject>("https://api.exmo.com/v1.1/ticker");
                var LTC_USD = exmo.GetValue("LTC_USD");

                double avg = LTC_USD.Value<double>("avg");
                double buy_price = LTC_USD.Value<double>("buy_price");

                kurs = avg > buy_price ? buy_price : avg;
                Startup.memoryCache.Set("Litecoin:kurs:ltc", kurs, DateTime.Now.AddMinutes(15));
            }

            return kurs;
        }
        #endregion

        [HttpGet]
        [AllowAnonymous]
        [Route("litecoin/getnewaddress")]
        async public Task<ActionResult> Index(string email)
        {
            if (!AppInit.conf.Merchant.LtcWallet.enable || string.IsNullOrWhiteSpace(email))
                return Content(string.Empty);

            email = decodeEmail(email);
            string pathEmail = $"merchant/invoice/litecoin/{CrypTo.md5(email)}.email";
            double buyprice = await LtcKurs();

            if (IO.Exists(pathEmail))
            {
                return Json(new
                {
                    payinaddress = IO.ReadAllText(pathEmail),
                    buyprice,
                    amount = AppInit.conf.Merchant.accessCost / buyprice
                });
            }
            else
            {
                string json = await Http.Post(AppInit.conf.Merchant.LtcWallet.rpc, "{\"method\": \"getnewaddress\"}", headers: HeadersModel.Init("Authorization", $"Basic {CrypTo.Base64($"{AppInit.conf.Merchant.LtcWallet.rpcuser}:{AppInit.conf.Merchant.LtcWallet.rpcpassword}")}"));

                string payinAddress = Regex.Match(json ?? string.Empty, "\"result\":\"([^\"]+)\"").Groups[1].Value.Trim();

                if (string.IsNullOrWhiteSpace(payinAddress) || !Regex.IsMatch(payinAddress, "^[0-9a-zA-Z]+$") || 20 > payinAddress.Length)
                {
                    return Json(new { });
                }
                else
                {
                    IO.WriteAllText(pathEmail, payinAddress);
                    IO.WriteAllText($"merchant/invoice/litecoin/{payinAddress}.ltc", email);
                }

                return Json(new
                {
                    payinaddress = payinAddress,
                    buyprice,
                    amount = AppInit.conf.Merchant.accessCost / buyprice
                });
            }
        }


        #region ChekTransactions
        async static Task ChekTransactions()
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromMinutes(1));
                if (!AppInit.conf.Merchant.LtcWallet.enable)
                    continue;

                try
                {
                    // Why: guard against misconfiguration — accessForMonths == 0 would cause divide-by-zero (cost = +Infinity ⇒ days = 0) and then the downstream fallback credits full months anyway.
                    if (AppInit.conf.Merchant.accessForMonths <= 0 || AppInit.conf.Merchant.accessCost <= 0)
                        continue;

                    double kurs = await LtcKurs();
                    if (kurs == -1 || kurs <= 0)
                        continue;

                    var root = await Http.Post<RootTransactions>(AppInit.conf.Merchant.LtcWallet.rpc, "{\"method\": \"listtransactions\", \"params\": [\"*\", 20]}", headers: HeadersModel.Init("Authorization", $"Basic {CrypTo.Base64($"{AppInit.conf.Merchant.LtcWallet.rpcuser}:{AppInit.conf.Merchant.LtcWallet.rpcpassword}")}"));

                    var transactions = root?.result;
                    if (transactions == null || transactions.Count == 0)
                        continue;

                    // Why: listtransactions is capped at 20; if the wallet returns a full page we may be silently dropping older receives — surface it to ops.
                    if (transactions.Count >= 20)
                        Console.WriteLine("Litecoin: listtransactions returned full page (20) — older receives may be missed; consider paging via listsinceblock.");

                    foreach (var trans in transactions)
                    {
                        if (trans.category != "receive" || string.IsNullOrWhiteSpace(trans.txid))
                            continue;

                        try
                        {
                            if (IO.Exists($"merchant/invoice/litecoin/{trans.txid}.txid"))
                                continue;

                            string email = IO.ReadAllText($"merchant/invoice/litecoin/{trans.address}.ltc");
                            IO.WriteAllText($"merchant/invoice/litecoin/{trans.txid}.txid", $"{email}\n{trans.address}");

                            double cost = (double)AppInit.conf.Merchant.accessCost / (double)(AppInit.conf.Merchant.accessForMonths * 30);
                            if (!(cost > 0) || double.IsNaN(cost) || double.IsInfinity(cost))
                                continue;

                            double rawDays = (trans.amount * kurs) / cost;
                            if (double.IsNaN(rawDays) || double.IsInfinity(rawDays) || rawDays < 1.0)
                                continue; // Why: dust / sub-cost payments must not grant access — the fallback PayConfirm(..., 0) path would otherwise credit full months.

                            // Why: clamp before cast to avoid silent double→int overflow wrap; 20 years is a generous upper bound for a single payment.
                            const int maxDays = 366 * 20; // 7320
                            if (rawDays > maxDays)
                                rawDays = maxDays;

                            int days;
                            try
                            {
                                days = checked((int)rawDays);
                            }
                            catch (OverflowException)
                            {
                                continue;
                            }

                            if (days <= 0)
                                continue;

                            PayConfirm(email, "litecoin", $"{trans.address} - {trans.txid}", days: days);
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        #endregion
    }
}
