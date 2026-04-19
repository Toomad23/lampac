using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Shared;
using System.Web;

namespace Lampac.Controllers
{
    public class WebLogController : BaseController
    {
        [HttpGet]
        [AllowAnonymous]
        [Route("weblog")]
        public ActionResult WebLog(string token, string pattern, string receive = "http")
        {
            if (!AppInit.conf.weblog.enable)
                return Content("Включите weblog в init.conf\n\n\"weblog\": {\n   \"enable\": true\n}", contentType: "text/plain; charset=utf-8");

            if (!string.IsNullOrEmpty(AppInit.conf.weblog.token) && token != AppInit.conf.weblog.token)
                return Content("Используйте /weblog?token=my_key\n\n\"weblog\": {\n   \"enable\": true,\n   \"token\": \"my_key\"\n}", contentType: "text/plain; charset=utf-8");

            // pattern / receive are reflected into HTML attributes below; encode
            // them before interpolation to prevent reflected XSS when weblog.token
            // is unset (anyone can hit this endpoint).
            //
            // Why HtmlEncode and not HtmlAttributeEncode? The pattern is spliced
            // into a *single-quoted* attribute (`value='...'`), and
            // HtmlAttributeEncode only escapes `<`, `&`, and `"` — a single
            // quote in `pattern` would close the attribute and let the caller
            // inject new attributes / event handlers. HtmlEncode also encodes
            // `'` to `&#39;`.
            string safePattern = HttpUtility.HtmlEncode(pattern ?? "");
            string safeReceive = receive == "request" ? "request" : "http";

            // Why: `token` is also reflected, but into JS string literals inside
            // <script> (see nwsCode/signalCode). HtmlAttributeEncode is the wrong
            // encoder for that context — `</script>` and backslash sequences pass
            // through unchanged. Use JSON serialisation to produce a properly
            // escaped JS string (including \u003c for `<`, which prevents
            // `</script>` breakouts in HTML inline-script contexts).
            string safeTokenJs = JsonConvert.ToString(token ?? "", '"', StringEscapeHandling.EscapeHtml);

            string html = $@"<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8' />
    <title>weblog</title>
    <style>
        details summary {{
          font-weight: bold;
          font-size: 1.2em;
          color: #2772d2;
          cursor: pointer;
          list-style: none;
          user-select: none;
          position: relative;
        }}

        details summary:hover {{
          color: #1a4bb8;
        }}
    </style>
</head>
<body style='margin: 0px;'>
    <div id='controls' style='margin-bottom: 1em; background: #f0f0f0; padding: 10px; border-bottom: 1px solid #ccc;'>
        <label style='margin-right: 20px;'>Запросы:
            <select id='receiveSelect' style='padding: 0px 5px 0px 0px;'>
                <option value='http' {(safeReceive == "http" ? "selected" : "")}>Исходящие</option>
                <option value='request' {(safeReceive == "request" ? "selected" : "")}>Входящие</option>
            </select>
        </label>
        <label for='patternInput'>Фильтр: </label>
        <input type='text' id='patternInput' placeholder='rezka.ag' value='{safePattern}' style='margin-right: 20px;' />
    </div>
    <div id='log'></div>
    <script src='/js/nws-client-es5.js'></script>
    <script src='/signalr-6.0.25_es5.js'></script>
    <script>
        let pattern = document.getElementById('patternInput').value.trim();
        let receive = document.getElementById('receiveSelect').value;

        document.getElementById('patternInput').addEventListener('input', e => {{
            pattern = e.target.value.trim();
        }});
        document.getElementById('receiveSelect').addEventListener('change', e => {{
            receive = e.target.value;
        }});

        function send(message) {{
            if (pattern && message.indexOf(pattern) === -1) return;

            var messageHtml = message.replace(/</g, '&lt;').replace(/>/g, '&gt;');

            const markers = [
              {{ text: 'CurrentUrl: ', caseSensitive: true }},
              {{ text: 'StatusCode: ', caseSensitive: true }},
              {{ text: '&lt;!doctype html&gt;', caseSensitive: false }}
            ];

            for (const marker of markers) {{
              let searchText = marker.text;
              let messageText = messageHtml;
  
              if (!marker.caseSensitive)
                messageText = messageHtml.toLowerCase();
  
              const index = messageText.indexOf(searchText);
              if (index !== -1) {{
                messageHtml = messageHtml.slice(0, index) 
                  + '<details><summary>Показать содержимое</summary>'
                  + messageHtml.slice(index) 
                  + '</details>';
                break;
              }}
            }}

            var par = document.getElementById('log');

            let messageElement = document.createElement('hr');
            messageElement.style.cssText = ' margin-bottom: 2.5em; margin-top: 2.5em;';
            par.insertBefore(messageElement, par.children[0]);

            messageElement = document.createElement('pre');
            messageElement.style.cssText = 'padding: 10px; background: cornsilk; white-space: pre-wrap; word-wrap: break-word;';
            if (messageHtml.indexOf('<details>') !== -1)
                messageElement.innerHTML = messageHtml;
            else 
                messageElement.innerText = message;
            par.insertBefore(messageElement, par.children[0]);
        }}


        let outageReported = false;
        function reportOutageOnce(message) {{
            if (!outageReported) {{
                send(message);
                outageReported = true;
            }}
        }}

        {(AppInit.conf.WebSocket.type == "signalr" ? signalCode(safeTokenJs) : nwsCode(safeTokenJs))}
    </script>
</body>
</html>";

            return Content(html, "text/html; charset=utf-8");
        }


        // `tokenJsLiteral` is already a fully-formed JS string literal
        // (JSON-encoded, including the surrounding double quotes), so it is
        // safe to splice straight into the script body without further
        // single-quoting.
        static string nwsCode(string tokenJsLiteral) => $@"
const client = new NativeWsClient(""/nws"", {{
    autoReconnect: true,
    reconnectDelay: 2000,

    onOpen: function () {{
        send('WebSocket connected');
        outageReported = false;
        client.invoke('RegistryWebLog', {tokenJsLiteral});
    }},

    onClose: function () {{
        reportOutageOnce('Connection closed');
    }},

    onError: function (err) {{
        reportOutageOnce('Connection error: ' + (err && err.message ? err.message : String(err)));
    }}
}});

client.on('Receive', function (message, e) {{
    if (receive === e) send(message);
}});

client.connect();
";

        static string signalCode(string tokenJsLiteral) => $@"
const hubConnection = new signalR.HubConnectionBuilder()
    .withUrl('/ws')
    .build();

let reconnectAttempts = 0;
const maxReconnectAttempts = 150; // 5 minutes
const reconnectDelay = 2000;      // 2 seconds

function startConnection() {{
    hubConnection.start()
        .then(function () {{
            if (reconnectAttempts != 0)
                send('WebSocket connected');
            reconnectAttempts = 0; // Reset counter on successful connection
            hubConnection.invoke('RegistryWebLog', {tokenJsLiteral});
        }})
        .catch(function (err) {{
            console.log(`${{err.toString()}}\n\nAttempting to reconnect (${{reconnectAttempts}}/${{maxReconnectAttempts}})...`);
            attemptReconnect();
        }});
}}

function attemptReconnect() {{
    if (reconnectAttempts < maxReconnectAttempts) {{
        reconnectAttempts++;
        setTimeout(function() {{
            startConnection();
        }}, reconnectDelay);
    }} else {{
        send('Max reconnection attempts reached. Please refresh the page.');
    }}
}}

hubConnection.on('Receive', function(message, e) {{
    if(receive === e) send(message);
}});

hubConnection.onclose(function(err) {{
    if (err) {{
        send('Connection closed due to error: ' + err.toString());
    }} else {{
        send('Connection closed');
    }}
    attemptReconnect();
}});

startConnection();
";
    }
}