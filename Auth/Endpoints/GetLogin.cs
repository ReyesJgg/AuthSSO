using Auth.BlackBoxes;
using Microsoft.IdentityModel.Tokens;
using System.Web;

namespace Auth.Endpoints
{
    public static class GetLogin
    {
        public static async Task Handler(
            string returnUrl,
            HttpResponse response
        )
        {
            response.Headers.ContentType = new string[] { "text/html" };

            var q = returnUrl.Split('?')[1].Split("&");

            bool requestValid = true;

            foreach ( var item in q )
            {
                string key = item.Split("=")[0];
                string value = item.Split("=")[1];

                bool paramsneeded = Boxes.RequiredParams.FirstOrDefault(x => x.Key.Equals(key)).Value;

                if (key.Equals("client_id")) {
                    Client client = Boxes.Clients.FirstOrDefault(x => x.ClientId.Equals(value));

                    if (client is null) {
                        await response.WriteAsync("$@<html><head><body style='background: black;'><h3 style='color:#0bab0b; font-family: monospace; font-size: 0.9rem;'>Unregistered client</h3></body></head></html>");
                        return;
                    }
                }

                if (value.IsNullOrEmpty() && paramsneeded)
                    requestValid = false;

                if (key == "redirect_uri")
                    Console.WriteLine(HttpUtility.UrlDecode(value));

                if (key == "redirect_uri" && !HttpUtility.UrlDecode(value).CheckURLValid())
                    requestValid = false;
            }

            if (!requestValid)
                response.Redirect("/ParametersError");

            await response.WriteAsync(
                $@"<html>
                        <head>
                            <title>Login</title>
                        </head>
                        <body style='background: black;'>
                        <form action='/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}' method='post'>
                            <input type='text' name='Username' placeholder='Username' value='suzuka'></input>
                            <input type='password' name='Password' placeholder='Password' value='password'></input>
                            <input value='Submit' type='submit' style='
                            border: none;
                            padding: 5px 20px;
                            background: ghostwhite;
                            font-family: revert;
                            '>
                        </form>
                        </body>
                    </html>"
            );
        }

        public static bool CheckURLValid(this string source) => Uri.TryCreate(source, UriKind.Absolute, out Uri uriResult) && uriResult.Scheme == Uri.UriSchemeHttps;

    }
}
