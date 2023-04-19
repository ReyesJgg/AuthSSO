using Auth.BlackBoxes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text.Json;
using System.Web;

namespace Auth.Endpoints.OAuth
{
    public static class AuthorizationEndpoint
    {
        public static IResult Handle(
            HttpRequest request,
            IDataProtectionProvider dataProtectionProvider
            )
        {
            request.Query.TryGetValue("state", out var state);
            request.Query.TryGetValue("client_id", out var clientId);

            Client client = Boxes.Clients.FirstOrDefault(x => x.ClientId.Equals(clientId));

            if (client is null)
            {
                return Results.Content(JsonConvert.SerializeObject(new { Message = "Invalid Client Id" }), "application/json");
            }

            var iss = HttpUtility.UrlEncode("https://identity.company.local");

            if (!request.Query.TryGetValue("response_type", out var responseType))
            {
                return Results.BadRequest(new
                {
                    error = "invalid_request",
                    state,
                    iss
                });
            }
            
            request.Query.TryGetValue("code_challenge", out var codeChallenge);
            request.Query.TryGetValue("code_challenge_method", out var codeChanllengeMethod);
            request.Query.TryGetValue("redirect_uri", out var redirect_uri);
            request.Query.TryGetValue("scope", out var scope);

            var protector = dataProtectionProvider.CreateProtector("oauth");

            var code = new AuthCode()
            {
                ClientId = clientId,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChanllengeMethod,
                RedirectUri = redirect_uri,
                Expiry = DateTime.Now.AddMinutes(5),
            };

            var codeString = protector.Protect(System.Text.Json.JsonSerializer.Serialize(code));

            return Results.Redirect($"{redirect_uri}?code={codeString}&state={state}&iss={iss}");
        }
    }
}
