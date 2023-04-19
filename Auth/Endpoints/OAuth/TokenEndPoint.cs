using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using System.Text.Json;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Auth.BlackBoxes;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Endpoints.OAuth
{
    public static class TokenEndPoint
    {
        public class RequestToken
        {
            public string ResourceId { get; set; }
            public string[] Scopes { get; set; }
        }

        public static async Task<IResult> Handle(
            HttpRequest request,
            DevKeys devKeys,
            IDataProtectionProvider dataProtectionProvider
        )
        {
            var bodyBytes = await request.BodyReader.ReadAsync();
            var bodyContent = Encoding.UTF8.GetString(bodyBytes.Buffer);

            

            string grantType = "", code = "", redirectUri = "", codeVerifier = "", clientId = "", clientSecret = "";

            foreach (var part in bodyContent.Split('&'))
            {
                var subParts = part.Split('=');
                var key = subParts[0];
                var value = subParts[1];

                if (key == "grant_type") grantType = value;
                else if (key == "code") code = value;
                else if (key == "redirect_uri") redirectUri = value;
                else if (key == "code_verifier") codeVerifier = value;
                else if (key == "client_id") clientId = value;
                else if (key == "client_secret") clientSecret = value;
            }

            Client client = Boxes.Clients.FirstOrDefault(x => x.ClientId.Equals(clientId));


            if (client is null ) return Results.Unauthorized();
            if (!client.ClientSecret.Equals(clientSecret)) return Results.Unauthorized();

            var protector = dataProtectionProvider.CreateProtector("oauth");
            var codeString = protector.Unprotect(code);
            var authCode = JsonSerializer.Deserialize<AuthCode>(codeString);

            if (!ValidateCodeVerifier(authCode, codeVerifier)) return Results.BadRequest();

            var handler = new JsonWebTokenHandler();

            var c = new
            {
                access_token = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    Claims = new Dictionary<string, object>()
                    {
                        [System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub] = Guid.NewGuid().ToString(),
                        ["custom"] = "foo"
                    },
                    Expires = DateTime.Now.AddMinutes(15),
                    TokenType = "Bearer",
                    SigningCredentials = new SigningCredentials(devKeys.RsaSecurityKey, SecurityAlgorithms.RsaSha256)
                }),
                token_type = "Bearer"
            };

            return Results.Ok(c);
        }

        private static bool ValidateCodeVerifier(
            AuthCode code,
            string codeVerifier
        )
        {
            using var sha256 = SHA256.Create();
            var codeChallenge = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));

            return code.CodeChallenge == codeChallenge;
        }
        public static async Task<IResult> GenerateToken()
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] _key = Encoding.ASCII.GetBytes("YQ2s3TxDB5engt4pZoXjkcHrm7LFUfZoXjkcHrm7LFUf");

            DateTime dtNow = DateTime.Now;
            DateTime dtExpiration = DateTime.Now.AddDays(1);


            var claims = new[]
            {
                new Claim("x","x"),
        };

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                NotBefore = dtNow,
                Expires = dtExpiration,
                Subject = new ClaimsIdentity(claims),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            string finalToken = tokenHandler.WriteToken(token);

            return Results.Ok(new { token = finalToken });
        }
    }
}
