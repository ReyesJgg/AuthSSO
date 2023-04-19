using Auth.BlackBoxes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Text.Json.Nodes;

namespace Auth.Endpoints
{
    public static class Login
    {
        public static async Task<IResult> Handler(
            HttpContext ctx,
            string returnUrl
        )
        {
            User user = new User()
            {
                UserName = ctx.Request.Form["Username"],
                Password = ctx.Request.Form["Password"]
            };


            if (!ValidateCredentials(user)) {
                return Results.Content(JsonConvert.SerializeObject(new { Message = "Invalid credential", Login = returnUrl }), "application/json");
            }

            await ctx.SignInAsync(
                "Auth",
                new ClaimsPrincipal(
                    new ClaimsIdentity(
                        new Claim[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
                        },
                        "Auth"
                    )
                )
            );

            return Results.Redirect(returnUrl);
        }

        public static bool ValidateCredentials(User user)
        {
            User currentUser = Boxes.Users.FirstOrDefault(x => x.UserName.Equals(user.UserName) & x.Password.Equals(user.Password));

            return currentUser is not null ? true : false;
        }
    }
}
