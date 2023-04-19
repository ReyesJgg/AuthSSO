using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect("127.0.0.1:6379"))
    .SetApplicationName("unique");

builder.Services.AddAuthentication("AppB")
    .AddCookie("AppB")
    .AddOAuth("custom", o => {
        o.ClientId = "866fe555-2837-4adc-9740-41f94c767397";
        o.ClientSecret = "22079015651133695097";

        o.AuthorizationEndpoint = "https://identity.company.local/oauth/authorize";
        o.TokenEndpoint = "https://identity.company.local/oauth/token";
        o.CallbackPath = "/oauth/custom-cb";

        o.UsePkce = true;
        o.ClaimActions.MapJsonKey("sub", "sub");
        o.ClaimActions.MapJsonKey("custom 34", "custom");

        o.Events.OnCreatingTicket = async ctx =>
        {
            var payloadBase64 = ctx.AccessToken.Split('.')[1];
            var payloadJson = Base64UrlTextEncoder.Decode(payloadBase64);
            var payload = JsonDocument.Parse(payloadJson);
            ctx.RunClaimActions(payload.RootElement);
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) => {

    if (!ctx.User.Identity.IsAuthenticated)
    {
        ctx.Response.Redirect("/login");
        return null;
    }

    return ctx.User.Claims.Select(x => x.ToString()).ToList();
});

app.MapGet("/login", () => {
    return Results.Challenge(new AuthenticationProperties()
    {
        RedirectUri = "https://app2.company.local/",
        IsPersistent = true,
        
    },   
        authenticationSchemes: new List<string>() { "custom" }
    );
});

app.MapGet("/protected", () => "secret!").RequireAuthorization();

app.Run();
