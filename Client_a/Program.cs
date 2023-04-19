using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using StackExchange.Redis;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect("127.0.0.1:6379"))
    .SetApplicationName("unique");

builder.Services.AddAuthentication("AppA")
    .AddCookie("AppA")
    .AddOAuth("custom", o => {
        o.ClientId = "d144077a-0660-4038-a680-6c0b085a4962";
        o.ClientSecret = "94052546133206508221";

        o.AuthorizationEndpoint = "https://identity.company.local/oauth/authorize";
        o.TokenEndpoint= "https://identity.company.local/oauth/token";
        o.CallbackPath= "/oauth/custom-cb";

        o.UsePkce = true;
        o.ClaimActions.MapJsonKey("sub", "sub");
        o.ClaimActions.MapJsonKey("custom 33", "custom");

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

//app.UseExceptionHandler(exceptionHandlerApp => {
//    exceptionHandlerApp.Run(async context => {
        
//        var exceptionHandlerPathFeature =
//                context.Features.Get<IExceptionHandlerPathFeature>();

//        if ((bool)(exceptionHandlerPathFeature?.Error.InnerException.Message.Contains("OAuth token endpoint failure: Status: Unauthorized;")))
//        {
//            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
//            context.Response.Redirect("/unauthorized");
//            return;
//        }

//        context.Response.Redirect("/error");
//    });
//});

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) => {

    //if (!ctx.User.Identity.IsAuthenticated) {
    //    ctx.Response.Redirect("/login");
    //    return null;
    //}
        
    return ctx.User.Claims.Select(x => x.ToString()).ToList();
});

app.MapGet("/error", (HttpContext ctx) => "Error");
app.MapGet("/unauthorized", (HttpContext ctx) => "Unauthorized");

app.MapGet("/login", () => {
    return Results.Challenge(new AuthenticationProperties()
    {
        RedirectUri = "http://app.company.local/",
        ExpiresUtc= DateTime.Now.AddSeconds(15),
    },
        authenticationSchemes: new List<string>() { "custom" }
    );
});

app.MapGet("/protected", () => "secret!").RequireAuthorization();

app.Run();
