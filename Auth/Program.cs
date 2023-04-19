using Auth;
using Auth.Endpoints;
using Auth.Endpoints.OAuth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection()
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect("127.0.0.1:6379"))
    .SetApplicationName("unique");

builder.Services.AddAuthorization();

builder.Services.AddAuthentication("Auth")
    .AddCookie("Auth", o => {
        o.LoginPath = "/login";
        o.Cookie.Domain = ".company.local";
    });

builder.Services.AddSingleton<DevKeys>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello World!");
app.MapGet("/ParametersError", () => "Parameter Error");

app.MapGet("/login", GetLogin.Handler);
app.MapPost("/login", Login.Handler);
app.MapGet("/oauth/authorize", AuthorizationEndpoint.Handle).RequireAuthorization();
app.MapPost("/oauth/token", TokenEndPoint.Handle);
app.MapPost("/oauth/GetToken", TokenEndPoint.GenerateToken).RequireAuthorization();
app.MapGet("/protected", () => "secret!").RequireAuthorization();

app.Run();
