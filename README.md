# Swevo.AutoAuth

[![NuGet](https://img.shields.io/nuget/v/Swevo.AutoAuth.svg)](https://www.nuget.org/packages/Swevo.AutoAuth)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Swevo.AutoAuth.svg)](https://www.nuget.org/packages/Swevo.AutoAuth)
[![CI](https://github.com/Swevo/AutoAuth/actions/workflows/build.yml/badge.svg)](https://github.com/Swevo/AutoAuth/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A free, MIT-licensed fluent configuration wrapper around [OpenIddict](https://github.com/openiddict/openiddict-core) (Apache 2.0) for building OAuth2/OIDC token servers in ASP.NET Core.

**AutoAuth exists because [Duende IdentityServer](https://duendesoftware.com/) v6+ requires a paid commercial license for production use** once your organization crosses Duende's revenue/usage thresholds (see [duendesoftware.com/license](https://duendesoftware.com/license)). OpenIddict is a fully free, Apache 2.0-licensed alternative — but it is a low-level *protocol toolkit*, not a turnkey product: you must wire up its server/validation options and write your own token/authorization endpoint controllers by hand. AutoAuth removes the boilerplate from that wiring and ships one ready-to-use endpoint, while being explicit about what it does and does not do.

## What AutoAuth actually is

AutoAuth is a **thin, fluent configuration and client-seeding layer**. It contains no cryptography and no custom protocol logic — every token is issued, signed, validated, and checked by OpenIddict itself. AutoAuth only:

1. Translates a small, fluent options object into the equivalent `AddOpenIddict().AddCore()/.AddServer()/.AddValidation()` calls, with sane, secure-by-default settings (PKCE required by default, explicit opt-in for development certificates).
2. Provides an idempotent client-seeding helper (`AutoAuthClientSeeder`) so you can declare your OAuth2 clients in code and have them created/updated safely on every startup.
3. Ships **one** pre-built, production-usable endpoint: the `client_credentials` grant token endpoint — the simplest and safest OAuth2 flow, since it never involves a user session, login form, or consent screen. Its implementation mirrors OpenIddict's own official sample (`openiddict/openiddict-samples`, `Aridka.Server/Controllers/AuthorizationController.cs`) line-for-line in logic, translated to a minimal API endpoint.

## What AutoAuth explicitly does NOT do

**Interactive flows (`authorization_code` with real user login/consent) are not implemented by AutoAuth.** Building a safe, tested login and consent UI is a substantial undertaking involving session management, CSRF protection, and consent-persistence — exactly the part of the puzzle where mistakes are most dangerous. Rather than shipping unproven login/consent code, AutoAuth configures the server correctly for `authorization_code` (including endpoint URIs and PKCE enforcement) and lets **you** bring your own controller, following OpenIddict's own official, security-reviewed samples:

- https://github.com/openiddict/openiddict-samples

If you need a complete, ready-made interactive login/consent experience out of the box, OpenIddict's samples repo or Duende IdentityServer's commercial UI remain your best options. AutoAuth's job is to remove the *configuration* boilerplate, not to replace security-critical UI code you haven't reviewed yourself.

## Install

```bash
dotnet add package Swevo.AutoAuth
```

## Quick start: client_credentials (machine-to-machine)

```csharp
using AutoAuth;
using AutoAuth.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("Default"));
    options.UseOpenIddict(); // registers OpenIddict's entities in your EF Core model
});

builder.Services.AddAuthorization();

builder.Services.AddAutoAuthServer<AppDbContext>(server => server
    .SetIssuer("https://auth.example.com/")
    .AllowClientCredentialsFlow()
    .AddSigningCertificate(myCertificate)      // or .UseDevelopmentCertificates() for local dev only
    .SetAccessTokenLifetime(TimeSpan.FromMinutes(60)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapAutoAuthClientCredentialsEndpoint(); // maps POST /connect/token

app.Run();
```

Seed a client on startup:

```csharp
using AutoAuth.Clients;

using var scope = app.Services.CreateScope();
var seeder = new AutoAuthClientSeeder(scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>());

await seeder.SeedAsync(new AutoAuthClientOptions("service-a")
    .WithSecret("a-strong-generated-secret")
    .WithDisplayName("Service A")
    .AllowClientCredentialsFlow()
    .WithScopes("api1"));
```

`SeedAsync` is idempotent — call it on every startup; existing clients (matched by `ClientId`) are updated in place, never duplicated.

## Validating tokens in a resource server (API)

```csharp
builder.Services.AddAutoAuthValidation(validation => validation
    .SetIssuer("https://auth.example.com/")
    .UseLocalValidation()); // or .UseIntrospection(clientId, clientSecret)
```

## Enabling authorization_code (bring your own login/consent controller)

```csharp
builder.Services.AddAutoAuthServer<AppDbContext>(server => server
    .SetIssuer("https://auth.example.com/")
    .AllowAuthorizationCodeFlow()   // requires PKCE by default
    .AllowRefreshTokenFlow()
    .AddSigningCertificate(myCertificate));
```

AutoAuth will map the `/connect/authorize` and `/connect/logout` endpoint URIs and enable ASP.NET Core passthrough for them, but **you must implement your own controller/endpoint** handling login, consent, and building the `ClaimsPrincipal` — see OpenIddict's `Velusia`/`Zirku` samples for a complete, working reference implementation of interactive flows.

## Security notes

- PKCE (`RequireProofKeyForCodeExchange`) is **required by default** for authorization_code requests.
- `UseDevelopmentCertificates()` uses OpenIddict's ephemeral signing/encryption certificates, regenerated on every restart. **Do not use in production** — tokens issued before a restart become unverifiable. Use `AddSigningCertificate(...)` with a real, persisted certificate instead.
- AutoAuth throws at startup if no issuer, no flow, or no signing certificate (and no explicit development opt-in) is configured — misconfiguration fails fast rather than silently running insecurely.

## Related Swevo packages

- [AutoBus](https://github.com/Swevo/AutoBus) — free MassTransit alternative
- [FluentPdf](https://github.com/Swevo/FluentPdf) — free QuestPDF alternative
- [FluentExcel](https://github.com/Swevo/FluentExcel) — free EPPlus alternative
- [AutoImage](https://github.com/Swevo/AutoImage) — free ImageSharp alternative

## License

MIT
