using AutoAuth.Clients;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace AutoAuth.Tests;

/// <summary>Boots the test app (see Program.cs) and seeds a known client_credentials client for use by tests.</summary>
public sealed class AutoAuthWebApplicationFactory : WebApplicationFactory<Program>
{
    public const string ClientId = "test-client";
    public const string ClientSecret = "test-secret";

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        base.ConfigureWebHost(builder);
    }

    public async Task SeedDefaultClientAsync()
    {
        using var scope = Services.CreateScope();

        var scopeManager = scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictScopeManager>();
        if (await scopeManager.FindByNameAsync("api1") is null)
        {
            await scopeManager.CreateAsync(new OpenIddict.Abstractions.OpenIddictScopeDescriptor
            {
                Name = "api1",
                DisplayName = "API 1",
                Resources = { "api1" },
            });
        }

        var seeder = new AutoAuthClientSeeder(scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictApplicationManager>());

        await seeder.SeedAsync(new AutoAuthClientOptions(ClientId)
            .WithSecret(ClientSecret)
            .WithDisplayName("Test Client")
            .AllowClientCredentialsFlow()
            .WithScopes("api1"));
    }
}
