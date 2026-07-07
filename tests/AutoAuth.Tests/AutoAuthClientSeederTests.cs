using AutoAuth.Clients;
using FluentAssertions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Xunit;

namespace AutoAuth.Tests;

public sealed class AutoAuthClientSeederTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private ServiceProvider _provider = null!;

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        await _connection.OpenAsync();

        var services = new ServiceCollection();
        services.AddDbContext<TestDbContext>(options =>
        {
            options.UseSqlite(_connection);
            options.UseOpenIddict();
        });

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .UseDevelopmentCertificates());

        _provider = services.BuildServiceProvider();

        using var scope = _provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<TestDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        await _provider.DisposeAsync();
        await _connection.DisposeAsync();
    }

    [Fact]
    public async Task SeedAsync_CalledTwiceWithSameClientId_DoesNotCreateDuplicate()
    {
        using var scope = _provider.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var seeder = new AutoAuthClientSeeder(applicationManager);

        var options = new AutoAuthClientOptions("idempotent-client")
            .WithSecret("secret")
            .WithDisplayName("Idempotent Client")
            .AllowClientCredentialsFlow();

        await seeder.SeedAsync(options);
        await seeder.SeedAsync(options);

        var count = 0;
        await foreach (var _ in applicationManager.ListAsync())
        {
            count++;
        }

        count.Should().Be(1);
    }

    [Fact]
    public async Task SeedAsync_CalledAgainWithChangedDisplayName_UpdatesExistingClient()
    {
        using var scope = _provider.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var seeder = new AutoAuthClientSeeder(applicationManager);

        await seeder.SeedAsync(new AutoAuthClientOptions("updatable-client")
            .WithSecret("secret")
            .WithDisplayName("Original Name")
            .AllowClientCredentialsFlow());

        await seeder.SeedAsync(new AutoAuthClientOptions("updatable-client")
            .WithSecret("secret")
            .WithDisplayName("Updated Name")
            .AllowClientCredentialsFlow());

        var application = await applicationManager.FindByClientIdAsync("updatable-client");
        application.Should().NotBeNull();
        (await applicationManager.GetDisplayNameAsync(application!)).Should().Be("Updated Name");
    }

    [Fact]
    public async Task SeedAsync_WithoutSecret_CreatesPublicClient()
    {
        using var scope = _provider.CreateScope();
        var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var seeder = new AutoAuthClientSeeder(applicationManager);

        await seeder.SeedAsync(new AutoAuthClientOptions("public-client")
            .WithDisplayName("Public Client")
            .AllowAuthorizationCodeFlow()
            .WithRedirectUri("https://client.example/callback"));

        var application = await applicationManager.FindByClientIdAsync("public-client");
        application.Should().NotBeNull();
        (await applicationManager.GetClientTypeAsync(application!)).Should().Be(OpenIddictConstants.ClientTypes.Public);
    }
}
