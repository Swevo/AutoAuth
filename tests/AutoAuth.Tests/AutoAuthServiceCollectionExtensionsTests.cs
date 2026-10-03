using FluentAssertions;
using AutoAuth.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using System.Text.Json;
using Xunit;

namespace AutoAuth.Tests;

public sealed class AutoAuthServiceCollectionExtensionsTests
{
    [Fact]
    public void AddAutoAuthServer_WithoutIssuer_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthServer<TestDbContext>(server => server
            .AllowClientCredentialsFlow()
            .UseDevelopmentCertificates());

        act.Should().Throw<InvalidOperationException>().WithMessage("*SetIssuer*");
    }

    [Fact]
    public void AddAutoAuthServer_WithoutAnyFlow_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .UseDevelopmentCertificates());

        act.Should().Throw<InvalidOperationException>().WithMessage("*flow*");
    }

    [Fact]
    public void AddAutoAuthServer_WithoutCertificateOrDevelopmentOptIn_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow());

        act.Should().Throw<InvalidOperationException>().WithMessage("*certificate*");
    }

    [Fact]
    public void AddAutoAuthServer_WithRequiredPar_RegistersParEndpointAndRequirement()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowAuthorizationCodeFlow()
            .RequirePushedAuthorizationRequests()
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;

        options.RequirePushedAuthorizationRequests.Should().BeTrue();
        options.PushedAuthorizationEndpointUris.Should().ContainSingle(uri => uri.OriginalString == "/connect/par");
        options.AuthorizationEndpointUris.Should().ContainSingle(uri => uri.OriginalString == "/connect/authorize");
    }

    [Fact]
    public void AddAutoAuthServer_WithRevocationEndpoint_RegistersRevocationUri()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnableRevocationEndpoint()
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value;
        options.RevocationEndpointUris.Should().ContainSingle(uri => uri.OriginalString == "/connect/revocation");
    }

    [Fact]
    public void AddAutoAuthServer_WithRequiredParButWithoutAuthorizationCodeFlow_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .RequirePushedAuthorizationRequests()
            .UseDevelopmentCertificates());

        act.Should().Throw<InvalidOperationException>().WithMessage("*AllowAuthorizationCodeFlow*");
    }

    [Fact]
    public void AddAutoAuthValidation_WithoutIssuer_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthValidation(validation => validation.UseLocalValidation());

        act.Should().Throw<InvalidOperationException>().WithMessage("*SetIssuer*");
    }

    [Fact]
    public void AddAutoAuthServer_Registers_DefaultFeatureServices()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IAutoAuthTenantResolver>().Should().NotBeNull();
        provider.GetRequiredService<IAutoAuthRiskEvaluator>().Should().NotBeNull();
        provider.GetRequiredService<IAutoAuthAuditSink>().Should().NotBeNull();
        provider.GetRequiredService<IAutoAuthSessionManager>().Should().NotBeNull();
    }

    [Fact]
    public void AddAutoAuthServer_FeatureFlags_AreCaptured()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnablePasskeys()
            .EnableMultiTenantIsolation()
            .EnableRiskBasedAuthentication()
            .EnableSessionManagement()
            .EnableComplianceAudit()
            .EnableKeyRotation(TimeSpan.FromHours(12))
            .EnableTelemetry()
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<AutoAuthFeatureOptions>();
        options.PasskeysEnabled.Should().BeTrue();
        options.MultiTenantEnabled.Should().BeTrue();
        options.RiskBasedAuthenticationEnabled.Should().BeTrue();
        options.SessionManagementEnabled.Should().BeTrue();
        options.ComplianceAuditEnabled.Should().BeTrue();
        options.KeyRotationEnabled.Should().BeTrue();
        options.KeyRotationInterval.Should().Be(TimeSpan.FromHours(12));
        options.TelemetryEnabled.Should().BeTrue();
    }

    [Fact]
    public async Task DefaultTenantResolver_Resolves_Header_When_MultiTenantEnabled()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnableMultiTenantIsolation()
            .UseTenantHeader("X-Tenant")
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var resolver = provider.GetRequiredService<IAutoAuthTenantResolver>();
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["X-Tenant"] = "tenant-a";

        var tenant = await resolver.ResolveTenantAsync(httpContext, default);
        tenant.Should().Be("tenant-a");
    }

    [Fact]
    public async Task DefaultRiskEvaluator_Denies_Configured_Ip()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnableRiskBasedAuthentication()
            .DenyIpAddresses("203.0.113.15")
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var evaluator = provider.GetRequiredService<IAutoAuthRiskEvaluator>();
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.15");

        var result = await evaluator.EvaluateAsync(httpContext, new OpenIddict.Abstractions.OpenIddictRequest(), default);
        result.Allowed.Should().BeFalse();
        result.Reason.Should().Contain("203.0.113.15");
    }

    [Fact]
    public void AddAutoAuthServer_WithKeyRotation_RegistersHostedService()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnableKeyRotation(TimeSpan.FromMinutes(30))
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var hostedServices = provider.GetServices<IHostedService>();
        hostedServices.Should().Contain(s => s.GetType().Name.Contains("AutoAuthKeyRotationBackgroundService"));
    }

    [Fact]
    public async Task DefaultAuditSink_Redacts_ConfiguredSensitiveFields()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthServer<TestDbContext>(server => server
            .SetIssuer("https://localhost/")
            .AllowClientCredentialsFlow()
            .EnableComplianceAudit()
            .AddRedactedAuditFields("api_key")
            .UseDevelopmentCertificates());

        using var provider = services.BuildServiceProvider();
        var sink = (DefaultAuditSink)provider.GetRequiredService<IAutoAuthAuditSink>();
        await sink.WriteAsync("test", new
        {
            client_secret = "secret-value",
            api_key = "my-key",
            plain = "ok"
        }, default);

        var payload = sink.Events.Single().JsonPayload;
        using var doc = JsonDocument.Parse(payload);
        doc.RootElement.GetProperty("client_secret").GetString().Should().Be("***REDACTED***");
        doc.RootElement.GetProperty("api_key").GetString().Should().Be("***REDACTED***");
        doc.RootElement.GetProperty("plain").GetString().Should().Be("ok");
    }

    [Fact]
    public async Task DefaultSessionManager_Supports_RevocationChecks()
    {
        var manager = new DefaultSessionManager();

        await manager.RevokeAsync("subject-a", "client-a", default);

        (await manager.IsRevokedAsync("subject-a", "client-a", default)).Should().BeTrue();
        (await manager.IsRevokedAsync("subject-a", "client-b", default)).Should().BeFalse();

        await manager.RevokeAsync("subject-b", null, default);
        (await manager.IsRevokedAsync("subject-b", "any-client", default)).Should().BeTrue();
    }
}
