using FluentAssertions;
using AutoAuth.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
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
}
