using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
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
    public void AddAutoAuthValidation_WithoutIssuer_Throws()
    {
        var services = new ServiceCollection();

        var act = () => services.AddAutoAuthValidation(validation => validation.UseLocalValidation());

        act.Should().Throw<InvalidOperationException>().WithMessage("*SetIssuer*");
    }
}
