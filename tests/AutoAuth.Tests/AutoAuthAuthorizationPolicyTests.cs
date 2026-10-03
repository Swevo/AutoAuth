using AutoAuth.Authorization;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace AutoAuth.Tests;

public sealed class AutoAuthAuthorizationPolicyTests
{
    [Fact]
    public void AddAutoAuthPolicies_Registers_Configured_Policies()
    {
        var services = new ServiceCollection();

        services.AddAutoAuthPolicies(policies => policies
            .RequireScope("api.read", "api.read")
            .RequireAnyScope("api.read-or-write", "api.read", "api.write")
            .RequireRole("admins", "admin")
            .RequireClaim("region.eu", "region", "eu"));

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;

        options.GetPolicy("api.read").Should().NotBeNull();
        options.GetPolicy("api.read-or-write").Should().NotBeNull();
        options.GetPolicy("admins").Should().NotBeNull();
        options.GetPolicy("region.eu").Should().NotBeNull();
    }
}
