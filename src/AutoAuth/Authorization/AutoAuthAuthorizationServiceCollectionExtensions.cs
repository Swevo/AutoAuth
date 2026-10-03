using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AutoAuth.Authorization;

public static class AutoAuthAuthorizationServiceCollectionExtensions
{
    /// <summary>
    /// Adds fluent authorization policy definitions for scope/role/claim based APIs.
    /// </summary>
    public static IServiceCollection AddAutoAuthPolicies(
        this IServiceCollection services,
        Action<AutoAuthPolicyCollection> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var collection = new AutoAuthPolicyCollection();
        configure(collection);

        services.AddAuthorization(options =>
        {
            foreach (var registration in collection.Registrations)
            {
                options.AddPolicy(registration.Name, registration.Configure);
            }
        });

        return services;
    }
}
