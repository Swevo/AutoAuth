using Microsoft.AspNetCore.Authorization;

namespace AutoAuth.Authorization;

/// <summary>
/// Fluent policy registration collection for common scope/role/claim requirements.
/// </summary>
public sealed class AutoAuthPolicyCollection
{
    private readonly List<(string Name, Action<AuthorizationPolicyBuilder> Configure)> _registrations = [];

    internal IReadOnlyList<(string Name, Action<AuthorizationPolicyBuilder> Configure)> Registrations => _registrations;

    public AutoAuthPolicyCollection AddPolicy(string name, Action<AuthorizationPolicyBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(configure);
        _registrations.Add((name, configure));
        return this;
    }

    public AutoAuthPolicyCollection RequireScope(string policyName, params string[] requiredScopes)
        => AddPolicy(policyName, builder => builder.RequireAssertion(context =>
        {
            var scopeClaims = context.User.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            var granted = new HashSet<string>(scopeClaims, StringComparer.OrdinalIgnoreCase);
            return requiredScopes.All(granted.Contains);
        }));

    public AutoAuthPolicyCollection RequireAnyScope(string policyName, params string[] requiredScopes)
        => AddPolicy(policyName, builder => builder.RequireAssertion(context =>
        {
            var scopeClaims = context.User.FindAll("scope").SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));
            var granted = new HashSet<string>(scopeClaims, StringComparer.OrdinalIgnoreCase);
            return requiredScopes.Any(granted.Contains);
        }));

    public AutoAuthPolicyCollection RequireRole(string policyName, params string[] roles)
        => AddPolicy(policyName, builder => builder.RequireRole(roles));

    public AutoAuthPolicyCollection RequireClaim(string policyName, string claimType, params string[] values)
        => AddPolicy(policyName, builder =>
        {
            if (values.Length == 0)
            {
                builder.RequireClaim(claimType);
            }
            else
            {
                builder.RequireClaim(claimType, values);
            }
        });
}
