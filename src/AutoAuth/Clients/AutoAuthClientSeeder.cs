using OpenIddict.Abstractions;

namespace AutoAuth.Clients;

/// <summary>
/// Idempotently creates or updates OpenIddict client applications from <see cref="AutoAuthClientOptions"/>.
/// Safe to call on every application startup — existing clients (matched by ClientId) are
/// updated in place rather than duplicated.
/// </summary>
public sealed class AutoAuthClientSeeder
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public AutoAuthClientSeeder(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    /// <summary>Creates the client described by <paramref name="options"/> if it does not already exist, or updates it in place if it does.</summary>
    public async Task SeedAsync(AutoAuthClientOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            ClientType = options.ClientSecret is null
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
            DisplayName = options.DisplayName ?? options.ClientId,
        };

        foreach (var permission in options.Permissions)
        {
            descriptor.Permissions.Add(permission);
        }

        foreach (var scope in options.Scopes)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        }

        foreach (var redirectUri in options.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri, UriKind.Absolute));
        }

        foreach (var postLogoutRedirectUri in options.PostLogoutRedirectUris)
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(postLogoutRedirectUri, UriKind.Absolute));
        }

        if (options.RequirePkceValue)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        var existing = await _applicationManager.FindByClientIdAsync(options.ClientId, cancellationToken);
        if (existing is null)
        {
            await _applicationManager.CreateAsync(descriptor, cancellationToken);
        }
        else
        {
            await _applicationManager.UpdateAsync(existing, descriptor, cancellationToken);
        }
    }
}
