namespace AutoAuth.Clients;

/// <summary>
/// Describes an OAuth2/OIDC client application to be idempotently seeded via
/// <see cref="AutoAuthClientSeeder"/>. Maps directly onto OpenIddict's
/// <c>OpenIddictApplicationDescriptor</c> — AutoAuth adds no new semantics, only a fluent
/// builder and idempotent create-or-update behavior.
/// </summary>
public sealed class AutoAuthClientOptions
{
    internal string ClientId { get; }
    internal string? ClientSecret { get; private set; }
    internal string? DisplayName { get; private set; }
    internal readonly HashSet<string> RedirectUris = [];
    internal readonly HashSet<string> PostLogoutRedirectUris = [];
    internal readonly HashSet<string> Permissions = [];
    internal readonly HashSet<string> Scopes = [];
    internal bool RequirePkceValue { get; private set; } = true;

    public AutoAuthClientOptions(string clientId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ClientId = clientId;
    }

    /// <summary>Registers this client as confidential (server-side) with the given secret. Omit for public clients (e.g. SPAs/mobile apps).</summary>
    public AutoAuthClientOptions WithSecret(string clientSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientSecret);
        ClientSecret = clientSecret;
        return this;
    }

    /// <summary>Sets a human-readable display name shown in consent screens/logs.</summary>
    public AutoAuthClientOptions WithDisplayName(string displayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        DisplayName = displayName;
        return this;
    }

    /// <summary>Adds an allowed redirect URI for the authorization_code flow.</summary>
    public AutoAuthClientOptions WithRedirectUri(string redirectUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        RedirectUris.Add(redirectUri);
        return this;
    }

    /// <summary>Adds an allowed post-logout redirect URI.</summary>
    public AutoAuthClientOptions WithPostLogoutRedirectUri(string postLogoutRedirectUri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(postLogoutRedirectUri);
        PostLogoutRedirectUris.Add(postLogoutRedirectUri);
        return this;
    }

    /// <summary>Grants this client the authorization_code flow (plus, by default, the token endpoint permission it needs to redeem the code).</summary>
    public AutoAuthClientOptions AllowAuthorizationCodeFlow()
    {
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Authorization);
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token);
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.ResponseTypes.Code);
        return this;
    }

    /// <summary>Grants this client the client_credentials flow.</summary>
    public AutoAuthClientOptions AllowClientCredentialsFlow()
    {
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token);
        return this;
    }

    /// <summary>Grants this client the refresh_token flow.</summary>
    public AutoAuthClientOptions AllowRefreshTokenFlow()
    {
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.GrantTypes.RefreshToken);
        Permissions.Add(OpenIddict.Abstractions.OpenIddictConstants.Permissions.Endpoints.Token);
        return this;
    }

    /// <summary>Grants this client one or more OAuth2/OIDC scopes (e.g. "api1", "openid", "offline_access").</summary>
    public AutoAuthClientOptions WithScopes(params string[] scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        foreach (var scope in scopes)
        {
            Scopes.Add(scope);
        }
        return this;
    }

    /// <summary>Requires PKCE for this specific client. Enabled by default.</summary>
    public AutoAuthClientOptions RequirePkce(bool value = true)
    {
        RequirePkceValue = value;
        return this;
    }
}
