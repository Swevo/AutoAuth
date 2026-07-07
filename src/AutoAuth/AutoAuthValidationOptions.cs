namespace AutoAuth;

/// <summary>
/// Configures OpenIddict's validation handler for a resource server (an API that accepts and
/// validates tokens issued by an AutoAuth/OpenIddict authorization server).
/// </summary>
public sealed class AutoAuthValidationOptions
{
    internal Uri? IssuerUri { get; private set; }
    internal bool UseIntrospectionValue { get; private set; }
    internal string? ClientId { get; private set; }
    internal string? ClientSecret { get; private set; }

    /// <summary>Sets the authorization server's canonical issuer URI (required).</summary>
    public AutoAuthValidationOptions SetIssuer(string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(issuerUri);
        IssuerUri = new Uri(issuerUri, UriKind.Absolute);
        return this;
    }

    /// <summary>
    /// Validates tokens locally (default) by fetching and caching the authorization server's
    /// signing keys from its discovery document. Fast; requires no round-trip per request.
    /// </summary>
    public AutoAuthValidationOptions UseLocalValidation()
    {
        UseIntrospectionValue = false;
        return this;
    }

    /// <summary>
    /// Validates tokens via an introspection request to the authorization server on every call.
    /// Slower, but lets the authorization server revoke tokens immediately. Requires
    /// <paramref name="clientId"/>/<paramref name="clientSecret"/> registered as a confidential
    /// client with introspection permission.
    /// </summary>
    public AutoAuthValidationOptions UseIntrospection(string clientId, string clientSecret)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(clientSecret);
        UseIntrospectionValue = true;
        ClientId = clientId;
        ClientSecret = clientSecret;
        return this;
    }
}
