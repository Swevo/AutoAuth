using System.Security.Cryptography.X509Certificates;

namespace AutoAuth;

/// <summary>
/// Configures the OpenIddict server. AutoAuth only translates these settings into calls against
/// <c>OpenIddictServerBuilder</c> — all token issuance, signing, and validation logic is
/// OpenIddict's, not AutoAuth's.
/// </summary>
public sealed class AutoAuthServerOptions
{
    internal Uri? IssuerUri { get; private set; }
    internal bool RequirePkce { get; private set; } = true;
    internal readonly HashSet<string> Flows = [];
    internal TimeSpan AccessTokenLifetime { get; private set; } = TimeSpan.FromMinutes(60);
    internal TimeSpan RefreshTokenLifetime { get; private set; } = TimeSpan.FromDays(14);
    internal TimeSpan AuthorizationCodeLifetime { get; private set; } = TimeSpan.FromMinutes(5);
    internal bool UseDevelopmentCertificatesValue { get; private set; }
    internal X509Certificate2? SigningCertificate { get; private set; }
    internal X509Certificate2? EncryptionCertificate { get; private set; }

    /// <summary>Sets the server's canonical issuer URI (required). Must match what clients are configured to expect.</summary>
    public AutoAuthServerOptions SetIssuer(string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(issuerUri);
        IssuerUri = new Uri(issuerUri, UriKind.Absolute);
        return this;
    }

    /// <summary>Enables the authorization_code grant (interactive user login). Requires you to implement your own login/consent endpoint — see the README.</summary>
    public AutoAuthServerOptions AllowAuthorizationCodeFlow()
    {
        Flows.Add(GrantType.AuthorizationCode);
        return this;
    }

    /// <summary>Enables the client_credentials grant (machine-to-machine). Paired with <see cref="Endpoints.AutoAuthEndpointRouteBuilderExtensions.MapAutoAuthClientCredentialsEndpoint"/>.</summary>
    public AutoAuthServerOptions AllowClientCredentialsFlow()
    {
        Flows.Add(GrantType.ClientCredentials);
        return this;
    }

    /// <summary>Enables the refresh_token grant.</summary>
    public AutoAuthServerOptions AllowRefreshTokenFlow()
    {
        Flows.Add(GrantType.RefreshToken);
        return this;
    }

    /// <summary>
    /// Requires the <c>code_challenge</c> parameter (PKCE) on every authorization_code request.
    /// Enabled by default — only disable this if you fully understand the security implications.
    /// </summary>
    public AutoAuthServerOptions RequireProofKeyForCodeExchange(bool value = true)
    {
        RequirePkce = value;
        return this;
    }

    /// <summary>Sets how long issued access tokens remain valid. Default: 60 minutes.</summary>
    public AutoAuthServerOptions SetAccessTokenLifetime(TimeSpan lifetime)
    {
        AccessTokenLifetime = lifetime;
        return this;
    }

    /// <summary>Sets how long issued refresh tokens remain valid. Default: 14 days.</summary>
    public AutoAuthServerOptions SetRefreshTokenLifetime(TimeSpan lifetime)
    {
        RefreshTokenLifetime = lifetime;
        return this;
    }

    /// <summary>Sets how long issued authorization codes remain valid. Default: 5 minutes.</summary>
    public AutoAuthServerOptions SetAuthorizationCodeLifetime(TimeSpan lifetime)
    {
        AuthorizationCodeLifetime = lifetime;
        return this;
    }

    /// <summary>Registers the signing certificate used to sign issued tokens. Required for production use.</summary>
    public AutoAuthServerOptions AddSigningCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        SigningCertificate = certificate;
        return this;
    }

    /// <summary>Registers the encryption certificate used to encrypt issued tokens.</summary>
    public AutoAuthServerOptions AddEncryptionCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        EncryptionCertificate = certificate;
        return this;
    }

    /// <summary>
    /// Uses OpenIddict's ephemeral development signing/encryption certificates instead of
    /// <see cref="AddSigningCertificate"/>/<see cref="AddEncryptionCertificate"/>.
    /// <b>Development and testing only</b> — these certificates are regenerated on every
    /// restart and are not suitable for production, where tokens must remain valid across
    /// deployments/restarts.
    /// </summary>
    public AutoAuthServerOptions UseDevelopmentCertificates()
    {
        UseDevelopmentCertificatesValue = true;
        return this;
    }

    internal static class GrantType
    {
        public const string AuthorizationCode = "authorization_code";
        public const string ClientCredentials = "client_credentials";
        public const string RefreshToken = "refresh_token";
    }
}
