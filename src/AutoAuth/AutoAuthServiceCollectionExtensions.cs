using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AutoAuth;

/// <summary>
/// Registers OpenIddict's server and/or validation handlers from AutoAuth's fluent options.
/// These methods only translate options into <c>OpenIddictServerBuilder</c>/
/// <c>OpenIddictValidationBuilder</c> calls — OpenIddict remains solely responsible for all
/// protocol and cryptographic behavior.
/// </summary>
public static class AutoAuthServiceCollectionExtensions
{
    /// <summary>
    /// Registers an OpenIddict authorization server backed by <typeparamref name="TContext"/>
    /// (an EF Core <see cref="DbContext"/> whose model includes OpenIddict's entities — call
    /// <c>options.UseOpenIddict()</c> in your <c>DbContext.OnModelCreating</c>).
    /// </summary>
    public static IServiceCollection AddAutoAuthServer<TContext>(
        this IServiceCollection services,
        Action<AutoAuthServerOptions> configure)
        where TContext : DbContext
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AutoAuthServerOptions();
        configure(options);

        if (options.IssuerUri is null)
        {
            throw new InvalidOperationException(
                "AutoAuth requires SetIssuer(...) to be called with the server's canonical issuer URI.");
        }

        if (options.Flows.Count == 0)
        {
            throw new InvalidOperationException(
                "AutoAuth requires at least one flow to be enabled (e.g. AllowClientCredentialsFlow()).");
        }

        if (!options.UseDevelopmentCertificatesValue && options.SigningCertificate is null)
        {
            throw new InvalidOperationException(
                "AutoAuth requires a signing certificate. Call AddSigningCertificate(certificate) for " +
                "production, or UseDevelopmentCertificates() for local development/testing only.");
        }

        services.AddOpenIddict()
            .AddCore(core => core.UseEntityFrameworkCore().UseDbContext<TContext>())
            .AddServer(server =>
            {
                server.SetIssuer(options.IssuerUri);

                if (options.Flows.Contains(AutoAuthServerOptions.GrantType.AuthorizationCode))
                {
                    server.AllowAuthorizationCodeFlow();
                    server.SetAuthorizationEndpointUris("/connect/authorize");
                }

                if (options.Flows.Contains(AutoAuthServerOptions.GrantType.ClientCredentials))
                {
                    server.AllowClientCredentialsFlow();
                }

                if (options.Flows.Contains(AutoAuthServerOptions.GrantType.RefreshToken))
                {
                    server.AllowRefreshTokenFlow();
                }

                if (options.RequirePkce)
                {
                    server.RequireProofKeyForCodeExchange();
                }

                server.SetTokenEndpointUris("/connect/token");
                server.SetUserInfoEndpointUris("/connect/userinfo");
                server.SetEndSessionEndpointUris("/connect/logout");

                server.SetAccessTokenLifetime(options.AccessTokenLifetime);
                server.SetRefreshTokenLifetime(options.RefreshTokenLifetime);
                server.SetAuthorizationCodeLifetime(options.AuthorizationCodeLifetime);

                if (options.UseDevelopmentCertificatesValue)
                {
                    server.AddDevelopmentEncryptionCertificate();
                    server.AddDevelopmentSigningCertificate();
                }
                else
                {
                    if (options.EncryptionCertificate is not null)
                        server.AddEncryptionCertificate(options.EncryptionCertificate);

                    server.AddSigningCertificate(options.SigningCertificate!);
                }

                var aspNetCore = server.UseAspNetCore()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableStatusCodePagesIntegration();

                if (options.Flows.Contains(AutoAuthServerOptions.GrantType.AuthorizationCode))
                {
                    aspNetCore.EnableAuthorizationEndpointPassthrough()
                        .EnableEndSessionEndpointPassthrough();
                }
            });

        return services;
    }

    /// <summary>Registers OpenIddict's validation handler for a resource server (an API validating tokens).</summary>
    public static IServiceCollection AddAutoAuthValidation(
        this IServiceCollection services,
        Action<AutoAuthValidationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AutoAuthValidationOptions();
        configure(options);

        if (options.IssuerUri is null)
        {
            throw new InvalidOperationException(
                "AutoAuth requires SetIssuer(...) to be called with the authorization server's issuer URI.");
        }

        services.AddOpenIddict()
            .AddValidation(validation =>
            {
                validation.SetIssuer(options.IssuerUri);
                validation.UseSystemNetHttp();

                if (options.UseIntrospectionValue)
                {
                    validation.UseIntrospection()
                        .SetClientId(options.ClientId!)
                        .SetClientSecret(options.ClientSecret!);
                }
                else
                {
                    validation.UseLocalServer();
                }

                validation.UseAspNetCore();
            });

        return services;
    }
}
