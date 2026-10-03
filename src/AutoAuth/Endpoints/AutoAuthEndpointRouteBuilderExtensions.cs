using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using AutoAuth.Features;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AutoAuth.Endpoints;

/// <summary>
/// Maps a ready-to-use client_credentials grant token endpoint, mirroring OpenIddict's own
/// official sample (openiddict/openiddict-samples, Aridka.Server/Controllers/AuthorizationController.cs)
/// as closely as possible so no new security logic is introduced.
///
/// This endpoint only handles the client_credentials grant. Interactive flows
/// (authorization_code with real user login/consent) are NOT implemented here — they require
/// your own login/consent endpoint. See the README for guidance and links to OpenIddict's
/// official interactive samples.
/// </summary>
public static class AutoAuthEndpointRouteBuilderExtensions
{
    /// <summary>Maps the client_credentials token endpoint at <paramref name="pattern"/> (default: "/connect/token").</summary>
    public static IEndpointRouteBuilder MapAutoAuthClientCredentialsEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern = "/connect/token")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapPost(pattern, async (
            HttpContext httpContext,
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            AutoAuthFeatureOptions featureOptions,
            IAutoAuthTenantResolver tenantResolver,
            IAutoAuthRiskEvaluator riskEvaluator,
            IAutoAuthAuditSink auditSink,
            IAutoAuthSessionManager sessionManager) =>
        {
            if (featureOptions.TelemetryEnabled)
            {
                AutoAuthTelemetry.TokenRequests.Add(1);
            }

            var request = httpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            using var activity = featureOptions.TelemetryEnabled
                ? AutoAuthTelemetry.ActivitySource.StartActivity("autoauth.token.request")
                : null;
            activity?.SetTag("grant_type", request.GrantType);
            activity?.SetTag("client_id", request.ClientId);

            if (!request.IsClientCredentialsGrantType())
            {
                if (featureOptions.TelemetryEnabled)
                {
                    AutoAuthTelemetry.TokenRejected.Add(1);
                }

                return Results.BadRequest(new OpenIddictResponse
                {
                    Error = Errors.UnsupportedGrantType,
                    ErrorDescription = "This endpoint only supports the client_credentials grant type. " +
                        "For other grant types (e.g. authorization_code), implement your own token " +
                        "endpoint — see the AutoAuth README for guidance.",
                });
            }

            var tenantId = await tenantResolver.ResolveTenantAsync(httpContext, httpContext.RequestAborted);
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                activity?.SetTag("tenant", tenantId);
            }

            if (featureOptions.RiskBasedAuthenticationEnabled)
            {
                var riskDecision = await riskEvaluator.EvaluateAsync(httpContext, request, httpContext.RequestAborted);
                if (!riskDecision.Allowed)
                {
                    if (featureOptions.TelemetryEnabled)
                    {
                        AutoAuthTelemetry.TokenRejected.Add(1);
                    }

                    await auditSink.WriteAsync("autoauth.token.rejected.risk", new
                    {
                        clientId = request.ClientId,
                        grantType = request.GrantType,
                        tenantId,
                        reason = riskDecision.Reason
                    }, httpContext.RequestAborted);

                    return Results.BadRequest(new OpenIddictResponse
                    {
                        Error = Errors.AccessDenied,
                        ErrorDescription = riskDecision.Reason ?? "Token request rejected by risk policy."
                    });
                }
            }

            // Note: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this delegate won't be invoked.
            var application = await applicationManager.FindByClientIdAsync(request.ClientId!) ??
                throw new InvalidOperationException("The application details cannot be found in the database.");

            // Create the claims-based identity that will be used by OpenIddict to generate tokens.
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Use the client_id as the subject identifier, as recommended for client_credentials.
            identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application));
            identity.SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

            // Set the list of scopes granted to the client application in the access token.
            identity.SetScopes(request.GetScopes());

            var resources = new List<string>();
            await foreach (var resource in scopeManager.ListResourcesAsync(identity.GetScopes()))
            {
                resources.Add(resource);
            }
            identity.SetResources(resources);
            identity.SetDestinations(GetDestinations);

            if (featureOptions.SessionManagementEnabled &&
                sessionManager is IAutoAuthSessionRevocationStore revocationStore)
            {
                var subject = identity.GetClaim(Claims.Subject) ?? string.Empty;
                var revoked = await revocationStore.IsRevokedAsync(subject, request.ClientId, httpContext.RequestAborted);
                if (revoked)
                {
                    if (featureOptions.TelemetryEnabled)
                    {
                        AutoAuthTelemetry.TokenRejected.Add(1);
                    }

                    await auditSink.WriteAsync("autoauth.token.rejected.session_revoked", new
                    {
                        subject,
                        clientId = request.ClientId
                    }, httpContext.RequestAborted);

                    return Results.BadRequest(new OpenIddictResponse
                    {
                        Error = Errors.AccessDenied,
                        ErrorDescription = "Session has been revoked for this subject/client."
                    });
                }
            }

            await auditSink.WriteAsync("autoauth.token.issued", new
            {
                clientId = request.ClientId,
                grantType = request.GrantType,
                tenantId,
                scopes = identity.GetScopes().ToArray()
            }, httpContext.RequestAborted);

            await sessionManager.RecordTokenIssuedAsync(
                identity.GetClaim(Claims.Subject) ?? string.Empty,
                request.ClientId ?? string.Empty,
                DateTimeOffset.UtcNow,
                httpContext.RequestAborted);

            if (featureOptions.TelemetryEnabled)
            {
                AutoAuthTelemetry.TokenIssued.Add(1);
            }

            return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });

        return endpoints;
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // By default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, they must be attached to a destination that
        // specifies whether they should be included in access tokens, identity tokens, or both.
        return claim.Type switch
        {
            Claims.Name or Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            _ => [Destinations.AccessToken],
        };
    }
}
