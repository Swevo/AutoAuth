using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;

namespace AutoAuth.Features;

internal sealed class DefaultTenantResolver(AutoAuthFeatureOptions options) : IAutoAuthTenantResolver
{
    public ValueTask<string?> ResolveTenantAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        if (!options.MultiTenantEnabled)
        {
            return ValueTask.FromResult<string?>(null);
        }

        if (httpContext.Request.Headers.TryGetValue(options.TenantHeaderName, out var values))
        {
            var value = values.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return ValueTask.FromResult<string?>(value.Trim());
            }
        }

        return ValueTask.FromResult<string?>(null);
    }
}

internal sealed class DefaultRiskEvaluator(AutoAuthFeatureOptions options) : IAutoAuthRiskEvaluator
{
    public ValueTask<AutoAuthRiskEvaluation> EvaluateAsync(HttpContext httpContext, OpenIddictRequest request, CancellationToken cancellationToken)
    {
        if (!options.RiskBasedAuthenticationEnabled)
        {
            return ValueTask.FromResult(AutoAuthRiskEvaluation.Allow());
        }

        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp) && options.DeniedIpAddresses.Contains(remoteIp))
        {
            return ValueTask.FromResult(AutoAuthRiskEvaluation.Deny($"Token request blocked for IP {remoteIp}."));
        }

        return ValueTask.FromResult(AutoAuthRiskEvaluation.Allow());
    }
}

internal sealed class DefaultAuditSink(AutoAuthFeatureOptions options) : IAutoAuthAuditSink
{
    public List<(string EventType, string JsonPayload, DateTimeOffset OccurredAtUtc)> Events { get; } = [];

    public ValueTask WriteAsync(string eventType, object payload, CancellationToken cancellationToken)
    {
        var jsonPayload = options.ComplianceAuditEnabled
            ? AutoAuthAuditRedactor.RedactToJson(payload, options.RedactedFieldNames)
            : System.Text.Json.JsonSerializer.Serialize(payload);

        Events.Add((eventType, jsonPayload, DateTimeOffset.UtcNow));
        return ValueTask.CompletedTask;
    }
}

internal sealed class DefaultSessionManager : IAutoAuthSessionManager, IAutoAuthSessionRevocationStore
{
    public List<(string Subject, string ClientId, DateTimeOffset IssuedAtUtc)> IssuedTokens { get; } = [];
    private readonly HashSet<string> _revoked = new(StringComparer.OrdinalIgnoreCase);

    public ValueTask RecordTokenIssuedAsync(string subject, string clientId, DateTimeOffset issuedAtUtc, CancellationToken cancellationToken)
    {
        IssuedTokens.Add((subject, clientId, issuedAtUtc));
        return ValueTask.CompletedTask;
    }

    public ValueTask RevokeAsync(string subject, string? clientId, CancellationToken cancellationToken)
    {
        var key = $"{subject}|{clientId ?? "*"}";
        _revoked.Add(key);
        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> IsRevokedAsync(string subject, string? clientId, CancellationToken cancellationToken)
    {
        var subjectWildcard = $"{subject}|*";
        var exact = $"{subject}|{clientId ?? "*"}";
        var revoked = _revoked.Contains(subjectWildcard) || _revoked.Contains(exact);
        return ValueTask.FromResult(revoked);
    }
}

internal sealed class NullKeyRotationHandler : IAutoAuthKeyRotationHandler
{
    public ValueTask RotateAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;
}
