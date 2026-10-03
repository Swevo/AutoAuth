using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;

namespace AutoAuth.Features;

public interface IAutoAuthTenantResolver
{
    ValueTask<string?> ResolveTenantAsync(HttpContext httpContext, CancellationToken cancellationToken);
}

public interface IAutoAuthRiskEvaluator
{
    ValueTask<AutoAuthRiskEvaluation> EvaluateAsync(HttpContext httpContext, OpenIddictRequest request, CancellationToken cancellationToken);
}

public sealed record AutoAuthRiskEvaluation(bool Allowed, string? Reason = null)
{
    public static AutoAuthRiskEvaluation Allow() => new(true);
    public static AutoAuthRiskEvaluation Deny(string reason) => new(false, reason);
}

public interface IAutoAuthAuditSink
{
    ValueTask WriteAsync(string eventType, object payload, CancellationToken cancellationToken);
}

public interface IAutoAuthSessionManager
{
    ValueTask RecordTokenIssuedAsync(string subject, string clientId, DateTimeOffset issuedAtUtc, CancellationToken cancellationToken);
}
