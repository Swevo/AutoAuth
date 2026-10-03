using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;

namespace AutoAuth.Features;

internal sealed class DefaultTenantResolver : IAutoAuthTenantResolver
{
    public ValueTask<string?> ResolveTenantAsync(HttpContext httpContext, CancellationToken cancellationToken)
        => ValueTask.FromResult<string?>(null);
}

internal sealed class DefaultRiskEvaluator : IAutoAuthRiskEvaluator
{
    public ValueTask<AutoAuthRiskEvaluation> EvaluateAsync(HttpContext httpContext, OpenIddictRequest request, CancellationToken cancellationToken)
        => ValueTask.FromResult(AutoAuthRiskEvaluation.Allow());
}

internal sealed class NullAuditSink : IAutoAuthAuditSink
{
    public ValueTask WriteAsync(string eventType, object payload, CancellationToken cancellationToken)
        => ValueTask.CompletedTask;
}

internal sealed class NullSessionManager : IAutoAuthSessionManager
{
    public ValueTask RecordTokenIssuedAsync(string subject, string clientId, DateTimeOffset issuedAtUtc, CancellationToken cancellationToken)
        => ValueTask.CompletedTask;
}
