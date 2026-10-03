using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace AutoAuth.Features;

internal static class AutoAuthTelemetry
{
    private static readonly Meter Meter = new("Swevo.AutoAuth");
    public static readonly ActivitySource ActivitySource = new("Swevo.AutoAuth");
    public static readonly Counter<long> TokenRequests = Meter.CreateCounter<long>("autoauth.token.requests");
    public static readonly Counter<long> TokenIssued = Meter.CreateCounter<long>("autoauth.token.issued");
    public static readonly Counter<long> TokenRejected = Meter.CreateCounter<long>("autoauth.token.rejected");
}
