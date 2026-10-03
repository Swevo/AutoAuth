namespace AutoAuth.Features;

/// <summary>
/// Optional feature flags and extension hooks used to incrementally compose higher-level auth capabilities.
/// </summary>
public sealed class AutoAuthFeatureOptions
{
    internal bool PasskeysEnabled { get; set; }
    internal bool MultiTenantEnabled { get; set; }
    internal bool KeyRotationEnabled { get; set; }
    internal TimeSpan? KeyRotationInterval { get; set; }
    internal bool RiskBasedAuthenticationEnabled { get; set; }
    internal bool SessionManagementEnabled { get; set; }
    internal bool ComplianceAuditEnabled { get; set; }
    internal bool TelemetryEnabled { get; set; } = true;
    internal string TenantHeaderName { get; set; } = "X-Tenant-Id";
    internal HashSet<string> DeniedIpAddresses { get; } = new(StringComparer.OrdinalIgnoreCase);
    internal HashSet<string> RedactedFieldNames { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "client_secret",
        "refresh_token",
        "access_token",
        "password",
        "token"
    };
}
