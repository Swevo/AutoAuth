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
}
