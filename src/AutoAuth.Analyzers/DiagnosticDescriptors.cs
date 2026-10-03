using Microsoft.CodeAnalysis;

namespace AutoAuth.Analyzers;

internal static class DiagnosticDescriptors
{
    public static readonly DiagnosticDescriptor DevelopmentCertificatesUsed = new(
        id: "AAUTH001",
        title: "Avoid UseDevelopmentCertificates in production code",
        messageFormat: "UseDevelopmentCertificates() is intended for local/dev testing only",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Development certificates are ephemeral and unsuitable for production token signing.");

    public static readonly DiagnosticDescriptor PkceDisabled = new(
        id: "AAUTH002",
        title: "Do not disable PKCE",
        messageFormat: "RequireProofKeyForCodeExchange(false) weakens authorization_code flow security",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "PKCE should stay enabled for authorization_code requests unless you have a very specific security-reviewed exception.");
}
