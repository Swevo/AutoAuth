# Swevo.AutoAuth.Analyzers

Security-focused Roslyn analyzers for AutoAuth configuration.

## Rules

- **AAUTH001** — warns when `UseDevelopmentCertificates()` is used.
- **AAUTH002** — warns when `RequireProofKeyForCodeExchange(false)` disables PKCE.
