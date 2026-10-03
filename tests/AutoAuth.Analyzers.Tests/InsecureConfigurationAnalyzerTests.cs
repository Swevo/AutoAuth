using Xunit;

namespace AutoAuth.Analyzers.Tests;

public class InsecureConfigurationAnalyzerTests
{
    [Fact]
    public async Task Reports_AAUTH001_For_UseDevelopmentCertificates()
    {
        const string source = """
            namespace AutoAuth
            {
                public sealed class AutoAuthServerOptions
                {
                    public AutoAuthServerOptions UseDevelopmentCertificates() => this;
                }
            }

            public class Demo
            {
                public void Configure(AutoAuth.AutoAuthServerOptions options)
                {
                    options.UseDevelopmentCertificates();
                }
            }
            """;

        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(source, new InsecureConfigurationAnalyzer());
        Assert.Contains(diagnostics, d => d.Id == "AAUTH001");
    }

    [Fact]
    public async Task Reports_AAUTH002_When_Pkce_Disabled()
    {
        const string source = """
            namespace AutoAuth
            {
                public sealed class AutoAuthServerOptions
                {
                    public AutoAuthServerOptions RequireProofKeyForCodeExchange(bool value = true) => this;
                }
            }

            public class Demo
            {
                public void Configure(AutoAuth.AutoAuthServerOptions options)
                {
                    options.RequireProofKeyForCodeExchange(false);
                }
            }
            """;

        var diagnostics = await AnalyzerTestHelper.GetDiagnosticsAsync(source, new InsecureConfigurationAnalyzer());
        Assert.Contains(diagnostics, d => d.Id == "AAUTH002");
    }
}
