using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace AutoAuth.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InsecureConfigurationAnalyzer : DiagnosticAnalyzer
{
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics
        => [DiagnosticDescriptors.DevelopmentCertificatesUsed, DiagnosticDescriptors.PkceDisabled];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation)
        {
            return;
        }

        var symbol = context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol as IMethodSymbol;
        if (symbol is null)
        {
            return;
        }

        if (symbol.Name == "UseDevelopmentCertificates")
        {
            context.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.DevelopmentCertificatesUsed,
                invocation.GetLocation()));
            return;
        }

        if (symbol.Name == "RequireProofKeyForCodeExchange")
        {
            var firstArg = invocation.ArgumentList.Arguments.FirstOrDefault();
            if (firstArg is null)
            {
                return;
            }

            var constant = context.SemanticModel.GetConstantValue(firstArg.Expression, context.CancellationToken);
            if (constant.HasValue && constant.Value is bool enabled && !enabled)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    DiagnosticDescriptors.PkceDisabled,
                    firstArg.GetLocation()));
            }
        }
    }
}
