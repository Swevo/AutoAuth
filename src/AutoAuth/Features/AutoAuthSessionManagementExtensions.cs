using Microsoft.Extensions.DependencyInjection;

namespace AutoAuth.Features;

public static class AutoAuthSessionManagementExtensions
{
    public static async Task RevokeAutoAuthSessionAsync(
        this IServiceProvider services,
        string subject,
        string? clientId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var store = services.GetService<IAutoAuthSessionRevocationStore>();
        if (store is null)
        {
            return;
        }

        await store.RevokeAsync(subject, clientId, cancellationToken);
    }
}
