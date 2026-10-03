namespace AutoAuth.Features;

public interface IAutoAuthSessionRevocationStore
{
    ValueTask RevokeAsync(string subject, string? clientId, CancellationToken cancellationToken);
    ValueTask<bool> IsRevokedAsync(string subject, string? clientId, CancellationToken cancellationToken);
}
