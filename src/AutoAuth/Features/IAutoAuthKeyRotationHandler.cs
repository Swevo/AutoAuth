namespace AutoAuth.Features;

public interface IAutoAuthKeyRotationHandler
{
    ValueTask RotateAsync(CancellationToken cancellationToken);
}
