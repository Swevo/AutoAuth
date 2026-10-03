using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AutoAuth.Features;

internal sealed class AutoAuthKeyRotationBackgroundService(
    AutoAuthFeatureOptions options,
    IAutoAuthKeyRotationHandler handler,
    ILogger<AutoAuthKeyRotationBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.KeyRotationEnabled || options.KeyRotationInterval is null)
        {
            return;
        }

        logger.LogInformation("AutoAuth key rotation scheduler started. Interval: {Interval}.", options.KeyRotationInterval);

        using var timer = new PeriodicTimer(options.KeyRotationInterval.Value);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await handler.RotateAsync(stoppingToken);
                logger.LogInformation("AutoAuth key rotation tick completed.");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "AutoAuth key rotation tick failed.");
            }
        }
    }
}
