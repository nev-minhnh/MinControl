using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "MinControl");
builder.Services.AddHostedService<SkeletonWorker>();
await builder.Build().RunAsync();

internal sealed class SkeletonWorker(ILogger<SkeletonWorker> logger) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("MinControl service skeleton");
        return Task.CompletedTask;
    }
}
