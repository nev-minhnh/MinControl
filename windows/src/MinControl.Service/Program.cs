using MinControl.Core;
using MinControl.Core.Abstractions;
using MinControl.Service.Enforcement;
using MinControl.Service.Hosting;
using MinControl.Service.Ipc;
using MinControl.Service.Sessions;
using MinControl.Service.Tamper;
using MinControl.Service.Users;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using MinControl.Browser;
using MinControl.Monitoring;
using MinControl.NetGuard;

var builder = Host.CreateApplicationBuilder(args);

// Deployment config written by `MinControl.Setup install` (SYSTEM/Administrators-only ACL):
// { "ServerUrl": "...", "Browser": { "ChromeExtensionId": "...", "EdgeExtensionId": "..." } }
var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl");
builder.Configuration.AddJsonFile(Path.Combine(dataDir, "config.json"), optional: true, reloadOnChange: false);

builder.Services.AddWindowsService(o => o.ServiceName = ServiceInstaller.ServiceName);
if (WindowsServiceHelpers.IsWindowsService())
{
    // Replaces WindowsServiceLifetime (last registration wins) to receive SERVICE_CONTROL_SESSIONCHANGE.
    builder.Services.AddSingleton<IHostLifetime, MinControlServiceLifetime>();
}

// ---- Core (win-core): policy, engine, event sink/outbox, cloud link, uploader, approvals, clock.
builder.Services.AddMinControlCore(_ => { });

// ---- Session host (win-session)
builder.Services.AddSingleton<UserDirectory>();
builder.Services.AddSingleton<IUserDirectory>(sp => sp.GetRequiredService<UserDirectory>());
builder.Services.AddSingleton<SessionTracker>();
builder.Services.AddSingleton<SessionChannelRegistry>();
builder.Services.AddSingleton<SessionActions>();
builder.Services.AddSingleton<ISessionActions>(sp => sp.GetRequiredService<SessionActions>());
builder.Services.AddSingleton<IForegroundTracker, ForegroundTracker>();
builder.Services.AddHostedService<HelperSupervisor>();
builder.Services.AddHostedService<Enforcer>();
builder.Services.AddHostedService<TamperWatch>();
builder.Services.AddHostedService<CloudLinkHost>();

// ---- Monitoring / NetGuard / Browser. AppMonitorHost starts IAppMonitor; PolicyApplier calls INetGuard.ApplyAsync and
// IBrowserPolicyWriter.ApplyAsync/RemoveAsync at start, on PolicyChanged and on managed-set changes.
builder.Services.AddMinControlMonitoring();
builder.Services.AddMinControlNetGuard();
builder.Services.AddMinControlBrowser(o => builder.Configuration.GetSection("Browser").Bind(o));
builder.Services.AddHostedService<AppMonitorHost>();
// ---- banned words (API.md §17): foreground titles from the session helper + fresh history visits
builder.Services.AddSingleton<MinControl.Service.Keywords.KeywordGuard>();
builder.Services.AddSingleton<IKeywordGuard>(sp => sp.GetRequiredService<MinControl.Service.Keywords.KeywordGuard>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<MinControl.Service.Keywords.KeywordGuard>());
builder.Services.AddHostedService<PolicyApplier>();

// ---- diag.report sections owned by the host (API.md §14); the others are registered by their components.
builder.Services.AddSingleton<MinControl.Core.Diagnostics.IDiagnosticsSection>(sp => new ServiceDiagnostics(sp,
    sp.GetRequiredService<MinControl.Core.CoreOptions>(), sp.GetRequiredService<IClock>()));
builder.Services.AddSingleton<MinControl.Core.Diagnostics.IDiagnosticsSection>(sp => new UsersDiagnostics(sp.GetRequiredService<UserDirectory>(),
    sp.GetRequiredService<SessionTracker>(), sp.GetRequiredService<IPolicyProvider>()));

await builder.Build().RunAsync();
