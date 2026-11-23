using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Service.Ipc;
using MinControl.Service.Native;
using MinControl.Service.Users;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace MinControl.Service.Sessions;

/// <summary>Starts MinControl.Session.exe as SYSTEM inside a user session (spec 8.1).</summary>
internal static class HelperLauncher
{
    public const string HelperExeName = "MinControl.Session.exe";

    public static string HelperPath => Path.Combine(AppContext.BaseDirectory, HelperExeName);

    /// <summary>Duplicates the service's SYSTEM token, sets TokenSessionId and calls CreateProcessAsUser on
    /// WinSta0\Default. The child runs as SYSTEM, so the (standard) user cannot open or kill it.</summary>
    public static (SafeProcessHandle Process, int Pid) Launch(int sessionId)
    {
        var exe = HelperPath;
        if (!File.Exists(exe)) throw new FileNotFoundException("session helper missing", exe);

        if (!Win32.OpenProcessTokenRaw(Win32.GetCurrentProcess(), Win32.TOKEN_DUPLICATE | Win32.TOKEN_QUERY, out var self))
            throw new System.ComponentModel.Win32Exception();
        using (self)
        {
            if (!Win32.DuplicateTokenEx(self, Win32.MAXIMUM_ALLOWED, IntPtr.Zero, Win32.SecurityImpersonation,
                    Win32.TokenPrimary, out var primary))
                throw new System.ComponentModel.Win32Exception();
            using (primary)
            {
                var sid = sessionId;
                if (!Win32.SetTokenInformation(primary, Win32.TokenSessionId, ref sid, sizeof(int))) // needs SeTcbPrivilege
                    throw new System.ComponentModel.Win32Exception();

                var desktop = Marshal.StringToHGlobalUni(@"WinSta0\Default");
                try
                {
                    var si = new Win32.STARTUPINFO { cb = Marshal.SizeOf<Win32.STARTUPINFO>(), lpDesktop = desktop };
                    var cmd = $"\"{exe}\" --session {sessionId} --service-pid {Environment.ProcessId}\0".ToCharArray();
                    if (!Win32.CreateProcessAsUser(primary, exe, cmd, IntPtr.Zero, IntPtr.Zero, false,
                            Win32.CREATE_NEW_PROCESS_GROUP, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out var pi))
                        throw new System.ComponentModel.Win32Exception();
                    Win32.CloseHandle(pi.hThread);
                    return (new SafeProcessHandle(pi.hProcess, ownsHandle: true), pi.dwProcessId);
                }
                finally { Marshal.FreeHGlobal(desktop); }
            }
        }
    }

    public static bool HasExited(SafeProcessHandle process) => Win32.WaitForSingleObject(process, 0) != Win32.WAIT_TIMEOUT;

    /// <summary>Terminates helper instances left over from a previous service run (only our own image path).</summary>
    public static void KillOrphans(ILogger log)
    {
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(HelperExeName)))
        {
            using (p)
            {
                try
                {
                    using var h = Win32.OpenProcess(Win32.PROCESS_TERMINATE | Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
                    if (h.IsInvalid) continue;
                    if (!string.Equals(Win32.ImagePath(h), HelperPath, StringComparison.OrdinalIgnoreCase)) continue;
                    if (UserDirectory.SidOfProcess(h) != "S-1-5-18") continue; // only our SYSTEM instances
                    Win32.TerminateProcess(h, 0);
                    log.LogInformation("terminated orphan session helper pid {Pid}", p.Id);
                }
                catch (Exception e) { log.LogDebug(e, "orphan check {Pid}", p.Id); }
            }
        }
    }
}

/// <summary>Keeps exactly one helper + pipe per managed session. Restarts an exited helper within ~1 s;
/// if a helper has not been healthy for 30 s: tamper.agent_killed + logoff (I4). Never touches admin or
/// unmanaged sessions (I1/I2).</summary>
internal sealed class HelperSupervisor(
    SessionTracker sessions,
    UserDirectory users,
    SessionChannelRegistry channels,
    IEventSink events,
    IClock clock,
    ILogger<HelperSupervisor> log) : BackgroundService
{
    public const long AbsentLimitMs = 30_000, StaleMs = 10_000, RelaunchMinIntervalMs = 1_000;

    private sealed class HelperState
    {
        public SafeProcessHandle? Process;
        public volatile int Pid;
        public long LastLaunchMono = long.MinValue / 2;
        public long LastHealthyMono;
        public long? LastLogoffMono;
        public bool TamperRaised;
    }

    private readonly Dictionary<int, HelperState> _helpers = new();

    public int? HelperPid(int sessionId)
    {
        lock (_helpers) return _helpers.TryGetValue(sessionId, out var s) && s.Pid != 0 ? s.Pid : null;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Yield();
        sessions.EnsureInitialized();
        HelperLauncher.KillOrphans(log);
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));
        do
        {
            try { await TickAsync(ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { log.LogError(e, "supervisor tick failed"); }
        } while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
    }

    private async Task TickAsync(CancellationToken ct)
    {
        var now = clock.MonotonicMs;
        var desired = sessions.Sessions.Where(s => s.Sid is not null && users.IsManaged(s.Sid)).ToList();
        var desiredIds = desired.Select(s => s.SessionId).ToHashSet();

        foreach (var s in desired)
        {
            HelperState state;
            lock (_helpers)
            {
                if (!_helpers.TryGetValue(s.SessionId, out state!))
                    _helpers[s.SessionId] = state = new HelperState { LastHealthyMono = now };
            }
            var sessionId = s.SessionId;
            var channel = channels.GetOrStart(sessionId, () => HelperPid(sessionId));

            if (state.Process is not null && HelperLauncher.HasExited(state.Process))
            {
                log.LogWarning("session helper in session {Session} exited (pid {Pid})", sessionId, state.Pid);
                state.Process.Dispose();
                state.Process = null;
                state.Pid = 0;
            }
            if (state.Process is null && now - state.LastLaunchMono >= RelaunchMinIntervalMs)
            {
                state.LastLaunchMono = now;
                try
                {
                    var (process, pid) = HelperLauncher.Launch(sessionId);
                    state.Process = process;
                    state.Pid = pid;
                    log.LogInformation("session helper started in session {Session} (pid {Pid})", sessionId, pid);
                }
                catch (Exception e) { log.LogWarning(e, "cannot start session helper in session {Session}", sessionId); }
            }

            var healthy = state.Process is not null && channel.Connected && now - channel.LastSeenMono < StaleMs;
            if (healthy)
            {
                state.LastHealthyMono = now;
                state.TamperRaised = false;
                state.LastLogoffMono = null;
                continue;
            }
            if (now - state.LastHealthyMono <= AbsentLimitMs) continue;

            if (!state.TamperRaised)
            {
                state.TamperRaised = true;
                log.LogWarning("session helper absent > 30 s in session {Session}: logging off", sessionId);
                events.Emit(EventTypes.TamperAgentKilled, s.Sid,
                    new JsonObject { ["detail"] = TamperText.HelperKilled, ["exe"] = HelperLauncher.HelperExeName });
            }
            if (state.LastLogoffMono is null || now - state.LastLogoffMono.Value >= AbsentLimitMs)
            {
                state.LastLogoffMono = now;
                if (users.IsManaged(s.Sid!) && !Wts.Logoff(sessionId)) // re-checked right before acting (I2)
                    log.LogError("WTSLogoffSession({Session}) failed: {Err}", sessionId, Marshal.GetLastWin32Error());
            }
        }

        List<(int Id, HelperState State)> gone;
        lock (_helpers) gone = _helpers.Where(kv => !desiredIds.Contains(kv.Key)).Select(kv => (kv.Key, kv.Value)).ToList();
        foreach (var (id, state) in gone)
        {
            // Session ended, or the user is no longer managed (became admin / removed from policy):
            // stop our own SYSTEM helper there.
            if (state.Process is not null)
            {
                if (!HelperLauncher.HasExited(state.Process)) Win32.TerminateProcess(state.Process, 0);
                state.Process.Dispose();
            }
            lock (_helpers) _helpers.Remove(id);
            await channels.StopAsync(id).ConfigureAwait(false);
        }
        foreach (var id in channels.SessionIds.Where(id => !desiredIds.Contains(id)))
            await channels.StopAsync(id).ConfigureAwait(false);
        _ = ct;
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        await base.StopAsync(ct).ConfigureAwait(false);
        lock (_helpers)
        {
            foreach (var s in _helpers.Values) s.Process?.Dispose(); // helpers keep running; next start kills orphans
            _helpers.Clear();
        }
    }
}
