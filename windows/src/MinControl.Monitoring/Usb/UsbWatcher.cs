using System.Collections.Concurrent;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Monitoring.Native;
using Microsoft.Extensions.Logging;

namespace MinControl.Monitoring.Usb;

/// <summary>
/// USB monitoring via WMI (read-only):
/// <list type="bullet">
/// <item><c>Win32_VolumeChangeEvent</c> → removable volumes (label, disk model, VID/PID via the parent USB devnode);</item>
/// <item><c>__InstanceCreation/DeletionEvent</c> on <c>Win32_PnPEntity</c> USB\VID_* → other USB devices (phones,
/// cameras, ...). Mass-storage (USBSTOR), hubs and composite-interface children are skipped there because the
/// volume event already reports them.</item>
/// </list>
/// Emitted only while at least one managed user has <c>monitoring.usb</c> enabled. USB is machine-wide, so
/// events carry no userSid.
/// </summary>
internal sealed partial class UsbWatcher : IMonitorComponent
{
    private readonly IUserDirectory _users;
    private readonly IPolicyProvider _policy;
    private readonly IEventSink _sink;
    private readonly ILogger _log;
    private readonly ConcurrentDictionary<string, (string Name, string? Vid, string? Pid, string? Label)> _volumes =
        new(StringComparer.OrdinalIgnoreCase);
    private ManagementEventWatcher? _volumeWatcher;
    private ManagementEventWatcher? _deviceWatcher;

    [GeneratedRegex(@"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})")]
    private static partial Regex VidPidRegex();

    private static readonly HashSet<string> SkipServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "USBSTOR", "UASPStor", "usbhub", "USBHUB3", "usbccgp", "WUDFRd_Hub",
    };

    public UsbWatcher(IUserDirectory users, IPolicyProvider policy, IEventSink sink, ILogger log)
    {
        _users = users;
        _policy = policy;
        _sink = sink;
        _log = log;
    }

    public void Start()
    {
        _volumeWatcher = new ManagementEventWatcher(
            new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3"));
        _volumeWatcher.EventArrived += (_, e) => Safe(() => OnVolume(e.NewEvent));
        _volumeWatcher.Start();

        _deviceWatcher = new ManagementEventWatcher(new WqlEventQuery(
            "SELECT * FROM __InstanceOperationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_PnPEntity' " +
            "AND TargetInstance.PNPDeviceID LIKE 'USB\\\\VID[_]%'"));
        _deviceWatcher.EventArrived += (_, e) => Safe(() => OnDevice(e.NewEvent));
        _deviceWatcher.Start();
    }

    public void Stop()
    {
        foreach (var w in new[] { _volumeWatcher, _deviceWatcher })
        {
            try { w?.Stop(); w?.Dispose(); } catch { /* ignore */ }
        }
        _volumeWatcher = _deviceWatcher = null;
    }

    private bool Enabled()
    {
        var p = _policy.Current;
        if (p is null) return false;
        foreach (var sid in _users.ManagedSids)
            if (p.Users.TryGetValue(sid, out var up) && up.Monitoring.Usb) return true;
        return false;
    }

    private void Safe(Action a)
    {
        try { a(); } catch (Exception ex) { _log.LogWarning(ex, "USB event handling failed"); }
    }

    // ---------------------------------------------------------------- volumes

    private void OnVolume(ManagementBaseObject ev)
    {
        var drive = ev["DriveName"] as string;                       // "E:"
        if (string.IsNullOrEmpty(drive)) return;
        int type = Convert.ToInt32(ev["EventType"]);

        if (type == 2)
        {
            DriveInfo di;
            try { di = new DriveInfo(drive + "\\"); } catch { return; }
            string? label = null;
            try { label = di.IsReady ? di.VolumeLabel : null; } catch { /* not ready */ }

            var (model, pnp) = DiskOf(drive);
            string? vid = null, pid = null;
            bool usb = false;
            if (pnp is not null && UsbParentId(pnp) is { } parentId)
            {
                usb = true;
                var m = VidPidRegex().Match(parentId);
                if (m.Success) { vid = m.Groups[1].Value; pid = m.Groups[2].Value; }
            }
            DriveType dt;
            try { dt = di.DriveType; } catch { dt = DriveType.Unknown; }
            if (!usb && dt != DriveType.Removable) return;          // internal disks / mounted ISOs

            string name = model ?? $"Removable drive {drive}";
            _volumes[drive] = (name, vid, pid, label);
            if (Enabled()) _sink.Emit(EventTypes.UsbAttached, null, EventData.Usb(name, vid, pid, label));
        }
        else if (type == 3 && _volumes.TryRemove(drive, out var v))
        {
            if (Enabled()) _sink.Emit(EventTypes.UsbDetached, null, EventData.Usb(v.Name, v.Vid, v.Pid, v.Label));
        }
    }

    /// <summary>Logical disk → partition → physical disk (model, PNPDeviceID).</summary>
    private static (string? Model, string? PnpId) DiskOf(string drive)
    {
        try
        {
            using var parts = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{drive}'}} WHERE AssocClass = Win32_LogicalDiskToPartition");
            foreach (ManagementObject part in parts.Get())
            {
                using (part)
                {
                    using var disks = new ManagementObjectSearcher(
                        $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part["DeviceID"]}'}} WHERE AssocClass = Win32_DiskDriveToDiskPartition");
                    foreach (ManagementObject disk in disks.Get())
                    {
                        using (disk) return (disk["Model"] as string, disk["PNPDeviceID"] as string);
                    }
                }
            }
        }
        catch { /* WMI hiccup: report without ids */ }
        return (null, null);
    }

    /// <summary>Walks up the device tree from a disk devnode to the first USB\VID_ ancestor.</summary>
    private static string? UsbParentId(string pnpId)
    {
        if (NativeMethods.CM_Locate_DevNodeW(out uint dev, pnpId, 0) != NativeMethods.CR_SUCCESS) return null;
        var sb = new StringBuilder(512);
        for (int depth = 0; depth < 6; depth++)
        {
            if (NativeMethods.CM_Get_Parent(out uint parent, dev, 0) != NativeMethods.CR_SUCCESS) return null;
            sb.Clear();
            if (NativeMethods.CM_Get_Device_IDW(parent, sb, sb.Capacity, 0) != NativeMethods.CR_SUCCESS) return null;
            var id = sb.ToString();
            if (id.StartsWith(@"USB\VID_", StringComparison.OrdinalIgnoreCase)) return id;
            dev = parent;
        }
        return null;
    }

    // ---------------------------------------------------------------- other USB devices

    private void OnDevice(ManagementBaseObject ev)
    {
        string cls = ev.ClassPath.ClassName;
        bool created = cls == "__InstanceCreationEvent";
        bool deleted = cls == "__InstanceDeletionEvent";
        if (!created && !deleted) return;
        if (ev["TargetInstance"] is not ManagementBaseObject target) return;

        var id = target["PNPDeviceID"] as string ?? "";
        if (id.Contains("&MI_", StringComparison.OrdinalIgnoreCase)) return;      // interface of a composite device
        if (target["Service"] is string svc && SkipServices.Contains(svc)) return;
        if (id.Contains("ROOT_HUB", StringComparison.OrdinalIgnoreCase)) return;

        var name = (target["Name"] as string) ?? (target["Description"] as string) ?? id;
        var m = VidPidRegex().Match(id);
        if (!Enabled()) return;
        _sink.Emit(created ? EventTypes.UsbAttached : EventTypes.UsbDetached, null,
            EventData.Usb(name, m.Success ? m.Groups[1].Value : null, m.Success ? m.Groups[2].Value : null, null));
    }
}
