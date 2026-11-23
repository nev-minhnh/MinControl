using System.Runtime.InteropServices;

namespace MinControl.Session;

/// <summary>
/// Closes what the service asked for (banned word, API.md §17), with checks so a stale request never hits the wrong
/// window: the window must still exist and belong to the expected process; for a browser tab it must also be the
/// foreground window, because Ctrl+W goes to whatever has the keyboard focus.
/// </summary>
internal static class WindowCloser
{
    public static (bool Ok, string? Error) Close(IntPtr hwnd, int pid, bool tab)
    {
        if (hwnd == IntPtr.Zero || !Native.IsWindow(hwnd)) return (false, "no_window");
        Native.GetWindowThreadProcessId(hwnd, out var owner);
        if (owner != pid) return (false, "pid_mismatch");
        if (!tab)
            return Native.PostMessage(hwnd, Native.WM_CLOSE, IntPtr.Zero, IntPtr.Zero) ? (true, null) : (false, "post_failed");

        if (Native.GetForegroundWindow() != hwnd) return (false, "not_foreground");
        // Release modifiers the child may be holding (Shift+Ctrl+W would close the whole window, Alt changes menus).
        var inputs = new List<Native.INPUT>();
        foreach (var vk in (ReadOnlySpan<ushort>)[Native.VK_SHIFT, Native.VK_MENU, Native.VK_LWIN, Native.VK_RWIN])
            if (Native.GetAsyncKeyState(vk) < 0) inputs.Add(Native.Key(vk, up: true));
        inputs.Add(Native.Key(Native.VK_CONTROL, up: false));
        inputs.Add(Native.Key(Native.VK_W, up: false));
        inputs.Add(Native.Key(Native.VK_W, up: true));
        inputs.Add(Native.Key(Native.VK_CONTROL, up: true));
        var arr = inputs.ToArray();
        var sent = Native.SendInput((uint)arr.Length, arr, Marshal.SizeOf<Native.INPUT>());
        return sent == arr.Length ? (true, null) : (false, "sendinput_" + Marshal.GetLastWin32Error());
    }
}
