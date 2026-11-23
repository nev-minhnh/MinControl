namespace MinControl.Core.Abstractions;

/// <summary>Light signal that something shown in the device <c>state</c> changed (foreground app, lock/unlock,
/// logon/logoff, quota threshold). CloudLink debounces it and sends <c>state</c> over the WebSocket (API.md section 15).</summary>
public interface IStateChangeNotifier
{
    event Action? Changed;
    void Notify();
}

public sealed class StateChangeNotifier : IStateChangeNotifier
{
    public event Action? Changed;

    public void Notify()
    {
        try { Changed?.Invoke(); } catch (Exception) { /* a subscriber must never break the caller */ }
    }
}
