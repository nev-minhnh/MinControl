using System.Text.Json;
using System.Text.Json.Serialization;

namespace MinControl.Core.Protocol;

[JsonPolymorphic(TypeDiscriminatorPropertyName = "type")]
[JsonDerivedType(typeof(LockNowCommand), "lock_now")]
[JsonDerivedType(typeof(UnlockCommand), "unlock")]
[JsonDerivedType(typeof(AddTimeCommand), "add_time")]
[JsonDerivedType(typeof(PauseLimitsCommand), "pause_limits")]
[JsonDerivedType(typeof(ScreenshotCommand), "screenshot")]
[JsonDerivedType(typeof(MessageCommand), "message")]
[JsonDerivedType(typeof(ApproveExeCommand), "approve_exe")]
[JsonDerivedType(typeof(KillProcessCommand), "kill_process")]
[JsonDerivedType(typeof(LogoffCommand), "logoff")]
[JsonDerivedType(typeof(RefreshCommand), "refresh")]
public abstract record Command(string CommandId);

public sealed record LockNowCommand(string CommandId, string UserSid, string? Until = null) : Command(CommandId);
public sealed record UnlockCommand(string CommandId, string UserSid) : Command(CommandId);
public sealed record AddTimeCommand(string CommandId, string UserSid, int Minutes, string? Group = null) : Command(CommandId);
public sealed record PauseLimitsCommand(string CommandId, string UserSid, string Until) : Command(CommandId);
public sealed record ScreenshotCommand(string CommandId, string? UserSid = null) : Command(CommandId);
public sealed record MessageCommand(string CommandId, string UserSid, string Text) : Command(CommandId);
public sealed record ApproveExeCommand(string CommandId, string UserSid, string Sha256, string Decision) : Command(CommandId);
public sealed record KillProcessCommand(string CommandId, string UserSid, int Pid, string? Exe = null) : Command(CommandId);
public sealed record LogoffCommand(string CommandId, string UserSid) : Command(CommandId);
public sealed record RefreshCommand(string CommandId) : Command(CommandId);

public static class ProtocolJson
{
    /// <summary>camelCase, nulls omitted (schemas use additionalProperties:false).</summary>
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        AllowOutOfOrderMetadataProperties = true, // "type" need not be the first property
    };
}
