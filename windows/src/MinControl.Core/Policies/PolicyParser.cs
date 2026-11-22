using System.Text.Json;
using System.Text.Json.Serialization;
using MinControl.Core.Policy;
using MinControl.Core.Protocol;

namespace MinControl.Core.Policies;

public sealed record PolicyParseResult(DevicePolicy? Policy, string? Error, string? Detail)
{
    public bool Ok => Policy is not null;
}

/// <summary>JSON → <see cref="DevicePolicy"/>: schema check, strict typed deserialisation, then semantic validation.</summary>
public static class PolicyParser
{
    /// <summary>ProtocolJson.Options plus strictness: unknown members and missing required members fail.</summary>
    public static readonly JsonSerializerOptions StrictOptions = new(ProtocolJson.Options)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
    };

    public static PolicyParseResult Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return Parse(doc.RootElement);
        }
        catch (JsonException e) { return new(null, "invalid_body", Trim(e.Message)); }
    }

    public static PolicyParseResult Parse(JsonElement body, SchemaValidator? schemas = null)
    {
        schemas ??= SchemaValidator.Shared;
        if (!schemas.IsValid("policy", body)) return new(null, "invalid_body", "policy does not match policy.schema.json");
        DevicePolicy? policy;
        try { policy = body.Deserialize<DevicePolicy>(StrictOptions); }
        catch (Exception e) when (e is JsonException or NotSupportedException or InvalidOperationException)
        { return new(null, "invalid_body", Trim(e.Message)); }
        if (policy is null) return new(null, "invalid_body", "empty policy");
        var errors = PolicyValidator.Validate(policy);
        return errors.Count == 0 ? new(policy, null, null) : new(null, "invalid_body", Trim(string.Join("; ", errors)));
    }

    internal static string Trim(string s) => s.Length <= 500 ? s : s[..497] + "...";
}
