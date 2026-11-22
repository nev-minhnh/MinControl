using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Browser.Policy;

namespace MinControl.Setup;

/// <summary>
/// Deployment config written by <c>MinControl.Setup install</c> to <c>%ProgramData%\MinControl\config.json</c>
/// (inherits the SYSTEM/Administrators-only ACL of that folder, I7). Shape (IConfiguration-friendly so the
/// Service can bind it with <c>AddJsonFile</c>):
/// <code>{ "ServerUrl": "https://…", "Browser": { "ChromeExtensionId": "…", "EdgeExtensionId": "…" } }</code>
/// Unknown keys are preserved on rewrite.
/// </summary>
internal sealed class AgentConfig
{
    public const string FileName = "config.json";

    private readonly JsonObject _root;

    private AgentConfig(JsonObject root) => _root = root;

    public string? ServerUrl
    {
        get => (string?)_root["ServerUrl"];
        set => _root["ServerUrl"] = value;
    }

    public string? ChromeExtensionId
    {
        get => (string?)Browser["ChromeExtensionId"];
        set => Browser["ChromeExtensionId"] = value;
    }

    public string? EdgeExtensionId
    {
        get => (string?)Browser["EdgeExtensionId"];
        set => Browser["EdgeExtensionId"] = value;
    }

    private JsonObject Browser
    {
        get
        {
            if (_root["Browser"] is JsonObject b) return b;
            var created = new JsonObject();
            _root["Browser"] = created;
            return created;
        }
    }

    public static string PathIn(string dataRoot) => Path.Combine(dataRoot, FileName);

    public static AgentConfig Load(string dataRoot)
    {
        var path = PathIn(dataRoot);
        if (!File.Exists(path)) return new AgentConfig(new JsonObject());
        var node = JsonNode.Parse(File.ReadAllText(path, Encoding.UTF8));
        return new AgentConfig(node as JsonObject ?? throw new InvalidDataException($"{path} is not a JSON object"));
    }

    /// <summary>Writes atomically (temp file + replace) so the Service never reads a half-written file.</summary>
    public void Save(string dataRoot)
    {
        var path = PathIn(dataRoot);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, _root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>Returns an error message or null. Empty extension ids are allowed (no force-install yet).</summary>
    public string? Validate(bool allowHttp)
    {
        if (ServerUrl is not { Length: > 0 } s) return "server URL is not set (--server https://…)";
        if (!Uri.TryCreate(s, UriKind.Absolute, out var u) || !(u.Scheme == "https" || (allowHttp && u.Scheme == "http")))
            return "server URL must be an absolute https:// URL";
        if (u.AbsolutePath != "/" || !string.IsNullOrEmpty(u.Query)) return "server URL must not contain a path or query";
        foreach (var (name, id) in new[] { ("Chrome", ChromeExtensionId), ("Edge", EdgeExtensionId) })
            if (!string.IsNullOrEmpty(id) && !BrowserPolicyMapper.IsExtensionId(id))
                return $"{name} extension id must be 32 characters a-p";
        return null;
    }
}
