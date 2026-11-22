using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Storage;

namespace MinControl.Core.Cloud;

/// <summary>PUT /v1/device/inventory (API.md §11) with the shared upload token. Stateless; the caller schedules.</summary>
public sealed class InventoryUploader
{
    public const int MaxBytes = 512 * 1024;

    private readonly HttpClient _http;
    private readonly StateStore _store;
    private readonly UploadTokenHolder _token;
    private readonly IClock _clock;
    private readonly Func<string?> _serverUrl;
    private readonly ILogger _log;

    public InventoryUploader(HttpClient http, StateStore store, UploadTokenHolder token, IClock clock,
        Func<string?> serverUrl, ILogger<InventoryUploader>? log = null)
    {
        _http = http; _store = store; _token = token; _clock = clock; _serverUrl = serverUrl;
        _log = log ?? (ILogger)NullLogger.Instance;
    }

    public string? DeviceId => _store.GetMeta(StateStore.MetaKeys.DeviceId);

    public async Task<UploadResult> PutAsync(string json, CancellationToken ct)
    {
        var token = _token.Valid(_clock.UtcNow);
        var baseUrl = _serverUrl();
        if (token is null || baseUrl is null) return UploadResult.NoToken;
        if (Encoding.UTF8.GetByteCount(json) > MaxBytes) { _log.LogError("inventory too large; not sent"); return UploadResult.Done; }
        using var req = new HttpRequestMessage(HttpMethod.Put, new Uri(new Uri(baseUrl), "/v1/device/inventory"))
        { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        try
        {
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.IsSuccessStatusCode) return UploadResult.Done;
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { _token.Clear(); return UploadResult.Unauthorized; }
            if ((int)resp.StatusCode is 400 or 413 or 422) { _log.LogError("inventory rejected ({Status})", (int)resp.StatusCode); return UploadResult.Done; }
            return UploadResult.Retry;
        }
        catch (HttpRequestException e) { _log.LogInformation("inventory upload failed: {Msg}", e.Message); return UploadResult.Retry; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return UploadResult.Retry; }
    }
}
