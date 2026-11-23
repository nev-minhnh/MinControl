using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using MinControl.Core.Crypto;
using MinControl.Core.Util;
using MinControl.Setup;
using Xunit;

namespace MinControl.Core.Tests;

public sealed class SetupDeregistrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mc-setup-" + Guid.NewGuid().ToString("N"));

    public SetupDeregistrationTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void SignatureString_has_the_exact_format()
    {
        Assert.Equal("deregister|" + TestData.DeviceId + "|1732363200", Deregistration.SignatureString(TestData.DeviceId, 1732363200));
    }

    [Fact]
    public void Body_signature_verifies_with_the_device_public_key()
    {
        using var identity = new DeviceIdentity(Path.Combine(_dir, "device.key"), new NoopKeyProtector());
        var pub = identity.CreateNew();
        var body = Deregistration.BuildBody(identity, TestData.DeviceId, 1732363200);

        Assert.Equal(TestData.DeviceId, (string?)body["deviceId"]);
        Assert.Equal(1732363200L, (long?)body["ts"]);
        Assert.True(Base64Url.TryDecode((string?)body["sig"], out var sig));
        var data = Encoding.UTF8.GetBytes("deregister|" + TestData.DeviceId + "|1732363200");
        Assert.True(Signatures.Verify("ed25519", pub, data, sig));
        Assert.False(Signatures.Verify("ed25519", pub, Encoding.UTF8.GetBytes("deregister|" + TestData.OtherDeviceId + "|1732363200"), sig));
    }

    private sealed class Capture(HttpStatusCode code) : HttpMessageHandler
    {
        public string? Url, Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Url = request.RequestUri!.ToString();
            Body = await request.Content!.ReadAsStringAsync(ct);
            return new HttpResponseMessage(code);
        }
    }

    [Fact]
    public async Task TrySend_posts_to_the_deregister_path_and_reports_failure_without_throwing()
    {
        using var identity = new DeviceIdentity(Path.Combine(_dir, "device.key"), new NoopKeyProtector());
        identity.CreateNew();
        var ok = new Capture(HttpStatusCode.OK);
        Assert.Null(await Deregistration.TrySendAsync(new Uri("https://example.test"), identity, TestData.DeviceId, DateTimeOffset.FromUnixTimeSeconds(1732363200), ok));
        Assert.Equal("https://example.test/v1/device/deregister", ok.Url);
        Assert.Equal(1732363200L, (long?)JsonNode.Parse(ok.Body!)!["ts"]);

        Assert.Equal("HTTP 401", await Deregistration.TrySendAsync(new Uri("https://example.test"), identity, TestData.DeviceId, DateTimeOffset.UtcNow, new Capture(HttpStatusCode.Unauthorized)));
    }
}
