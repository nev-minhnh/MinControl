using MinControl.Setup;
using Xunit;

namespace MinControl.Core.Tests;

public class PairingQrTests
{
    [Fact]
    public void Builds_v2_with_urlencoded_server()
    {
        var qr = PairingQr.Build("https://mc.example.com:8443", "AbC-_123", "0123456789ab");
        Assert.Equal("mincontrol://pair?v=2&u=https%3A%2F%2Fmc.example.com%3A8443&c=AbC-_123&f=0123456789ab", qr);
    }
}
