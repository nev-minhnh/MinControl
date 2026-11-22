<#
.SYNOPSIS
  (VM) Network bypass attempts (SPEC 8.4, M4 "done when"). Run it twice:
    - as the MANAGED standard user  -> every bypass must FAIL (script reports PASS when blocked)
    - as the ADMIN user (-AsAdminBaseline) -> everything must WORK (I2: admin unaffected)
.PARAMETER BlockedHost
  A host in the test policy's blockDomains (runbook uses example.org).
.PARAMETER AllowedHost
  A host the policy allows (runbook uses www.wikipedia.org).
#>
param(
    [string]$BlockedHost = "example.org",
    [string]$AllowedHost = "www.wikipedia.org",
    [switch]$AsAdminBaseline,
    [string]$SaveTo
)
. "$PSScriptRoot\_common.ps1"
if ($AsAdminBaseline) { Assert-Admin } else { Assert-NotAdmin }
$expectBlocked = -not $AsAdminBaseline
$who = if ($expectBlocked) { "managed user: must be BLOCKED" } else { "admin baseline: must WORK" }
Write-Host "== network tests ($who) as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan

# Result helper: $worked = the bypass/connection succeeded.
function Check([string]$id, [string]$name, [bool]$worked, [string]$detail, [string]$hint) {
    $ok = if ($expectBlocked) { -not $worked } else { $worked }
    Write-Result $id $name $ok $detail $hint
}

# 1. Direct TCP, ignoring the system proxy (curl --noproxy '*')
$r = Invoke-Exe $Curl @("-sS", "-o", "NUL", "-w", "%{http_code}", "--noproxy", "*", "--max-time", "10", "https://$AllowedHost/")
Check "NET-01" "direct HTTPS without proxy (curl --noproxy)" ($r.Code -eq 0) "curl exit $($r.Code) $($r.Out)" "WFP block filter missing for this SID: run verify-wfp.ps1"

# 2. Direct IP literal (no DNS)
$r = Invoke-Exe $Curl @("-sS", "-o", "NUL", "--noproxy", "*", "--max-time", "10", "-k", "https://1.1.1.1/")
Check "NET-02" "direct HTTPS to an IP literal (1.1.1.1)" ($r.Code -eq 0) "curl exit $($r.Code)"

# 3. DoH (direct)
foreach ($u in "https://cloudflare-dns.com/dns-query?name=example.com&type=A", "https://dns.google/resolve?name=example.com&type=A") {
    $r = Invoke-Exe $Curl @("-sS", "--noproxy", "*", "--max-time", "10", "-H", "accept: application/dns-json", $u)
    Check "NET-03" "DoH direct: $(([uri]$u).Host)" ($r.Code -eq 0 -and $r.Out -match '"Answer"') "curl exit $($r.Code)"
}

# 4. DoH through the proxy (the proxy must refuse known DoH endpoints)
$r = Invoke-Exe $Curl @("-sS", "--max-time", "10", "-H", "accept: application/dns-json", "https://cloudflare-dns.com/dns-query?name=example.com&type=A")
Check "NET-04" "DoH via system proxy (cloudflare-dns.com)" ($r.Code -eq 0 -and $r.Out -match '"Answer"') "curl exit $($r.Code)" "DoH host list in NetGuard does not cover this endpoint"

# 5. Plain DNS to a public resolver over UDP/53 (DNS client service is another SID and stays allowed)
try { $null = Resolve-DnsName -Name example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop; $dnsWorked = $true } catch { $dnsWorked = $false }
Check "NET-05" "UDP DNS from the user's process to 8.8.8.8" $dnsWorked ""

# 6. UDP 443 (QUIC) - raw UDP send/receive to a QUIC endpoint is hard to verify; check that a UDP socket cannot
#    reach anything: DNS query over a raw socket to 1.1.1.1:53 with a 3 s timeout.
$udpWorked = $false
try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.ReceiveTimeout = 3000
    $q = [byte[]](0x12,0x34,1,0,0,1,0,0,0,0,0,0,7) + [Text.Encoding]::ASCII.GetBytes("example") + [byte[]](3) + [Text.Encoding]::ASCII.GetBytes("com") + [byte[]](0,0,1,0,1)
    [void]$udp.Send($q, $q.Length, "1.1.1.1", 53)
    $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $null = $udp.Receive([ref]$ep); $udpWorked = $true
} catch { } finally { if ($udp) { $udp.Close() } }
Check "NET-06" "raw UDP from the user's process (QUIC/DoT/VPN class)" $udpWorked ""

# 7. Proxy path: allowed site works, blocked site refused (managed user only)
if ($expectBlocked) {
    $r = Invoke-Exe $Curl @("-sS", "-o", "NUL", "-w", "%{http_code}", "--max-time", "15", "https://$AllowedHost/")
    Write-Result "NET-07" "allowed site via proxy works ($AllowedHost)" ($r.Code -eq 0) "curl exit $($r.Code) http $($r.Out)" "proxy not running or WinINET proxy not set for this user"
    $r = Invoke-Exe $Curl @("-sS", "-o", "NUL", "--max-time", "15", "https://$BlockedHost/")
    Write-Result "NET-08" "blocked site via proxy refused ($BlockedHost)" ($r.Code -ne 0) "curl exit $($r.Code) $($r.Out)" "blockDomains in the test policy?"
    $ie = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue)
    Write-Result "NET-09" "WinINET proxy = 127.0.0.1:<port> for this user" ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer -match "127\.0\.0\.1") "ProxyEnable=$($ie.ProxyEnable) ProxyServer=$($ie.ProxyServer)"
    try {
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0 -ErrorAction Stop
        $r = Invoke-Exe $Curl @("-sS", "-o", "NUL", "--max-time", "10", "https://$AllowedHost/")
        Write-Result "NET-10" "user disables WinINET proxy -> still no direct internet" ($r.Code -ne 0) "curl exit $($r.Code)"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
    } catch { Write-Result "NET-10" "user cannot change proxy settings" $true $_.Exception.Message }
}

# 8. VPN: create a per-user IKEv2 profile (allowed for standard users) and dial it.
$vpnName = "mc-test-vpn"
try {
    Add-VpnConnection -Name $vpnName -ServerAddress "vpn.example.net" -TunnelType Ikev2 -AuthenticationMethod Eap -Force -ErrorAction Stop -WarningAction SilentlyContinue
    $r = Invoke-Exe "rasdial.exe" @($vpnName) 40
    Check "NET-11" "VPN dial (IKEv2 profile created by the user)" ($r.Code -eq 0) "rasdial exit $($r.Code)" ""
} catch {
    Write-Result "NET-11" "VPN profile creation" $null $_.Exception.Message
} finally {
    Invoke-Exe "rasdial.exe" @($vpnName, "/disconnect") 10 | Out-Null
    Remove-VpnConnection -Name $vpnName -Force -ErrorAction SilentlyContinue
}
Write-Result "NET-12" "manual: third-party VPN apps (WireGuard/OpenVPN/Psiphon portable)" $null "install needs admin; portable ones: copy into C:\Games and run -> must have no network (test-portable.ps1)"
Write-Result "NET-13" "manual: Edge/Chrome with --proxy-server=direct:// or --no-proxy-server" $null "start msedge.exe --no-proxy-server https://$AllowedHost -> page must fail (WFP), policy ProxyMode wins"

Write-Summary $SaveTo
