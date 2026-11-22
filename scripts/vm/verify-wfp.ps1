<#
.SYNOPSIS
  (VM, elevated admin) Dumps WFP filters with "netsh wfp show filters" and checks MinControl's persistent
  per-user lock (SPEC 8.4 / I4): provider present, filters persistent, block + loopback-permit filters on
  ALE_AUTH_CONNECT v4/v6 (+ RECV_ACCEPT), scoped to the managed SID only, never to an admin SID.
.PARAMETER ManagedUser
  Local account name of the managed (standard) user, e.g. "kid".
.EXAMPLE
  .\verify-wfp.ps1 -ManagedUser kid
#>
param([Parameter(Mandatory = $true)][string]$ManagedUser, [string]$SaveTo, [string]$OutDir = "$env:PUBLIC\MinControlTest")
. "$PSScriptRoot\_common.ps1"
Assert-Admin

$ProviderKey = "{6d1f3c2a-8b4e-4f7a-9c51-2e8a7d0b4c11}"   # MinControl.NetGuard.Wfp.WfpManager.ProviderKey
New-Item -ItemType Directory -Force $OutDir | Out-Null
$xmlPath = Join-Path $OutDir "wfp-filters.xml"

$sid = (New-Object Security.Principal.NTAccount($ManagedUser)).Translate([Security.Principal.SecurityIdentifier]).Value
$adminSids = @(Get-LocalGroupMember -SID "S-1-5-32-544" | Where-Object { $_.SID } | ForEach-Object { $_.SID.Value })
Write-Host "managed SID: $sid   admin SIDs: $($adminSids -join ', ')"

$r = Invoke-Exe "netsh.exe" @("wfp", "show", "filters", "file=$xmlPath") 120
Write-Result "WFP-00" "netsh wfp show filters" ($r.Code -eq 0 -and (Test-Path $xmlPath)) $xmlPath "run elevated"
if (-not (Test-Path $xmlPath)) { Write-Summary $SaveTo }

[xml]$doc = Get-Content $xmlPath -Raw
$all = @($doc.SelectNodes("//filters/item"))
$ours = @($all | Where-Object { $_.providerKey -and $_.providerKey.ToLower() -eq $ProviderKey })
Write-Host ("{0} filters total, {1} from the MinControl provider" -f $all.Count, $ours.Count)

Write-Result "WFP-01" "MinControl provider has filters" ($ours.Count -gt 0) "" "service not running / no managed user in policy yet / NetGuard.ApplyAsync never ran"
if ($ours.Count -eq 0) { Write-Summary $SaveTo }

$notPersistent = @($ours | Where-Object { $_.OuterXml -notmatch "FWPM_FILTER_FLAG_PERSISTENT" })
Write-Result "WFP-02" "all MinControl filters are PERSISTENT (survive service stop / reboot, I4)" ($notPersistent.Count -eq 0) "$($notPersistent.Count) non-persistent"

function Get-Layer($f) { [string]$f.layerKey }
function Get-Action($f) { [string]$f.action.type }
$layers = $ours | ForEach-Object { Get-Layer $_ } | Sort-Object -Unique
Write-Host "layers: $($layers -join ', ')"
foreach ($l in "FWPM_LAYER_ALE_AUTH_CONNECT_V4", "FWPM_LAYER_ALE_AUTH_CONNECT_V6") {
    $blocks = @($ours | Where-Object { (Get-Layer $_) -eq $l -and (Get-Action $_) -eq "FWP_ACTION_BLOCK" })
    $permits = @($ours | Where-Object { (Get-Layer $_) -eq $l -and (Get-Action $_) -eq "FWP_ACTION_PERMIT" })
    Write-Result "WFP-03" "$l has block filter(s) for the managed user" ($blocks.Count -gt 0) "$($blocks.Count) block, $($permits.Count) permit"
    Write-Result "WFP-04" "$l has a permit (loopback proxy) above the block" ($permits.Count -gt 0) ""
}
$recv = @($ours | Where-Object { (Get-Layer $_) -like "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT*" })
Write-Result "WFP-05" "ALE_AUTH_RECV_ACCEPT filters present" ($recv.Count -gt 0) "$($recv.Count) filters"

$text = ($ours | ForEach-Object { $_.OuterXml }) -join "`n"
Write-Result "WFP-06" "filters are scoped by ALE_USER_ID" ($text -match "FWPM_CONDITION_ALE_USER_ID") ""
Write-Result "WFP-07" "managed SID appears in the filter conditions" ($text -match [regex]::Escape($sid)) $sid "policy may not list this user as managed"
$leak = @($adminSids | Where-Object { $text -match [regex]::Escape($_) })
Write-Result "WFP-08" "no admin SID is targeted (I2)" ($leak.Count -eq 0) ($leak -join ", ")

$protoBlocks = @($ours | Where-Object { (Get-Action $_) -eq "FWP_ACTION_BLOCK" -and $_.OuterXml -match "FWPM_CONDITION_IP_PROTOCOL" })
Write-Result "WFP-09" "block filters are protocol-agnostic (TCP + UDP: QUIC/DoT/VPN die)" ($protoBlocks.Count -eq 0) "$($protoBlocks.Count) block filters restricted to one IP protocol"

Write-Result "WFP-10" "filters survive service stop (manual)" $null "sc stop MinControl (admin) -> re-run this script -> WFP-01/02 still PASS -> sc start MinControl"
Write-Summary $SaveTo
