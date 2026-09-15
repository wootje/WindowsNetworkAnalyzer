# Offline explanation checks. No packet capture, network access or Pester required.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'ConnectionExplanations.ps1')
$script:ExplanationChecks=0
function Assert-Explanation($Condition,[string]$Label) {
    if (-not $Condition) { throw ('Failed: '+$Label) }
    $script:ExplanationChecks++
}
function New-ExplanationRow([hashtable]$Changes=@{}) {
    $row=@{ id='c1';processName='svchost.exe';processId=123;processPath='C:\Windows\System32\svchost.exe';attributionStatus='MatchedLiveProcess';processEvidence='The observed socket owner matched the process instance.';protocol='UDP';localAddress='10.20.30.2';localPort=52000;remoteAddress='10.20.30.1';remotePort=53;direction='Outbound';state='Unknown';source='WFP5156';signatureStatus='Valid';signer='CN=Microsoft Windows, O=Microsoft Corporation, C=US';services=@('Dnscache');serviceDetails=@();dnsNames=@();ptrNames=@();ipRegistration=$null }
    foreach ($key in $Changes.Keys) { $row[$key]=$Changes[$key] }
    return [pscustomobject]$row
}
$meta=[pscustomobject]@{networkContext=[pscustomobject]@{SystemRoot='C:\Windows';DnsServers=@([pscustomobject]@{ServerAddresses=@('10.20.30.1','2606:4700:4700::1111')});DefaultRoutes=@([pscustomobject]@{NextHop='10.20.30.1'});Addresses=@([pscustomobject]@{IPAddress='10.20.30.2'})}}
$explanation=Get-NrConnectionExplanation (New-ExplanationRow) $meta
Assert-Explanation ($explanation.confidence -eq 'Likely') 'DNS purpose is inferred'
Assert-Explanation ($explanation.category -eq 'DNS candidate') 'DNS port rule'
Assert-Explanation ($explanation.processRole -like 'Windows Service Host*') 'expected Microsoft-signed Windows path'
Assert-Explanation (($explanation.evidence -join ' ') -match 'configured DNS server') 'configured DNS evidence'
Assert-Explanation (($explanation.evidence -join ' ') -match 'default gateway') 'gateway evidence from context'
Assert-Explanation ($explanation.purpose -match 'on behalf of other applications') 'DNS client origin caveat'
Assert-Explanation (($explanation.limitations -join ' ') -match 'not.*safe or necessary') 'signature is not behavioral proof'
Assert-Explanation ($explanation.necessity -match 'Not determined automatically') 'no automatic necessity classification'

$shared=Get-NrConnectionExplanation (New-ExplanationRow @{services=@('wuauserv','BITS');protocol='TCP';remotePort=443;remoteAddress='8.8.8.8'}) $meta
Assert-Explanation ($shared.serviceContext -match 'Windows Update.*Background Intelligent') 'service roles described'
Assert-Explanation (($shared.limitations -join ' ') -match 'not the exact service') 'shared service caveat'
Assert-Explanation ($shared.purpose -match 'possible explanation') 'update purpose qualified'
Assert-Explanation ($shared.purpose -notmatch 'is downloading a Windows update') 'no exact payload inference'

$spoof=Get-NrConnectionExplanation (New-ExplanationRow @{processPath='C:\Users\Pat\Downloads\svchost.exe'}) $meta
Assert-Explanation ($spoof.processRole -match 'identity is not confirmed') 'renamed executable not Windows proof'
Assert-Explanation ($spoof.purpose -notmatch 'on behalf of other applications') 'service-purpose enrichment constrained by executable path'
$badbase=Get-NrConnectionExplanation (New-ExplanationRow @{processPath='C:\Windows\System32\evil.exe'}) $meta
Assert-Explanation ($badbase.processRole -match 'identity is not confirmed') 'basename/path discrepancy'
$unchecked=Get-NrConnectionExplanation (New-ExplanationRow @{signatureStatus='Not checked';signer=''}) $meta
Assert-Explanation ($unchecked.processRole -match '^Possible Windows component') 'unverified file identity labeled'
$differentRoot=[pscustomobject]@{networkContext=@{SystemRoot='D:\WinNT'}}
$custom=Get-NrConnectionExplanation (New-ExplanationRow @{processPath='D:\WinNT\System32\svchost.exe'}) $differentRoot
Assert-Explanation ($custom.processRole -like 'Windows Service Host*') 'captured custom Windows directory'
$wrongRoot=Get-NrConnectionExplanation (New-ExplanationRow) $differentRoot
Assert-Explanation ($wrongRoot.processRole -match 'identity is not confirmed') 'other Windows-named directory is not captured root'

$inbound=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';direction='Inbound';localPort=3389;remotePort=54000})
Assert-Explanation ($inbound.category -eq 'Remote Desktop candidate') 'inbound rule uses local destination'
$inboundEphemeral=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';direction='Inbound';localPort=54000;remotePort=3389})
Assert-Explanation ($inboundEphemeral.category -eq 'Unclassified traffic') 'inbound source port is not treated as destination'
$unknown=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';direction='Unknown (snapshot)';source='TcpSnapshot';localPort=50000;remotePort=443})
Assert-Explanation ($unknown.category -eq 'Encrypted web traffic') 'unknown direction still allows explicitly qualified endpoint hint'
Assert-Explanation (($unknown.limitations -join ' ') -match 'does not establish which side initiated') 'snapshot direction not invented'
$ambiguous=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';direction='Unknown (snapshot)';localPort=22;remotePort=443})
Assert-Explanation ($ambiguous.confidence -eq 'Unknown') 'two conflicting service ports cannot choose protocol'
$quic=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='UDP';remotePort=443})
Assert-Explanation ($quic.category -eq 'QUIC / HTTP/3 candidate') 'QUIC candidate category'
Assert-Explanation ($quic.purpose -match 'Other protocols can also use') 'UDP443 is not proof'
$tcpQuic=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';remotePort=443})
Assert-Explanation ($tcpQuic.category -ne 'QUIC / HTTP/3 candidate') 'transport distinguishes TCP443'

$listener=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';localPort=3389;remotePort=0;remoteAddress='0.0.0.0';state='Listen';source='TcpSnapshot';direction='Unknown'})
Assert-Explanation ($listener.category -eq 'Local listener') 'listener not remote connection'
Assert-Explanation ($listener.confidence -eq 'Observed') 'bound socket fact observed'
Assert-Explanation (($listener.limitations -join ' ') -match 'not proof.*reachable from the internet') 'listener does not prove exposure'
$bound=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';remoteAddress='0.0.0.0';remotePort=0;state='Bound';source='TcpSnapshot'})
Assert-Explanation ($bound.category -eq 'Local endpoint') 'TCP Bound is not a listener'
Assert-Explanation ($bound.purpose -notmatch 'listening socket was observed') 'TCP Bound no invented listener'
$unsupported=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='Unknown';remoteAddress='';state='Unknown'})
Assert-Explanation ($unsupported.category -eq 'Local endpoint') 'unknown protocol peerless row is not TCP listener'
$udp=Get-NrConnectionExplanation (New-ExplanationRow @{source='UdpEndpoint';localPort=5353;remoteAddress='';remotePort=0;direction='Unknown (local endpoint)'})
Assert-Explanation ($udp.category -eq 'Local UDP endpoint') 'UDP has no fabricated peer'
Assert-Explanation ($udp.purpose -match 'does not prove that any datagrams') 'UDP binding does not imply traffic'
Assert-Explanation ($udp.purpose -match 'multicast DNS') 'local UDP port hint remains useful'

$dns=Get-NrConnectionExplanation (New-ExplanationRow @{dnsNames=@('example.test','cdn.example.test');ptrNames=@('edge.provider.test');ipRegistration=@{organization='Example Hosting'}})
Assert-Explanation (($dns.evidence -join ' ') -match 'example.test') 'retains observed DNS candidates'
Assert-Explanation (($dns.limitations -join ' ') -match 'not proof that this process requested') 'shared DNS is not process evidence'
Assert-Explanation (($dns.limitations -join ' ') -match 'shared hosting and CDNs') 'RDAP provider not service purpose'
$noDns=Get-NrConnectionExplanation (New-ExplanationRow @{remotePort=55555;processName='unknown';processPath='';services=@();attributionStatus='Unavailable'})
Assert-Explanation ($noDns.confidence -eq 'Unknown') 'unknown port remains unknown'
Assert-Explanation (($noDns.limitations -join ' ') -match 'does not prove.*peer-to-peer') 'IP-only does not prove P2P'
Assert-Explanation ($noDns.summary -notmatch 'example.test|Google|Microsoft update') 'no invented destination'
Assert-Explanation (($noDns.limitations -join ' ') -match 'same PID') 'incomplete process attribution caveat'
$historical=Get-NrConnectionExplanation (New-ExplanationRow @{attributionStatus='WfpEventPathOnly';services=@()})
Assert-Explanation (($historical.limitations -join ' ') -match 'not a verified historical in-memory process') 'event path inspection is not verified live process'

$blocked=Get-NrConnectionExplanation (New-ExplanationRow @{source='WFP5157'})
Assert-Explanation ($blocked.purpose -match '^Windows recorded a blocked connection attempt') 'blocked attempt meaning'
Assert-Explanation (($blocked.limitations -join ' ') -match 'does not establish that data reached') 'blocked is not completed traffic'
$permitted=Get-NrConnectionExplanation (New-ExplanationRow)
Assert-Explanation (($permitted.limitations -join ' ') -match 'another firewall') 'permit is not complete outcome'
$system=Get-NrConnectionExplanation (New-ExplanationRow @{processName='System';processId=4;processPath='';services=@();attributionStatus='SystemProcess'})
Assert-Explanation ($system.processRole -match 'kernel and driver activity') 'System PID4 explained'
$fakeSystem=Get-NrConnectionExplanation (New-ExplanationRow @{processName='System';processId=999;processPath='C:\Apps\System.exe'})
Assert-Explanation ($fakeSystem.processRole -notmatch 'kernel and driver activity') 'System basename alone insufficient'
$wv=Get-NrConnectionExplanation (New-ExplanationRow @{processName='msedgewebview2.exe';processPath='C:\Program Files (x86)\Microsoft\EdgeWebView\Application\1.0\msedgewebview2.exe';services=@()})
Assert-Explanation (($wv.limitations -join ' ') -match 'does not identify which host application') 'WebView host app not invented'

$ipv6=Get-NrConnectionExplanation (New-ExplanationRow @{remoteAddress='2606:4700:4700:0:0:0:0:1111'}) $meta
Assert-Explanation (($ipv6.evidence -join ' ') -match 'configured DNS server') 'equivalent IPv6 DNS addresses normalize'
$loopback=Get-NrConnectionExplanation (New-ExplanationRow @{remoteAddress='::1';remotePort=50001}) $meta
Assert-Explanation (($loopback.evidence -join ' ') -match 'loopback address') 'loopback recognized'
$gatewayTls=Get-NrConnectionExplanation (New-ExplanationRow @{protocol='TCP';remotePort=443}) $meta
Assert-Explanation ($gatewayTls.purpose -notmatch 'This is the router administration') 'gateway HTTPS service not asserted'

$customService=Get-NrConnectionExplanation (New-ExplanationRow @{services=@('ExampleSvc');serviceDetails=@(@{name='ExampleSvc';displayName='Example background helper'})})
Assert-Explanation ($customService.serviceContext -match 'Example background helper') 'unknown service friendly name retained'
$rows=@((New-ExplanationRow),(New-ExplanationRow @{id='c2';remotePort=443}))
Update-NrConnectionExplanations $rows $meta
$firstJson=$rows[0].explanation | ConvertTo-Json -Depth 8 -Compress
Update-NrConnectionExplanations $rows $meta
Assert-Explanation (($rows[0].explanation | ConvertTo-Json -Depth 8 -Compress) -eq $firstJson) 'updates are idempotent'
Assert-Explanation ($rows[1].explanation.category -eq 'QUIC / HTTP/3 candidate') 'updates all rows'
$hashrow=@{protocol='UDP';remoteAddress='';localPort=20000}
Update-NrConnectionExplanations @($hashrow)
Assert-Explanation ($hashrow.explanation.category -eq 'Local UDP endpoint') 'hashtable inputs and missing fields supported'
Assert-Explanation (@(Update-NrConnectionExplanations @()).Count -eq 0) 'empty array no extra output'
foreach($port in @(53,67,68,123,5353,5355,1900,546,547)) {
    $candidate=Get-NrConnectionExplanation (New-ExplanationRow @{remotePort=$port})
    Assert-Explanation ($candidate.confidence -eq 'Likely') ('UDP rule '+$port)
}
Write-Host ('PASS: '+$script:ExplanationChecks+' connection explanation checks.')
