# Conservative, offline connection explanations. Windows PowerShell 5.1 and later.
# Protocol names describe candidates; this module does not inspect packet contents.
# References: Microsoft Windows service/port overview; Service Host grouping;
# Microsoft WebView2 process model; RFCs 9114 (HTTP/3), 6762 (mDNS), 4795 (LLMNR).

$script:NrExplanationProcessRoles = @{
    'svchost'='Windows Service Host loads one or more Windows services into a shared executable.'
    'lsass'='Local Security Authority handles Windows authentication and security policy.'
    'services'='Service Control Manager starts, stops and manages Windows services.'
    'spoolsv'='Print Spooler manages print jobs and can communicate with printers or print servers.'
    'msmpeng'='Microsoft Defender Antivirus engine performs malware protection and can contact protection services.'
    'searchapp'='Windows Search provides search features; some configured search features can use online services.'
    'searchhost'='Windows Search provides search features; some configured search features can use online services.'
    'searchindexer'='Windows Search Indexer maintains searchable indexes, including configured data sources.'
    'runtimebroker'='Runtime Broker supports permissions and background coordination for Windows applications.'
    'csrss'='Client Server Runtime supports Windows user-session functions.'
    'dwm'='Desktop Window Manager composes the Windows desktop.'
    'winlogon'='Windows Logon supports interactive sign-in and session management.'
    'explorer'='Windows Explorer provides the desktop and file browsing, including network locations.'
    'taskhostw'='Windows Task Host runs tasks implemented by Windows components.'
    'sihost'='Shell Infrastructure Host supports the Windows desktop shell.'
    'backgroundtaskhost'='Background Task Host runs background tasks for Windows applications.'
    'smartscreen'='Microsoft Defender SmartScreen checks application or download reputation when configured.'
    'mousocoreworker'='Update Session Orchestrator coordinates Windows update activity.'
    'usoclient'='Update Session Orchestrator coordinates Windows update activity.'
}
$script:NrExplanationServiceRoles = @{
    'dnscache'='DNS Client: resolves and caches names, often on behalf of other applications'
    'dhcp'='DHCP Client: obtains and renews network address configuration'
    'w32time'='Windows Time: synchronizes the computer clock'
    'wuauserv'='Windows Update: detects and obtains Windows updates'
    'bits'='Background Intelligent Transfer Service: transfers files for Windows and applications'
    'dosvc'='Delivery Optimization: downloads supported content and can share it with peers according to settings'
    'usosvc'='Update Orchestrator: coordinates Windows updates'
    'cryptsvc'='Cryptographic Services: supports certificates, signatures and catalog validation'
    'nlasvc'='Network Location Awareness: identifies network connectivity and configuration'
    'netprofm'='Network List Service: tracks network profiles'
    'ssdpsrv'='SSDP Discovery: discovers compatible local network devices'
    'upnphost'='UPnP Device Host: hosts discoverable UPnP devices'
    'fdphost'='Function Discovery Provider Host: supports network resource discovery'
    'fdrespub'='Function Discovery Resource Publication: advertises computer resources'
    'lanmanworkstation'='Workstation: accesses remote SMB file and printer shares'
    'lanmanserver'='Server: provides SMB file and printer sharing'
    'termservice'='Remote Desktop Services: supports remote desktop sessions'
    'spooler'='Print Spooler: manages print jobs and shared printers'
    'winrm'='Windows Remote Management: supports remote administration'
    'rpcss'='Remote Procedure Call: supports communication between software components'
    'dcomlaunch'='DCOM Server Process Launcher: starts components requested through COM/DCOM'
    'diagtrack'='Connected User Experiences and Telemetry: provides configured diagnostics and related experiences'
    'winhttpautoproxysvc'='WinHTTP Web Proxy Auto-Discovery: discovers proxy settings when applications request them'
    'iphlpsvc'='IP Helper: supports IP configuration and selected transition/network features'
}

function Get-NrExplanationValue {
    param($Object,[string]$Name,$Default='')
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
        return $Default
    }
    $property=$Object.PSObject.Properties[$Name]
    if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
    return $Default
}
function ConvertTo-NrExplanationIp {
    param([string]$Address)
    $parsed=$null
    if ([Net.IPAddress]::TryParse($Address,[ref]$parsed)) {
        if ($parsed.IsIPv4MappedToIPv6) { return $parsed.MapToIPv4().ToString() }
        return $parsed.ToString().ToLowerInvariant()
    }
    return $Address.ToLowerInvariant()
}
function Get-NrExplanationPortRule {
    param([string]$Protocol,[int]$Port)
    $key=$Protocol.ToUpperInvariant()+'/'+$Port
    if ($null -eq (Get-Variable -Name NrExplanationPortRules -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NrExplanationPortRules=@{
        'TCP/443'=@('Encrypted web traffic','This port commonly carries HTTPS for websites, application APIs, updates or other encrypted services.','Compare the application activity and DNS candidates with what you were doing. The URL and encrypted contents are unavailable.')
        'UDP/443'=@('QUIC / HTTP/3 candidate','UDP port 443 is commonly used by QUIC, including HTTP/3 for web pages, streaming and application services. Other protocols can also use this port.','Compare the process and timing with browser, streaming or application activity; the port alone cannot identify a website or prove QUIC.')
        'TCP/80'=@('Web traffic candidate','TCP port 80 commonly carries HTTP, including web content, redirects, updates or application APIs.','Check the application and DNS candidates. No HTTP request or response content was captured.')
        'UDP/53'=@('DNS candidate','UDP port 53 commonly carries DNS queries or responses that translate names into network addresses.','Check whether the peer is an intended DNS server; the individual query is not captured.')
        'TCP/53'=@('DNS candidate','TCP port 53 can carry DNS queries or responses, including larger replies.','Check whether the peer is an intended DNS server; the individual query is not captured.')
        'TCP/853'=@('Encrypted DNS candidate','TCP port 853 is conventionally used for DNS over TLS.','Compare the peer with configured encrypted-DNS providers; the port does not prove which names were queried.')
        'UDP/853'=@('Encrypted DNS candidate','UDP port 853 is conventionally used for DNS over QUIC.','Compare the peer with configured encrypted-DNS providers; the port does not prove which names were queried.')
        'UDP/5353'=@('Local name discovery candidate','UDP port 5353 is used by multicast DNS to resolve names and support discovery on a local network.','Check whether local device discovery is expected for this application; unicast replies are also possible.')
        'UDP/5355'=@('Local name resolution candidate','UDP port 5355 is used by LLMNR for local-link name resolution.','Check whether local name resolution is needed in your network configuration.')
        'TCP/5355'=@('Local name resolution candidate','TCP port 5355 can be used by LLMNR for local-link name resolution.','Check whether local name resolution is needed in your network configuration.')
        'UDP/1900'=@('Device discovery candidate','UDP port 1900 is used by SSDP/UPnP discovery to find or advertise compatible devices.','Compare the process with media, printer or device-discovery features you use.')
        'UDP/67'=@('Network address configuration candidate','UDP ports 67 and 68 are associated with DHCPv4 address assignment and renewal.','Check the network adapter and DHCP server configuration.')
        'UDP/68'=@('Network address configuration candidate','UDP ports 67 and 68 are associated with DHCPv4 address assignment and renewal.','Check the network adapter and DHCP server configuration.')
        'UDP/546'=@('Network address configuration candidate','UDP ports 546 and 547 are associated with DHCPv6 configuration.','Check the IPv6 configuration of the adapter.')
        'UDP/547'=@('Network address configuration candidate','UDP ports 546 and 547 are associated with DHCPv6 configuration.','Check the IPv6 configuration of the adapter.')
        'UDP/123'=@('Clock synchronization candidate','UDP port 123 commonly carries Network Time Protocol traffic used to synchronize clocks.','Compare the peer with the configured time service.')
        'TCP/445'=@('File or printer sharing candidate','TCP port 445 commonly carries SMB for file shares, printers or Windows network communication.','Check the expected server or sharing feature and whether sharing is intended on this network.')
        'TCP/139'=@('Legacy file sharing candidate','TCP port 139 is associated with NetBIOS sessions, including legacy SMB sharing.','Check whether a legacy share or device requires this connection.')
        'UDP/137'=@('Legacy name resolution candidate','UDP port 137 is associated with NetBIOS name resolution.','Check whether legacy Windows or device discovery is required.')
        'UDP/138'=@('Legacy network discovery candidate','UDP port 138 is associated with NetBIOS datagrams, including legacy discovery.','Check whether legacy Windows or device discovery is required.')
        'TCP/3389'=@('Remote Desktop candidate','TCP port 3389 is the default Remote Desktop Protocol port.','Verify that you intended to use or provide Remote Desktop and recognize the other device.')
        'UDP/3389'=@('Remote Desktop candidate','UDP port 3389 can support Remote Desktop Protocol transport.','Verify that you intended to use or provide Remote Desktop and recognize the other device.')
        'TCP/135'=@('Windows RPC candidate','TCP port 135 is associated with the RPC Endpoint Mapper used by Windows components and administration tools.','Check the Windows service, expected peer and administration or discovery activity.')
        'TCP/5985'=@('Windows remote management candidate','TCP port 5985 is conventionally used by WinRM over HTTP.','Verify the intended remote management client or server.')
        'TCP/5986'=@('Windows remote management candidate','TCP port 5986 is conventionally used by WinRM over HTTPS.','Verify the intended remote management client or server.')
        'TCP/22'=@('SSH candidate','TCP port 22 commonly carries SSH, SFTP or related remote administration traffic.','Verify the intended client, server and remote administration session.')
    }
    }
    if ($script:NrExplanationPortRules.ContainsKey($key)) { return $script:NrExplanationPortRules[$key] }
    return $null
}

function Get-NrConnectionExplanation {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Connection,$Meta=$null)
    $evidence=New-Object 'System.Collections.Generic.List[string]'
    $limitations=New-Object 'System.Collections.Generic.List[string]'
    $name=[string](Get-NrExplanationValue $Connection 'processName' 'Unknown')
    $path=([string](Get-NrExplanationValue $Connection 'processPath')).Replace('/','\')
    $baseName=($name -replace '\.exe$','').ToLowerInvariant()
    $processNumber=[long](Get-NrExplanationValue $Connection 'processId' 0)
    $attribution=[string](Get-NrExplanationValue $Connection 'attributionStatus')
    $source=[string](Get-NrExplanationValue $Connection 'source' 'Unknown')
    $protocol=([string](Get-NrExplanationValue $Connection 'protocol' 'Unknown')).ToUpperInvariant()
    $localPort=[int](Get-NrExplanationValue $Connection 'localPort' 0)
    $remotePort=[int](Get-NrExplanationValue $Connection 'remotePort' 0)
    $remote=ConvertTo-NrExplanationIp ([string](Get-NrExplanationValue $Connection 'remoteAddress'))
    $direction=[string](Get-NrExplanationValue $Connection 'direction')
    $state=[string](Get-NrExplanationValue $Connection 'state')
    $signature=[string](Get-NrExplanationValue $Connection 'signatureStatus')
    $signer=[string](Get-NrExplanationValue $Connection 'signer')
    $context=Get-NrExplanationValue $Meta 'networkContext'
    $root=[string](Get-NrExplanationValue $context 'SystemRoot')
    $isMicrosoftSignature=$signature -eq 'Valid' -and $signer -match '(?i)(^|[=, ])Microsoft (Windows|Corporation)($|[, ])'
    $isSystemPath=$false
    if ($root) { $isSystemPath=$path -match ('(?i)^'+[regex]::Escape($root.TrimEnd('\'))+'\\(System32|SysWOW64)\\[^\\]+\.exe$') }
    else { $isSystemPath=$path -match '(?i)^[a-z]:\\Windows\\(System32|SysWOW64)\\[^\\]+\.exe$' }
    $shellPrefix=if ($root) { [regex]::Escape($root.TrimEnd('\')) } else { '[a-z]:\\Windows' }
    $isShellPath=$path -match ('(?i)^'+$shellPrefix+'\\(SystemApps\\[^\\]+\\[^\\]+\.exe$|explorer\.exe$)')
    $isDefenderPath=$path -match '(?i)^[a-z]:\\(ProgramData\\Microsoft\\Windows Defender\\Platform\\[^\\]+\\|Program Files\\Windows Defender\\)MsMpEng\.exe$'
    $pathBase=($path -split '\\')[-1] -replace '(?i)\.exe$',''
    $consistentBase=$pathBase -eq $baseName
    $recognizedWindows=$consistentBase -and ($isSystemPath -or $isShellPath -or ($baseName -eq 'msmpeng' -and $isDefenderPath))
    $processRole='The executable role is not identified from the collected metadata.'
    if ($processNumber -eq 4 -and $baseName -eq 'system' -and $source -match '^(TcpSnapshot|UdpEndpoint|WFP515[67])$') {
        $processRole='Windows attributed this record to System (PID 4), which represents kernel and driver activity rather than one ordinary application.'
        $limitations.Add('System attribution cannot identify the exact driver or Windows component responsible for this record.')
    } elseif ($script:NrExplanationProcessRoles.ContainsKey($baseName)) {
        $role=$script:NrExplanationProcessRoles[$baseName]
        if ($recognizedWindows -and $isMicrosoftSignature) {
            $processRole=$role
            $evidence.Add('The executable path matches an expected Windows location and its inspected file has a valid Microsoft signature.')
        } elseif ($recognizedWindows) {
            $processRole='Possible Windows component: '+$role
            $limitations.Add('The name and path fit a Windows component, but a valid Microsoft signature was not established for the inspected file.')
        } else {
            $processRole='The name resembles a Windows component, but its identity is not confirmed by the collected path and signature.'
            $limitations.Add('A familiar executable name alone does not prove that the program is the Windows component with that name.')
        }
    } elseif ($baseName -eq 'msedgewebview2') {
        $processRole='Possible Microsoft Edge WebView2 runtime: applications use it to display web content and make web requests.'
        if (-not ($isMicrosoftSignature -and $path -match '(?i)\\Microsoft\\(EdgeWebView|Edge)\\Application\\')) {
            $limitations.Add('WebView2 identity is suggested by the name; an expected installation path and valid Microsoft signature were not both established.')
        }
        $limitations.Add('The WebView2 executable alone does not identify which host application, window or document requested this connection.')
    } elseif ($baseName -in @('msedge','chrome','firefox','brave','opera','vivaldi')) {
        $processRole='The executable name suggests a web browser, which can connect for open pages, extensions, synchronization, media and background services.'
        $limitations.Add('The process name does not identify a browser tab, extension or individual request, and does not by itself verify the application identity.')
    }
    if ($processNumber -gt 0) { $evidence.Add(('Captured process identifier: {0}; reported name: {1}.' -f $processNumber,$name)) }
    if ($path) { $evidence.Add('Captured executable path: '+$path) }
    if ($attribution) { $evidence.Add('Process attribution status: '+$attribution) }
    $processEvidence=[string](Get-NrExplanationValue $Connection 'processEvidence')
    if ($processEvidence) { $evidence.Add($processEvidence) }
    $serviceEvidence=[string](Get-NrExplanationValue $Connection 'serviceEvidence')
    if ($serviceEvidence) { $evidence.Add($serviceEvidence) }
    if (-not $path -or $attribution -match 'Unknown|Unresolved|Mismatch|Reused|Exited|Unavailable|Unassigned') {
        $limitations.Add('The process identity is incomplete or could not be fully matched at observation time; later processes using the same PID must not be treated as the owner.')
    }
    if ($attribution -eq 'WfpEventPathOnly') {
        $limitations.Add('The audit event supplies an executable path, but a running process instance was not matched. Later inspection describes the file at that path, not a verified historical in-memory process.')
    }
    if ($signature -eq 'Valid') { $limitations.Add('A valid file signature identifies the inspected signer and file integrity; it does not establish that this connection is safe or necessary.') }
    $serviceNames=New-Object 'System.Collections.Generic.List[string]'
    $serviceText=New-Object 'System.Collections.Generic.List[string]'
    foreach ($service in @(Get-NrExplanationValue $Connection 'services' @())) {
        $serviceName=if ($service -is [string]) { [string]$service } else { [string](Get-NrExplanationValue $service 'name') }
        if ($serviceName -and -not $serviceNames.Contains($serviceName)) { $serviceNames.Add($serviceName) }
    }
    foreach ($service in @(Get-NrExplanationValue $Connection 'serviceDetails' @())) {
        $serviceName=[string](Get-NrExplanationValue $service 'name')
        if ($serviceName -and -not $serviceNames.Contains($serviceName)) { $serviceNames.Add($serviceName) }
    }
    foreach ($serviceName in $serviceNames) {
        $serviceKey=$serviceName.ToLowerInvariant()
        if ($script:NrExplanationServiceRoles.ContainsKey($serviceKey)) { $serviceText.Add($script:NrExplanationServiceRoles[$serviceKey]) }
        else {
            $detail=@(Get-NrExplanationValue $Connection 'serviceDetails' @() | Where-Object { (Get-NrExplanationValue $_ 'name') -eq $serviceName } | Select-Object -First 1)
            $display=if ($detail.Count) { [string](Get-NrExplanationValue $detail[0] 'displayName') } else { '' }
            if ($display -and $display -ne $serviceName) { $serviceText.Add($serviceName+': '+$display) } else { $serviceText.Add($serviceName) }
        }
    }
    $serviceContext=if ($serviceText.Count) { 'Services reported in the matched process: '+($serviceText -join '; ')+'.' } else { 'No Windows service association was available for this process.' }
    if ($serviceNames.Count) {
        $evidence.Add('Windows service membership: '+($serviceNames -join ', ')+'.')
        $limitations.Add('Service membership identifies services hosted in the process, not the exact service that created this connection. Service names and configuration are not authenticity checks.')
    }
    if ($serviceNames.Count -gt 1 -or $baseName -eq 'svchost') {
        $limitations.Add('A Service Host process can contain several services. This capture does not assign a socket to an individual service inside that process.')
    }
    $noRemote=($remote -in @('','0.0.0.0','::','*'))
    $isListener=$protocol -eq 'TCP' -and $state -match '^(Listen|Listening)$'
    $confidence='Unknown';$category='Unclassified traffic'
    $purpose='The available process, endpoint and registration data do not establish the specific purpose of this connection.'
    $suggested='Compare the observation time with application activity and check the executable path, publisher and any associated services.'
    $selectedPort=0; $portPosition=''
    if ($noRemote -or $isListener) { $selectedPort=$localPort; $portPosition='local bound' }
    elseif ($direction -eq 'Inbound') { $selectedPort=$localPort; $portPosition='local destination' }
    elseif ($direction -eq 'Outbound') { $selectedPort=$remotePort; $portPosition='remote destination' }
    else {
        $localRule=Get-NrExplanationPortRule $protocol $localPort
        $remoteRule=Get-NrExplanationPortRule $protocol $remotePort
        if ($remoteRule -and -not $localRule) { $selectedPort=$remotePort; $portPosition='remote endpoint' }
        elseif ($localRule -and -not $remoteRule) { $selectedPort=$localPort; $portPosition='local endpoint' }
        elseif ($localPort -eq $remotePort -and $localRule) { $selectedPort=$localPort; $portPosition='both endpoints' }
        $limitations.Add('The snapshot does not establish which side initiated this communication; an endpoint port is not automatically a destination port.')
    }
    $rule=Get-NrExplanationPortRule $protocol $selectedPort
    if ($rule) {
        $category=$rule[0]; $purpose=$rule[1]; $suggested=$rule[2]; $confidence='Likely'
        $evidence.Add(('Protocol/port hint: {0} {1}, {2} port.' -f $protocol,$selectedPort,$portPosition))
        $limitations.Add('Protocol and application purpose are inferred from endpoint metadata; packet contents and application requests were not inspected.')
    }
    if ($noRemote -or $isListener) {
        $category=if ($protocol -eq 'UDP') { 'Local UDP endpoint' } elseif ($isListener) { 'Local listener' } else { 'Local endpoint' }
        $purpose=if ($protocol -eq 'UDP') { 'A local UDP socket was observed. This row does not contain a remote peer and does not prove that any datagrams were sent or received.' } elseif ($isListener) { 'A local TCP listening socket was observed. A listener is ready to accept connections; this row does not establish a completed remote connection.' } else { 'A local endpoint was recorded without a remote peer. Its recorded state does not establish that it was listening or communicating with another device.' }
        if ($rule) { $purpose+=' Port hint: '+$rule[1] }
        $confidence='Observed'
        $limitations.Add('A bound port is not proof that the computer is reachable from the internet; firewall rules, routing and interface binding determine reachability.')
        $suggested='Check the recorded state and whether the owning application or service should bind this interface. Use WFP records to investigate observed remote peers.'
    } else {
        $evidence.Add(('Observed remote endpoint: {0}:{1} ({2}).' -f $remote,$remotePort,$protocol))
        $dnsServerAddresses=@(foreach ($item in @(Get-NrExplanationValue $context 'DnsServers' @())) { foreach($addr in @(Get-NrExplanationValue $item 'ServerAddresses' @())) { ConvertTo-NrExplanationIp ([string]$addr) } })
        $gateways=@(foreach ($item in @(Get-NrExplanationValue $context 'DefaultRoutes' @())) { ConvertTo-NrExplanationIp ([string](Get-NrExplanationValue $item 'NextHop')) })
        $localAddresses=@(foreach ($item in @(Get-NrExplanationValue $context 'Addresses' @())) { ConvertTo-NrExplanationIp ([string](Get-NrExplanationValue $item 'IPAddress')) })
        if ($remote -in $dnsServerAddresses) {
            $evidence.Add('The remote address matches a configured DNS server in the captured adapter settings.')
            if ($selectedPort -eq 53) { $purpose+=' The peer also matches a configured DNS server, which supports the DNS explanation.' }
        }
        if ($remote -in $gateways) {
            $evidence.Add('The remote address matches a default gateway in the captured route table.')
            $purpose+=' This row addresses the gateway itself; being the gateway does not identify which service on it is involved.'
            $limitations.Add('A gateway can also host DNS, a management interface or other services. Traffic routed through a gateway is not the same as a connection addressed to that gateway.')
        }
        $remoteParsed=$null
        if (($remote -in $localAddresses) -or ([Net.IPAddress]::TryParse($remote,[ref]$remoteParsed) -and [Net.IPAddress]::IsLoopback($remoteParsed))) {
            $evidence.Add('The remote endpoint is a loopback address or an address assigned to this computer in the captured network context.')
            $purpose+=' This can represent communication between components on this computer.'
        }
        if ($recognizedWindows -and $serviceNames.Count -eq 1 -and $serviceNames[0] -eq 'Dnscache' -and $selectedPort -eq 53) {
            $purpose+=' The process also hosts DNS Client, which can resolve names on behalf of other applications; the original requesting application is not identified here.'
        }
        if ($recognizedWindows -and $selectedPort -in @(80,443) -and @($serviceNames | Where-Object { $_ -in @('wuauserv','BITS','DoSvc','UsoSvc') }).Count) {
            $purpose+=' Hosted update or transfer services make background content transfer a possible explanation, but the record cannot establish the transferred content or responsible service.'
        }
    }
    $names=@(Get-NrExplanationValue $Connection 'dnsNames' @() | Where-Object { [string]$_ -ne '' } | Select-Object -Unique)
    if ($names.Count) {
        $evidence.Add('DNS-cache name candidates for this IP: '+($names -join ', ')+'.')
        $limitations.Add('DNS-cache candidates can share an IP and are not proof that this process requested any listed domain. They do not identify the requested URL or content.')
    } elseif (-not $noRemote) { $limitations.Add('No DNS-cache name was associated with this record. An IP-only row does not prove that the application bypassed DNS or used peer-to-peer communication.') }
    $ptrNames=@(Get-NrExplanationValue $Connection 'ptrNames' @() | Where-Object { [string]$_ -ne '' })
    if ($ptrNames.Count) { $evidence.Add('Reverse-DNS names: '+($ptrNames -join ', ')+'.'); $limitations.Add('Reverse DNS is naming information supplied by the address operator; it does not identify the application or establish trust.') }
    $registration=Get-NrExplanationValue $Connection 'ipRegistration'
    $organization=[string](Get-NrExplanationValue $registration 'organization')
    if ($organization) { $evidence.Add('IP registration organization: '+$organization+'.'); $limitations.Add('IP registration identifies an address holder or provider; shared hosting and CDNs prevent it from proving which application service used this address.') }
    if ($source -match '5157') { $purpose='Windows recorded a blocked connection attempt. '+$purpose; $limitations.Add('A blocked attempt does not establish that data reached the peer, and does not by itself establish malicious activity.') }
    elseif ($source -match '5156') { $limitations.Add('A WFP permit event is an audit decision; it does not prove that another firewall allowed the traffic or that the remote service answered.') }
    $summary=$purpose
    return [pscustomobject][ordered]@{
        category=$category; summary=$summary; processRole=$processRole; purpose=$purpose
        confidence=$confidence; evidence=@($evidence.ToArray()); limitations=@($limitations.ToArray())
        suggestedCheck=$suggested; serviceContext=$serviceContext
        necessity='Not determined automatically. Whether this connection is necessary depends on the Windows features, applications and network services you intend to use.'
    }
}

function Update-NrConnectionExplanations {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Connections=@(),$Meta=$null)
    foreach ($connection in $Connections) {
        if ($null -eq $connection) { continue }
        $explanation=Get-NrConnectionExplanation -Connection $connection -Meta $Meta
        if ($connection -is [System.Collections.IDictionary]) { $connection['explanation']=$explanation }
        else { $connection | Add-Member -MemberType NoteProperty -Name explanation -Value $explanation -Force }
    }
}
