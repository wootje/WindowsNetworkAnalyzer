# Windows PowerShell 5.1 compatible, deterministic local analysis.
# Findings are investigation aids. No malware score or trust verdict is produced.

function Get-NaValue {
    param($Object, [string]$Name, $Default = '')
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
    } elseif ($null -ne $Object.PSObject.Properties[$Name] -and $null -ne $Object.$Name) { return $Object.$Name }
    return $Default
}

function Get-NaAddress {
    param([string]$Address)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Address.Trim().Trim('[',']'), [ref]$ip)) {
        if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
        return $ip.ToString()
    }
    return $Address.Trim().ToLowerInvariant()
}

function Get-NaApplicationKey {
    param($Connection)
    $path = ([string](Get-NaValue $Connection 'processPath')).Trim().Replace('/','\').ToLowerInvariant()
    if ($path) { return 'path:' + $path }
    $name = ([string](Get-NaValue $Connection 'processName' 'Unknown')).Trim().ToLowerInvariant()
    $processNumber = [string](Get-NaValue $Connection 'processId' 0)
    $started = [string](Get-NaValue $Connection 'processStartTimeUtc')
    return 'unknown:' + $name + '|pid:' + $processNumber + '|start:' + $started
}

function Get-NaPortLabel {
    param([string]$Protocol, [int]$Port)
    # Port associations describe conventions; they do not identify the payload.
    if ($Protocol -eq 'UDP') {
        switch ($Port) {
            53 { return 'DNS-associated port' }
            67 { return 'DHCP server-associated port' }
            68 { return 'DHCP client-associated port' }
            123 { return 'NTP-associated port' }
            443 { return 'QUIC / HTTP/3 candidate; port alone is not proof' }
            500 { return 'IKE-associated port' }
            1900 { return 'SSDP-associated port' }
            3478 { return 'STUN / TURN-associated port' }
            4500 { return 'IPsec NAT traversal-associated port' }
            5353 { return 'Multicast DNS-associated port' }
        }
    }
    if ($Protocol -eq 'TCP') {
        switch ($Port) {
            22 { return 'SSH-associated port' }
            23 { return 'Telnet-associated port' }
            25 { return 'SMTP-associated port' }
            53 { return 'DNS-associated port' }
            80 { return 'HTTP-associated port' }
            110 { return 'POP3-associated port' }
            135 { return 'RPC endpoint mapper-associated port' }
            139 { return 'NetBIOS session-associated port' }
            143 { return 'IMAP-associated port' }
            443 { return 'HTTPS-associated port' }
            445 { return 'SMB-associated port' }
            465 { return 'SMTP over TLS-associated port' }
            587 { return 'Mail submission-associated port' }
            993 { return 'IMAP over TLS-associated port' }
            995 { return 'POP3 over TLS-associated port' }
            1433 { return 'SQL Server-associated port' }
            3306 { return 'MySQL-associated port' }
            3389 { return 'Remote Desktop-associated port' }
            5432 { return 'PostgreSQL-associated port' }
            5900 { return 'VNC-associated port' }
            5985 { return 'WinRM HTTP-associated port' }
            5986 { return 'WinRM HTTPS-associated port' }
            6379 { return 'Redis-associated port' }
            8883 { return 'MQTT over TLS-associated port' }
            27017 { return 'MongoDB-associated port' }
        }
    }
    return 'No application inferred from this port'
}

function Get-NetworkAnalysis {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Connections = @(), $Meta = $null)

    $apps = @{}; $destinations = @{}; $portGroups = @{}; $sourceCounts = @{}; $scopeCounts = @{}
    $endpointSet = @{}; $publicSet = @{}; $findingGroups = @{}; $timeRows = New-Object 'System.Collections.Generic.List[object]'
    $rows = @($Connections | Where-Object { $null -ne $_ })
    $missingRemote = 0; $dnsRows = 0; $blockedRows = 0; $listenerRows = 0; $unattributed = 0
    $signatureUncheckedRows = 0; $publicWithoutDns = 0; $invalidTimeRows = 0; $publicRows = 0

    function Add-NaFindingRow {
        param([string]$Code, [string]$AppKey, [string]$Level, [string]$Title, [string]$Explanation, [string]$Evidence, [string]$RowId, [string]$Path, [string]$Remote)
        $key = $Code + '|' + $AppKey
        if (-not $findingGroups.ContainsKey($key)) {
            $findingGroups[$key] = @{code=$Code; applicationKey=$AppKey; level=$Level; title=$Title; explanation=$Explanation; evidence=$Evidence; processPath=$Path; remotes=@{}; ids=New-Object 'System.Collections.Generic.List[string]'}
        }
        $findingGroups[$key].ids.Add($RowId)
        if ($Remote) { $findingGroups[$key].remotes[$Remote] = $true }
    }

    for ($index = 0; $index -lt $rows.Count; $index++) {
        $row = $rows[$index]
        $rowId = [string](Get-NaValue $row 'id' (Get-NaValue $row 'rowid' ('c{0:d6}' -f ($index + 1))))
        if (-not $rowId) { $rowId = 'c{0:d6}' -f ($index + 1) }
        $appKey = Get-NaApplicationKey $row
        $path = [string](Get-NaValue $row 'processPath')
        $name = [string](Get-NaValue $row 'application' (Get-NaValue $row 'processName' 'Unknown'))
        $processName = [string](Get-NaValue $row 'processName' 'Unknown')
        $source = [string](Get-NaValue $row 'source' 'Unknown')
        $protocol = ([string](Get-NaValue $row 'protocol' 'Unknown')).ToUpperInvariant()
        $remote = Get-NaAddress ([string](Get-NaValue $row 'remoteAddress'))
        $local = Get-NaAddress ([string](Get-NaValue $row 'localAddress'))
        $remotePort = 0; $localPort = 0
        $null = [int]::TryParse([string](Get-NaValue $row 'remotePort' 0), [ref]$remotePort)
        $null = [int]::TryParse([string](Get-NaValue $row 'localPort' 0), [ref]$localPort)
        $direction = [string](Get-NaValue $row 'direction' 'Unknown')
        $scope = [string](Get-NaValue $row 'ipScope' 'Unknown')
        if (-not $scope) { $scope = 'Unknown' }
        if ($scope -eq 'Unknown' -and $remote -and (Get-Command Get-NetworkAddressScope -ErrorAction SilentlyContinue)) {
            $scope = (Get-NetworkAddressScope $remote).scope
        }
        $knownRemote = ($remote -and $remote -notin @('0.0.0.0','::','*'))
        $isPublic = ($knownRemote -and $scope -eq 'Public')
        $stateValues = @((Get-NaValue $row 'states' @())) + @([string](Get-NaValue $row 'state'))
        $isListener = ($source -eq 'UdpEndpoint' -or @($stateValues | Where-Object { $_ -match '^(Listen|Listening)$' }).Count -gt 0)
        $first = [string](Get-NaValue $row 'firstSeen')
        $last = [string](Get-NaValue $row 'lastSeen' $first)
        $signature = [string](Get-NaValue $row 'signatureStatus' 'Not checked')
        $dns = @(@(Get-NaValue $row 'dnsNames' @()) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
        $ptr = @(@(Get-NaValue $row 'ptrNames' @()) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
        $sourceCounts[$source]++; $scopeCounts[$scope]++
        if ($dns.Count -gt 0 -or $ptr.Count -gt 0) { $dnsRows++ }
        if (-not $knownRemote) { $missingRemote++ }
        if (-not $path) { $unattributed++ }
        if ($signature -match '^(Not checked|NotChecked|Skipped|Disabled|Unknown|)$') { $signatureUncheckedRows++ }
        if ($isListener) { $listenerRows++ }
        if ($isPublic) { $publicRows++; $publicSet[$remote]=$true }
        if ($isPublic -and $dns.Count -eq 0 -and $ptr.Count -eq 0) { $publicWithoutDns++ }

        if (-not $apps.ContainsKey($appKey)) {
            $apps[$appKey] = @{key=$appKey;name=$name;processName=$processName;path=$path;processIds=@{};services=@{};serviceDetails=@{};processRoles=@{};attributionStatuses=@{};company=[string](Get-NaValue $row 'company');signatures=@{};signer=[string](Get-NaValue $row 'signer');sha256=[string](Get-NaValue $row 'sha256');records=0;endpoints=@{};remotes=@{};publicRemotes=@{};domains=@{};firstSeen=$first;lastSeen=$last;ids=New-Object 'System.Collections.Generic.List[string]';findingIds=New-Object 'System.Collections.Generic.List[string]'}
        }
        $app = $apps[$appKey]; $app.records++; $app.ids.Add($rowId)
        $app.processIds[[string](Get-NaValue $row 'processId' 0)] = $true
        $app.signatures[$signature] = $true
        foreach ($service in @(Get-NaValue $row 'services' @())) { if ($service) { $app.services[[string]$service] = $true } }
        foreach ($detail in @(Get-NaValue $row 'serviceDetails' @())) {
            $serviceName = [string](Get-NaValue $detail 'name')
            if ($serviceName) { $app.serviceDetails[$serviceName] = $detail }
        }
        $role = [string](Get-NaValue (Get-NaValue $row 'explanation' $null) 'processRole')
        if ($role) { $app.processRoles[$role] = $true }
        $identityStatus = [string](Get-NaValue $row 'attributionStatus' 'Not recorded')
        $app.attributionStatuses[$identityStatus] = $true

        foreach ($domain in $dns) { $app.domains[$domain] = $true }
        if ($first -and (-not $app.firstSeen -or $first -lt $app.firstSeen)) { $app.firstSeen = $first }
        if ($last -and (-not $app.lastSeen -or $last -gt $app.lastSeen)) { $app.lastSeen = $last }
        $endpointKey = @($appKey,$protocol,$local,$localPort,$remote,$remotePort) -join '|'
        if ($knownRemote) {
            $endpointSet[$endpointKey]=$true; $app.endpoints[$endpointKey]=$true; $app.remotes[$remote]=$true
            if ($isPublic) { $app.publicRemotes[$remote]=$true }
            if (-not $destinations.ContainsKey($remote)) {
                $registration=Get-NaValue $row 'ipRegistration' $null
                $destinations[$remote]=@{address=$remote;scope=$scope;organization=[string](Get-NaValue $registration 'organization');country=[string](Get-NaValue $registration 'country');domains=@{};ptrNames=@{};records=0;endpoints=@{};apps=@{};protocols=@{};ports=@{};firstSeen=$first;lastSeen=$last;ids=New-Object 'System.Collections.Generic.List[string]'}
            }
            $destination=$destinations[$remote];$destination.records++;$destination.ids.Add($rowId)
            $destination.endpoints[$endpointKey]=$true;$destination.apps[$appKey]=$true;$destination.protocols[$protocol]=$true
            $destination.ports[($protocol+'/'+$remotePort)]=$true
            foreach ($domain in $dns) { $destination.domains[$domain]=$true }
            foreach ($domain in $ptr) { $destination.ptrNames[$domain]=$true }
            if ($first -and (-not $destination.firstSeen -or $first -lt $destination.firstSeen)) { $destination.firstSeen=$first }
            if ($last -and (-not $destination.lastSeen -or $last -gt $destination.lastSeen)) { $destination.lastSeen=$last }
        }
        if (($knownRemote -or $isListener) -and $protocol -in @('TCP','UDP')) {
            $endpointSide = if ($knownRemote) { 'remote' } else { 'local-listener' }
            $port = if ($knownRemote) { $remotePort } else { $localPort }
            if ($port -gt 0) {
                $portKey=$protocol+'/'+$port+'/'+$endpointSide
                if (-not $portGroups.ContainsKey($portKey)) { $portGroups[$portKey]=@{protocol=$protocol;port=$port;endpoint=$endpointSide;label=(Get-NaPortLabel $protocol $port);records=0;endpoints=@{};apps=@{};ids=New-Object 'System.Collections.Generic.List[string]'} }
                $portGroup=$portGroups[$portKey];$portGroup.records++;$portGroup.endpoints[$endpointKey]=$true;$portGroup.apps[$appKey]=$true;$portGroup.ids.Add($rowId)
            }
        }
        $firstTime=[datetimeoffset]::MinValue
        if ($first -and [datetimeoffset]::TryParse($first,[ref]$firstTime)) { $timeRows.Add([pscustomobject]@{time=$firstTime.ToUniversalTime();id=$rowId}) }
        else { $invalidTimeRows++ }

        if ($source -eq 'WFP5157') {
            $blockedRows++
            Add-NaFindingRow 'wfp-blocked' $appKey 'info' 'Windows recorded blocked connection attempts' 'Event 5157 records a block at the audited Windows Filtering Platform layer. It does not identify which product caused the block and does not prove a successful connection or a malicious attempt.' 'Source: WFP5157. Counts are aggregated source records, not packets or distinct attempts.' $rowId $path $remote
        }
        if ($isListener -and $local -in @('0.0.0.0','::')) {
            Add-NaFindingRow 'wildcard-binding' $appKey 'info' 'A socket is bound on all local interfaces' 'An unspecified local address binds to all applicable interfaces. A TCP listener can accept connections if the firewall permits them; a bound UDP endpoint alone does not establish an active session. This is not evidence of internet exposure or router port forwarding.' 'Local address is 0.0.0.0 or :: and the source reports a TCP listener or a local UDP endpoint.' $rowId $path ''
        }
        if ($isPublic -and $protocol -eq 'UDP' -and $remotePort -eq 443) {
            Add-NaFindingRow 'quic-candidate' $appKey 'info' 'UDP 443 traffic: QUIC / HTTP/3 candidate' 'UDP 443 commonly carries QUIC, including HTTP/3. Port numbers alone do not identify the protocol or the content, and this collector does not decrypt traffic.' 'A public remote endpoint uses UDP port 443. In inbound records this is the peer source port.' $rowId $path $remote
        }
        if ($isPublic -and $dns.Count -eq 0 -and $ptr.Count -eq 0) {
            Add-NaFindingRow 'no-dns-name' $appKey 'info' 'Some public addresses have no captured DNS name' 'A missing name can result from cached or encrypted DNS, direct IP use, absent PTR records, or activity outside the capture window. It does not prove P2P or unwanted traffic.' 'No DNS-cache candidate or reverse-DNS name was available for these records.' $rowId $path $remote
        }
        if ($path -match '(?i)(\\users\\[^\\]+\\|\\temp\\|\\tmp\\|\\downloads\\)') {
            Add-NaFindingRow 'profile-path' $appKey 'review' 'Executable observed in a user-profile or temporary path' 'Confirm that this application was expected. Many legitimate applications install or update in a user profile. The path pattern does not establish the file permissions, maliciousness, or the purpose of a connection.' ('Recorded executable path: '+$path) $rowId $path ''
        }
        if ($path -and $signature -match '^(NotSigned|HashMismatch|NotTrusted|PublisherMismatch|Revoked)$') {
            Add-NaFindingRow 'signature-review' $appKey 'review' 'Executable signature needs interpretation' 'Review the recorded Authenticode status. Unsigned software can be legitimate; a valid signature would establish neither safe behavior nor the necessity of a connection. Metadata describes the file checked after capture, which might have changed since a connection was recorded.' ('Recorded signature status: '+$signature) $rowId $path ''
        } elseif ($path -and $signature -match '^(UnknownError|NotSupportedFileFormat|Incompatible|Unavailable|AccessDenied|FileNotFound|Error|Uncheckable|Timeout|LargeFileSkipped|NonLocalPathSkipped|NonLocalDriveSkipped|ReparsePointSkipped|ChangedDuringInspection|FileUnavailable)') {
            Add-NaFindingRow 'signature-unavailable' $appKey 'info' 'Executable signature could not be checked' 'The file or signature could not be evaluated. This is a collection limitation, not an unsigned or untrusted verdict.' ('Recorded signature status: '+$signature) $rowId $path ''
        }
        if ($isPublic -and $protocol -eq 'TCP') {
            $servicePort = 0; $serviceSide = ''
            if ($direction -eq 'Outbound') { $servicePort=$remotePort; $serviceSide='remote destination' }
            elseif ($direction -eq 'Inbound') { $servicePort=$localPort; $serviceSide='local destination' }
            if ($servicePort -in @(22,23,135,139,445,1433,3306,3389,5432,5900,5985,5986,6379,27017)) {
                Add-NaFindingRow ('service-port-'+$servicePort+'-'+$direction) $appKey 'review' 'Public peer on an administration or database-associated port' 'Check whether the observed activity is expected for this application. A conventional service port does not prove the protocol, a successful session, or an exposed service.' ($direction+' WFP record with a public peer; '+$serviceSide+' TCP port '+$servicePort+' ('+(Get-NaPortLabel 'TCP' $servicePort)+').') $rowId $path $remote
            }
        }
    }

    foreach ($app in $apps.Values) {
        if ($app.publicRemotes.Count -ge 25) {
            $key='many-destinations|'+$app.key
            $findingGroups[$key]=@{code='many-destinations';applicationKey=$app.key;level='info';title='Application contacted or attempted many public addresses';explanation='The review threshold is 25 distinct public peer addresses in this capture. Browsers, CDNs, cloud services and games commonly use many addresses. This threshold is a navigation aid, not a baseline anomaly detector or a threat assessment.';evidence=([string]$app.publicRemotes.Count+' distinct public peer addresses across '+$app.records+' source records; sources may overlap.');processPath=$app.path;remotes=$app.publicRemotes;ids=$app.ids}
        }
    }
    $findings=New-Object 'System.Collections.Generic.List[object]'; $findingIndex=0
    foreach ($key in @($findingGroups.Keys | Sort-Object)) {
        $group=$findingGroups[$key];$findingIndex++;$findingId='f{0:d5}' -f $findingIndex
        $remotes=@($group.remotes.Keys | Sort-Object)
        $remoteValue=if($remotes.Count -eq 1){$remotes[0]}else{''}
        $findings.Add([pscustomobject][ordered]@{id=$findingId;code=$group.code;level=$group.level;title=$group.title;explanation=$group.explanation;evidence=$group.evidence;applicationKey=$group.applicationKey;processPath=$group.processPath;remoteAddress=$remoteValue;remoteAddresses=$remotes;records=$group.ids.Count;connectionIds=@($group.ids.ToArray())})
        $apps[$group.applicationKey].findingIds.Add($findingId)
    }
    $applicationOutput=@(foreach ($app in @($apps.Values | Sort-Object @{Expression='records';Descending=$true},key)) {
        [pscustomobject][ordered]@{key=$app.key;name=$app.name;processName=$app.processName;path=$app.path;processIds=@($app.processIds.Keys | Sort-Object);services=@($app.services.Keys | Sort-Object);serviceDetails=@($app.serviceDetails.Values | Sort-Object name);processRoles=@($app.processRoles.Keys | Sort-Object);attributionStatuses=@($app.attributionStatuses.Keys | Sort-Object);company=$app.company;signatureStatus=(@($app.signatures.Keys | Sort-Object) -join ', ');signer=$app.signer;sha256=$app.sha256;records=$app.records;endpointCombinations=$app.endpoints.Count;publicRemoteAddresses=$app.publicRemotes.Count;remoteAddresses=$app.remotes.Count;domains=@($app.domains.Keys | Sort-Object);firstSeen=$app.firstSeen;lastSeen=$app.lastSeen;connectionIds=@($app.ids.ToArray());findingIds=@($app.findingIds.ToArray())}
    })
    $destinationOutput=@(foreach ($destination in @($destinations.Values | Sort-Object @{Expression='records';Descending=$true},address)) {
        [pscustomobject][ordered]@{address=$destination.address;scope=$destination.scope;organization=$destination.organization;country=$destination.country;domains=@($destination.domains.Keys | Sort-Object);ptrNames=@($destination.ptrNames.Keys | Sort-Object);records=$destination.records;endpointCombinations=$destination.endpoints.Count;applications=$destination.apps.Count;applicationKeys=@($destination.apps.Keys | Sort-Object);protocols=@($destination.protocols.Keys | Sort-Object);ports=@($destination.ports.Keys | Sort-Object);firstSeen=$destination.firstSeen;lastSeen=$destination.lastSeen;connectionIds=@($destination.ids.ToArray())}
    })
    $portOutput=@(foreach ($portGroup in @($portGroups.Values | Sort-Object @{Expression='records';Descending=$true},protocol,port)) {
        [pscustomobject][ordered]@{protocol=$portGroup.protocol;port=$portGroup.port;endpoint=$portGroup.endpoint;label=$portGroup.label;records=$portGroup.records;endpointCombinations=$portGroup.endpoints.Count;applicationKeys=@($portGroup.apps.Keys | Sort-Object);connectionIds=@($portGroup.ids.ToArray())}
    })
    $timeline=New-Object 'System.Collections.Generic.List[object]'
    if ($timeRows.Count -gt 0) {
        $orderedTimes=@($timeRows | Sort-Object time)
        $minTime=$orderedTimes[0].time;$maxTime=$orderedTimes[-1].time
        $span=[Math]::Max(1,($maxTime-$minTime).TotalSeconds)
        $bucketSeconds=[int][Math]::Max(1,[Math]::Ceiling($span/60))
        $buckets=@{}
        foreach ($entry in $orderedTimes) { $bucket=[int][Math]::Floor(($entry.time-$minTime).TotalSeconds/$bucketSeconds);$buckets[$bucket]++ }
        foreach ($bucket in @($buckets.Keys | Sort-Object)) {
            $bucketStart=$minTime.AddSeconds($bucket*$bucketSeconds)
            $timeline.Add([pscustomobject][ordered]@{start=$bucketStart.ToString('o');end=$bucketStart.AddSeconds($bucketSeconds).ToString('o');firstObservedRecords=$buckets[$bucket]})
        }
    }
    $reviewCount=@($findings | Where-Object level -eq 'review').Count
    $infoCount=@($findings | Where-Object level -eq 'info').Count
    $sources=@(foreach ($source in @($sourceCounts.Keys | Sort-Object)) { [pscustomobject]@{source=$source;records=$sourceCounts[$source]} })
    $scopes=@(foreach ($scope in @($scopeCounts.Keys | Sort-Object)) { [pscustomobject]@{scope=$scope;records=$scopeCounts[$scope]} })
    return [pscustomobject][ordered]@{
        summary=[pscustomobject][ordered]@{records=$rows.Count;applications=$apps.Count;remoteAddresses=$destinations.Count;publicRemoteAddresses=$publicSet.Count;endpointCombinations=$endpointSet.Count;recordsWithoutRemote=$missingRemote;recordsWithDnsCandidates=$dnsRows;blockedAuditRecords=$blockedRows;listenerRecords=$listenerRows;reviewFindings=$reviewCount;infoFindings=$infoCount}
        applications=$applicationOutput;destinations=$destinationOutput;ports=$portOutput;timeline=@($timeline.ToArray());findings=@($findings.ToArray())
        coverage=[pscustomobject][ordered]@{
            sources=$sources;scopes=$scopes;publicRecords=$publicRows;publicRecordsWithoutDns=$publicWithoutDns;recordsWithoutProcessPath=$unattributed;recordsWithoutRemote=$missingRemote;signatureUncheckedRecords=$signatureUncheckedRows;recordsWithoutValidTime=$invalidTimeRows
            truncated=[bool](Get-NaValue $Meta 'truncated' $false)
            recordDefinition='A record is one aggregated observation key within one source. Snapshot repetitions and repeated audit observations are not packet counts.'
            endpointDefinition='Endpoint combinations deduplicate application key, protocol, local address/port and remote address/port across sources. They are not exact session counts and exclude unknown or unspecified remote endpoints.'
            timelineDefinition='First-observed source records per time bucket, not packets, bytes or connection concurrency. TCP sockets that existed before capture appear when first observed.'
            directionDefinition='WFP records supply direction; TCP snapshots and UDP endpoint snapshots do not establish who initiated a connection. Remote-port summaries do not imply that every remote port is a server destination port.'
            dnsDefinition='DNS-cache and reverse-DNS names are candidates. Shared IPs, encrypted DNS and caching prevent reliable domain-to-process attribution from these sources alone.'
            signatureDefinition='Signature, company, version and SHA-256 describe an accessible file inspected after capture. File metadata is not a verdict on runtime behavior; paths and files may change.'
            registrationDefinition='RDAP registration names and countries identify registration records, not necessarily the operating service, physical location, trustworthiness or traffic purpose.'
            captureDefinition='Existing UDP flows, very short connections, kernel traffic, dropped or overwritten audit events, audit restrictions and the record limit can reduce coverage. WFP permission does not prove a server replied or every security product allowed the traffic.'
        }
    }
}
