# Windows PowerShell 5.1 compatible. All network lookups run AFTER capture.
# Registration data are RDAP (the structured successor to WHOIS), not a safety verdict.
# Sources: RFC 9224 (bootstrap), RFC 9083 (RDAP), RFC 9537 (redaction);
# IANA special-purpose registries; publicsuffix.org/list/.
$script:NrEnrichmentResourceRoot = Join-Path $PSScriptRoot 'resources'

function Get-NrProperty {
    param($Object, [string]$Name, $Default = '')
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
    } elseif ($null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Test-NrPrefix {
    param([System.Net.IPAddress]$Address, [string]$Prefix)
    $parts = $Prefix.Split('/')
    $network = [System.Net.IPAddress]::Parse($parts[0])
    $left = $Address.GetAddressBytes(); $right = $network.GetAddressBytes()
    if ($left.Length -ne $right.Length) { return $false }
    $bits = [int]$parts[1]; $whole = [int][Math]::Floor($bits / 8); $rest = $bits % 8
    for ($i = 0; $i -lt $whole; $i++) { if ($left[$i] -ne $right[$i]) { return $false } }
    if ($rest -gt 0) {
        $mask = 256 - [int][Math]::Pow(2, 8 - $rest)
        if (($left[$whole] -band $mask) -ne ($right[$whole] -band $mask)) { return $false }
    }
    return $true
}

function Get-NetworkAddressScope {
    param([AllowEmptyString()][string]$Address)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address.Trim().Trim('[', ']'), [ref]$parsed)) {
        return [pscustomobject]@{address=$Address; family='Unknown'; scope='Unknown'; isPublic=$false; lookupAddress=''}
    }
    $original = $parsed.ToString(); $mapped = $parsed.IsIPv4MappedToIPv6
    if ($mapped) { $parsed = $parsed.MapToIPv4() }
    $family = if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    $scope = 'Public'; $public = $true
    if ($family -eq 'IPv4') {
        $ranges = @(
            @('255.255.255.255/32','Broadcast'), @('0.0.0.0/8','Unspecified'),
            @('10.0.0.0/8','Private'), @('100.64.0.0/10','Shared-CGNAT'),
            @('127.0.0.0/8','Loopback'), @('169.254.0.0/16','LinkLocal'),
            @('172.16.0.0/12','Private'), @('192.0.2.0/24','Documentation'),
            @('192.88.99.0/24','Deprecated-Transition'), @('192.168.0.0/16','Private'),
            @('198.18.0.0/15','Benchmark'), @('198.51.100.0/24','Documentation'),
            @('203.0.113.0/24','Documentation'), @('224.0.0.0/4','Multicast'),
            @('240.0.0.0/4','Reserved')
        )
        if ($parsed.ToString() -notin @('192.0.0.9','192.0.0.10')) { $ranges += ,@('192.0.0.0/24','IETF-Special') }
        foreach ($range in $ranges) { if (Test-NrPrefix $parsed $range[0]) { $scope=$range[1]; $public=$false; break } }
    } else {
        $ranges = @(
            @('::/128','Unspecified'), @('::1/128','Loopback'), @('fc00::/7','Private'),
            @('fe80::/10','LinkLocal'), @('fec0::/10','Deprecated-SiteLocal'), @('ff00::/8','Multicast'),
            @('2001:db8::/32','Documentation'), @('3fff::/20','Documentation'),
            @('64:ff9b::/96','Translation'), @('64:ff9b:1::/48','Translation-Local'),
            @('100::/64','Discard'), @('100:0:0:1::/64','Dummy'),
            @('2001::/32','Teredo-Transition'), @('2001:2::/48','Benchmark'),
            @('2001:10::/28','Deprecated-ORCHID'), @('2001:20::/28','ORCHID'),
            @('2001:30::/28','DRIP-Identifier'), @('2002::/16','6to4-Transition'),
            @('5f00::/16','Segment-Routing')
        )
        foreach ($range in $ranges) { if (Test-NrPrefix $parsed $range[0]) { $scope=$range[1]; $public=$false; break } }
        if ($public -and (Test-NrPrefix $parsed '2001::/23')) {
            $exception = $parsed.ToString() -in @('2001:1::1','2001:1::2','2001:1::3')
            $exception = $exception -or (Test-NrPrefix $parsed '2001:3::/32') -or (Test-NrPrefix $parsed '2001:4:112::/48')
            if (-not $exception) { $scope='IETF-Special'; $public=$false }
        }
        if ($public -and -not (Test-NrPrefix $parsed '2000::/3')) { $scope='Reserved'; $public=$false }
    }
    if ($mapped) { $family = 'IPv4-mapped IPv6' }
    return [pscustomobject]@{address=$original; family=$family; scope=$scope; isPublic=$public; lookupAddress=$parsed.ToString()}
}

function ConvertTo-NrDomain {
    param([AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $candidate = $Name.Trim().TrimEnd('.').ToLowerInvariant()
    if ($candidate.Length -gt 253 -or $candidate -notmatch '\.' -or $candidate -match '[/\\:@\s]') { return '' }
    $ip = $null; if ([System.Net.IPAddress]::TryParse($candidate, [ref]$ip)) { return '' }
    try { $candidate = (New-Object System.Globalization.IdnMapping).GetAscii($candidate).ToLowerInvariant() } catch { return '' }
    foreach ($label in $candidate.Split('.')) {
        if ($label.Length -gt 63 -or $label -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$') { return '' }
    }
    return $candidate
}

function Test-NrPublicDomain {
    param([string]$Name)
    $domain = ConvertTo-NrDomain $Name
    if (-not $domain) { return $false }
    foreach ($suffix in @('local','localhost','localdomain','lan','home','internal','intranet','corp','test','invalid','example','onion','alt','arpa','example.com','example.net','example.org')) {
        if ($domain -eq $suffix -or $domain.EndsWith('.' + $suffix)) { return $false }
    }
    return $true
}

function Get-NetworkDnsCacheSnapshot {
    $when = [DateTime]::UtcNow.ToString('o')
    foreach ($record in @(Get-DnsClientCache -ErrorAction Stop)) {
        $name = [string](Get-NrProperty $record 'Name')
        if (-not $name) { $name = [string](Get-NrProperty $record 'Entry') }
        [pscustomobject]@{name=$name; data=[string](Get-NrProperty $record 'Data'); type=[string](Get-NrProperty $record 'Type'); ttl=Get-NrProperty $record 'TimeToLive' 0; observedUtc=$when}
    }
}

function Get-NrHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Write-NrText {
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Invoke-NrHttps {
    param([string]$Url, [int]$TimeoutSeconds=8, [int]$MaxBytes=4194304)
    # One request-wide budget includes redirects and reading the response body.
    # BeginGetResponse avoids the synchronous DNS resolver's potentially longer timeout.
    $current=$Url; $clock=[Diagnostics.Stopwatch]::StartNew(); $budget=[int]($TimeoutSeconds*1000)
    for ($redirect=0; $redirect -le 4; $redirect++) {
        $uri=$null
        if (-not [Uri]::TryCreate($current,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Port -ne 443) {
            return [pscustomobject]@{ok=$false;status=0;body='';url=$current;error='Only HTTPS without credentials on port 443 is accepted.';timedOut=$false}
        }
        $literal=$null
        if ($uri.IsLoopback -or ([Net.IPAddress]::TryParse($uri.DnsSafeHost,[ref]$literal) -and -not (Get-NetworkAddressScope $literal.ToString()).isPublic)) {
            return [pscustomobject]@{ok=$false;status=0;body='';url=$current;error='Private/loopback service URL refused.';timedOut=$false}
        }
        $response=$null; $reader=$null; $request=$null; $waitHandle=$null
        try {
            $remaining=[int]($budget-$clock.ElapsedMilliseconds)
            if ($remaining -le 0) { throw [TimeoutException]::new('HTTPS lookup exceeded its total time budget.') }
            $request=[Net.HttpWebRequest]::Create($uri)
            $request.Method='GET'; $request.Timeout=$remaining; $request.ReadWriteTimeout=$remaining
            $request.AllowAutoRedirect=$false; $request.UserAgent='PC-Network-Analyzer/2.0 (RDAP diagnostic)'
            $request.Accept='application/rdap+json, application/json, text/plain;q=0.8'
            $request.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
            $pending=$request.BeginGetResponse($null,$null); $waitHandle=$pending.AsyncWaitHandle
            if (-not $waitHandle.WaitOne($remaining)) { throw [TimeoutException]::new('HTTPS lookup exceeded its total time budget.') }
            try { $response=$request.EndGetResponse($pending) } catch [Net.WebException] {
                $response=$_.Exception.Response
                if ($null -eq $response) { throw }
            }
            $status=[int]$response.StatusCode
            if ($status -ge 300 -and $status -le 399) {
                $location=[string]$response.Headers['Location']
                if (-not $location) { throw 'Redirect without Location.' }
                $current=(New-Object Uri($uri,$location)).AbsoluteUri
                continue
            }
            $reader=New-Object IO.StreamReader($response.GetResponseStream(),[Text.Encoding]::UTF8)
            $builder=New-Object Text.StringBuilder; $buffer=New-Object char[] 8192
            while ($true) {
                $remaining=[int]($budget-$clock.ElapsedMilliseconds)
                if ($remaining -le 0) { throw [TimeoutException]::new('HTTPS response body exceeded its total time budget.') }
                $reading=$reader.ReadAsync($buffer,0,$buffer.Length)
                if (-not $reading.Wait($remaining)) { throw [TimeoutException]::new('HTTPS response body exceeded its total time budget.') }
                $count=$reading.Result
                if ($count -eq 0) { break }
                if ($builder.Length+$count -gt $MaxBytes) { throw 'Response exceeds size limit.' }
                [void]$builder.Append($buffer,0,$count)
            }
            $errorText=if ($status -ge 200 -and $status -lt 300) { '' } else { 'HTTP '+$status }
            return [pscustomobject]@{ok=($status -ge 200 -and $status -lt 300);status=$status;body=$builder.ToString();url=$current;error=$errorText;timedOut=$false}
        } catch {
            $timeout=$false; $exception=$_.Exception
            while ($null -ne $exception) {
                if ($exception -is [TimeoutException] -or ($exception -is [Net.WebException] -and $exception.Status -eq [Net.WebExceptionStatus]::Timeout)) { $timeout=$true; break }
                $exception=$exception.InnerException
            }
            return [pscustomobject]@{ok=$false;status=0;body='';url=$current;error=$_.Exception.Message;timedOut=$timeout}
        } finally {
            # Abort first so an unfinished asynchronous body read cannot hold disposal open.
            if ($null -ne $request) { try { $request.Abort() } catch {} }
            if ($null -ne $reader) { try { $reader.Dispose() } catch {} }
            if ($null -ne $response) { try { $response.Close() } catch {} }
            if ($null -ne $waitHandle) { try { $waitHandle.Close() } catch {} }
        }
    }
    return [pscustomobject]@{ok=$false;status=0;body='';url=$current;error='Redirect limit reached.';timedOut=$false}
}

function Get-NrResource {
    param([string]$Name, [string]$Url, $Context)
    $response = Invoke-NrHttps -Url $Url -TimeoutSeconds $Context.timeout
    if ($response.ok) {
        try {
            if ($Name.EndsWith('.json')) { $parsed = $response.body | ConvertFrom-Json -ErrorAction Stop; if ($null -eq $parsed.services) { throw 'Missing services' } }
            elseif ($response.body -notmatch 'BEGIN ICANN DOMAINS') { throw 'Invalid suffix list' }
            Write-NrText (Join-Path $Context.resourceDirectory $Name) $response.body
            return $response.body
        } catch { $response.error=$_.Exception.Message }
    }
    $bundled = Join-Path $script:NrEnrichmentResourceRoot $Name
    if (Test-Path -LiteralPath $bundled) {
        [void]$Context.warnings.Add("Resource ${Name}: live refresh failed; bundled snapshot used. $($response.error)")
        $body = [IO.File]::ReadAllText($bundled)
        Write-NrText (Join-Path $Context.resourceDirectory $Name) $body
        return $body
    }
    [void]$Context.warnings.Add("Resource $Name unavailable: $($response.error)")
    return ''
}

function New-NrSuffixRules {
    param([string]$Text)
    $rules = @{exact=@{};wildcard=@{};exception=@{}}
    $inside = $false
    foreach ($line in ($Text -split '\r?\n')) {
        if ($line -match 'BEGIN ICANN DOMAINS') { $inside=$true; continue }
        if ($line -match 'END ICANN DOMAINS') { break }
        if (-not $inside -or $line -match '^\s*(//|$)') { continue }
        $entry = $line.Trim(); $kind='exact'
        if ($entry.StartsWith('!')) { $kind='exception'; $entry=$entry.Substring(1) }
        elseif ($entry.StartsWith('*.')) { $kind='wildcard'; $entry=$entry.Substring(2) }
        try { $entry=(New-Object Globalization.IdnMapping).GetAscii($entry).ToLowerInvariant() } catch { continue }
        $rules[$kind][$entry]=$true
    }
    return $rules
}

function Get-NrRegisteredDomain {
    param([string]$Name, $Rules)
    $domain = ConvertTo-NrDomain $Name
    if (-not (Test-NrPublicDomain $domain) -or $null -eq $Rules -or $Rules.exact.Count -eq 0) { return '' }
    $labels = $domain.Split('.'); $publicLabels=1
    for ($i=0; $i -lt $labels.Length; $i++) {
        $suffix = ($labels[$i..($labels.Length-1)] -join '.')
        $count = $labels.Length-$i
        if ($Rules.exception.ContainsKey($suffix)) { $publicLabels=$count-1; break }
        if ($Rules.exact.ContainsKey($suffix) -and $count -gt $publicLabels) { $publicLabels=$count }
        if ($i -gt 0 -and $Rules.wildcard.ContainsKey($suffix) -and $count+1 -gt $publicLabels) { $publicLabels=$count+1 }
    }
    if ($labels.Length -le $publicLabels) { return '' }
    return ($labels[($labels.Length-$publicLabels-1)..($labels.Length-1)] -join '.')
}

function Get-NrRdapBase {
    param([string]$Query, [string]$Kind, $Bootstrap)
    if ($null -eq $Bootstrap) { return '' }
    $longest=-1; $chosen=''; $ip=$null
    if ($Kind -eq 'ip') { if (-not [Net.IPAddress]::TryParse($Query,[ref]$ip)) { return '' } }
    foreach ($service in $Bootstrap.services) {
        foreach ($entry in $service[0]) {
            $length=-1
            if ($Kind -eq 'ip') {
                try { if (Test-NrPrefix $ip ([string]$entry)) { $length=[int](([string]$entry).Split('/')[1]) } } catch { continue }
            } else {
                $suffix=([string]$entry).ToLowerInvariant()
                if ($Query -eq $suffix -or $Query.EndsWith('.'+$suffix)) { $length=$suffix.Length }
            }
            if ($length -gt $longest) {
                foreach ($url in $service[1]) {
                    if ([string]$url -match '^https://') { $chosen=([string]$url).TrimEnd('/')+'/'; $longest=$length; break }
                }
            }
        }
    }
    return $chosen
}

function New-NrWhoisResult {
    param([string]$Query,[string]$Status,[string]$ErrorText='')
    return [pscustomobject][ordered]@{query=$Query;status=$Status;name='';handle='';country='';organization='';startAddress='';endAddress='';registrar='';sourceUrl='';error=$ErrorText;rawFile='';registeredDomain='';retrievedUtc='';httpStatus=0;attempts=0;entities=@();registrationEvents=@();registrationStatuses=@();registeredUtc='';updatedUtc='';notices=@();redactedFields=@()}
}

function Get-NrEntityNames {
    param($Entities,[int]$Depth=0)
    if ($Depth -gt 4) { return }
    foreach ($entity in @($Entities)) {
        if ($null -eq $entity) { continue }
        $roles=@(Get-NrProperty $entity 'roles' @()); $name=''; $org=''
        $vcard=Get-NrProperty $entity 'vcardArray' @()
        if (@($vcard).Count -ge 2) {
            foreach ($item in $vcard[1]) {
                if (@($item).Count -ge 4) {
                    if ($item[0] -eq 'fn') { $name = @($item[3]) -join ' ' }
                    if ($item[0] -eq 'org') { $org = @($item[3]) -join ' ' }
                }
            }
        }
        [pscustomobject]@{name=$name;organization=$org;roles=$roles;handle=[string](Get-NrProperty $entity 'handle')}
        Get-NrEntityNames (Get-NrProperty $entity 'entities' @()) ($Depth+1)
    }
}

function Invoke-NrRdapQuery {
    param([string]$Query,[string]$Kind,$Context)
    $key=$Kind+':'+$Query
    if ($Context.queryCache.ContainsKey($key)) { return $Context.queryCache[$key] }
    $bootstrap=$null
    if ($Kind -eq 'domain') {
        if (-not (Test-NrPublicDomain $Query)) { return New-NrWhoisResult $Query 'SkippedNonPublic' 'Local, reserved or invalid DNS name; not sent externally.' }
        $bootstrap=$Context.dns
    } else {
        $scope=Get-NetworkAddressScope $Query
        if (-not $scope.isPublic) { return New-NrWhoisResult $Query 'SkippedNonPublic' $scope.scope }
        if ($Query.Contains(':')) { $bootstrap=$Context.ipv6 } else { $bootstrap=$Context.ipv4 }
    }
    $base=Get-NrRdapBase $Query $Kind $bootstrap
    $result=New-NrWhoisResult $Query 'NoRdapService'
    if (-not $base) { $result.error='No HTTPS RDAP service found in IANA bootstrap.'; $Context.queryCache[$key]=$result; return $result }
    $url=$base+$Kind+'/'+[Uri]::EscapeDataString($Query)
    if ($Context.delay -gt 0) { Start-Sleep -Milliseconds $Context.delay }
    $result.attempts=1
    $response=Invoke-NrHttps -Url $url -TimeoutSeconds $Context.timeout
    if ($response.status -eq 429) {
        $result.attempts=2
        Start-Sleep -Milliseconds 1500
        $response=Invoke-NrHttps -Url $url -TimeoutSeconds $Context.timeout
    }
    $result.httpStatus=[int]$response.status
    $result.sourceUrl=$response.url; $result.retrievedUtc=[DateTime]::UtcNow.ToString('o')
    $result.error=$response.error
    if ($response.body) {
        $filename=$Kind+'-'+(Get-NrHash $Query)+'.json'
        Write-NrText (Join-Path $Context.rawDirectory $filename) $response.body
        $result.rawFile='rdap/raw/'+$filename
    }
    if (-not $response.ok) {
        if ($response.status -eq 404) { $result.status='NotFound' }
        elseif ($response.status -eq 429) { $result.status='RateLimited' }
        elseif (Get-NrProperty $response 'timedOut' $false) { $result.status='Timeout' }
        else { $result.status='Error' }
    } else {
        try {
            $data=$response.body | ConvertFrom-Json -ErrorAction Stop
            if (Get-NrProperty $data 'errorCode') { throw ('RDAP error '+$data.errorCode) }
            $expectedClass=if ($Kind -eq 'ip') { 'ip network' } else { 'domain' }
            if ([string](Get-NrProperty $data 'objectClassName') -ne $expectedClass) { throw ('Unexpected RDAP object class; expected '+$expectedClass+'.') }
            $result.status='OK'
            $result.name=[string](Get-NrProperty $data 'name')
            if (-not $result.name) { $result.name=[string](Get-NrProperty $data 'ldhName') }
            $result.handle=[string](Get-NrProperty $data 'handle'); $result.country=[string](Get-NrProperty $data 'country')
            $result.startAddress=[string](Get-NrProperty $data 'startAddress'); $result.endAddress=[string](Get-NrProperty $data 'endAddress')
            $entities=@(Get-NrEntityNames (Get-NrProperty $data 'entities' @()))
            $result.entities=$entities
            $holders=@(); $registrars=@()
            foreach ($entity in $entities) {
                if ('registrar' -in $entity.roles) { if ($entity.name) { $registrars+=$entity.name }; continue }
                if ('registrant' -in $entity.roles -and $entity.organization) { $holders+=$entity.organization }
                elseif ('registrant' -in $entity.roles -and $entity.name) { $holders+=$entity.name }
            }
            $result.organization=(@($holders | Sort-Object -Unique) -join '; ')
            $result.registrar=(@($registrars | Sort-Object -Unique) -join '; ')
            # RFC 9083: retain the registry's labels, dates and role names verbatim.
            # A registry country is not a measurement of the server's physical location.
            $result.registrationStatuses=@(Get-NrProperty $data 'status' @())
            $events=@()
            foreach ($event in @(Get-NrProperty $data 'events' @())) {
                $action=[string](Get-NrProperty $event 'eventAction'); $rawDate=Get-NrProperty $event 'eventDate'
                $date=if ($rawDate -is [DateTime]) { $rawDate.ToUniversalTime().ToString('o') } else { [string]$rawDate }
                if (-not $action) { continue }
                $events+=[pscustomobject]@{action=$action;date=$date}
                if ($action -eq 'registration') { $result.registeredUtc=$date }
                elseif ($action -eq 'last changed') { $result.updatedUtc=$date }
            }
            $result.registrationEvents=$events
            $notices=@()
            foreach ($notice in @(@(Get-NrProperty $data 'notices' @())+@(Get-NrProperty $data 'remarks' @()))) {
                if ($null -eq $notice) { continue }
                $notices+=[pscustomobject]@{title=[string](Get-NrProperty $notice 'title');type=[string](Get-NrProperty $notice 'type');description=@(Get-NrProperty $notice 'description' @())}
            }
            $result.notices=$notices
            $redacted=@()
            foreach ($entry in @(Get-NrProperty $data 'redacted' @())) {
                if ($null -eq $entry) { continue }
                $name=Get-NrProperty $entry 'name' $null; $reason=Get-NrProperty $entry 'reason' $null
                $redacted+=[pscustomobject]@{name=[string](Get-NrProperty $name 'type' (Get-NrProperty $name 'description'));reason=[string](Get-NrProperty $reason 'type' (Get-NrProperty $reason 'description'));method=[string](Get-NrProperty $entry 'method')}
            }
            $result.redactedFields=$redacted
            if ($Kind -eq 'domain') { $result.registeredDomain=$Query }
        } catch { $result.status='ParseError'; $result.error=$_.Exception.Message }
    }
    $Context.queryCache[$key]=$result
    return $result
}

function Get-NrPtr {
    param([string]$Address,[int]$TimeoutMilliseconds=2500)
    $scope=Get-NetworkAddressScope $Address
    if (-not $scope.isPublic) { return [pscustomobject]@{status='SkippedNonPublic';names=@();error=$scope.scope} }
    $pending=$null
    try {
        $pending=[Net.Dns]::GetHostEntryAsync([Net.IPAddress]::Parse($Address))
        if (-not $pending.Wait($TimeoutMilliseconds)) { return [pscustomobject]@{status='Timeout';names=@();error='PTR lookup exceeded time budget.'} }
        $entry=$pending.Result; $names=@()
        foreach ($value in @($entry.HostName)+@($entry.Aliases)) { $valid=ConvertTo-NrDomain $value; if ($valid) { $names+=$valid } }
        $status=if ($names.Count) { 'OK' } else { 'NoName' }
        return [pscustomobject]@{status=$status;names=@($names | Sort-Object -Unique);error=''}
    } catch { return [pscustomobject]@{status='Error';names=@();error=$_.Exception.Message} }
}

function Get-NrLookupStatusCounts {
    param([object[]]$Results=@())
    $counts=[ordered]@{}
    foreach ($record in $Results) {
        $status=[string](Get-NrProperty $record 'status' 'Unknown')
        if (-not $counts.Contains($status)) { $counts[$status]=0 }
        $counts[$status]++
    }
    return [pscustomobject]$counts
}

function Write-NrEnrichmentCheckpoint {
    param([string]$Path,$Items,$Domains,[string]$Stage,$Context)
    if (-not $Path) { return }
    $temporary=$Path+'.writing'
    try {
        $parent=Split-Path -Parent $Path
        if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
        $snapshot=[pscustomobject]@{partial=($Stage -ne 'Complete');stage=$Stage;writtenUtc=[DateTime]::UtcNow.ToString('o');addresses=@($Items.ToArray());domains=@($Domains.ToArray());warnings=@($Context.warnings.ToArray())}
        Write-NrText $temporary ($snapshot | ConvertTo-Json -Depth 24 -Compress)
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary,$Path,[System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } catch {
        if (-not $Context.checkpointWarning) {
            [void]$Context.warnings.Add('Could not write enrichment checkpoint: '+$_.Exception.Message)
            $Context.checkpointWarning=$true
        }
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Invoke-NetworkEnrichment {
    [CmdletBinding()]
    param(
        [string[]]$Addresses=@(), [object[]]$DnsRecords=@(),
        [Parameter(Mandatory=$true)][string]$OutputDirectory,
        [ValidateRange(1,60)][int]$TimeoutSeconds=8,
        [ValidateRange(0,10000)][int]$DelayMilliseconds=250,
        [ValidateRange(0,100000)][int]$MaxIpLookups=0,
        [ValidateRange(0,100000)][int]$MaxDomainLookups=0,
        [ValidateRange(0,100000)][int]$MaxPtrLookups=0,
        [switch]$SkipPtr, [switch]$SkipRdap,
        [string]$CheckpointPath=''
    )
    $enrichmentClock=[Diagnostics.Stopwatch]::StartNew()
    $rdapDirectory=Join-Path $OutputDirectory 'rdap'
    $rawDirectory=Join-Path $rdapDirectory 'raw'; $resourceDirectory=Join-Path $rdapDirectory 'resources'
    [void][IO.Directory]::CreateDirectory($rawDirectory); [void][IO.Directory]::CreateDirectory($resourceDirectory)
    $context=@{warnings=(New-Object 'System.Collections.Generic.List[string]');timeout=$TimeoutSeconds;delay=$DelayMilliseconds;rawDirectory=$rawDirectory;resourceDirectory=$resourceDirectory;queryCache=@{};ipv4=$null;ipv6=$null;dns=$null;checkpointWarning=$false}
    $previousTls=[Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol=$previousTls -bor [Net.SecurityProtocolType]::Tls12
        $suffixRules=$null
        if (-not $SkipRdap) {
            foreach ($resource in @('ipv4','ipv6','dns')) {
                $body=Get-NrResource ($resource+'.json') ('https://data.iana.org/rdap/'+$resource+'.json') $context
                if ($body) { try { $context[$resource]=$body | ConvertFrom-Json -ErrorAction Stop } catch { [void]$context.warnings.Add("Invalid $resource bootstrap: $($_.Exception.Message)") } }
            }
            $psl=Get-NrResource 'public_suffix_list.dat' 'https://publicsuffix.org/list/public_suffix_list.dat' $context
            if ($psl) { $suffixRules=New-NrSuffixRules $psl }
        }
        $addressNames=@{}; $aliases=@{}
        foreach ($record in $DnsRecords) {
            $name=ConvertTo-NrDomain ([string](Get-NrProperty $record 'name'))
            if (-not $name) { continue }
            $data=[string](Get-NrProperty $record 'data'); $parsed=$null
            if ([Net.IPAddress]::TryParse($data,[ref]$parsed)) {
                $normal=(Get-NetworkAddressScope $data).lookupAddress
                if (-not $addressNames.ContainsKey($normal)) { $addressNames[$normal]=@{} }
                $addressNames[$normal][$name]=$true
            } else {
                $type=[string](Get-NrProperty $record 'type')
                if ($type -in @('5','CNAME')) {
                    $target=ConvertTo-NrDomain $data
                    if ($target) { if (-not $aliases.ContainsKey($target)) { $aliases[$target]=@{} }; $aliases[$target][$name]=$true }
                }
            }
        }
        foreach ($ipKey in @($addressNames.Keys)) {
            for ($depth=0; $depth -lt 16; $depth++) {
                $added=$false
                foreach ($name in @($addressNames[$ipKey].Keys)) {
                    if ($aliases.ContainsKey($name)) {
                        foreach ($alias in $aliases[$name].Keys) { if (-not $addressNames[$ipKey].ContainsKey($alias)) { $addressNames[$ipKey][$alias]=$true; $added=$true } }
                    }
                }
                if (-not $added) { break }
            }
        }
        $items=New-Object 'System.Collections.Generic.List[object]'; $domainNames=@{}; $ipResults=@{}; $ptrResults=@{}; $ipCount=0; $ptrCount=0; $domainCount=0
        $unique=@($Addresses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $domains=New-Object 'System.Collections.Generic.List[object]'
        $index=0
        foreach ($address in $unique) {
            $index++
            Write-Progress -Activity 'Looking up DNS and WHOIS/RDAP' -Status ("IP {0}/{1}: {2}" -f $index,$unique.Count,$address) -PercentComplete ([int](100*$index/[Math]::Max(1,$unique.Count)))
            $scope=Get-NetworkAddressScope $address; $normal=$scope.lookupAddress; $candidates=@()
            if ($addressNames.ContainsKey($normal)) { $candidates=@($addressNames[$normal].Keys | Sort-Object) }
            $ptr=[pscustomobject]@{status='SkippedNonPublic';names=@();error=''}
            $whois=New-NrWhoisResult $normal 'SkippedNonPublic' $scope.scope
            if ($scope.isPublic) {
                if ($ptrResults.ContainsKey($normal)) { $ptr=$ptrResults[$normal] }
                else {
                    if ($SkipPtr) { $ptr.status='Disabled' }
                    elseif ($MaxPtrLookups -gt 0 -and $ptrCount -ge $MaxPtrLookups) { $ptr.status='LimitReached' }
                    else { $ptrCount++; $ptr=Get-NrPtr -Address $normal -TimeoutMilliseconds ([Math]::Min(2500,$TimeoutSeconds*1000)) }
                    $ptrResults[$normal]=$ptr
                }
                if ($ipResults.ContainsKey($normal)) { $whois=$ipResults[$normal] }
                else {
                    if ($SkipRdap) { $whois=New-NrWhoisResult $normal 'Disabled' }
                    elseif ($MaxIpLookups -gt 0 -and $ipCount -ge $MaxIpLookups) { $whois=New-NrWhoisResult $normal 'LimitReached' }
                    else { $ipCount++; $whois=Invoke-NrRdapQuery $normal 'ip' $context }
                    $ipResults[$normal]=$whois
                }
            }
            $allNames=@(@($candidates)+@($ptr.names) | Sort-Object -Unique)
            foreach ($name in $allNames) { if (-not $domainNames.ContainsKey($name)) { $domainNames[$name]=$false }; if ($scope.isPublic) { $domainNames[$name]=$true } }
            [void]$items.Add([pscustomobject]@{address=$address;lookupAddress=$normal;family=$scope.family;scope=$scope.scope;isPublic=$scope.isPublic;dnsCandidates=$candidates;ptrNames=@($ptr.names);ptrStatus=$ptr.status;ptrError=$ptr.error;whois=$whois;domainWhois=@();names=$allNames})
            if ($index % 20 -eq 0) { Write-NrEnrichmentCheckpoint $CheckpointPath $items $domains 'IPLookups' $context }
        }
        Write-Progress -Activity 'Looking up DNS and WHOIS/RDAP' -Completed
        Write-NrEnrichmentCheckpoint $CheckpointPath $items $domains 'DomainLookups' $context
        $domainResults=@{}; $registeredResults=@{}; $di=0
        foreach ($name in @($domainNames.Keys | Sort-Object)) {
            $di++; Write-Progress -Activity 'Looking up domain registrations' -Status ("Name {0}/{1}: {2}" -f $di,$domainNames.Count,$name) -PercentComplete ([int](100*$di/[Math]::Max(1,$domainNames.Count)))
            $result=New-NrWhoisResult $name 'SkippedNonPublic'
            if ($SkipRdap) { $result.status='Disabled' }
            elseif (-not $domainNames[$name]) { $result.status='SkippedPrivateContext'; $result.error='Name only associated with non-public IPs in capture.' }
            elseif (Test-NrPublicDomain $name) {
                $registered=Get-NrRegisteredDomain $name $suffixRules
                if (-not $registered) { $result.status='NoRegistrationDomain'; $result.error='No registrable domain found using ICANN public suffix rules.' }
                elseif (-not (Get-NrRdapBase $registered 'domain' $context.dns)) { $result.status='NoRdapService';$result.registeredDomain=$registered;$result.error='No HTTPS RDAP service in IANA DNS bootstrap.' }
                else {
                    if (-not $registeredResults.ContainsKey($registered)) {
                        if ($MaxDomainLookups -gt 0 -and $domainCount -ge $MaxDomainLookups) { $registeredResults[$registered]=New-NrWhoisResult $registered 'LimitReached' }
                        else { $domainCount++; $registeredResults[$registered]=Invoke-NrRdapQuery $registered 'domain' $context }
                    }
                    $source=$registeredResults[$registered]
                    foreach ($property in $source.PSObject.Properties) { if ($property.Name -ne 'query') { $result.($property.Name)=$property.Value } }
                    $result.registeredDomain=$registered
                }
            } else { $result.error='Local, reserved or invalid DNS name; not sent externally.' }
            [void]$domains.Add($result); $domainResults[$name]=$result
            if ($di % 20 -eq 0) { Write-NrEnrichmentCheckpoint $CheckpointPath $items $domains 'DomainLookups' $context }
        }
        Write-Progress -Activity 'Looking up domain registrations' -Completed
        foreach ($item in $items) { $results=@(); foreach ($name in $item.names) { $results+=$domainResults[$name] }; $item.domainWhois=$results }
        if ($MaxIpLookups -gt 0 -or $MaxDomainLookups -gt 0 -or $MaxPtrLookups -gt 0) { [void]$context.warnings.Add("Explicit lookup limits: IP=$MaxIpLookups; registered domains=$MaxDomainLookups; PTR=$MaxPtrLookups. 0 means unlimited. Omitted records show LimitReached.") }
        $rdapErrors=@($context.queryCache.Values | Where-Object { $_.status -in @('Error','Timeout','ParseError','RateLimited') })
        $ptrErrors=@($ptrResults.Values | Where-Object { $_.status -in @('Error','Timeout') })
        if ($rdapErrors.Count) { [void]$context.warnings.Add(('{0} unique RDAP lookups failed or timed out; their individual statuses and errors are preserved. This is not a safety verdict.' -f $rdapErrors.Count)) }
        if ($ptrErrors.Count) { [void]$context.warnings.Add(('{0} reverse DNS lookups failed or timed out. Missing PTR records do not indicate malicious traffic.' -f $ptrErrors.Count)) }
        Write-NrEnrichmentCheckpoint $CheckpointPath $items $domains 'Complete' $context
        return [pscustomobject]@{
            addresses=@($items.ToArray());domains=@($domains.ToArray());warnings=@($context.warnings.ToArray())
            stats=[pscustomobject]@{
                uniqueAddresses=$unique.Count;uniquePublicAddresses=$ipResults.Count
                ipLookups=$ipCount;ptrLookups=$ptrCount;registeredDomainLookups=$domainCount;dnsNames=$domainNames.Count
                ipRdapStatuses=Get-NrLookupStatusCounts @($ipResults.Values)
                ptrStatuses=Get-NrLookupStatusCounts @($ptrResults.Values)
                registeredDomainRdapStatuses=Get-NrLookupStatusCounts @($registeredResults.Values)
                domainNameRdapStatuses=Get-NrLookupStatusCounts @($domains.ToArray())
                rdapErrors=$rdapErrors.Count;ptrErrors=$ptrErrors.Count
                elapsedSeconds=[Math]::Round($enrichmentClock.Elapsed.TotalSeconds,2)
                skipPtr=[bool]$SkipPtr;skipRdap=[bool]$SkipRdap;maxIpLookups=$MaxIpLookups;maxDomainLookups=$MaxDomainLookups;maxPtrLookups=$MaxPtrLookups
                timeoutSeconds=$TimeoutSeconds;delayMilliseconds=$DelayMilliseconds
            }
        }
    } finally { [Net.ServicePointManager]::SecurityProtocol=$previousTls }
}
