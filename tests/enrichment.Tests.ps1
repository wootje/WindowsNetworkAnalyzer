# Self-contained enrichment checks; no Pester dependency and no network requests.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Enrichment.ps1')
$script:testCount=0
function Assert-Equal($Actual,$Expected,[string]$Label) {
    if ($Actual -cne $Expected) { throw "$Label`: expected [$Expected], got [$Actual]" }
    $script:testCount++
}
foreach ($case in @(
    @('8.8.8.8','Public',$true),@('10.10.10.1','Private',$false),@('100.64.0.1','Shared-CGNAT',$false),
    @('127.0.0.1','Loopback',$false),@('169.254.1.1','LinkLocal',$false),@('172.31.255.255','Private',$false),
    @('192.0.2.1','Documentation',$false),@('198.51.100.2','Documentation',$false),@('203.0.113.3','Documentation',$false),
    @('198.18.1.1','Benchmark',$false),@('224.0.0.251','Multicast',$false),@('255.255.255.255','Broadcast',$false),
    @('::','Unspecified',$false),@('::1','Loopback',$false),@('::ffff:10.0.0.1','Private',$false),@('::ffff:8.8.8.8','Public',$true),
    @('fe80::1%3','LinkLocal',$false),@('fd00::1','Private',$false),@('ff02::1','Multicast',$false),
    @('2001:db8::1','Documentation',$false),@('3fff:123::1','Documentation',$false),@('2001:2::1','Benchmark',$false),
    @('64:ff9b::a00:1','Translation',$false),@('2606:4700:4700::1111','Public',$true),@('bad-address','Unknown',$false)
)) {
    $s=Get-NetworkAddressScope $case[0]
    Assert-Equal $s.scope $case[1] ('scope '+$case[0])
    Assert-Equal $s.isPublic $case[2] ('public '+$case[0])
}
Assert-Equal (Get-NetworkAddressScope '::ffff:8.8.8.8').lookupAddress '8.8.8.8' 'mapped normalization'
$rules=New-NrSuffixRules ([IO.File]::ReadAllText((Join-Path (Split-Path $PSScriptRoot -Parent) 'resources/public_suffix_list.dat')))
foreach ($case in @(
    @('www.bbc.co.uk','bbc.co.uk'),@('co.uk',''),@('a.b.ck','a.b.ck'),@('x.www.ck','www.ck'),
    @('x.city.kawasaki.jp','city.kawasaki.jp'),@('a.b.kawasaki.jp','a.b.kawasaki.jp'),
    @('foo.github.io','github.io'),@('router.local',''),@('foo.home.arpa',''),@('8.8.8.8',''),
    @('api.microsoft.com','microsoft.com')
)) { Assert-Equal (Get-NrRegisteredDomain $case[0] $rules) $case[1] ('registrable '+$case[0]) }
$unicode='b'+[char]0x00FC+'cher.de'
Assert-Equal (ConvertTo-NrDomain $unicode) 'xn--bcher-kva.de' 'IDNA'
Assert-Equal (ConvertTo-NrDomain 'https://google.com') '' 'URL is not a DNS name'
Assert-Equal (ConvertTo-NrDomain 'a_b.google.com') '' 'invalid DNS label'
$bootstrap=@{services=@(@(@('0.0.0.0/0'),@('https://rdap.example.net/')),@(@('8.8.0.0/16'),@('http://unsafe.example/','https://rdap.example.org/')))}
Assert-Equal (Get-NrRdapBase '8.8.8.8' 'ip' $bootstrap) 'https://rdap.example.org/' 'RDAP longest prefix and HTTPS'
Assert-Equal (Get-NrRdapBase '1.1.1.1' 'ip' $bootstrap) 'https://rdap.example.net/' 'RDAP default prefix'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('nr-enrichment-test-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$originalHttps=(Get-Item function:Invoke-NrHttps).ScriptBlock
$originalPtr=(Get-Item function:Get-NrPtr).ScriptBlock
try {
    # Capture-only DNS association: CNAME root included; private targets never queried.
    $dns=@([pscustomobject]@{name='edge.microsoft.com';data='8.8.8.8';type='A'},[pscustomobject]@{name='api.microsoft.com';data='edge.microsoft.com';type='CNAME'},[pscustomobject]@{name='camera.local';data='10.0.0.1';type='A'})
    $report=Invoke-NetworkEnrichment -Addresses @('8.8.8.8','10.0.0.1') -DnsRecords $dns -OutputDirectory $temporary -SkipRdap -SkipPtr
    $public=@($report.addresses | Where-Object address -eq '8.8.8.8')[0]
    Assert-Equal (@($public.dnsCandidates).Count) 2 'CNAME candidates'
    Assert-Equal $public.whois.status 'Disabled' 'RDAP disabled status'
    Assert-Equal (@($report.addresses | Where-Object address -eq '10.0.0.1')[0].whois.status) 'SkippedNonPublic' 'private WHOIS skipped'
    $script:mockCalls=0
    function Invoke-NrHttps {
        param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes)
        $script:mockCalls++
        if ($script:mockCalls -eq 1) { return [pscustomobject]@{ok=$false;status=429;body='{}';url=$Url;error='HTTP 429'} }
        return [pscustomobject]@{ok=$true;status=200;url=$Url;error='';body='{"objectClassName":"ip network","name":"TEST-NETWORK","handle":"TEST-1","country":"NL","startAddress":"8.8.8.0","endAddress":"8.8.8.255","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example Holder"]]]}]}' }
    }
    $context=@{queryCache=@{};ipv4=$bootstrap;ipv6=$null;dns=$null;delay=0;timeout=1;rawDirectory=$temporary}
    $result=Invoke-NrRdapQuery '8.8.8.8' 'ip' $context
    Assert-Equal $result.status 'OK' 'retry 429 succeeds'
    Assert-Equal $result.organization 'Example Holder' 'vCard registration holder'
    Assert-Equal $script:mockCalls 2 'one bounded retry'
    $again=Invoke-NrRdapQuery '8.8.8.8' 'ip' $context
    Assert-Equal $script:mockCalls 2 'RDAP response reused'
    Assert-Equal $again.country 'NL' 'RDAP cache fields'
    $privateResult=Invoke-NrRdapQuery '192.168.1.1' 'ip' $context
    Assert-Equal $privateResult.status 'SkippedNonPublic' 'direct private query guarded'
    Assert-Equal $script:mockCalls 2 'no external request for private address'
    function Invoke-NrHttps { param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes); [pscustomobject]@{ok=$false;status=404;body='{"errorCode":404}';url=$Url;error='HTTP 404'} }
    $missing=Invoke-NrRdapQuery '1.1.1.1' 'ip' $context
    Assert-Equal $missing.status 'NotFound' '404 is explicit'
    function Invoke-NrHttps { param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes); [pscustomobject]@{ok=$true;status=200;body='not JSON';url=$Url;error=''} }
    $bad=Invoke-NrRdapQuery '9.9.9.9' 'ip' $context
    Assert-Equal $bad.status 'ParseError' 'bad JSON is explicit'
    function Invoke-NrHttps { param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes); [pscustomobject]@{ok=$false;status=0;body='';url=$Url;error='Time budget expired';timedOut=$true} }
    $timeout=Invoke-NrRdapQuery '4.4.4.4' 'ip' $context
    Assert-Equal $timeout.status 'Timeout' 'timeout is distinguished from network errors'
    Assert-Equal $timeout.attempts 1 'no retry on timeout'
    $localDomain=Invoke-NrRdapQuery 'camera.home.arpa' 'domain' $context
    Assert-Equal $localDomain.status 'SkippedNonPublic' 'direct private DNS query guarded'
    Assert-Equal (Get-NrPtr '192.168.1.1').status 'SkippedNonPublic' 'direct PTR private guard'
    Assert-Equal (Get-NrPtr '2001:db8::1').status 'SkippedNonPublic' 'direct PTR documentation guard'

    function Invoke-NrHttps {
        param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes)
        $data=@{
            objectClassName='domain';ldhName='microsoft.com';handle='DOMAIN-TEST'
            status=@('active','client transfer prohibited')
            events=@(@{eventAction='registration';eventDate='1991-05-02T00:00:00Z'},@{eventAction='last changed';eventDate='2026-01-01T00:00:00Z'})
            entities=@(
                @{roles=@('registrant');handle='HOLDER';vcardArray=@('vcard',@(@('fn',@{},'text','Registration Holder'),@('org',@{},'text','Holder Organization')))},
                @{roles=@('technical');handle='TECH';vcardArray=@('vcard',@(@('fn',@{},'text','Technical Contact'),@('org',@{},'text','Technical Organization')))},
                @{roles=@('registrar');handle='REGISTRAR';vcardArray=@('vcard',@(,@('fn',@{},'text','Domain Registrar')))}
            )
            notices=@(@{title='Privacy';description=@('Some registration fields are redacted.')})
            redacted=@(@{name=@{type='Registrant Email'};reason=@{description='Server policy'};method='removal'})
        }
        return [pscustomobject]@{ok=$true;status=200;body=($data|ConvertTo-Json -Depth 15);url=$Url;error=''}
    }
    $context.dns='{"services":[[["com"],["https://registry.example.net/"]]]}' | ConvertFrom-Json
    $meta=Invoke-NrRdapQuery 'microsoft.com' 'domain' $context
    Assert-Equal $meta.status 'OK' 'domain registration metadata parsed'
    Assert-Equal $meta.organization 'Holder Organization' 'technical contact not misidentified as registration holder'
    Assert-Equal $meta.registrar 'Domain Registrar' 'registrar role'
    Assert-Equal $meta.entities.Count 3 'entity roles retained'
    Assert-Equal $meta.entities[1].handle 'TECH' 'entity handle retained'
    Assert-Equal $meta.registrationEvents.Count 2 'registry event dates retained'
    Assert-Equal ([DateTime]::Parse($meta.registeredUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) '1991-05-02T00:00:00Z' 'registration event identified'
    Assert-Equal ([DateTime]::Parse($meta.updatedUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) '2026-01-01T00:00:00Z' 'last changed event identified'
    Assert-Equal $meta.registrationStatuses.Count 2 'registry statuses retained'
    Assert-Equal $meta.notices[0].title 'Privacy' 'registry notice retained'
    Assert-Equal $meta.redactedFields[0].name 'Registrant Email' 'redacted field retained'
    Assert-Equal $meta.redactedFields[0].reason 'Server policy' 'redaction reason retained'
    Assert-Equal $meta.httpStatus 200 'HTTP status retained'
    Assert-Equal $meta.attempts 1 'attempt count retained'
    $wrongClass=Invoke-NrRdapQuery '8.8.4.4' 'ip' $context
    Assert-Equal $wrongClass.status 'ParseError' 'unexpected object class is not called successful'

    # Full pipeline: normalized IP cache, shared domain deduplication, private DNS
    # protection, counters, checkpoint replacement and explicit lookup limits.
    $script:queryUrls=New-Object 'System.Collections.Generic.List[string]'
    $script:ptrAddresses=New-Object 'System.Collections.Generic.List[string]'
    function Invoke-NrHttps {
        param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes)
        if ($Url -match 'data\.iana\.org/rdap/(ipv4|ipv6|dns)\.json') {
            $body=[IO.File]::ReadAllText((Join-Path $script:NrEnrichmentResourceRoot ($Matches[1]+'.json')))
        } elseif ($Url -match 'publicsuffix\.org/') {
            $body=[IO.File]::ReadAllText((Join-Path $script:NrEnrichmentResourceRoot 'public_suffix_list.dat'))
        } else {
            [void]$script:queryUrls.Add($Url)
            if ($Url -match '/ip/') { $body='{"objectClassName":"ip network","name":"MOCK NETWORK"}' }
            else { $body='{"objectClassName":"domain","ldhName":"mock-domain.com"}' }
        }
        return [pscustomobject]@{ok=$true;status=200;body=$body;url=$Url;error=''}
    }
    function Get-NrPtr {
        param([string]$Address,[int]$TimeoutMilliseconds)
        [void]$script:ptrAddresses.Add($Address)
        if ($Address -eq '1.1.1.1') { return [pscustomobject]@{status='Timeout';names=@();error='Mock DNS timeout'} }
        return [pscustomobject]@{status='OK';names=@('dns.google');error=''}
    }
    $dns=@(
        [pscustomobject]@{name='api.microsoft.com';data='8.8.8.8';type='A'},
        [pscustomobject]@{name='edge.microsoft.com';data='8.8.8.8';type='A'},
        [pscustomobject]@{name='secret.business.com';data='10.10.10.1';type='A'},
        [pscustomobject]@{name='printer.local';data='8.8.8.8';type='A'}
    )
    $checkpoint=Join-Path $temporary 'checkpoint.json'
    $full=Invoke-NetworkEnrichment -Addresses @('8.8.8.8','::ffff:8.8.8.8','1.1.1.1','10.10.10.1') -DnsRecords $dns -OutputDirectory $temporary -DelayMilliseconds 0 -CheckpointPath $checkpoint
    Assert-Equal $full.stats.ipLookups 2 'IP queries deduplicated after normalization'
    Assert-Equal $full.stats.uniquePublicAddresses 2 'distinct normalized public IP count'
    Assert-Equal $full.stats.ptrLookups 2 'PTR queries deduplicated after normalization'
    Assert-Equal $full.stats.registeredDomainLookups 2 'subdomains share one registration lookup'
    Assert-Equal $full.stats.ipRdapStatuses.OK 2 'IP status count'
    Assert-Equal $full.stats.ptrStatuses.Timeout 1 'PTR timeout status count'
    Assert-Equal $full.stats.ptrErrors 1 'PTR aggregate errors'
    Assert-Equal $full.stats.domainNameRdapStatuses.SkippedPrivateContext 1 'private-associated public-looking name skipped'
    Assert-Equal $full.stats.domainNameRdapStatuses.SkippedNonPublic 1 'local suffix skipped even with public IP'
    Assert-Equal (@($script:queryUrls | Where-Object { $_ -match '/domain/microsoft.com$' }).Count) 1 'one registry call for multiple subdomains'
    Assert-Equal (@($script:queryUrls | Where-Object { $_ -match 'business|printer|10\.10' }).Count) 0 'private addresses and DNS context never queried'
    Assert-Equal (@($script:ptrAddresses | Where-Object { $_ -eq '10.10.10.1' }).Count) 0 'no private PTR request'
    $saved=Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
    Assert-Equal $saved.stage 'Complete' 'atomic checkpoint finalized'
    Assert-Equal $saved.partial $false 'checkpoint completion flag'
    Assert-Equal $saved.addresses.Count 4 'checkpoint keeps observed address forms'
    Assert-Equal $saved.domains.Count 5 'checkpoint domain associations retained'
    Assert-Equal ([IO.File]::Exists($checkpoint+'.writing')) $false 'no temporary checkpoint left'

    $limited=Invoke-NetworkEnrichment -Addresses @('8.8.8.8','1.1.1.1') -DnsRecords $dns -OutputDirectory $temporary -DelayMilliseconds 0 -MaxIpLookups 1 -MaxDomainLookups 1 -MaxPtrLookups 1
    Assert-Equal $limited.stats.ipLookups 1 'explicit IP lookup bound'
    Assert-Equal $limited.stats.ptrLookups 1 'explicit PTR lookup bound'
    Assert-Equal $limited.stats.registeredDomainLookups 1 'explicit domain lookup bound'
    Assert-Equal $limited.stats.ipRdapStatuses.LimitReached 1 'omitted IP status'

    # Refresh failures must use bundled IANA/PSL while preserving failed lookup states.
    function Invoke-NrHttps { param([string]$Url,[int]$TimeoutSeconds,[int]$MaxBytes); [pscustomobject]@{ok=$false;status=0;body='';url=$Url;error='Offline test';timedOut=$true} }
    $offline=Invoke-NetworkEnrichment -Addresses @('8.8.8.8') -DnsRecords @() -OutputDirectory $temporary -DelayMilliseconds 0 -SkipPtr
    Assert-Equal $offline.stats.ipRdapStatuses.Timeout 1 'bundled bootstrap still reaches explicit lookup attempt'
    Assert-Equal $offline.stats.rdapErrors 1 'RDAP error summary'
    Assert-Equal (@($offline.warnings | Where-Object { $_ -match 'bundled snapshot used' }).Count) 4 'all resource fallback warnings'

} finally {
    Set-Item function:Invoke-NrHttps $originalHttps
    Set-Item function:Get-NrPtr $originalPtr
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
Write-Host ("Enrichment: {0} checks passed." -f $script:testCount)
