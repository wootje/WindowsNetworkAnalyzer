# Windows Network Analyzer that generates a webpage with filter options

**Version 3.0.1** — Record Windows network activity, link observations to processes and Windows services, and explore an English explanation for each connection in a searchable offline HTML report.

Choose how long to record, use your applications normally, and inspect which processes contacted which IP addresses. The analyzer adds DNS candidates, reverse DNS, public IP/domain registration information, executable metadata, digital-signature results and SHA-256 hashes.

The collector runs independently through native Windows interfaces. It requires no third-party firewall API, packet-capture driver, Python installation, account or API key. All console messages, dashboard text and documentation are in English.

## New in version 3.0

This release updates the supplied connection-table edition while keeping its compact, single-table report and light/dark themes.

- English console messages, report labels, explanations and documentation.
- The Portmaster integration has been removed; collection uses native Windows socket and audit interfaces.
- An interactive **recording-duration prompt in minutes**, with **3 minutes** as the default, decimal values and an early-stop key.
- Executable name and PID shown prominently, with process-attribution evidence and associated Windows services.
- English explanations of each connection's possible purpose, supporting evidence, limitations and a suggested next check.
- Expanded executable, signature, hash, DNS, reverse-DNS and public registration details.
- Additional connection filters for processes, services, addresses, ports, registration data, signatures and observation times.
- GitHub documentation, generated-output exclusions and repeatable offline tests.

## Quick start

1. Extract the **entire ZIP** into a local folder, for example `C:\Tools\Windows-Network-Analyzer`.
2. Double-click `Start-Network-Analyzer.cmd`.
3. Accept the Windows administrator prompt so the collector can read connection-audit events.
4. Enter the recording duration in **minutes**, or press Enter for **3 minutes**. Examples: `0.5`, `1`, `3`, `10`, `30`, `60`.
5. Use the applications and websites you want to investigate. Press **S** in the collector window to finish recording early.
6. Wait for file inspection and registration lookups to finish. The report opens in your default browser.

Your results appear in a new `Report-<date>-<time>-<id>` folder beside the script. Open `report.html` again whenever you want; the dashboard works offline.

**Recording duration controls the capture phase.** File inspection, DNS/PTR queries, registration lookups and report generation run afterward and can take additional minutes. A preliminary HTML report and the captured data are saved before those slower steps begin.

## Requirements

- Windows 11, with 64-bit Windows PowerShell 5.1 or PowerShell 7.
- Administrator access for the default Windows connection-audit mode. A limited non-administrator mode is available with `-SkipWfp`.
- A writable local output folder and enough space for the chosen recording length.
- Internet access for public registration and reverse-DNS lookups, unless those options are disabled.
- A browser with JavaScript enabled to explore the generated report. No web server is needed.

The `.cmd` launcher uses Windows PowerShell included with Windows. Its execution-policy override applies only to that PowerShell process. It does not change the machine's execution-policy configuration. Organization-enforced policy may still prevent execution.

## Responsive layout update (3.0.1)

The connection table no longer requires horizontal scrolling. On a wide screen,
all nine columns share the available width. Long process names, IPv6 addresses,
DNS names, explanations and timestamps wrap onto additional lines instead of
expanding the table or being truncated. On narrower windows (below 1,200 CSS
pixels), each record becomes a labeled grid; on phone-sized screens its fields
are stacked vertically. Increasing browser zoom can also activate this layout.
All column-sort buttons, filters, details, pagination and CSV export remain
available. Vertical scrolling is still used where appropriate.

### Update an existing report without another capture

1. Extract the complete 3.0.1 package, or the small **Responsive Layout Fix** ZIP.
2. Double-click `Fix-Existing-Report.cmd` and select your existing `report.html`.
   Alternatively, drag one HTML report onto that `.cmd` file.
3. The tool creates `report-responsive.html` **in the same folder as the original**
   and opens it in your default browser. Existing files are never overwritten;
   a unique suffix is added when needed.

The patch only adds/replaces the responsive stylesheet and updates the old
horizontal-scrolling accessibility hint. Embedded record data and JavaScript
are unchanged. It requires no administrator privileges, does not start a new
measurement and does not make DNS/RDAP requests or change firewall settings.
The report's original capture-version metadata is retained. Keeping the result
next to its source preserves links to saved registration evidence.

Command-line example, without opening the resulting report:

```powershell
.\Apply-Responsive-Layout.ps1 -InputHtml "C:\Reports\report.html" -NoOpen
```

For **new captures**, use `Start-Network-Analyzer.cmd` from the full 3.0.1 package;
the layout is already embedded in the report template. `report-responsive.css`
is also supplied for manual editing. Its contents are embedded in the generated
HTML, so no external CSS file is required when viewing or sharing a report.
Do not solve an oversized table by simply hiding horizontal overflow: that can
make the rightmost columns inaccessible.

## Explore the connection table

The HTML report keeps the compact single-table layout. Its counters update with the current selection. Use the search box, filters and sortable column headings, then click the process/application entry in a row to open its details. The report supports light and dark themes, pagination, a listening-endpoint toggle, UDP-443/public-Internet quick filters and CSV export of the filtered selection.

| Information | Available details |
| --- | --- |
| **Connection** | Protocol, local and remote endpoint, source, state, audit decision, direction when recorded, first/last observation and observation count. |
| **Process** | Executable name, PID, path, process start time when available, product/application context and the evidence used to associate the process. |
| **Windows services** | Service name, display name, description, state and start mode when available. Windows supplies service metadata, so those descriptions may use the PC's display language. |
| **Possible purpose** | An English explanation, process role, confidence category, supporting facts, limitations and a suggested follow-up. |
| **Executable inspection** | Available company/version information, signature status and signer, SHA-256, inspection status and time. |
| **DNS and registration** | DNS-cache candidates, PTR results, public IP/domain RDAP information and links to supporting records. |

The original JSON is available in the details. CSV text fields are protected against spreadsheet-formula prefixes. Exporting CSV does not change the saved capture.

### Filters and examples

The main filters cover **application, protocol, state, source, address scope, audit decision, explanation category, explanation confidence and process-attribution status**. Advanced filters add process names/PIDs/paths, Windows services, local and remote IPs, ports, DNS/PTR names, organization, country, signature/signer/company/hash, direction, IP family, metadata/RDAP status, observation counts, time range and the presence of DNS or remote-endpoint information.

Filters in different fields are combined with **AND**. Supported lists within numeric, IP-address and country fields are combined with **OR**. For example, set protocol to TCP and remote ports to `80,443` to select TCP records whose remote port is either 80 or 443. The general search searches the recorded data, including process/service descriptions and explanation text.

| Investigation | Suggested filters |
| --- | --- |
| A particular program | Search its executable name, or use the process-name/PID/path fields. |
| Traffic involving your router | Set the relevant local or remote IP filter to your router's address, such as `10.10.10.1`. |
| A local subnet | Use an IP prefix such as `10.10.10.0/24`; comma-separated IPs/prefixes select any matching entry. |
| Web-related port patterns | Use remote ports `80,443`; select UDP and port `443` to inspect possible QUIC traffic. A port number alone does not prove the protocol. |
| A port range | Enter a range such as `8000-8100` in a port field. |
| Registration countries | Use two-letter codes such as `NL,US`; these describe registry records, not verified server locations. |
| A shared Windows service process | Filter for `svchost.exe`, then inspect the associated services and attribution evidence. |
| Missing hostname evidence | Select the DNS-presence filter. PTR results have a separate filter and do not count as DNS-cache candidates. |
| A period of interest | Set the UTC time bounds to retain records whose first/last-observation interval overlaps that period. |

The organization, country and RDAP-status filters use remote-IP and associated domain registrations. They do not use the local endpoint's registration. The IP-family filter uses the remote endpoint when available and otherwise the local binding. Time overlap does not establish that a connection was continuously active between its first and last observations.

Unknown, unavailable and skipped values remain visible as such. A filter match is an investigation aid, not a security verdict. Reset the filters to return to the complete captured table.

## Understanding a connection's explanation

Open a connection to inspect its explanation alongside its process identity. The explanation separates these questions:

| Field | Meaning |
| --- | --- |
| **Process role** | What the identified executable commonly does, when identity evidence supports that description. A familiar filename alone is not verification. |
| **Purpose** | What the observed endpoint, protocol and service context may indicate, such as name resolution or encrypted web traffic. |
| **Confidence** | `Observed`, `Likely` or `Unknown`: the basis for the description, not a safety score. A recorded endpoint is observable; an exact business purpose may remain unknown. |
| **Evidence** | The captured facts supporting the explanation, including process-attribution evidence and relevant address/port context. |
| **Limitations** | What those facts cannot establish, including shared service hosts and uncertain DNS names. |
| **Suggested check** | A practical follow-up to determine whether the activity fits your use of the application. |
| **Necessity** | Why the record alone cannot establish that the connection is required or safe. |

For example, UDP port 443 can be described as a possible QUIC/HTTP/3 connection. A query to the PC's configured DNS server on port 53 can support a name-resolution explanation. Neither observation identifies the exact page, task or payload. A connection to the default gateway identifies a local network role, but does not automatically identify which router feature is being used.

For `svchost.exe`, the report can list services observed in the owning process, such as `Dnscache` or `wuauserv`. **It does not select one service as the connection initiator merely because that service shares the process.** Exited or inaccessible processes retain the evidence actually available; missing identities are not filled using unrelated current processes.

Explanations are generated by deterministic local rules. No connection data are sent to an AI service. See Microsoft's [Service Host overview](https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring), [Windows service and port reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements), [HTTP/3 specification](https://www.rfc-editor.org/rfc/rfc9114.html) and [Multicast DNS specification](https://www.rfc-editor.org/rfc/rfc6762.html) for the technical basis of the relevant associations.

## Command-line examples

Open **PowerShell as administrator**, change to the extracted folder, and run one of these commands. Use either `-DurationMinutes` or `-DurationSeconds`, not both.

```powershell
# Record for the default three minutes.
.\Start-Network-Analyzer.ps1

# Record for ten minutes.
.\Start-Network-Analyzer.ps1 -DurationMinutes 10

# Record for exactly 30 requested seconds.
.\Start-Network-Analyzer.ps1 -DurationSeconds 30

# Prompt for the recording duration.
.\Start-Network-Analyzer.ps1 -Interactive

# Sample sockets every second and choose a fresh output folder.
.\Start-Network-Analyzer.ps1 -DurationMinutes 15 -IntervalSeconds 1 -OutputDirectory 'C:\NetworkReports\Session-01'

# Limit registration queries for a busy PC; PTR lookups are disabled separately.
.\Start-Network-Analyzer.ps1 -DurationMinutes 5 -MaxIpLookups 100 -MaxDomainLookups 100 -SkipPtr

# Capture and analyze locally, with registry, PTR and certificate checks disabled.
# Local DNS-cache reading, file-version inspection and hashing remain available.
.\Start-Network-Analyzer.ps1 -DurationMinutes 5 -SkipRdap -SkipPtr -SkipSignatures

# Limited socket-only recording, without changing the audit setting.
.\Start-Network-Analyzer.ps1 -DurationMinutes 5 -SkipWfp
```

If the current shell blocks script execution and your organization's policy permits it, invoke the script in a separate process:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Network-Analyzer.ps1 -DurationMinutes 10
```

The requested capture length ranges from **10 seconds to 24 hours**. Decimal minutes are accepted; the interactive prompt also accepts a decimal comma. Collection calls and the final event-drain step can make the measured duration slightly longer than requested. Long or busy captures can consume substantial memory and disk space; start with a short session.

## Options

| Parameter | Default | Meaning |
| --- | --- | --- |
| `-DurationMinutes` | `3` | Requested capture length in minutes; decimals accepted. |
| `-DurationSeconds` | Not set | Alternative duration, from `10` to `86400` seconds. |
| `-IntervalSeconds` | `2` | Target interval between socket snapshots, from `1` to `60` seconds. Slow collection calls can extend it. |
| `-Interactive` | Off | Prompt for duration if no duration was supplied, request elevation when needed, and pause before closing. |
| `-OutputDirectory` | New timestamped folder beside the script | Folder for this run. An existing `capture.json` prevents accidental reuse. |
| `-SkipWfp` | Off | Skip Windows connection auditing; retain TCP/UDP socket snapshots. |
| `-SkipRdap` | Off | Skip public IP and registered-domain RDAP queries. |
| `-SkipPtr` | Off | Skip public IP reverse-DNS queries. Local DNS-cache correlation still runs. |
| `-SkipSignatures` | Off | Skip Authenticode digital-signature checks. |
| `-CheckSignatures` | Not needed | Compatibility option from the earlier edition; signature checks are already enabled by default. Cannot be combined with `-SkipSignatures`. |
| `-SkipHashes` | Off | Skip executable SHA-256 hashing. |
| `-NoOpen` | Off | Generate the HTML without opening a browser. |
| `-MaxConnections` | `50000` | Maximum retained source records, from `100` to `500000`. New record combinations beyond the limit are omitted and flagged. |
| `-LookupTimeoutSeconds` | `8` | Per-request lookup timeout, from `1` to `30` seconds; retries can extend the total for a registration lookup. |
| `-FileTimeoutSeconds` | `15` | Per-executable worker timeout, from `3` to `120` seconds. |
| `-MaxIpLookups` | `0` | Maximum unique public IP RDAP queries; `0` means unlimited. Does not cap PTR queries. |
| `-MaxDomainLookups` | `0` | Maximum unique registered-domain RDAP queries; `0` means unlimited. |
| `-ReportFrom` | Not set | Rebuild a report from a version-2-format `capture.json` created by analyzer 2.x or 3.x, without starting a new capture. |
| `-RestoreAuditPolicy` | Not set | Restore the saved connection-audit setting using an existing recovery file on the original PC. |

## Collection and attribution

The collector combines periodic TCP/UDP socket snapshots with Windows Filtering Platform connection-audit events. Windows event **5156** records a permitted connection, while **5157** records a blocked connection. Event data can supply the process, endpoint addresses, ports and direction. See Microsoft's [event 5156 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) and [event 5157 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157).

Process association uses available process paths and start times to avoid attaching an old observation to a later process that reused the same PID. If attribution is unavailable or uncertain, the report says so. A service list for a shared service-host process describes associated services; it does not identify which individual service initiated a particular connection.

If the CIM process query fails, the collector attempts a `Get-Process` fallback and applies the same process-lifetime check. Restricted paths or start times can still prevent a match. The service list is collected independently; failure to read services does not turn a guessed service association into a confirmed one. Full process command lines are not collected.

Windows DNS-cache snapshots are collected approximately every ten seconds. Names associated with an observed IP are shown as **candidates**, not as proof that the process requested that domain. Multiple unrelated domains can share an address, and browser-managed encrypted DNS may never appear in the Windows cache.

Socket snapshots and audit events are retained as distinct evidence sources. A single real connection may appear in more than one source. The table counts retained source records, not packets, transferred bytes or connections that are necessarily still active. First-observation times refer to this capture and may be later than the underlying connection's creation. Repeated observations can be combined in one row.

## Public registration lookups: RDAP / WHOIS information

The analyzer uses **RDAP**, a structured registration-data protocol, to retrieve public IP-network and domain-registration information. It does not depend on a separate WHOIS executable. The response format is defined in [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083.html).

Public IPs are deduplicated and queried through the relevant registry selected from IANA's RDAP bootstrap data. Domain lookups use the registrable domain determined from the ICANN section of the bundled Public Suffix List, so a query for `api.example.co.uk` would concern `example.co.uk`. The registered domain's holder may differ from the operator of a subdomain or hosted application.

Where the registry provides them, results include network name and range, organization, entity roles, registrar, registration/update events, status values, notices and redaction explanations. Raw responses are saved with their source URL and retrieval time. Missing, unsupported, rate-limited and failed results have explicit statuses; there is no fallback to an unencrypted port-43 WHOIS query.

Private, loopback, link-local, multicast and other special-purpose addresses are excluded from external registration/PTR queries. DNS names seen only in a private-address context are excluded from public domain-registration queries. A registry's country field is registration metadata and should not be treated as the physical location of the server.

## Executable checks and analysis

Executable inspection collects available company/product/version details, Authenticode results and SHA-256 hashes. Each unique eligible file is inspected in a separate PowerShell worker with a timeout. The analyzer reads the file; it does not launch that executable. Network paths, reparse-point paths and unsupported drive/path types are skipped. Files larger than 256 MiB are excluded from hashing.

File changes during inspection cause the affected fingerprint and signature result to be discarded. Inspection happens after capture, so a file's current hash or signature is not proof of the exact bytes that previously ran in memory. A valid signature identifies a signing relationship; it does not establish that all network activity is necessary or safe.

The generated analysis data include explained observations such as:

- UDP port 443 traffic that may be QUIC/HTTP/3, without claiming that the port proves the protocol.
- Public-peer connections on ports commonly associated with management or database services.
- Unsigned or untrusted executable results, distinguished from unavailable or timed-out checks.
- Executables located in a user profile or temporary directory.
- Applications contacting many distinct public destinations.
- Missing DNS evidence, local listening endpoints and blocked audit events.

These are investigation aids, not malware verdicts. The tool does not decide whether a connection is necessary, decrypt HTTPS, inspect message contents or create firewall rules.

## Audit-setting restoration

The default mode temporarily enables success/failure auditing for the **Filtering Platform Connection** subcategory. It saves the original setting before changing it and attempts to restore it in cleanup. It does not disable your existing firewalls or change their allow/block rules. Audit events already written to the Windows Security log remain there.

Press **S** for an orderly early stop. Closing the window, forcibly terminating PowerShell or losing power can interrupt cleanup. If `audit-recovery.json` remains, run this command in an elevated PowerShell window on the **same PC**:

```powershell
.\Start-Network-Analyzer.ps1 -RestoreAuditPolicy 'C:\NetworkReports\Session-01\audit-recovery.json'
```

Use the recovery path printed by your own run. Restoration checks for concurrent policy changes so it does not silently overwrite a different setting applied by another administrator or policy. Read any recovery warning; a concurrent-change warning may require you to review the effective policy manually. A named mutex prevents simultaneous collectors from changing this audit subcategory through this tool.

## Rebuild an interrupted or saved report

The collector writes a `capture.json` checkpoint approximately every 30 seconds and again at the end of capture. A journal records the first sighting of each retained record combination as it is collected. This improves recoverability, but a hard stop can still lose observations after the latest checkpoint.

To rebuild from a v2 checkpoint into a **new** folder:

```powershell
.\Start-Network-Analyzer.ps1 -ReportFrom 'C:\NetworkReports\Session-01\capture.json' -OutputDirectory 'C:\NetworkReports\Session-01-Rebuilt'
```

Rebuilding does not capture new activity. It regenerates analysis and retries enrichment. Use the skip options to avoid new lookups or executable checks. Local file inspection is meaningful on the original Windows PC; rebuilding elsewhere cannot recreate missing process or file information. The supported saved-data identifier is `WindowsNetworkAnalyzerCapture-v2`; the `v2` in that identifier is a data-format version, not this release number. Saved outputs from the original version 1 edition are not supported by this entry point. Run a fresh capture to obtain the new service and process details.

## Output files

| File or folder | Purpose |
| --- | --- |
| `report.html` | Self-contained interactive report. A preliminary version is written before enrichment. |
| `report-data.json` | Data, per-connection explanations and computed analysis used by the HTML report. |
| `capture.json` | Captured records, DNS-cache evidence, settings and warnings; used by `-ReportFrom`. |
| `observations.jsonl` | Incremental first-sighting journal; not a packet log or a complete history of every repeat observation. |
| `file-metadata.json` | Results of executable inspection, when performed on Windows. |
| `enrichment.json` | Completed enrichment results and lookup statistics, if enrichment completes. |
| `enrichment-partial.json` | Enrichment checkpoint, updated after batches and at completion. |
| `rdap/` | Raw registry responses and reference data used for enrichment. |
| `audit-recovery.json` | Original audit state; normally removed after successful restoration. |

The main report works as a single HTML file. Keep the report folder together if you also want its relative links to raw registration JSON. A browser already displaying the preliminary report must be refreshed to show the final version.

## Privacy and publication

Reports can contain computer names, local usernames embedded in paths, process names, IP addresses, internal DNS names and browsing-related destination metadata. Treat generated reports as private unless you have reviewed them.

RDAP queries disclose the queried public IP or registered domain to the contacted registry. PTR queries use the system's DNS infrastructure. Certificate verification may contact certificate services. These operations occur after recording so the analyzer's own enrichment requests are not mixed into its capture window. Executable files, hashes and report contents are not uploaded by the analyzer.

To publish the source on GitHub, place the extracted project files at your repository root. Keep `README.md`, the scripts, template, resources, tests and third-party notices together. The supplied `.gitignore` excludes default report folders and common generated result files. Review `git status` before committing, especially if you use a custom output-folder name or export CSV files outside a report folder. The archive contains source and tests, not a capture of your PC. `SHA256SUMS.txt` lists distributed-file hashes for integrity checks; it is not a publisher signature or malware assessment.

## Known coverage limits

- This is a metadata collector for the PC on which it runs. It does not inventory every device behind your router.
- Short TCP connections can occur entirely between snapshots. Audit events improve visibility, but event loss, delayed events, Security-log rollover and policy restrictions can still create gaps.
- A UDP socket snapshot normally identifies a local endpoint. A remote peer requires suitable audit evidence; pre-existing UDP flows may lack new audit events during the recording window. Missing peers remain unknown.
- A Windows audit decision describes the observed filtering event. It does not prove that every other security product allowed the traffic or that a remote server answered. Third-party firewall blocks are not guaranteed to appear here.
- Snapshot direction is not inferred solely from port numbers. Listening on a wildcard address does not prove Internet exposure.
- Windows firewall-profile context is not a description of a third-party firewall's effective policy.
- VPNs, proxies, tunnels and shared infrastructure can make the visible peer differ from the ultimate destination.
- The collector does not inspect packet payloads, decrypt TLS, calculate transferred bytes, scan remote hosts or query a malware-reputation service.
- Output marked `Complete` means processing ended; review the report warnings for skipped sources, lookup failures or record limits.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Script/module not found | Extract the whole ZIP and run from the extracted project folder. Keep helper scripts and `resources` beside the entry point. |
| Administrator error | Run the launcher or PowerShell as administrator. Use `-SkipWfp` only if its reduced coverage is acceptable. |
| No UDP remote addresses | Check the coverage warnings for unavailable audit events. Generate fresh activity during capture; socket-only UDP rows cannot provide remote peers. |
| Unknown application or signature | Protected/exited processes, skipped paths, missing files and timeouts are reported explicitly. Review the attribution and metadata-status fields. |
| Few or no domain names | The app may use direct IPs, its own DNS cache or encrypted DNS. A blank DNS field alone does not establish suspicious behavior. |
| Slow processing after recording | File checks and registry timeouts can accumulate. Start with a shorter run, lower lookup limits, or use the relevant skip options. The preliminary report is already in the output folder. |
| No browser opens | Open the printed `report.html` path manually. |
| Existing capture in output folder | Choose a fresh output folder; the tool avoids overwriting an earlier capture. |
| Audit-restoration warning | Use the recovery command above and review the exact warning on the original Windows PC. |

## Project layout and tests

| Source | Responsibility |
| --- | --- |
| `Start-Network-Analyzer.ps1` / `.cmd` | User options, duration prompt, capture orchestration and report generation. |
| `WindowsCapture.ps1` | Native Windows collection, process association, network context and audit recovery. |
| `Enrichment.ps1` | Address classification, DNS correlation, reverse DNS, RDAP and lookup checkpoints. |
| `FileMetadata.ps1` / `Inspect-Executable.ps1` | Bounded executable inspection and worker isolation. |
| `Analysis.ps1` | Computed summaries, coverage and investigative findings in the saved analysis data. |
| `ConnectionExplanations.ps1` | Local English explanations for individual records, including process/service context, evidence and uncertainty. |
| `ReportBuilder.ps1` | Record normalization, merging, checkpoints and safe report embedding. |
| `report-template.html` | Offline connection table, details and CSV export, with embedded responsive CSS. |
| `report-responsive.css` | Source stylesheet for the responsive layout; also used by the existing-report patcher. |
| `Fix-Existing-Report.cmd` / `Apply-Responsive-Layout.ps1` | Apply the layout to a saved report without collecting new data. |
| `report-filters.js` | Filter engine embedded into generated HTML; keep it beside the report template. |
| `resources/` | Bundled RDAP bootstrap data and Public Suffix List. |
| `tests/` | Offline PowerShell fixtures and dependency-free JavaScript interaction tests. |

For development, run each PowerShell test in a **fresh PowerShell 7 process**. These tests use mocked Windows interfaces and do not require administrator rights:

```powershell
Get-ChildItem .\tests\*.Tests.ps1 | ForEach-Object {
    & pwsh -NoLogo -NoProfile -File $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "Failed: $($_.Name)" }
}

# Node.js is needed only for the dashboard's development tests.
node .\tests\report-filters.Tests.cjs
node .\tests\report-ui.Tests.cjs
```

See [VALIDATION.md](VALIDATION.md) for the test scope and environment limits. The fixtures cover process attribution, audit cleanup, DNS/RDAP handling, executable inspection, report generation and filtering. Native Windows capture still requires a real-PC check. Version 3.0.1 adds Chromium browser layout checks with synthetic data; these do not establish Windows collection compatibility or identical rendering in every browser.

## Third-party data

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for bundled reference data and its notices. Those notices concern the included datasets and do not assign a license to the rest of the project. Choose an appropriate project license when publishing your repository if you want to grant reuse rights.


<img alt="GitHub all releases" src="https://img.shields.io/github/downloads/wootje/WindowsNetworkAnalyzer/total">
