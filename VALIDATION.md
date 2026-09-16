# Validation

## Scope

The project includes offline PowerShell and JavaScript regression tests for:

- Socket and connection-audit normalization, process attribution, PID reuse and Windows service association.
- Audit-policy cleanup and recovery, including concurrent-policy-change handling.
- Duration parsing, orchestration and report rebuilding.
- Address classification, DNS correlation, RDAP response parsing and exclusions for private/special-purpose addresses.
- Isolated executable inspection, worker timeouts and file-change handling.
- Local English connection explanations and their uncertainty labels.
- JSON/HTML escaping, CSV handling and the filterable single-table report.
- Advanced filters, including address prefixes, port ranges, missing values and observation-time overlap.

## Execution environment and limitations

These tests use PowerShell 7 on Linux with simulated Windows interfaces, plus a deterministic JavaScript DOM harness. They do not establish a successful live capture on a Windows PC.

Native Windows socket collection, Security-log auditing, elevation, audit-policy restoration and Authenticode behavior still require a real Windows test. The original 3.0.0 release did not visually verify browser layout; the 3.0.1 checks below cover the new responsive CSS in Chromium. Test fixtures do not replace that validation.

## Run the tests

Run each PowerShell fixture in a fresh PowerShell process:

```powershell
Get-ChildItem .\tests\*.Tests.ps1 | ForEach-Object {
    & pwsh -NoLogo -NoProfile -File $_.FullName
    if ($LASTEXITCODE -ne 0) { throw "Failed: $($_.Name)" }
}
node .\tests\report-filters.Tests.cjs
node .\tests\report-ui.Tests.cjs
```

PowerShell 7 and Node.js are development-test dependencies. Ordinary use on Windows requires neither Node.js nor a separately installed PowerShell 7.

## Historical release results: 3.0.0

All nine regression suites passed for version 3.0.0 on 15 September 2026:

| Suite | Result |
|---|---|
| Windows capture | Passed: audit recovery, concurrent policy changes, process/PID attribution, protected-process fallback, services and IPv4/IPv6 event normalization |
| Enrichment | 123 checks passed |
| File metadata | 43 checks passed |
| Analysis | 39 checks passed |
| Connection explanations | 66 checks passed |
| Report builder and duration input | 40 checks passed |
| Capture/report orchestration | Passed: selectable duration, audit cleanup, UDP endpoint preservation and saved-capture rebuild |
| Advanced filter engine | 39 checks passed, including 10,000 records |
| Report UI | 53 checks passed against 10,000 simulated records |

The seven suites with numeric check counts total 403 checks; the two remaining suites report scenario-based pass results. An independent comparison of 9,412 IPv4/IPv6 CIDR cases against Python's `ipaddress` module also passed.

All distributed PowerShell files use UTF-8 with a byte-order mark and Windows line endings for Windows PowerShell 5.1 compatibility. The ZIP manifest was checked against its contents, and the four bundled reference resources match the uploaded edition byte for byte. These checks do not establish live Windows compatibility or browser layout quality; neither was tested in this environment.


## Version 3.0.1 validation (16 September 2026)

This update changes the report layout and adds a separate existing-report
patcher. It does not change the collection, enrichment, explanation or
normalization modules. Those module files and the filter engine were compared
byte for byte with the supplied 3.0.0 archive. The report's embedded JavaScript
is unchanged; its HTML changes are the new style block and an accessibility
hint that no longer instructs the user to scroll horizontally.

Executed in this environment:

| Check | Result |
|---|---|
| Existing JavaScript filter suite | 39 checks passed with 10,000 synthetic records |
| Existing JavaScript report UI suite | 53 checks passed with 10,000 synthetic records |
| Real Chromium 144 layout checks | Passed at 15 viewport widths, each in light and dark mode (30 combinations) |
| Viewport widths | 320, 360, 390, 650, 768, 850, 1024, 1199, 1200, 1280, 1366, 1440, 1669, 1920 and 2560 CSS pixels |
| Overflow and visibility | No horizontal page/table overflow; no overflowing data cells; all nine cells retained per record; sort buttons fill their responsive grid slots |
| Browser interactions | Sorting both ways, search, full details with long values, filtered CSV download, pagination, empty state and print layout passed |
| Browser diagnostics | No JavaScript page errors and no external HTTP(S) requests during the test |
| Visual review | Chromium screenshots inspected at 390, 1024 and 1669 pixels |
| CSS source parity | The standalone patch stylesheet matches the embedded template stylesheet |

Long unbroken process names, long DNS names, IPv6 endpoints and long registration
values were included. These are synthetic data, not a capture from a real PC.
The test injects the self-contained report into Chromium using Playwright's
`set_content`; it does not verify Windows Explorer's file association or the
user's browser policies for opening local files.

Run the browser test with development dependencies Python and Playwright:

```sh
python tests/browser-layout.Tests.py --browser /path/to/chromium
```

A PowerShell runtime was not available in this update environment. The existing
PowerShell regression suites and the new `responsive-patch.Tests.ps1` were
therefore **not executed for 3.0.1**. The new patcher was reviewed statically but
its Windows file picker, PowerShell execution and automatic browser launch
still need a live Windows check. Windows collection also remains outside the
scope of this CSS update. No live Firefox or Edge rendering test was performed.
