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

Native Windows socket collection, Security-log auditing, elevation, audit-policy restoration and Authenticode behavior still require a real Windows test. Actual browser layout has not been visually verified. Test fixtures do not replace that validation.

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

## Release results

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
