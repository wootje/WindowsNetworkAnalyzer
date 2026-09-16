# Changelog

## 3.0.1 - Responsive report layout

- Fit all nine columns to the available desktop width using a fixed table layout.
- Wrap long process names, endpoints, DNS candidates, explanations and timestamps.
- Remove conflicting minimum cell widths without hiding or clipping horizontal overflow.
- Use labeled record grids on narrow windows; keep every field and all sort buttons.
- Keep the advanced filters, CSV export, details, dark/light themes and pagination.
- Add an offline existing-report patcher that writes a new HTML file alongside the original.
- Update the accessibility hint and document patching without a new measurement.
- Leave collection, DNS/RDAP analysis and firewall behavior unchanged.

## 3.0.0

This release upgrades the supplied Windows Network Analyzer connection-table edition.

- Translate the collector, report, launcher and documentation into English.
- Remove the third-party firewall integration and use native Windows socket snapshots and connection-audit events.
- Preserve the original single-table report, light/dark themes, sorting, pagination and CSV export.
- Add a duration prompt in minutes, keeping the three-minute default. Accept decimal durations and allow an orderly early stop with **S**.
- Keep command-line duration options, including explicit seconds for automated use.
- Show executable name and PID prominently and retain structured process-attribution evidence.
- Add Windows service descriptions, state and start mode where Windows exposes them.
- Add local English connection explanations, with evidence, limitations and follow-up suggestions.
- Expand executable inspection with available file metadata, Authenticode results and SHA-256.
- Expand public registration details, lookup statuses and saved raw evidence.
- Add advanced filters for process/service identity, addresses, CIDR prefixes, ports/ranges, DNS/PTR, registration data, signatures, counts and time overlap.
- Support rebuilding captures that use the v2 data format. Original version 1 saved outputs require a new capture.
- Preserve the earlier `-CheckSignatures` option for compatibility; checks are now enabled by default. Reject conflicting `-CheckSignatures` and `-SkipSignatures` options.
- Include an English GitHub README, generated-output exclusions, dataset notices, validation documentation and a file-integrity manifest.

The analyzer produces explanations and investigative metadata. It does not automatically block traffic or determine whether a connection is necessary or safe.
