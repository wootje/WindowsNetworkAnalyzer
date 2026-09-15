# Changelog

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
