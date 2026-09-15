# Third-party data and references

## Public Suffix List

`resources/public_suffix_list.dat` is a bundled snapshot of the Public Suffix List. Its original header and license notice are preserved. The analyzer uses its ICANN section to determine registered domains for registry lookups.

- Source: [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat)
- Snapshot marker: `2026-09-08_12-18-37_UTC`
- Commit marker: `3955e3ec29b94c3cca7bd4509c5f14a7c0959e26`
- License: [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/)

The supplied dataset states:

> This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.

The dataset is supplied as source text with its notices intact. The license applies to that file; it does not by itself assign a license to the analyzer's other source files.

## IANA RDAP bootstrap data

The following public IANA bootstrap datasets are included as fallbacks when current bootstrap data cannot be downloaded:

| Local file | Source |
| --- | --- |
| `resources/ipv4.json` | [IPv4 RDAP bootstrap](https://data.iana.org/rdap/ipv4.json) |
| `resources/ipv6.json` | [IPv6 RDAP bootstrap](https://data.iana.org/rdap/ipv6.json) |
| `resources/dns.json` | [DNS RDAP bootstrap](https://data.iana.org/rdap/dns.json) |

Each file retains its dataset metadata. Bootstrap data locate registration services; they are not a threat feed or a claim about the safety of any address.

## Technical references

- [RFC 9224 — Finding the Authoritative RDAP Service](https://www.rfc-editor.org/rfc/rfc9224.html)
- [RFC 9083 — JSON Responses for RDAP](https://www.rfc-editor.org/rfc/rfc9083.html)
- [RFC 9537 — Redacted Fields in RDAP](https://www.rfc-editor.org/rfc/rfc9537.html)
- [Microsoft Windows event 5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156)
- [Microsoft Windows event 5157](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157)
- [Microsoft Service Host grouping](https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring)
- [Microsoft Windows service and port reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
- [Microsoft WebView2 process model](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/process-model)
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [RFC 6762 — Multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html)
- [RFC 4795 — LLMNR](https://www.rfc-editor.org/rfc/rfc4795.html)

No external JavaScript framework, CSS framework or font is required by the generated dashboard.
