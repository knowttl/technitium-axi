# Read contracts and protected results

The read catalogue covers the 46 operations in the 0.1.0 read slice.
`inventory --json` describes every canonical command, operation ID, typed parameter, flag and wire location.
`--help` on a command works without credentials or a network connection.
Parameters use kebab-case flags; the form keeps the vendor's original parameter name.
Booleans require explicit `true` or `false` values.
The selected credential is sent only in the Authorization bearer header.
`--if-modified-since` requires an RFC 1123 GMT date and is sent only as an HTTP header.
`--include-zones` accepts comma-separated zone names, including an empty selection.

```sh
technitium-axi zone list --fields name,type
technitium-axi zone list --full --max-pages 3
technitium-axi log query --name QueryLogs --class-path QueryLogs.App --page-number 2
technitium-axi admin cluster primary transfer-config --include-zones example.test --if-modified-since 'Mon, 01 Jan 2024 00:00:00 GMT' --result-file /absolute/path/config.zip
```

TOON is the default output; `--json` serializes the same approved projection.
The encoder is pinned to TOON 2.3.1 to match the Artium host decoder contract.
Unknown vendor fields are tolerated and omitted from ordinary output.
Required envelope and collection fields and the types of projected fields are validated before output.
Known passwords, TSIG shared secrets and token values are excluded from generic projections.
Session output preserves the existing typed identity and permission projection.
Opaque app configuration produces only metadata, even when its keys do not look like secrets.
`--full` expands the approved projection, not the set of confidential fields allowed into stdout.
The collection, field-selection, paging and retry controls below apply to the additional read commands; `status` and `user session get` retain the interfaces described in the [README](../README.md).

Collections default to at most 100 rows with four summary fields per object row.
`--fields` selects documented fields on the primary object collection, or response fields for a detail read.
`--full` permits up to 10,000 rows per collection and expands summary fields.
Strings are bounded to 1,000 characters by default and 1,000,000 with `--full`.
The output reports truncation, returned and available collection counts, request/page counts and completion.
Provider totals remain provider totals; missing totals are never invented.

Zone and query-log reads request vendor pages and expose `nextPage` when more data remains.
`--full` follows pages until completion or a cap is reached, deduplicating zone names or query-log row numbers.
The defaults are 10 pages, 12 requests, 30 seconds overall and 16 MiB of response bytes.
`--max-pages`, `--max-requests`, `--max-elapsed-ms` and `--max-bytes` can lower those caps or raise them within the limits reported by input errors.
A request lasts at most ten seconds.
Page and request caps preserve completed rows and mark the result incomplete.
An explicit byte or elapsed cap reached during a later page also preserves completed rows and the continuation.
A provider-total mismatch is incomplete rather than a claim of exhaustive coverage.

One immediate retry is permitted for HTTP 429, 502, 503 or 504 within the request and elapsed caps.
A nonzero Retry-After prevents an immediate retry and produces retry guidance.
Single-use identities never retry.
Transport, malformed JSON, missing required fields, invalid credentials, second-factor requirements, permission denial, unavailable operations and vendor failures have structured errors.
Vendor error messages and stack traces are not echoed.

Use `--result-file <absolute-path>` to preserve exact response bytes in an atomic protected native file.
The result reference reports the file path, byte count and SHA-256; it never puts confidential bytes in stdout.
For a paged read, this file contains the initial vendor page, while the ordinary projection may aggregate subsequent pages with `--full`.
Choose an explicit page number when saving a particular vendor page.
Windows file output remains refused until native ACL verification is implemented.
All downloads reject JSON error envelopes and unexpected content types.
An incomplete, oversized or failed response cannot replace a previously valid result file.
Zone exports, ZIP archives, CSV, logs and allowed/blocked exports produce metadata in ordinary output and exact bytes in the protected file.
Prometheus output also permits a bounded text preview.
Hosted result paths are supplied by the host; callers cannot choose server filesystem destinations.

The monitor read journeys cover dashboard metrics and charts, cache navigation, DNS health checks, app and settings reads, DHCP leases and scopes, and logs.
Run `npm run check:journey -- --task B2.05 --paths native --offline` for this group, or select an individual operation with `--task B2.OP-015 --operation OP-015`.
Use `--paths artium` with the reviewed frozen fixture environment to exercise authenticated host result custody.
Log download `--limit` is the vendor's megabyte limit; `--max-bytes` is the separate local response cap.
Log filenames cannot contain paths.
Opaque app configurations accept string or null values and remain available only in protected results.

# Archive entry review

Backup and transfer contracts in `inventory --json` include the source-reviewed entry map.
The source revision is `0dd592aad21eced4221a9a46204cb1a299972ca0`.
The relevant source files and their SHA-256 digests are recorded in the map.
The review covers [BackupConfigAsync](https://github.com/TechnitiumSoftware/DnsServer/blob/0dd592aad21eced4221a9a46204cb1a299972ca0/DnsServerCore/DnsWebService.cs#L643), [TransferConfigAsync](https://github.com/TechnitiumSoftware/DnsServer/blob/0dd592aad21eced4221a9a46204cb1a299972ca0/DnsServerCore/WebServiceClusterApi.cs#L384) and [cluster component selection](https://github.com/TechnitiumSoftware/DnsServer/blob/0dd592aad21eced4221a9a46204cb1a299972ca0/DnsServerCore/Cluster/ClusterManager.cs#L858).

Ordinary backups select the components requested by explicit boolean flags.
They include `zones/*.zone` and all app files recursively.
Certificate files qualify only when they exist beneath the server configuration directory.
Cluster transfers exclude certificates, cluster/web/log configuration, scopes, statistics and logs.
They include eligible signed Primary catalog-member keys as `zones/<name>.keys`.
Selected zone names force eligible key inclusion; newer unselected keys remain eligible.
Configuration file mtimes and key StateChangedOn comparisons use strict greater-than.
Ordinary zone, app, scope, statistic and log backups include their selected category files without applying the transfer timestamp filter.

An unchanged app directory emits the zero-byte `apps/<name>/.exists` marker.
A changed package emits `apps/<name>/<name>.zip`; a changed configuration emits `apps/<name>/dnsApp.config`.
Either changed file suppresses the marker.
Empty and key-only transfer fixtures contain no app directories.
An empty ZIP is a valid HTTP 200 protected result, with a response-time Last-Modified header.
These fixtures are synthetic source-based evidence and do not establish behavior on a live server.
