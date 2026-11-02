# technitium-axi

Agent-facing CLI for Technitium DNS Server with reads and explicitly granted writes.
It provides strict credential profiles, offline discovery, protected result files and a durable mutation journal.

[Why](#why-this-exists) | [Quickstart](#quickstart) | [Commands](#commands) | [Writes](#writes) | [Safety](#safety) | [Configuration](#configuration) | [Limitations](#limitations) | [Development](#development)

## Why this exists

Agents need to inspect a DNS server without holding broad credentials or flooding their context.
`technitium-axi` returns bounded TOON output by default (`--json` serializes the same projection) with next-step hints on errors.
Collections, strings, pages, requests, time and response bytes all have caps.
Vendor mutations require explicit grants and preview confirmation, and secrets are only accepted as references, never inline.

## Quickstart

Requires Node `>=24.14.0 <25` (see [.node-version](.node-version)).

```sh
npm install --global @knowttl/technitium-axi
technitium-axi --help
```

Without a selected profile the tool refuses to run and says how to select one:

```text
error:
  code: PROFILE_REQUIRED
  message: Select a credential profile
help[1]: Use --config <file> --profile <name>
```

Import a config, then make a first authenticated read:

```sh
technitium-axi config import --input-file /absolute/path/config.json
technitium-axi auth status --profile automation
technitium-axi zone list --profile automation --fields name,type
```

## Use with your agent

No session hooks or agent skill ship with this package yet; both are PENDING.
Agents can use the CLI directly.
`technitium-axi --help` and `technitium-axi inventory` describe every command offline.

## Commands

Run `technitium-axi --help` for the full generated list and `technitium-axi <command> --help` for each command's parameters.
The packaged `command-inventory.json` is the reference; this table lists the groups.

| Group | Examples |
| --- | --- |
| Local | `schema`, `inventory`, `auth status`, `profile list`, `config path`, `config import`, `doctor` |
| Server | `status`, `user session get`, `user profile get`, `user check-for-update` |
| Dashboard | `dashboard metrics json`, `dashboard metrics text`, `dashboard stats get`, `dashboard stats get-top` |
| Zones | `zone list`, `zone catalog list`, `zone export`, `zone options get`, `zone permission get`, `zone dnssec view-ds`, `zone dnssec properties get`, `zone record get` |
| Cache and lists | `cache list`, `allowed list`, `allowed export`, `blocked list`, `blocked export` |
| Apps and DNS client | `app list`, `app list-store-apps`, `app config get`, `dns-client health-check` |
| Settings | `settings get`, `settings get-tsig-key-names`, `settings backup` |
| DHCP | `dhcp lease list`, `dhcp scope list`, `dhcp scope get` |
| Admin | `admin session list`, `admin user list`, `admin user get`, `admin group list`, `admin group get`, `admin permission list`, `admin permission get`, `admin sso get`, `admin ldap get`, `admin cluster state`, `admin cluster primary transfer-config` |
| Logs | `log list`, `log download`, `log query`, `log export` |

Read commands share `--config`, `--profile`, `--json`, `--result-file`, `--fields`, `--full`, `--max-bytes`, `--max-requests`, `--max-pages` and `--max-elapsed-ms`.
Operation-specific flags such as `--node`, `--filter-name` and `--page-number` appear in each command's `--help`.

```sh
technitium-axi zone list --profile automation --full
technitium-axi settings get --profile automation --result-file /absolute/path/settings.json
technitium-axi settings backup --profile automation --zones true --result-file /absolute/path/zones.zip
```

See [Read contracts and protected results](docs/reads.md) for output bounds, paging, transfer formats and the reviewed archive-entry map.

## Writes

`technitium-axi inventory --json` is the generated reference for write commands, operation IDs, input fields, required fields, SecretRef fields and record selectors.
Write inputs use vendor parameter names inside a JSON `parameters` object, supplied through a protected absolute `--input-file` owned by the current user with no group or other access (for example, mode 0600).
Input and upload files are limited to 16 MiB each.
See [protected results](docs/reads.md) for result replacement and destination permissions.
Booleans and integers use JSON types; list fields use arrays of strings.
Write commands use the flags listed in their `--help`, rather than the read projection and paging flags.

Account actions use the same grants, protected input and preview confirmation as other writes.
`user login` (also `auth login`) explicitly acquires a Standard session with `user`, a `pass` SecretRef and an optional `totp` SecretRef.
Select a `tokenKind: "session"` profile with a matching `username` and `token: {"stored": true}` to use the issued session on subsequent calls.
Only the issued session is stored, bound to the profile name, origin, username, token kind and TLS settings; passwords and one-time codes are discarded.
Ordinary reads never acquire or refresh credentials.
`user logout` (also `auth logout`) reports remote revocation and bound local removal separately, including when revocation fails.

`user create-token` accepts either the selected Standard bearer or an explicit `user` and `pass` SecretRef, with optional `totp`, and never falls back between them.
`user create-single-use-token`, `user change-password`, `user 2fa init`, `user 2fa enable`, `user 2fa disable` and `user profile set` require a Standard session.
Token creation and 2FA initialization require `--result-file` on execution; their confidential response never appears in ordinary output.
Password changes use `pass` and `newPass` SecretRefs; `totp` is also a SecretRef.
`user session delete` accepts the exact `partialToken` returned by a profile read.
`admin user set` supports a protected `newPass` and an ordinary boolean `totpEnabled`.
`admin session create-token` accepts `user` and `tokenName`, and requires a protected `--result-file` before issuing the API token.
`admin session delete` selects the exact `partialToken` and optional `node`; it never deletes sessions on other nodes implicitly.
`admin user create` requires `user` and a `pass` SecretRef, with optional `displayName`.
`admin user set` can also rename an account with `newUser`, update its display name, disabled state and session timeout, or replace `memberOfGroups`.
`admin user delete`, `admin group create` and `admin group delete` select one named account or group.
`admin group set` supports `newGroup`, `description` and replacement `members`, with an exact selected baseline.
`admin permission set` selects a `section` and optional `node`, with typed `userPermissions` and `groupPermissions` rows and an exact selected baseline.
Section permission writes require the primary when clustering is enabled; the vendor enforces caller permissions.

`admin sso user create` and `admin sso user set` require an initialized secondary profile.
Preview and execution read the same selected caller's session with `includeInfo=true` and require exactly `info.permissions.Administration.canModify: true` before dispatch.
The cluster-state preflight also requires Administration View on the selected secondary.
The preview names the requested secondary, effective primary and caller.
The vendor proxy supplies its cluster identity; the tool never acquires that identity.
Direct primary calls, missing or malformed permissions, and single-use credentials fail before SSO mutation.

Cluster lifecycle commands are available under `admin cluster`, with `primary` and `secondary` subgroups.
Run `inventory --json` for their exact typed inputs and routing scopes.
Cluster preflight and verification require Administration View in addition to the vendor's Modify or Delete permission.
Use an API token or Standard session; single-use tokens cannot support the required reads.
Previews bind the selected topology, describe replicated effects and identify affected members.

`admin cluster init-join` accepts `primaryNodePassword` and optional `primaryNodeTotp` only as SecretRefs.
`ignoreCertificateErrors` is an explicit vendor join parameter; it does not change this tool's TLS trust.
Join and update-secondary accept a base64url DER public certificate in `secondaryNodeCertificate`.
Cluster options use integer intervals: heartbeat refresh and retry accept 10-300 seconds, config refresh and retry accept 30-3600 seconds, and config refresh must exceed heartbeat refresh.
Omitted timers remain unchanged.

Successful lifecycle output verifies only the selected node's topology.
Notify and resync acknowledge scheduled synchronization; they do not prove every zone has synchronized.
Graceful remove asks the secondary to leave; delete-secondary removes primary membership without resetting that secondary.
Forced leave, delete and promotion can leave remote configuration behind, which requires separate reads through explicitly trusted profiles.
Changed listeners, URLs and certificates never cause automatic credential forwarding to a new origin.
After a lost response, retain the audit ID and use the original input and confirmation with `--reconcile` on the original trusted binding.
For init and init-join, add `--reconcile-profile <name>` to verify through an explicitly configured trusted replacement profile after a listener or identity change.
The replacement profile is used only for the read and receives no mutation.
An unreachable or unverifiable target remains `OUTCOME_UNKNOWN` and must not be replayed.

Literal `node=cluster` is accepted only for supported dashboard aggregation and blocking relay operations.
Other commands require a named node or the configured origin.

`settings set` accepts all fields listed in the inventory's configuration map, including modern fields and the `preferIPv6` and `reverseProxyNetworkACL` compatibility inputs.
Omitted fields are preserved; arrays replace collections.
An empty array clears collections except `dnsServerLocalEndPoints` and `webServiceLocalAddresses`, which reset to wildcard listeners.
To append, include the existing collection plus the new entries and retain the original collection in the baseline.
The optional input `encoding` selects `form` (default) or `json`; `--json` controls output only.
Use the inventory's configuration map for field types and structured row columns.
`defaultResponsiblePerson` accepts only a plain `local@domain` address in parameters and baselines, preserving its case; an empty string clears the value.
Display names, comments and angle brackets are rejected locally before any vendor request; full MailAddress syntax is deferred.
TSIG shared secrets and proxy and certificate passwords require SecretRefs in both changed values and baselines.
In parameters, a TSIG shared-secret reference resolving to an empty string requests a vendor-generated secret.
For an absent certificate or proxy password, use a baseline SecretRef resolving to an empty string; an absent proxy username uses an empty string directly.
Updating a certificate password requires an existing or selected certificate path.
Proxy updates preserve unselected proxy fields; disabling the proxy clears its configuration.
Forwarder replacement preserves the current transport unless selected explicitly; clearing the list resets it to UDP.
Settings comparisons account for case and trailing dots in `dnsServerDomain`, blank web-service headers restoring defaults, and `HttpsJson` normalizing to `Https`.
Never submit a redacted GET response as a patch.
Settings are not transactional: a handler error can leave earlier assignments saved and requires inspection before another write.

```json
{
  "parameters": {"defaultRecordTtl": 300, "forwarders": ["192.0.2.2"], "enableBlocking": false},
  "baseline": {"defaultRecordTtl": 3600, "forwarders": ["192.0.2.1"], "enableBlocking": true},
  "encoding": "json"
}
```

`app install`, `app update` and `settings restore` use `upload: {"file": "/absolute/path/package.zip"}` in the input envelope.
These uploads must be ZIP archives with safe relative entry names and no symbolic links; invalid archives are rejected locally with `UPLOAD_INVALID`.
The preview binds the exact upload hash, and execution sends one binary file with operation parameters in the query string for vendor proxy compatibility.
`app download-and-install` and `app download-and-update` take `name` and an HTTPS `url` in `parameters`; the DNS server downloads the package.
`app uninstall` takes `name` and leaves APP records intact.
`app config set` takes `name` and `config: {"file": "/absolute/path/dnsApp.config"}` in `parameters`.
The protected config file is sent as an exact opaque string, including unknown keys and whitespace, and is never printed.
Restore selection flags are independent booleans and default to false at the vendor.
Restore is not transactional: a handler error can leave earlier categories restored and requires inspection before another write.
Use `--result-file` to retain exact settings or restore responses, including returned proxy and TSIG secrets, in a protected file.
Restore responses can include current DNS settings secrets even when `dnsSettings` is false.
An unsafe explicit result destination is rejected before write dispatch.
`settings temporary-disable-blocking` takes a positive integer `minutes` and returns the vendor's expiry time; `settings force-update-block-lists` triggers an asynchronous update.
`log delete` takes the `fileName` returned by `log list` as its `log` value, without a path, and optional `node`; `log delete-all` accepts optional `node`.

DHCP lease removal and conversion require a scope `name` and exactly one of `clientIdentifier` or `hardwareAddress`.
Scope enable, disable and delete take `name`; reservation removal also requires `hardwareAddress`.
Reservation addition requires `name`, `hardwareAddress` and `ipAddress`, with optional `hostName` and `comments`, and checks for an existing hardware or address reservation before dispatch.
Use a single-writer window for this check because the vendor does not atomically reject a concurrent duplicate address.
`dhcp scope set` updates an existing scope using typed fields from the inventory's `dhcpFields` map.
When renaming, `baseline.newName` is the current scope name.
Omitted fields are preserved, arrays replace collections, and empty arrays clear them.
Structured rows retain the listed column order when encoded for the vendor, including option bytes, static routes, exclusions and reservations.
Scope setters and reservation addition need a reusable API or session credential for their preflight reads.

Mutations require the selected file profile's `writes.allowWrites` to be `true` and its `writes.operations` to contain the exact capability from the inventory.
The accepted grant values live in `technitium-axi schema --json`; there are no wildcard grants.
`TECHNITIUM_AXI_READ_ONLY=true` or `1` overrides all mutation grants; `false` or `0` leaves grants effective.
`dns-client resolve` without `parameters.import: true` needs no write grant; importing requires `OP-077.import`.
The resolve response includes the DNS reply and any DNSSEC `warningMessage`.
When import is requested, a nonempty DNSSEC warning suppresses import and reports `mutation: suppressed`.

Cache deletion (`OP-054`) accepts a `domain`; cache flush (`OP-055`) takes an empty `parameters` object.
Allowed and blocked lists each support `add`, `delete`, `flush` and `import`, with their exact operation grants shown in the inventory.
Add and delete accept `domain`; flush takes empty parameters.
Imports accept `{"parameters":{"allowedZones":["a.test","b.test"]}}` or `blockedZones` for the blocked list.
These arrays are sent as comma-separated form fields, including duplicates or an empty array; imports merge membership and do not use uploads.
Each import entry must be nonempty and contain no ASCII whitespace, ASCII control characters or commas.
Dashboard history deletion (`OP-019`) accepts an optional `node` and preserves current query counters.

For example, authorize only record additions with this field in the selected profile:

```json
"writes": { "allowWrites": true, "operations": ["OP-049"] }
```

An input file for a record addition can contain:

```json
{"parameters":{"zone":"example.test","domain":"www.example.test","type":"A","ipAddress":"192.0.2.10","ttl":300}}
```

First preview, then execute with the exact returned `preview.digest` and the same profile and input:

```sh
technitium-axi zone record add --profile automation --input-file /absolute/path/add.json --json
technitium-axi zone record add --profile automation --input-file /absolute/path/add.json --execute --confirm '<preview.digest>'
```

A preview resolves credentials, operation SecretRefs and uploads locally.
Only the [SSO preflight](#writes) sends vendor reads during preview; previews never dispatch mutations.
It reports permission, target and upload metadata without secret values.
Each preview issues a fresh invocation ID within its digest, bound to the selected profile, target and input contents.
Bearer-authenticated writes also bind the selected credential; explicit identity acquisition uses a private local acquisition key.
An executed mutation creates an exclusive durable intent before dispatch and retains its receipt; if that confirmation reaches journal creation again, it is refused with `REPLAY_DENIED`.
A new preview permits a later legitimate operation with identical content.

Journal entries default to `$XDG_STATE_HOME/technitium-axi/writes.log.d/<digest>.json`, or `~/.local/state/technitium-axi/writes.log.d/<digest>.json` when no absolute XDG state directory is set.
Set `TECHNITIUM_AXI_WRITE_LOG` to an absolute base path to use `<base-path>.d/<digest>.json` instead.
The journal stores operation identity, state and keyed hashes, without parameter or secret values.
Failure to persist an intent prevents dispatch.
Dispatched mutations never retry automatically; a failed response or unproven postcondition returns `OUTCOME_UNKNOWN` and an audit ID.
Never replay an uncertain write or create a new preview to bypass its journal entry.

`zone options set`, `zone permission set`, `settings set`, `dhcp scope set`, `admin group set` and `admin permission set` require an additional `baseline` object containing exactly the changed fields, excluding target identifiers.
Read the selected target first and supply its current values; execution re-reads them and returns `CONFLICT` before dispatch if they differ.
Zone-option and group lists are explicit replacements, including empty arrays; omitted fields remain unchanged.
See the settings guidance above for collection reset and coupled-field behavior.
Null settings collection baselines map to empty arrays, and null catalog/primary-transfer TSIG names map to empty strings.
Group renames use `baseline.newGroup` for the current group name; settings proxy fields use the getter's nested `proxy` values.
Update-security-policy baselines accept getter rows or the setter string representation.
These operations verify selected fields after dispatch, including renamed group and scope targets.
The vendor has no atomic conditional setter, so maintain a single-writer window between the final read and write.
For these operations, use `--reconcile <audit-id> --confirm '<original-preview.digest>'` with the original input and profile to prove the postcondition without resending the mutation.
Other operations, except resync as described below, require manual inspection of the exact selected target when their outcome is uncertain.
Baseline checks, verification and reconciliation account for vendor member ordering and case, TSIG name sets, catalog names, enum case, IPv6 formatting, ACL network prefixes and merged update-policy rows.
TSIG names, catalog names and update-policy keys and domains compare case-insensitively after trimming leading and trailing dots; other ASCII characters and numeric labels remain literal, so `key/a` differs from `key/b` and `127.1` differs from `127.0.0.1`.
Permission replacements use arrays of getter-shaped rows: `userPermissions` rows contain `username`, `canView`, `canModify` and `canDelete`; `groupPermissions` rows use `name` instead of `username`.
An empty user permission array clears that collection; group permission replacements retain the mandatory administrator groups for the selected zone or section with all permissions.
See the inventory's `permissions` contract for the exact groups.
An omitted collection remains unchanged.
Administrators membership replacements retain the authenticated caller.

Zone import and Primary or Forwarder zone creation accept `upload: {"file":"/absolute/path/zone.txt"}` alongside `parameters`, without inline `records`.
The upload is read before preview or dispatch and bound into the confirmation by its bytes, hash and format.
For imports, `upload.format: "text"` sends the exact file bytes with `Content-Type: text/plain`; the default format is `"multipart"`.
Creation uploads require multipart format.
Zone imports also accept inline zone text in `parameters.records` through the form transport.
Zone creation, cloning, conversion, enable, disable, deletion and resync use the same preview and exact-grant boundary.
Delete accepts either `parameters.zone` or a nonempty `parameters.zones` array; mixed batch results report `status: "partial"` with the deleted and failed targets.
Resync requires an API or session credential, reads the original SOA serial, then checks up to three complete zone reads for serial advancement.
SOA matching trims leading and trailing dots, ignores case and normalizes internationalized zone names to ASCII while preserving distinct ASCII labels.
If advancement cannot be proven, it returns `OUTCOME_UNKNOWN` with an audit ID and never resends the resync.
Reconciliation can prove later serial advancement with the original input, confirmation and audit ID.
An unchanged serial can conservatively remain unknown even after a successful transfer.
Operation secret fields (including PEM keys, FWD proxy passwords and LDAP bind passwords) accept only `{"env":"VARIABLE"}` or `{"file":"/absolute/path/secret"}` references, not stored references or inline values.
Resolved operation secrets are limited to 1 MiB and are not trimmed.

DNSSEC write parameters accept integer `iterations` from 0 to 50, `saltLength` from 0 to 32 bytes, `keyTag` from 0 to 65535, and `rolloverDays` or `zskRolloverDays` from 0 to 365, where supported by the operation.
DNSSEC writes report success when the vendor accepts the request, without waiting for key lifecycle progress or verifying the resulting zone state.
Inspect `zone dnssec properties get`, `zone record get` and, for delegation data, `zone dnssec view-ds` to check the selected zone afterward.

Record selectors and replacement fields depend on both family and action; use the inventory's `recordFamilies` instead of copying a read projection.
Known decimal record types are normalized to names before validation; raw `rdata` selectors apply only to genuinely unknown numeric types.
SOA uses apex update, while generated DNSSEC records use lifecycle operations.
DNAME deletion, including numeric type `"39"`, is refused with `PREREQUISITE_PENDING` until shipped-library mapping is reviewed in [issue #18](https://github.com/knowttl/technitium-axi/issues/18).

Single-use credentials are never retried and are refused for operations requiring baseline reads.
After dispatch they are reported as consumed, or consumed-or-uncertain on an unknown outcome.

## Safety

- Writes follow the [grant, confirmation and journal policy](#writes).
- Ordinary reads never acquire, refresh or store credentials.
- `status` and the no-argument view perform one unauthenticated HTTPS status read and send no credential.
- `user session get` returns a redacted projection.
  `--result-file` additionally saves the exact confidential JSON in an atomic protected file and reports its path, byte count and SHA-256.
- Config and CA files must be owned by the current user and not writable by group or others.
  File SecretRefs and stored credentials must additionally deny all group and other access.
  These reads reject symlinks and redirected paths before consuming the file.
- `caFile` and `tlsServerName` select trust and certificate identity while certificate verification stays enabled.
- `doctor` verifies credential protection and performs one bounded session read.

## Configuration

A version 1 config holds named profiles.
Each profile has an HTTPS `origin`, `auth: "token"`, a `tokenKind` and a `token` SecretRef such as `{"env": "MY_TECHNITIUM_TOKEN"}`.
The accepted credential kinds and optional write policy are defined by the schema below; see [Writes](#writes) for execution requirements.
`technitium-axi schema --json` describes the accepted profile fields.
SecretRefs also support protected absolute files and explicitly stored credentials.
Inline secrets and secret flags are refused.

Config selection uses `--config`, then `TECHNITIUM_AXI_CONFIG`, then the platform config directory.
`technitium-axi config path` shows the selected path.

Profile selection uses `--profile`, `TECHNITIUM_AXI_PROFILE`, a complete environment profile, the configured default, or the sole profile.
A selected file profile ignores competing environment fields.
Partial environment profiles fail without borrowing fields.

The environment profile uses `TECHNITIUM_AXI_ORIGIN`, `TECHNITIUM_AXI_AUTH`, `TECHNITIUM_AXI_TOKEN_KIND` and `TECHNITIUM_AXI_TOKEN`.
Optional fields use the same prefix: `TECHNITIUM_AXI_USERNAME`, `TECHNITIUM_AXI_CA_FILE` and `TECHNITIUM_AXI_TLS_SERVER_NAME`.
Environment-only profiles and env SecretRefs work when no config file is present.
Relative `caFile` paths resolve beside the config file that declares them; environment profiles require an absolute CA path.

## Output and exit codes

- Output is TOON by default; `--json` gives the same approved projection.
- Collections default to at most 100 rows with four summary fields per object row.
  Strings are bounded to 1,000 characters, or 1,000,000 with `--full`.
- Defaults are 10 pages, 12 requests, 30 seconds overall and 16 MiB of response bytes.
  `--max-pages`, `--max-requests`, `--max-elapsed-ms` and `--max-bytes` can lower those caps or raise them within the limits reported by input errors.
- Usage and input errors print an `error` block with a `code`, a `message` and a `help` hint, and exit with code 2.

## Limitations

- Native Windows file protection and interruption verification are PENDING.
  Windows file reads and writes are refused until ownership and ACL verification is available.
- Linux file protection is verified natively.
- Hosted write admission requires separate release-candidate proof; see [Offline package journeys](docs/offline-checks.md).
- Session hooks and an agent skill are PENDING.

## Development

Use the Node version pinned in [.node-version](.node-version) and the npm version in the `packageManager` field of [package.json](package.json).

```sh
npm ci
npm run build
npm run typecheck
npm run check:generated
npm run check:journey -- --task B1.01 --paths native --offline
```

Native checks run on Linux with `unshare`, `ip` and `openssl` installed.
See [Offline package journeys](docs/offline-checks.md) for isolation, synthetic harness boundaries, cleanup and the full native and Artium checks.
See [CONTRIBUTING.md](CONTRIBUTING.md) for test-quality rules.
Release automation runs `npm run test:release` and installs the packed package for CLI smoke checks.
`npm test` also checks the packed file list, offline installation, CLI help/version, and published module imports in a network namespace.
Run this check alone with `npm run test:contract`.

## Security

No `SECURITY.md` ships yet; this is PENDING.

## License

`LICENSE` and `package.json` declare `UNLICENSED`.
