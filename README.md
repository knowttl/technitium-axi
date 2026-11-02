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
Booleans and integers use JSON types; list fields use arrays of strings.
Write commands use the flags listed in their `--help`, rather than the read projection and paging flags.

Mutations require the selected file profile's `writes.allowWrites` to be `true` and its `writes.operations` to contain the exact capability from the inventory.
The accepted grant values live in `technitium-axi schema --json`; there are no wildcard grants.
`TECHNITIUM_AXI_READ_ONLY=true` or `1` overrides all mutation grants; `false` or `0` leaves grants effective.
`dns-client resolve` without `parameters.import: true` needs no write grant; importing requires `OP-077.import`.

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

A preview resolves credentials, operation SecretRefs and uploads locally but sends no vendor request.
It reports permission, target and upload metadata without secret values.
Each preview issues a fresh invocation ID within its digest, bound to the selected credential, target and input contents.
An executed mutation creates an exclusive durable intent before dispatch and retains its receipt; if that confirmation reaches journal creation again, it is refused with `REPLAY_DENIED`.
A new preview permits a later legitimate operation with identical content.

Journal entries default to `$XDG_STATE_HOME/technitium-axi/writes.log.d/<digest>.json`, or `~/.local/state/technitium-axi/writes.log.d/<digest>.json` when no absolute XDG state directory is set.
Set `TECHNITIUM_AXI_WRITE_LOG` to an absolute base path to use `<base-path>.d/<digest>.json` instead.
The journal stores operation identity, state and keyed hashes, without parameter or secret values.
Failure to persist an intent prevents dispatch.
Dispatched mutations never retry automatically; a failed response or unproven postcondition returns `OUTCOME_UNKNOWN` and an audit ID.
Never replay an uncertain write or create a new preview to bypass its journal entry.

`zone options set`, `settings set` and `admin group set` require an additional `baseline` object containing exactly the changed fields, excluding target identifiers.
Read the selected target first and supply its current values; execution re-reads them and returns `CONFLICT` before dispatch if they differ.
Lists are explicit replacements, including empty arrays; omitted fields remain unchanged.
Null forwarder/blocklist baselines map to empty arrays, and null catalog/primary-transfer TSIG names map to empty strings.
Group renames use `baseline.newGroup` for the current group name; settings proxy bypass uses the getter's `proxy.bypass` value.
Update-security-policy baselines accept getter rows or the setter string representation.
Forwarder replacement preserves the current transport (clearing the list resets it to UDP); proxy bypass replacement requires an existing proxy and preserves its configuration.
These operations verify selected fields after dispatch, including the renamed group target.
The vendor has no atomic conditional setter, so maintain a single-writer window between the final read and write.
For these operations, use `--reconcile <audit-id> --confirm '<original-preview.digest>'` with the original input and profile to prove the postcondition without resending the mutation.
Other operations require manual inspection of the exact selected target when their outcome is uncertain.
Server normalization can conservatively leave verification and reconciliation at `OUTCOME_UNKNOWN`; this accepted limitation is tracked in [issue #22](https://github.com/knowttl/technitium-axi/issues/22).

Zone import and Primary zone creation accept `upload: {"file":"/absolute/path/zone.txt"}` alongside `parameters`, without inline `records`.
The upload is read before preview or dispatch, bound into the confirmation by its bytes and hash, and sent as multipart data.
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
