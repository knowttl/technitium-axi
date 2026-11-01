# technitium-axi

Agent-facing CLI for Technitium DNS Server, read-only by design.
It provides 46 read operations, strict credential profiles, offline discovery and protected result files.

[Why](#why-this-exists) | [Quickstart](#quickstart) | [Commands](#commands) | [Safety](#safety) | [Configuration](#configuration) | [Limitations](#limitations) | [Development](#development)

## Why this exists

Agents need to inspect a DNS server without holding broad credentials or flooding their context.
`technitium-axi` returns bounded TOON output by default (`--json` serializes the same projection) with next-step hints on errors.
Collections, strings, pages, requests, time and response bytes all have caps.
Vendor mutations are unavailable, and secrets are only accepted as references, never inline.

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

## Safety

- Every operation is a read. No create, update, delete or other vendor mutation is exposed.
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
Each profile has an HTTPS `origin`, `auth: "token"`, `tokenKind: "api"` and a `token` SecretRef such as `{"env": "MY_TECHNITIUM_TOKEN"}`.
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
- No vendor mutations are available.
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

## Security

No `SECURITY.md` ships yet; this is PENDING.

## License

No license file ships yet; this is PENDING.
`package.json` declares `UNLICENSED`.
