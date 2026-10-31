# technitium-axi

AXI-standard agent-facing CLI for Technitium DNS Server.
The package provides status and session reads, strict credential profiles, offline discovery and protected session-result files.
Vendor mutations are unavailable.

Use the Node version pinned in [.node-version](.node-version) and the npm version in the `packageManager` field of [package.json](package.json).

```sh
npm ci
npm run build
npm pack
npm install --prefix /tmp/technitium-install ./knowttl-technitium-axi-0.1.0.tgz
/tmp/technitium-install/node_modules/.bin/technitium-axi --help
/tmp/technitium-install/node_modules/.bin/technitium-axi schema --json
```

Run native package and harness checks on Linux with `unshare`, `ip` and `openssl` installed:

```sh
npm run typecheck
npm run check:generated
npm run check:journey -- --task B1.01 --paths native --offline
npm run check:journey -- --task B1.02 --paths native --offline
```

See [Offline package journeys](docs/offline-checks.md) for isolation, synthetic harness boundaries, cleanup and the full native and Artium checks with their required fixture setup.

Configure a version 1 config with a named profile containing an HTTPS `origin`, `auth: "token"`, `tokenKind: "api"` and `token: {"env": "MY_TECHNITIUM_TOKEN"}`.
`schema --json` describes all accepted fields.
SecretRefs also support protected absolute files and explicitly stored credentials.
Inline secrets and secret flags are refused.
Ordinary reads never acquire, refresh or store credentials.

```sh
technitium-axi config path
technitium-axi config import --input-file /absolute/path/config.json
technitium-axi profile list
technitium-axi auth status --profile automation
technitium-axi status --profile automation
technitium-axi user session get --profile automation --result-file /absolute/path/session.json
```

Config selection uses `--config`, then `TECHNITIUM_AXI_CONFIG`, then the platform config directory.
Profile selection uses `--profile`, `TECHNITIUM_AXI_PROFILE`, a complete environment profile, the configured default, or the sole profile.
A selected file profile ignores competing environment fields.
Partial environment profiles fail without borrowing fields.
The environment profile uses `TECHNITIUM_AXI_ORIGIN`, `TECHNITIUM_AXI_AUTH`, `TECHNITIUM_AXI_TOKEN_KIND`, `TECHNITIUM_AXI_TOKEN` and optional `USERNAME`, `CA_FILE`, `TLS_SERVER_NAME` fields with the same prefix.

`status` and the no-argument view perform one unauthenticated HTTPS status read.
`user session get` returns a redacted projection; `--result-file` additionally saves the exact confidential JSON in an atomic protected file and reports its path, byte count and SHA-256.
`caFile` and `tlsServerName` select trust and certificate identity while certificate verification stays enabled.
`doctor` verifies credential protection and performs one bounded session read.
Linux file protection is verified natively; native Windows file protection and interruption verification remain PENDING.
Windows file reads and writes are refused until ownership and ACL verification is available.
Environment-only profiles and env SecretRefs remain supported when no config file is present.
