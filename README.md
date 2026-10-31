# technitium-axi

AXI-standard agent-facing CLI for Technitium DNS Server.
The initial package provides offline help, version, credential schema and command inventory discovery.
Vendor operations, credential resolution and write support arrive in later slices.

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
