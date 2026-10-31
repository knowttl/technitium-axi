# technitium-axi

AXI-standard agent-facing CLI for Technitium DNS Server.
The initial package provides offline help, version, credential schema and command inventory discovery.
Vendor operations, credential resolution and write support arrive in later slices.

Use Node 24.14.0 and npm 11.9.0, pinned in the setup files and package manifest.
Node 24 is a [supported LTS line](https://nodejs.org/en/about/previous-releases).

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

The journey runner packs and installs the executable in a temporary prefix, removes inherited credentials, and uses a kernel network namespace with only loopback enabled.
Its two disposable HTTPS endpoints and identities are synthetic harness infrastructure.
Discovery commands make zero vendor requests; these checks do not claim that a vendor operation has been implemented.
The runner removes child processes, keys and temporary installation roots on completion or cancellation.
A missing selected execution path fails the run.
The full approved checks select `--paths native,artium` and require the separately prepared local Artium admission fixture.
