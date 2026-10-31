# Offline package journeys

The B1.01 and B1.02 checks run the installed npm tarball, never a TypeScript loader.
They require Linux with user, PID, mount and network namespaces, iproute2 and OpenSSL.
The namespace enables only loopback and contains the CLI, server, adapter and subprocesses.
The setup pins Node 24.14.0 and npm 11.9.0.
Fetch the pinned npm dependencies once with `npm ci`, then keep all journeys offline.

```sh
npm test
node --test tests/journey.test.mjs
npm run typecheck
npm run check:generated
```

The hosted checks require the separately prepared, unmerged Artium admission fixture at revision `6d1e406705803a657241295ddf322b4c21fb4ef9`.
This is local test support, not a claim of stock Artium admission.
Obtain the fixture export and its manifest from the fixture owner and follow its startup preparation instructions.
Prepare its dependencies and build before entering the offline namespace.
The original fixture worktree is read-only.
Use a disposable exported copy for these checks.
Its frozen pnpm lockfile contains relative artifact locations, so preserve their resolution when arranging the export and tarballs.

```sh
export ARTIUM_FIXTURE_ROOT=/absolute/path/to/prepared/artium-fixture
export ARTIUM_FIXTURE_MANIFEST=/absolute/path/to/fixture/manifest.json
npm run check:journey -- --task B1.01 --paths native,artium --offline
npm run check:journey -- --task B1.02 --paths native,artium --offline
```

The harness checks the manifest digest, source-contract digests and current package tarball against the reviewed pin before starting the server.
The host registry must contain that exact installed package, with pnpm integrity checks intact.
Missing fixture inputs and unselected or unknown paths fail explicitly.
Each report separates expected, executed, failed, pending and skipped cases.

Hosted setup uses public login, password replacement, recent authentication, credential, tool, user and role endpoints.
The synthetic alpha caller has the tool grant; beta is authenticated without that grant.
The fixture stages a shared tool credential and does not consume it during discovery.
The two generated HTTPS boundaries are harness probes, not implemented vendor operations.
Per-caller vendor identity conformance remains part of later credential slices.

The source-reviewed run, input-file and existing transfer contracts live in `tests/fixtures/host-contract.json`.
The current host has no Technitium transfer route or transfer selection.
The harness checks that limit without inventing a route or claiming a completed transfer.
Later transfer slices require a host extension.

Node diagnostics report actual child PID, argv and executable hash without replacing the runner.
Public request traces retain method, path, safe header metadata, input hash and synthetic caller identity.
They omit authorization values and request bodies.
Save reports outside the repository when retaining local evidence.
Owned server processes, disposable keys, database, sessions and temporary installations are removed after the run.
