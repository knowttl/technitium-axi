# Offline package journeys

The B1 and B2 package, credential and read checks run the installed npm tarball, never a TypeScript loader.
They require Linux with user, PID, mount and network namespaces, iproute2, OpenSSL and a C compiler for process-interruption checks.
The namespace enables only loopback and contains the CLI, server, adapter and subprocesses.
Follow the [README setup](../README.md) to fetch the pinned npm dependencies once, then keep all journeys offline.
The runner removes inherited credentials and packs and installs the executable in an empty temporary prefix.
Discovery commands make zero vendor requests.
B1.02 and the credential journeys start two disposable HTTPS boundaries with synthetic identities.
Status and session fixtures follow the vendor top-level JSON response shapes.

```sh
npm test
node --test tests/journey.test.mjs tests/vendor.test.mjs tests/private-file.test.mjs
npm run typecheck
npm run check:generated
```

The hosted checks require a maintainer-supplied, reviewed but unmerged Artium admission fixture matching [the reviewed host contract](../tests/fixtures/host-contract.json).
The default pipeline checks run native only; hosted journeys run separately at the final head using the reviewed frozen fixture with `--paths native,artium` (or `--paths artium` for hosted checks alone).
Stock Artium is unsupported until admission lands upstream.
Obtain the prepared Artium checkout, its revision and its exact reviewed JSON manifest from a maintainer.
The manifest supplies the revision as `fixtureCommit` and lists each tool tarball in `tools`, with a `tool` name, `tarball` path and hexadecimal `sha256` digest.
It must include `technitium-axi`; its tarball paths must resolve from the journey runner's working directory, so use absolute paths when preparing the fixture.
The manifest bytes must match the reviewed digest; rewriting paths requires a newly reviewed manifest and contract pin.
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

Pass the prepared checkout path through `ARTIUM_FIXTURE_ROOT` and the manifest path through `ARTIUM_FIXTURE_MANIFEST`; the revision is supplied through the manifest, not a separate flag.
The harness verifies the manifest SHA-256, its `fixtureCommit` against the reviewed revision, the pinned source-file SHA-256 digests, and the `technitium-axi` tarball SHA-256 against both the manifest and the freshly packed package before starting the server.
It refuses to continue on a mismatch; other tool tarballs are installed through the fixture's frozen pnpm lockfile with integrity checks.
Record the fixture revision used for this PR in the PR body only, rather than copying the contract pin into this guide.
The host registry must contain that exact installed package, with pnpm integrity checks intact.
Missing fixture inputs for a selected Artium path, an omitted path selection and unknown paths fail explicitly.
Native-only runs do not require the Artium fixture; every selected path must execute successfully.
Each report separates expected, executed, failed, pending and skipped cases.

Hosted setup uses public login, password replacement, recent authentication, credential, tool, user and role endpoints.
The synthetic alpha caller has the tool grant; beta is authenticated without that grant.
The fixture stages a shared tool credential; status sends no bearer and session get consumes only the isolated injected SecretRef.
Session get returns a caller-bound, credential-revision-bound, one-time protected-result reference alongside its redacted projection.
The protected result is retained in bounded host memory for at most five minutes and is never written into ordinary output or audit.

The source-reviewed run, input-file and existing transfer contracts live in `tests/fixtures/host-contract.json`.
The current host has no Technitium transfer route or transfer selection.
The harness checks that limit without inventing a route or claiming a completed transfer.
Later transfer slices require a host extension.

B2.01 through B2.04 cover the generated read matrix, protected formats, bounded paging/errors and archive-entry review.
They use the same task selector and paths as B1.
The B2 hosted path requires a newly reviewed fixture admitting the complete read inventory and generalizing protected result custody beyond sessions.
It uses the authenticated result path returned by the host rather than inventing a Technitium transfer endpoint.
The response matrix is generated from typed contracts and retained public documentation example seeds; all POST fixtures are synthetic.
The archive review task performs no successful backup or transfer request.
The format task exercises independently defined ZIP entry worlds and exact protected bytes.
Hosted expiry checks advance the server process clock boundary without sleeping.

```sh
npm run check:journey -- --task B2.01 --paths native,artium --offline
npm run check:journey -- --task B2.02 --paths native,artium --offline
npm run check:journey -- --task B2.03 --paths native,artium --offline
npm run check:journey -- --task B2.04 --paths native,artium --offline
```

Node diagnostics report actual child PID, argv and executable hash without replacing the runner.
The harness verifies exact executable paths before normalizing their prefixes in emitted evidence.
Public request traces retain method, path, safe header metadata, input hash and synthetic caller identity.
They omit authorization values and request bodies.
Save reports outside the repository when retaining local evidence.
Owned server processes, disposable keys, database, sessions and temporary installations are removed after the run.

Credential tasks are B1.03, B1.04 and B1.CR-001, B1.CR-002, B1.CR-003, B1.CR-004, B1.CR-005, B1.CR-008, B1.CR-011 and B1.CR-012.
Each uses the same selector form as the package tasks.

```sh
npm run check:journey -- --task B1.03 --paths native,artium --offline
npm run check:journey -- --task B1.04 --paths native,artium --offline
npm run check:journey -- --task B1.OP-001 --paths native,artium --offline --operation OP-001
npm run check:journey -- --task B1.OP-006 --paths native,artium --offline --operation OP-006
```

Linux atomic-write checks interrupt the actual packaged process at libc temporary-file creation, fsync and replacement boundaries and verify the prior config bytes survive.
Native Windows ACL and interruption checks are deferred and reported as PENDING in platform evidence; passing Linux journeys do not establish Windows conformance.
