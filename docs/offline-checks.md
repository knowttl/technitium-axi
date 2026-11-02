# Offline package journeys

The B1 through B5 package, credential, read and write checks run the installed npm tarball, never a TypeScript loader.
They require Linux with user, PID, mount and network namespaces, iproute2, OpenSSL and a C compiler for process-interruption checks.
The namespace enables only loopback and contains the CLI, server, adapter and subprocesses.
Follow the [README setup](../README.md) to fetch the pinned npm dependencies once, then keep all journeys offline.
The runner removes inherited credentials and packs and installs the executable in an empty temporary prefix.
Discovery commands make zero vendor requests.
B1.02 and the credential journeys start two disposable HTTPS boundaries with synthetic identities.
Status and session fixtures follow the vendor top-level JSON response shapes.
`npm run test:users` covers explicit login, bound session storage and removal, user mutations, protected issuance, admin sessions, accounts, groups and section permissions, and actual SSO caller authorization through a secondary-to-primary HTTPS proxy fixture.
Run the admin matrix alone with `npm run check:journey -- --task B5.admin-accounts --paths native --offline`; its individual plan IDs are defined in [admin-accounts-journey.mjs](../scripts/admin-accounts-journey.mjs).
Every B5 identity, user and admin account task also accepts its individual plan ID through `check:journey -- --task <id> --paths native --offline`.
The B5 protected-result journey repeats the restore secrets and custody-denial checks.
`npm test` also includes `npm run test:cluster`, which selects `B5.03` for the cluster routing and lifecycle matrix, including the protected configuration transfer read.
Run an individual lifecycle task with `npm run check:journey -- --task B5.OP-119 --paths native --offline`, replacing `119` with an ID from [cluster-journey.mjs](../scripts/cluster-journey.mjs).
These cluster journeys use synthetic HTTPS boundaries and accept only the native path; hosted write proof remains a separate release-candidate check.

```sh
npm test
node --test tests/journey.test.mjs tests/vendor.test.mjs tests/private-file.test.mjs
npm run typecheck
npm run check:generated
```

The hosted checks require a maintainer-supplied, reviewed but unmerged Artium admission fixture matching [the reviewed host contract](../tests/fixtures/host-contract.json).
Slices merge on this repository's gate, including the [package-contract check](../README.md#development) and native journeys, plus the separate deny check.
Hosted proof runs once per release or in one nightly batch using the reviewed frozen fixture with `--paths native,artium` (or `--paths artium` for hosted checks alone).
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
Record the fixture revision with the release or nightly batch results, rather than copying the contract pin into this guide.
The host registry must contain that exact installed package, with pnpm integrity checks intact.
Missing fixture inputs for a selected Artium path, an omitted path selection and unknown paths fail explicitly.
Native-only runs do not require the Artium fixture; every selected path must execute successfully.
Each report separates expected, executed, failed, pending and skipped cases.

Hosted setup uses public login, password replacement, recent authentication, credential, tool, user and role endpoints.
The synthetic alpha caller has the tool grant; beta is authenticated without that grant.
The fixture stages a shared tool credential; status sends no bearer and authenticated reads consume only the isolated injected SecretRef.
Authenticated reads return a protected-result reference alongside their approved projection.
The protected result is retained in bounded host memory and is never written into ordinary output or audit.

The source-reviewed run, input-file, protected-result and existing transfer contracts live in [the reviewed host contract](../tests/fixtures/host-contract.json), including result binding, retrieval and retention limits.
The current host has no Technitium transfer route or transfer selection.
The harness checks that limit without inventing a route or claiming a completed transfer.
Later transfer slices require a host extension.

B2.01 through B2.04 cover the generated read matrix, protected formats, bounded paging/errors and archive-entry review.
B2.05 covers the 19 monitor reads: dashboard metrics and charts, cache navigation, DNS health checks, apps, settings and backup, DHCP leases and scopes, and logs.
Select one monitor operation with `--task B2.OP-015 --operation OP-015`, or run the group with `--task B2.05`.
They use the same task selector and paths as B1.
The B2 hosted path uses the same pinned fixture, which admits the complete read inventory and protected results beyond sessions.
It uses the authenticated result path returned by the host rather than inventing a Technitium transfer endpoint.
The response matrix is generated from typed contracts, retained public documentation example seeds and synthetic acceptance scenarios in [monitor-reads.json](../tests/fixtures/monitor-reads.json) and [admin-read-cases.json](../tests/fixtures/admin-read-cases.json); all POST fixtures are synthetic.
The archive review task performs no successful backup or transfer request.
The format task exercises independently defined ZIP entry worlds and exact protected bytes.
Hosted expiry checks advance the server process clock boundary without sleeping.

```sh
npm run check:journey -- --task B2.01 --paths native,artium --offline
npm run check:journey -- --task B2.02 --paths native,artium --offline
npm run check:journey -- --task B2.03 --paths native,artium --offline
npm run check:journey -- --task B2.04 --paths native,artium --offline
npm run check:journey -- --task B2.05 --paths native,artium --offline
```

`npm test` also runs `B2.admin-reads` on the native path for the admin, user, LDAP, zone, catalog, DNSSEC-view, record and allowed/blocked reads in the operation fixtures.
Use the same prepared Artium fixture described above to run this slice on both paths.
Select an individual operation with a matching `--task B2.OP-…` and `--operation OP-…` pair; supported IDs are the keys in the operation fixtures.

```sh
npm run check:journey -- --task B2.admin-reads --paths native,artium --offline
npm run check:journey -- --task B2.OP-141 --operation OP-141 --paths native,artium --offline
```

B3 checks cover write policy and journal (B3.01), record inputs and composite selectors (B3.02), concurrency and unknown outcomes (B3.03), upload materialization (B3.04), operation SecretRefs (B3.05), and credential conformance (B3.CR-013 and B3.CR-014).
They use loopback fake vendor HTTPS and synthetic credentials, and accept only `--paths native`.
Hosted write admission is separate release-candidate proof, not established by these journeys or the existing read admission fixture.
`npm test` includes those seven native B3 tasks, the DNSSEC write matrix (`B3.dnssec`), the list, cache, dashboard-history and DNS-client matrix (`B3.lists-cache`), and the zone lifecycle and record-write suite (`npm run test:zones`).
The DNSSEC matrix covers signing, unsigning, NSEC/NSEC3 conversion and parameters, DNSKEY TTL, private key creation and updates, publication, rollover, retirement, deletion and KSK activation.
Select an individual DNSSEC write with `--task B3.OP-035`, replacing `035` with the desired operation number, without a separate `--operation` flag.
Synthetic worlds check exact form inputs, protected PEM references, preview and replay boundaries, vendor prerequisite failures, selected-zone properties and records, and preservation of other zones.
NSEC3 conversion includes omitted values, explicit zeros, effective maxima of 50 iterations and 32 salt bytes, and rejection before dispatch above those bounds.
Lifecycle fixtures advance explicitly to show published, active and retired keys; see [Writes](../README.md#writes) for success semantics and subsequent inspection.
These fixtures prove CLI behavior against a fake vendor, not cryptographic correctness or live-server interoperability.

```sh
npm run check:journey -- --task B3.dnssec --paths native --offline
npm run check:journey -- --task B3.OP-040 --paths native --offline
```

`B3.lists-cache` covers dashboard history deletion, cache deletion and flush, allowed/blocked add, delete, flush and import, and DNS-client resolution with and without import.
Select an individual operation with `--task B3.OP-019`, replacing `019` with `054`, `055`, `057`, `058`, `059`, `060`, `063`, `064`, `065`, `066` or `077`; no separate `--operation` flag is needed.
The synthetic list and cache worlds check exact form inputs, preview and replay boundaries, import merging, vendor denial and preservation of unrelated storage.
The resolve worlds check grant separation, vendor permission and zone-type branches, AXFR and SOA cases, DNSSEC warning suppression, and zone, record and permission readbacks through a separate observer credential.
These checks prove behavior against synthetic HTTPS boundaries, not live-server interoperability.

```sh
npm run check:journey -- --task B3.lists-cache --paths native --offline
npm run check:journey -- --task B3.OP-077 --paths native --offline
```

B3.02 and B3.OP-052 report one pending case for the accepted [DNAME deletion deferral](../README.md#writes), rather than claiming full-management coverage.
The record cases live in [record-inputs.json](../tests/fixtures/record-inputs.json).

Run the zone lifecycle and record-write suite alone with `npm run test:zones`.
Its operation selectors are listed in [zone-writes.test.mjs](../tests/zone-writes.test.mjs), using the lifecycle task list from [zone-journey.mjs](../scripts/zone-journey.mjs).
Select a task with `--task B3.OP-022`, for example, without a separate `--operation` flag.
The record-add, update and delete selectors each run the complete B3.02 record matrix.

```sh
npm run test:zones
npm run check:journey -- --task B3.OP-022 --paths native --offline
```

```sh
npm run check:journey -- --task B3.01 --paths native --offline
npm run check:journey -- --task B3.02 --paths native --offline
npm run check:journey -- --task B3.03 --paths native --offline
npm run check:journey -- --task B3.04 --paths native --offline
npm run check:journey -- --task B3.05 --paths native --offline
npm run check:journey -- --task B3.CR-013 --paths native --offline
npm run check:journey -- --task B3.CR-014 --paths native --offline
```

Node diagnostics report actual child PID, argv and executable hash without replacing the runner.

B4.OP-070, B4.OP-071, B4.OP-072, B4.OP-073, B4.OP-074, B4.OP-076 and B4.OP-085 cover app downloads, package uploads, uninstall, opaque config replacement and selected backup restore.
Run each with `npm run check:journey -- --task <id> --paths native --offline`, or run all seven with `npm run test:apps-restore`, also included in `npm test`.
The shared matrix checks exact form or multipart mapping, preserved unrelated state, protected response bytes and journal secrecy.
Handler failures report an unknown outcome and cannot replay the confirmed mutation.
Restore checks both delete-existing modes, a failure after an earlier category changed, and returned secrets with DNS settings excluded.

B4 settings checks use the field matrix in [configuration-matrix.json](../tests/fixtures/configuration-matrix.json) for form/JSON patches, structured fields, omitted-secret preservation and protected results.
The transfer checks cover file-only multipart, exact ZIP entry bytes, preview hash changes, size limits and custody denial before dispatch.
The settings and log action checks exercise success and vendor failure, retaining uncertain journal entries without replay.
Run each task with `npm run check:journey -- --task <id> --paths native --offline`, using `B4.01`, `B4.02`, `B4.03`, `B4.OP-080`, `B4.OP-082`, `B4.OP-083`, `B4.OP-136` or `B4.OP-137`.
Hosted proof remains a separate release-candidate check.

`B4.dhcp` runs the DHCP write matrix, or select `B4.OP-087`, `088`, `089`, `092`, `093`, `094`, `095`, `096` or `097` with the full `B4.OP-` prefix.
The native journeys verify lease selectors, conversions, reservation conflicts, scope rename and configuration preservation, scope state and disk deletion through loopback HTTPS.
Scope replacement checks include stale baselines and reconciliation after a lost response.
The worlds are synthetic and do not establish live-server interoperability.

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
