<!-- Security fixes do not start here. Report the vulnerability privately first, per
     https://github.com/ridi-oss/proxy-monster/blob/main/SECURITY.md — a public pull request
     hands the hole to everyone running proxy-monster before there is a fix. -->

## What this changes

<!-- The change and why, in a few sentences. Link the issue it closes, if any. -->

## Components

<!-- Check what this touches. -->

- [ ] `goproxy` — the wire proxy (data plane)
- [ ] `control-plane` — decisions, policy, catalog, admin API
- [ ] `analyzer` — SQL lineage and required grants
- [ ] `engine` — shared enforcement code the control plane calls
- [ ] `web` — the console
- [ ] `pmon` / `auditmon`
- [ ] Build, deployment, or docs

Engines affected: <!-- MySQL / PostgreSQL / both / neither -->

## Enforcement

<!-- Delete this section only if the change cannot affect any decision. -->

- What decision changes, for which statements and roles — ALLOW, MASK, or DENY.
- Why the new behavior is provably safe: what the analyzer establishes, and what
  a masked column is still guaranteed. proxy-monster is fail-closed, and a
  coverage gap is a security gap.
- If this widens what a statement may reach, the deny it replaces and the policy
  that now authorizes it.

## Verification

`mise run verify` is the gate — lint, JVM tests, Go tests, web unit tests, and
the web build. Docker must be running: the tests are DB-backed and fail rather
than skip.

- [ ] `mise run verify` passes locally
- [ ] Tests cover the change, DB-backed against real MySQL and PostgreSQL where
      enforcement is involved
- [ ] `mise run format` run, if this touched `.md`, `.json`, `.yml`/`.yaml`, or
      `.css`

<!-- Paste the failing-then-passing output, or the new test names, if that is the
     clearest evidence. -->

## Conventions

See
[CONTRIBUTING.md](https://github.com/ridi-oss/proxy-monster/blob/main/CONTRIBUTING.md)
for the full set.

- [ ] English, US spelling; comments and docs describe the current state in
      present tense, with no task or phase codes
- [ ] Every new user-facing string is localized — the server returns a stable
      dot-namespaced code, and each key exists under both `web/messages/en/` and
      `web/messages/ko/`
- [ ] Docs updated where the change makes them stale — including
      [KNOWN_LIMITATIONS.md](https://github.com/ridi-oss/proxy-monster/blob/main/KNOWN_LIMITATIONS.md)
      if it adds or closes a caveat
