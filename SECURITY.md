# Security Policy

proxy-monster is a database access-control proxy: it sits inline on the wire and
is the thing standing between a client and sensitive data. We take security
reports seriously and appreciate responsible disclosure.

## Reporting a vulnerability

Use
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately):
open the repository's **Security** tab and choose **Report a vulnerability**.
The report stays private between you and the maintainers, and it keeps the
discussion, the fix, and the advisory in one place.

Do not open a public issue, pull request, or discussion for a suspected security
problem — that hands the hole to everyone running proxy-monster before there is
a fix.

Include enough to reproduce: the affected component (`goproxy`, `control-plane`,
`analyzer`, `auditmon`, `pmon`, or `web`), the engine (MySQL or PostgreSQL), a
minimal query or request, and the observed versus expected behavior. A query
that returns an unmasked value it should not, or that runs where it should have
been denied, is exactly the kind of report we want.

We aim to acknowledge a report within a few business days and will coordinate a
fix and disclosure timeline with you.

## Supported versions

proxy-monster is pre-1.0 and has no tagged releases. Security fixes land on
`main`, which is the only supported line — there are no release branches and no
backports. Run from a recent `main` and expect to update to pick up a fix.

## Security posture

proxy-monster is deny-by-default. It authorizes every statement, masks columns
per role, and follows sensitive values through expressions, functions,
subqueries, and joins so a masked column stays masked wherever it flows.
Anything the lineage analyzer cannot prove safe is denied through
[Cedar](https://www.cedarpolicy.com/) policy rather than passed through — the
deny is a policy decision, and the production floor stays closed
(**fail-closed**). Coverage gaps are treated as security gaps. See
[DESIGN.md](./DESIGN.md) for the architecture and
[KNOWN_LIMITATIONS.md](./KNOWN_LIMITATIONS.md) for accepted caveats.
