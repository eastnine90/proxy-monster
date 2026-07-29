# Supported database versions

proxy-monster supports two kinds of database, and the version set differs
between them.

**Targets** — the databases the proxy brokers queries to:

<!-- prettier-ignore -->
| Engine | Series |
| --- | --- |
| MySQL | 8.0, 8.4 |
| PostgreSQL | 16, 17 |

**Storage** — where the control plane keeps its own state (catalog, policy,
roles, audit):

<!-- prettier-ignore -->
| Engine | Series |
| --- | --- |
| PostgreSQL | 16, 17 |

Storage is PostgreSQL-only because the store SQL uses `RETURNING`,
`ON CONFLICT`, `jsonb`, and `::` casts.

Support is claimed per _series_ — the PostgreSQL major, the MySQL major.minor —
because that is the granularity at which these engines change behavior. Patch
releases within a series are covered by the floating image tag the tests run, so
a new patch is picked up without a code change.

## Where the set is declared

[`db-support.json`](../db-support.json) at the repo root. Everything else
derives from it:

- The CI matrix generates its legs from the file, so a version cannot be
  declared without being run.
- `DbSupportMatrixTest` fails the build if the file and the engine's bundled
  system-classification manifests disagree in either direction, so a version
  cannot be run without being curated.

Adding a version means editing that file and adding
`engine/src/main/resources/system-classification/<engine>/<series>.json`. A
target series needs a manifest because the classifier's system-catalog and
dangerous-function tags are version-specific; without one the datasource falls
back to the version-independent floor and loses them.

## Running the tests

A plain test run uses the newest supported series of each engine — the version
most installs are on, and one container per engine:

```
mise run test          # JVM + Go
mise run test-jvm
mise run test-go
```

To pin one version, set the image:

```
PM_TEST_MYSQL_IMAGE=mysql:8.0 mise run test-jvm
PM_TEST_POSTGRES_IMAGE=postgres:16 PM_TEST_MYSQL_IMAGE=mysql:8.0 mise run test-go
```

To sweep every supported version locally:

```
mise run test-db-matrix              # sequential, one version at a time
mise run test-db-matrix-parallel     # concurrent, 2 version legs at once
```

The parallel sweep's limit is the Docker VM, not the machine. Docker Desktop
gives its VM a fixed slice of host RAM — often around 8 GB on a 64 GB machine,
so host memory is not the number that matters — and each leg starts its own
PostgreSQL and MySQL server inside that slice. `PM_MATRIX_JOBS` caps how many
legs run at once; the default of 2 (four database servers) fits an ~8 GB VM, and
4 legs does not. Over the budget, connections are refused mid-suite and it
surfaces as `Communications link failure`, which looks like a product bug rather
than exhaustion. Raise Docker's memory limit before raising the cap.
`PM_MATRIX_HEAP` (default `3g`) sizes each leg's Gradle heap, since every leg
compiles from its own cold build tree.

CI does not need any of this: it runs one leg per runner, so every version is
genuinely parallel.

Test containers are named after their image, so switching versions starts a
separate container rather than reusing one built from another version. A test
asserts the live server's version matches the image it was configured with, so a
leg cannot report a pass for a version it never ran.

`PM_REQUIRE_DB_TESTS=true` turns "Docker unavailable" from a skip into a
failure. CI sets it: without it, a runner with no Docker daemon skips every
DB-backed test and the suite still reports success.

## Version-specific behavior in tests

MySQL 8.4 ships `mysql_native_password` disabled, so
`IDENTIFIED WITH mysql_native_password` is error 1524 there while it still works
on 8.0. A test needing an account with a known auth plugin asks for
`SharedMySql.defaultAuthPlugin` (JVM) or `dbtest.MySQLAuthPlugin` (Go) instead
of naming one, so one test body covers both series.
