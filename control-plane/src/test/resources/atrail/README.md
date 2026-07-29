# Audit canonical byte format

The Go audit monitor CI replays `canonical-golden.json`; changing any byte
requires a coordinated cross-language format/version change.

## Constants and layouts

- `DOMAIN_SEP`: ASCII `pm-audit-event`
- `chain_version`: unsigned 32-bit big-endian integer, currently `1`
- canonical bytes: `DOMAIN_SEP || u32be(chain_version) || fields(event)`
- row-hash preimage:
  `DOMAIN_SEP || u32be(chain_version) || u64be(id) || fields(event) || prev_hash`
- `row_hash`: SHA-256 of the row-hash preimage
- genesis hash: SHA-256 of ASCII `pm-audit-genesis` =
  `88d4f4719f26cf7f32839ac30b1d6a94edf3f9133fb75667d1415fff81bbcd08`

`DOMAIN_SEP` and `chain_version` occur exactly once in either byte stream.
Canonical bytes exclude `id`, `prev_hash`, and `row_hash`; the row-hash preimage
adds `id` before the shared field encoding and adds the exactly-32-byte previous
hash after it.

Each chained row also persists its `chain_version` in the
`audit_event.chain_version` column (NULL for pre-chain historical rows). A
verifier reads that column to select the field set for the row before
recomputing its hash, so later releases can add fields under a bumped version
without invalidating earlier segments. It is stored metadata only — the
authoritative version for the hash is the one encoded in the preimage above.

## Fields

`fields(event)` encodes these 22 business columns in this fixed order:

1. `kind`
2. `ts` as signed epoch microseconds
3. `principal`
4. `roles`
5. `datasource`
6. `client_addr`
7. `statement`
8. `decision` enum name
9. `failed_stage`
10. `effective_namespace`
11. `masked_columns`
12. `pii_touched`
13. `latency_ms`
14. `detail`
15. `channel`
16. `context_tags`
17. `action`
18. `resource`
19. `outcome`
20. `rows_returned`
21. `bytes_returned`
22. `decision_id`

A non-null string is `u32be(UTF-8 byte length) || UTF-8 bytes`; an empty string
has length zero. A null scalar is the four bytes `FF FF FF FF` with no payload.
A signed int64 is `u32be(8) || i64be(value)`. Arrays are `u32be(element count)`
followed by each element as `u32be(length) || UTF-8 bytes`. Roles, masked
columns, PII touched, and context tags sort ascending by unsigned UTF-8 byte
order with duplicates preserved. Effective namespace preserves input order. Java
modified UTF-8 (`writeUTF`) is never used. Timestamp conversion is
`epochSecond * 1_000_000 + nano / 1_000` after truncation to microseconds.

## Worked example

The `minimal-null-and-empty` case begins with:

- ASCII domain separator: `706d2d61756469742d6576656e74`
- version 1: `00000001`
- kind `decision`: `000000086465636973696f6e`
- timestamp: length `00000008`, followed by its signed epoch-microsecond value

Its empty arrays are each encoded as `00000000`; nullable fields are `ffffffff`.
The fixture freezes the complete canonical bytes and the SHA-256 row hash for
this and five additional edge cases.
