package com.ridi.oss.proxymonster.controlplane

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/**
 * Canonical audit-event byte format shared with independent chain verifiers.
 *
 * `canonical(event, tsMicros)` is `DOMAIN_SEP || u32be(CHAIN_VERSION) || fields(event)`.
 * The row-hash preimage is `DOMAIN_SEP || u32be(CHAIN_VERSION) || u64be(id) || fields(event) || prev_hash`,
 * where `prev_hash` is exactly 32 bytes. [fields] encodes, in order: kind, timestamp epoch microseconds,
 * principal, roles, datasource, client address, statement, decision, failed stage, effective namespace,
 * masked columns, PII touched, latency milliseconds, detail, channel, context tags, action, resource,
 * outcome, rows returned, bytes returned, and decision id. It never includes id, prev_hash, or row_hash.
 *
 * Strings are `u32be(UTF-8 byte length) || UTF-8`; a null scalar is `0xFFFFFFFF` with no payload. Int64
 * values are `u32be(8) || signed i64be`. Arrays are `u32be(count)` followed by length-prefixed UTF-8
 * elements. Set-valued arrays (roles, masked columns, PII touched, context tags) sort ascending by unsigned
 * UTF-8 bytes and preserve duplicates; effective namespace preserves input order. Java modified UTF-8 is not
 * used. The row hash is SHA-256 of the row-hash preimage.
 */
object AuditCanonical {
    const val CHAIN_VERSION: Int = 1
    val DOMAIN_SEP: ByteArray = "pm-audit-event".toByteArray(StandardCharsets.US_ASCII)

    fun epochMicros(instant: Instant): Long =
        Math.addExact(Math.multiplyExact(instant.epochSecond, 1_000_000L), instant.nano.toLong() / 1_000L)

    fun canonical(event: AuditEvent, tsMicros: Long): ByteArray = bytes { out ->
        out.write(DOMAIN_SEP)
        out.writeInt(CHAIN_VERSION)
        out.write(fields(event, tsMicros))
    }

    fun rowHash(id: Long, event: AuditEvent, tsMicros: Long, prevHash: ByteArray): ByteArray {
        require(prevHash.size == SHA256_BYTES) { "prev_hash must be exactly $SHA256_BYTES bytes" }
        val preimage = bytes { out ->
            out.write(DOMAIN_SEP)
            out.writeInt(CHAIN_VERSION)
            out.writeLong(id)
            out.write(fields(event, tsMicros))
            out.write(prevHash)
        }
        return MessageDigest.getInstance("SHA-256").digest(preimage)
    }

    private fun fields(event: AuditEvent, tsMicros: Long): ByteArray = bytes { out ->
        out.writeString(event.kind)
        out.writeInt64(tsMicros)
        out.writeString(event.principal)
        out.writeArray(event.roles, sort = true)
        out.writeString(event.datasource)
        out.writeNullableString(event.clientAddr)
        out.writeString(event.statement)
        out.writeString(event.decision.name)
        out.writeNullableString(event.failedStage)
        out.writeArray(event.effectiveNamespace, sort = false)
        out.writeArray(event.maskedColumns, sort = true)
        out.writeArray(event.piiTouched, sort = true)
        out.writeInt64(event.latencyMs)
        out.writeNullableString(event.detail)
        out.writeNullableString(event.channel)
        out.writeArray(event.contextTags, sort = true)
        out.writeNullableString(event.authzAction)
        out.writeNullableString(event.authzResource)
        out.writeNullableString(event.outcome)
        out.writeNullableInt64(event.rowsReturned)
        out.writeNullableInt64(event.bytesReturned)
        out.writeNullableInt64(event.decisionId)
    }

    private fun bytes(write: (DataOutputStream) -> Unit): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use(write)
        return buffer.toByteArray()
    }

    private fun DataOutputStream.writeString(value: String) {
        val encoded = value.toByteArray(StandardCharsets.UTF_8)
        writeInt(encoded.size)
        write(encoded)
    }

    private fun DataOutputStream.writeNullableString(value: String?) {
        if (value == null) {
            writeInt(NULL_LENGTH)
        } else {
            writeString(value)
        }
    }

    private fun DataOutputStream.writeInt64(value: Long) {
        writeInt(Long.SIZE_BYTES)
        writeLong(value)
    }

    private fun DataOutputStream.writeNullableInt64(value: Long?) {
        if (value == null) {
            writeInt(NULL_LENGTH)
        } else {
            writeInt64(value)
        }
    }

    private fun DataOutputStream.writeArray(values: List<String>, sort: Boolean) {
        val encoded = values.map { it.toByteArray(StandardCharsets.UTF_8) }
        val ordered = if (sort) encoded.sortedWith(UNSIGNED_UTF8_COMPARATOR) else encoded
        writeInt(ordered.size)
        ordered.forEach {
            writeInt(it.size)
            write(it)
        }
    }

    private val UNSIGNED_UTF8_COMPARATOR = Comparator<ByteArray> { left, right ->
        val common = minOf(left.size, right.size)
        for (index in 0 until common) {
            val compared = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (compared != 0) return@Comparator compared
        }
        left.size.compareTo(right.size)
    }

    private const val NULL_LENGTH = -1
    private const val SHA256_BYTES = 32
}
