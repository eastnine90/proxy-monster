package com.ridi.oss.proxymonster.controlplane

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class AuditCanonicalGoldenTest {
    @Test
    fun `canonical bytes and row hashes match the cross-language golden vectors`() {
        val resource = requireNotNull(javaClass.getResource("/atrail/canonical-golden.json")) {
            "missing required /atrail/canonical-golden.json resource"
        }
        val fixture = Json.decodeFromString<GoldenFixture>(resource.readText())
        assertEquals("pm-audit-event", fixture.domainSep)
        assertEquals(AuditCanonical.CHAIN_VERSION, fixture.chainVersion)
        assertEquals(6, fixture.cases.size)

        fixture.cases.forEach { case ->
            val event = case.event.toAuditEvent()
            val tsMicros = AuditCanonical.epochMicros(Instant.parse(case.event.ts))
            assertContentEquals(
                case.canonicalHex.hexBytes(),
                AuditCanonical.canonical(event, tsMicros),
                "canonical bytes differ for ${case.name}",
            )
            assertContentEquals(
                case.rowHashHex.hexBytes(),
                AuditCanonical.rowHash(case.id, event, tsMicros, case.prevHashHex.hexBytes()),
                "row hash differs for ${case.name}",
            )
        }
    }

    @Test
    fun `row hash rejects a previous hash with the wrong length`() {
        val event = AuditEvent(
            principal = "alice",
            datasource = "main",
            statement = "select 1",
            decision = Decision.ALLOW,
        )
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            AuditCanonical.rowHash(1, event, 0, ByteArray(31))
        }
    }

    @Serializable
    private data class GoldenFixture(
        val domainSep: String,
        val chainVersion: Int,
        val cases: List<GoldenCase>,
    )

    @Serializable
    private data class GoldenCase(
        val name: String,
        val id: Long,
        val prevHashHex: String,
        val event: GoldenEvent,
        val canonicalHex: String,
        val rowHashHex: String,
    )

    @Serializable
    private data class GoldenEvent(
        val ts: String,
        val principal: String,
        val roles: List<String>,
        val datasource: String,
        val clientAddr: String?,
        val statement: String,
        val decision: Decision,
        val failedStage: String?,
        val effectiveNamespace: List<String>,
        val maskedColumns: List<String>,
        val piiTouched: List<String>,
        val latencyMs: Long,
        val detail: String?,
        val channel: String?,
        val contextTags: List<String>,
        val authzAction: String?,
        val authzResource: String?,
        val outcome: String?,
        val kind: String,
        val rowsReturned: Long?,
        val bytesReturned: Long?,
        val decisionId: Long?,
    ) {
        fun toAuditEvent() = AuditEvent(
            ts = ts,
            principal = principal,
            roles = roles,
            datasource = datasource,
            clientAddr = clientAddr,
            statement = statement,
            decision = decision,
            failedStage = failedStage,
            effectiveNamespace = effectiveNamespace,
            maskedColumns = maskedColumns,
            piiTouched = piiTouched,
            latencyMs = latencyMs,
            detail = detail,
            channel = channel,
            contextTags = contextTags,
            authzAction = authzAction,
            authzResource = authzResource,
            outcome = outcome,
            kind = kind,
            rowsReturned = rowsReturned,
            bytesReturned = bytesReturned,
            decisionId = decisionId,
        )
    }

    private fun String.hexBytes(): ByteArray {
        require(length % 2 == 0) { "hex string must have even length" }
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
