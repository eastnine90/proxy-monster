package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ValidateApprovalSourceTest {
    private fun record(principal: String = "alice", decision: Decision = Decision.DENY) = AuditEvent(
        principal = principal,
        datasource = "ds",
        statement = "select 1",
        decision = decision,
    )

    @Test fun `own DENY is OK`() {
        assertEquals(SourceValidation.OK, validateApprovalSource(record(), "alice"))
    }

    @Test fun `null source is NOT_FOUND`() {
        assertEquals(SourceValidation.NOT_FOUND, validateApprovalSource(null, "alice"))
    }

    @Test fun `another principal's DENY is NOT_FOUND`() {
        assertEquals(SourceValidation.NOT_FOUND, validateApprovalSource(record(principal = "bob"), "alice"))
    }

    @Test fun `own non-DENY decisions are NOT_DENY`() {
        for (decision in listOf(Decision.ALLOW, Decision.MASK, Decision.ERROR)) {
            assertEquals(SourceValidation.NOT_DENY, validateApprovalSource(record(decision = decision), "alice"))
        }
    }
}

class ValidateProactiveComposeTest {
    @Test fun `missing datasource is invalid`() {
        assertEquals("datasourceId", validateProactiveCompose(null, "select 1", "title", "reason"))
    }

    @Test fun `blank sql is invalid`() {
        assertEquals("sql", validateProactiveCompose(1, "  ", "title", "reason"))
    }

    @Test fun `blank title is invalid`() {
        assertEquals("title", validateProactiveCompose(1, "select 1", "  ", "reason"))
    }

    @Test fun `blank reason is invalid`() {
        assertEquals("reason", validateProactiveCompose(1, "select 1", "title", "  "))
    }

    @Test fun `complete proactive compose input is valid`() {
        assertNull(validateProactiveCompose(1, "select 1", "title", "reason"))
    }
}

