package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.Engine
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The per-decision redaction predicate. `mayReadUnmasked` is the Cedar `result.read.unmasked`-on-
 * datasource authorization (dev preset or a production unmasked grant), supplied as a thunk so the Cedar
 * call is skipped when the diagnostic can't carry a protected value anyway. See docs/diagnostic-redaction.md.
 */
class DiagnosticsRedactionTest {
    private fun redact(engine: Engine, action: EnfAction, mayReadUnmasked: Boolean) =
        redactsDiagnostics(engine, action) { mayReadUnmasked }

    @Test
    fun `MySQL ALLOW never redacts, whatever the principal`() {
        assertFalse(redact(Engine.MYSQL, EnfAction.ALLOW, mayReadUnmasked = false))
        assertFalse(redact(Engine.MYSQL, EnfAction.ALLOW, mayReadUnmasked = true))
    }

    @Test
    fun `MySQL ALLOW skips the Cedar unmasked-reader check (cannot leak on allow)`() {
        var called = false
        val got = redactsDiagnostics(Engine.MYSQL, EnfAction.ALLOW) { called = true; false }
        assertFalse(got)
        assertFalse(called, "the Cedar check must be skipped when the engine cannot leak on ALLOW")
    }

    @Test
    fun `MySQL MASK or DENY redacts unless the principal reads the datasource unmasked`() {
        assertTrue(redact(Engine.MYSQL, EnfAction.MASK, mayReadUnmasked = false))
        assertTrue(redact(Engine.MYSQL, EnfAction.DENY, mayReadUnmasked = false))
        assertFalse(redact(Engine.MYSQL, EnfAction.MASK, mayReadUnmasked = true))
    }

    @Test
    fun `PostgreSQL redacts even an ALLOW unless the principal reads the datasource unmasked`() {
        assertTrue(redact(Engine.POSTGRES, EnfAction.ALLOW, mayReadUnmasked = false))
        assertFalse(redact(Engine.POSTGRES, EnfAction.ALLOW, mayReadUnmasked = true))
        assertTrue(redact(Engine.POSTGRES, EnfAction.MASK, mayReadUnmasked = false))
    }

    @Test
    fun `only PostgreSQL leaks diagnostics on an allowed query`() {
        assertTrue(Engine.POSTGRES.leaksDiagnosticsOnAllow)
        assertFalse(Engine.MYSQL.leaksDiagnosticsOnAllow)
    }
}
