package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.grpc.columnMask
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * APPROVAL role discovery (approval-workflow.md) — pure logic, exercised through a stub `decide` closure that
 * stands in for the real decideQuery. Proves the "offer roles that return MORE than the requester's own"
 * ranking: a role that unmasks a baseline-masked column, or makes a baseline-denied Q runnable, is offered;
 * one that returns the same (or denies Q, or is already held) is not.
 */
class RoleDiscoveryTest {
    private fun ctx(action: EnfAction, maskedCols: List<String> = emptyList()) = DecisionContext(
        action = action,
        denyReason = if (action == EnfAction.DENY) "denied" else null,
        masks = maskedCols.mapIndexed { i, c -> columnMask { column = c; maskFn = "mask"; kind = "FIXED"; ordinal = i } },
        piiTouched = emptyList(),
        effectiveRoles = emptyList(),
        failedStage = null,
        detail = null,
        passthrough = false,
    )

    private val roles = listOf(Role(1, "analyst"), Role(2, "pii-reader"), Role(3, "auditor"))

    @Test
    fun `a role that unmasks a baseline-masked column is offered with the unmasked column`() {
        // own role analyst masks rrn; pii-reader unmasks it; auditor still masks it (no improvement).
        val decide = { r: Set<String> ->
            when {
                "pii-reader" in r -> ctx(EnfAction.ALLOW) // rrn unmasked → no masks
                else -> ctx(EnfAction.MASK, listOf("rrn"))
            }
        }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.baselineAllowed, "a MASK baseline is 'allowed' (not denied)")
        assertEquals(listOf("pii-reader"), res.options.map { it.roleName }, "only the role that returns more is offered")
        assertEquals(listOf("rrn"), res.options.single().unmasksColumns)
    }

    @Test
    fun `a role that returns the same is not offered`() {
        val decide = { _: Set<String> -> ctx(EnfAction.MASK, listOf("rrn")) } // every role masks rrn
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.options.isEmpty(), "no role improves on the baseline → nothing offered")
    }

    @Test
    fun `a role under which Q is denied is not offered`() {
        val decide = { r: Set<String> -> if ("auditor" in r) ctx(EnfAction.DENY) else ctx(EnfAction.MASK, listOf("rrn")) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        // pii-reader isn't distinguished here (same masks as baseline), auditor denies → neither offered.
        assertTrue(res.options.none { it.roleName == "auditor" }, "a role that denies Q is never offered")
    }

    @Test
    fun `when baseline is denied, a role that makes Q runnable is offered`() {
        // requester's own roles can't run Q at all (no read grant); pii-reader can.
        val decide = { r: Set<String> -> if ("pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertFalse(res.baselineAllowed, "baseline is denied")
        assertEquals(listOf("pii-reader"), res.options.map { it.roleName }, "a role that makes a denied Q runnable is offered")
    }

    @Test
    fun `a role the requester already holds is never offered`() {
        val decide = { _: Set<String> -> ctx(EnfAction.MASK, listOf("rrn")) }
        val res = discoverRoles(setOf("analyst", "pii-reader"), roles, decide)
        assertTrue(res.options.none { it.roleName in setOf("analyst", "pii-reader") }, "already-held roles are filtered out")
    }

    @Test
    fun `a candidate is previewed under R ALONE, not unioned with the requester's own roles`() {
        // decide ALLOWs only when BOTH "analyst" (the requester's own role) AND "pii-reader" (the candidate)
        // are present together — modeling a policy whose grant only fires on the union. A unioned
        // preview would compute decide({analyst, pii-reader}) = ALLOW and offer pii-reader — but
        // execution decides under {pii-reader} ALONE and would DENY there, so offering it would be a lie.
        val decide = { r: Set<String> -> if ("analyst" in r && "pii-reader" in r) ctx(EnfAction.ALLOW) else ctx(EnfAction.DENY) }
        val res = discoverRoles(setOf("analyst"), roles, decide)
        assertTrue(res.options.isEmpty(), "R-alone preview must DENY (analyst is not in {pii-reader} alone) → pii-reader must not be offered")
    }
}
