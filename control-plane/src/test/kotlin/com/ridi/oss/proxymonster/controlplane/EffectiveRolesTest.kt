package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EffectiveRolesTest {
    @Test fun `group grants a role`() {
        assertTrue("pii-reader" in effectiveRoles(emptyList(), emptyList(), listOf("pii-reader")))
    }

    @Test fun `principal in no group unaffected`() {
        assertEquals(setOf("analyst"), effectiveRoles(listOf("analyst"), emptyList(), emptyList()))
    }

    @Test fun `union dedupes across sources`() {
        assertEquals(
            setOf("analyst", "pii-reader"),
            effectiveRoles(listOf("analyst"), listOf("pii-reader"), listOf("pii-reader", "analyst")),
        )
    }

    @Test fun `all empty invents no roles`() {
        assertEquals(emptySet(), effectiveRoles(emptyList(), emptyList(), emptyList()))
    }
}
