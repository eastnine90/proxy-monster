package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals

/** Pure tests for the IdP-group → pm-group resolver (docs/backlog.md). */
class OidcGroupMappingTest {
    @Test fun `parse reads idpGroup=pmGroup pairs and ignores malformed entries`() {
        val m = OidcGroupMapping.parse("proxy-monster-admin=system:admin, proxy-monster-users=acme-users ,junk,=x,y=", null)
        assertEquals(mapOf("proxy-monster-admin" to "system:admin", "proxy-monster-users" to "acme-users"), m.map)
        assertEquals(null, m.prefix)
    }

    @Test fun `an explicit mapping wins over the prefix rule`() {
        val m = OidcGroupMapping(mapOf("proxy-monster-admin" to "system:admin"), "proxy-monster-")
        assertEquals(setOf("system:admin"), m.resolve(listOf("proxy-monster-admin")))
    }

    @Test fun `an unmapped group is taken by name with the prefix stripped`() {
        val m = OidcGroupMapping(emptyMap(), "proxy-monster-")
        assertEquals(setOf("analysts", "keep"), m.resolve(listOf("proxy-monster-analysts", "keep")))
    }

    @Test fun `no prefix keeps unmapped names as-is`() {
        val m = OidcGroupMapping(emptyMap(), null)
        assertEquals(setOf("eng", "on-call"), m.resolve(listOf("eng", "on-call")))
    }

    @Test fun `a group that is blank after stripping the prefix is dropped`() {
        val m = OidcGroupMapping(emptyMap(), "proxy-monster-")
        assertEquals(setOf("x"), m.resolve(listOf("proxy-monster-", "proxy-monster-x")))
    }

    @Test fun `the reserved system namespace is unreachable via the unmapped fallback`() {
        // A raw "system:admin" in the IdP claim, with NO mapping, must not self-assign the
        // seeded admin group. Only an explicit map entry may name a system group.
        assertEquals(emptySet<String>(), OidcGroupMapping(emptyMap(), null).resolve(listOf("system:admin")))
        // Nor via prefix-stripping down into the reserved namespace.
        assertEquals(emptySet<String>(), OidcGroupMapping(emptyMap(), "proxy-monster-").resolve(listOf("proxy-monster-system:admin")))
        // Case-insensitively — no fold variant of the prefix slips through.
        assertEquals(emptySet<String>(), OidcGroupMapping(emptyMap(), null).resolve(listOf("System:Admin", "SYSTEM:admin")))
        // A non-reserved group alongside a reserved one still resolves; only the reserved one is dropped.
        assertEquals(setOf("analysts"), OidcGroupMapping(emptyMap(), null).resolve(listOf("system:admin", "analysts")))
    }

    @Test fun `an explicit mapping may target the reserved system namespace`() {
        // The trusted operator-configured map IS the admin path — it may name a system group.
        val m = OidcGroupMapping(mapOf("proxy-monster-admin" to "system:admin"), "proxy-monster-")
        assertEquals(setOf("system:admin"), m.resolve(listOf("proxy-monster-admin")))
    }
}
