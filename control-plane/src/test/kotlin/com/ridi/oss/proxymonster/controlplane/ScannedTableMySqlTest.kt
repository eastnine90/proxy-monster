package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

/**
 * Scanned-table enforcement on MySQL (docs/facts-emission.md: "Verify both CTE bindings live
 * on PostgreSQL and MySQL"). The PG half lives in [KnownGapsTest]; this proves the same deny-by-default
 * holds through the real MySQL decision path (dialect + `def`/db namespace + case folding differ, the
 * gate does not). Fixture: `analyst@example.com` holds `result.read` on the `users` table; `orders` is
 * UNGRANTED.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ScannedTableMySqlTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
    }

    @Test
    fun `count(star) on an ungranted table is denied`() {
        assertEquals(EnfAction.DENY, fx.run("select count(*) from orders").decision)
    }

    @Test
    fun `count(star) on a table the principal can read is allowed`() {
        assertEquals(EnfAction.ALLOW, fx.run("select count(*) from users").decision)
    }

    @Test
    fun `a pure CTE shadow of the ungranted table is allowed`() {
        val result = fx.run("with orders as (select 1) select count(*) from orders")
        assertEquals(EnfAction.ALLOW, result.decision, result.denyReason)
    }

    @Test
    fun `a CTE body scanning the real ungranted table is denied`() {
        assertEquals(EnfAction.DENY, fx.run("with o as (select count(*) as c from orders) select c from o").decision)
    }
}
