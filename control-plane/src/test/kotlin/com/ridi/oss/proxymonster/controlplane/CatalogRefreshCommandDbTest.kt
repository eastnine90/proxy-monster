package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.controlplane.support.requireDocker
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CatalogRefreshCommandDbTest {
    private lateinit var fx: EnforcementFixture

    @BeforeAll
    fun setup() {
        requireDocker()
        fx = EnforcementFixture.mysql()
    }

    private fun decide(sql: String, principal: String = "writer@example.com") = decideQuery(
        principal = principal,
        ds = fx.datasource,
        sql = sql,
        channel = Channel.WIRE,
        catalog = fx.datasourceStore.catalog(fx.datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        systemClassification = SystemClassificationService(),
    )

    @Test
    fun `allowed non-temporary DDL carries a catalog refresh command`() {
        val decision = decide("CREATE TABLE catalog_refresh_probe AS SELECT id, region FROM users")

        assertEquals(EnfAction.ALLOW, decision.action, decision.denyReason)
        assertEquals(true, decision.catalogChanging)
    }

    @Test
    fun `allowed SELECT carries no catalog refresh command`() {
        val decision = decide("SELECT id FROM users", principal = "analyst@example.com")

        assertEquals(EnfAction.ALLOW, decision.action, decision.denyReason)
        assertEquals(false, decision.catalogChanging)
    }

    @Test
    fun `denied DDL carries no catalog refresh command`() {
        val decision = decide("CREATE TABLE denied_catalog_refresh_probe (id BIGINT)", principal = "analyst@example.com")

        assertEquals(EnfAction.DENY, decision.action)
        assertEquals(false, decision.catalogChanging)
    }

    @Test
    fun `allowed temporary CTAS carries no catalog refresh command`() {
        val decision = decide("CREATE TEMPORARY TABLE temp_catalog_refresh_probe AS SELECT id, region FROM users")

        assertEquals(EnfAction.ALLOW, decision.action, decision.denyReason)
        assertEquals(false, decision.catalogChanging)
    }

    @Test
    fun `bare PREPARE is denied without a catalog refresh command`() {
        val decision = decide("PREPARE stmt FROM 'SELECT 1'")

        assertEquals(EnfAction.DENY, decision.action)
        assertEquals(false, decision.catalogChanging)
    }
}
