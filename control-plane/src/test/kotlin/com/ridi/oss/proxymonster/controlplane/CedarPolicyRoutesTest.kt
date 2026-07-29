package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicy
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.cedarPolicyRoutes
import com.ridi.oss.proxymonster.controlplane.management.PolicyManagementService
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * HTTP contract proof for docs/policy-store.md. The route layer exposes provenance,
 * renders store-enforced SYSTEM immutability as 409, renders the reserved USER namespace as 400, and
 * deliberately leaves enable/disable available for migration-owned rows.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CedarPolicyRoutesTest {
    private lateinit var ds: DataSource
    private lateinit var store: CedarPolicyStore
    private lateinit var authz: Authz

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_cedar_policy_routes"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = CedarPolicyStore(ds)
        authz = Authz(CedarEngine(store), store, RoleSource { emptySet() })
    }

    @Test
    fun `list exposes system provenance without accepting it in input`() = testApplication {
        val client = policyClient()

        val response = client.get("/api/policies")
        assertEquals(HttpStatusCode.OK, response.status)
        val system = response.body<List<CedarPolicy>>().single { it.id == -1L }
        assertEquals("SYSTEM", system.origin)
        assertEquals("bootstrap.pm-admin", system.systemKey)
        assertEquals("system:admin", system.name)
    }

    @Test
    fun `POST and USER rename reject the reserved system namespace`() = testApplication {
        val client = policyClient()
        val postResponse = client.post("/api/policies") {
            contentType(ContentType.Application.Json)
            setBody(CedarPolicyInput("system:operator-policy", ADMIN_SOURCE))
        }
        assertEquals(HttpStatusCode.BadRequest, postResponse.status)
        assertEquals("policy.reserved_name", postResponse.body<ApiError>().code)

        val user = store.create(
            CedarPolicyInput("route-user-${System.nanoTime()}", ADMIN_SOURCE),
            updatedBy = "operator@example.com",
        )
        val putResponse = client.put("/api/policies/${user.id}") {
            contentType(ContentType.Application.Json)
            setBody(CedarPolicyInput("system:renamed-user", ADMIN_SOURCE))
        }
        assertEquals(HttpStatusCode.BadRequest, putResponse.status)
        assertEquals("policy.reserved_name", putResponse.body<ApiError>().code)
        assertEquals(user.name, store.get(user.id)!!.name)
    }

    @Test
    fun `PUT and DELETE of a system policy return the immutable conflict`() = testApplication {
        val client = policyClient()
        val before = store.get(-1)!!

        val putResponse = client.put("/api/policies/-1") {
            contentType(ContentType.Application.Json)
            setBody(CedarPolicyInput("system:rewritten", "not cedar", enabled = false))
        }
        assertEquals(HttpStatusCode.Conflict, putResponse.status)
        assertEquals("policy.system_immutable", putResponse.body<ApiError>().code)

        val deleteResponse = client.delete("/api/policies/-1")
        assertEquals(HttpStatusCode.Conflict, deleteResponse.status)
        assertEquals("policy.system_immutable", deleteResponse.body<ApiError>().code)
        assertEquals(before, store.get(-1))
    }

    @Test
    fun `enable and disable remain available for system policies`() = testApplication {
        val client = policyClient()
        store.setEnabled(-1, enabled = true, updatedBy = "setup@example.com")

        val disableResponse = client.post("/api/policies/-1/disable")
        assertEquals(HttpStatusCode.OK, disableResponse.status)
        assertFalse(disableResponse.body<CedarPolicy>().enabled)

        val enableResponse = client.post("/api/policies/-1/enable")
        assertEquals(HttpStatusCode.OK, enableResponse.status)
        assertTrue(enableResponse.body<CedarPolicy>().enabled)
        assertTrue(store.get(-1)!!.enabled)
    }

    @Test
    fun `REST-shaped policy mutation remains bound to its numeric id after name reuse`() {
        val management = PolicyManagementService(store, PolicyStore(ds))
        val original = store.create(CedarPolicyInput("id-stable-policy", ADMIN_SOURCE), "operator@example.com")
        store.update(original.id, CedarPolicyInput("id-stable-policy-renamed", ADMIN_SOURCE), "operator@example.com")
        val replacement = store.create(CedarPolicyInput("id-stable-policy", ADMIN_SOURCE), "operator@example.com")

        val updated = management.updatePolicy(
            original.id,
            CedarPolicyInput("id-stable-policy-final", ADMIN_SOURCE),
            "operator@example.com",
        )

        assertEquals(original.id, updated.id)
        assertEquals("id-stable-policy-final", store.get(original.id)?.name)
        assertEquals("id-stable-policy", store.get(replacement.id)?.name)
    }

    private fun ApplicationTestBuilder.policyClient(): HttpClient {
        application {
            val config = config()
            install(ContentNegotiation) { json(Json { encodeDefaults = true }) }
            routing { cedarPolicyRoutes(config, authz, store) }
        }
        return createClient {
            expectSuccess = false
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
    }

    private fun config() = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = true,
        secretToken = null,
        sessionSecret = "policy-route-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
    )

    private companion object {
        const val ADMIN_SOURCE =
            "permit(principal in Role::\"system:admin\", action == Action::\"admin.policies\", resource);"
    }
}
