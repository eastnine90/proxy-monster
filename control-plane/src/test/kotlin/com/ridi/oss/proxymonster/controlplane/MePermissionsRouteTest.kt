package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.set
import io.ktor.server.sessions.sessions
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import java.sql.Connection
import java.util.logging.Logger
import javax.sql.DataSource
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class MePermissionsRouteTest {
    private val dataSource: DataSource by lazy {
        com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip()
        com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.hikari(
            com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.freshDatabase("pm_me_permissions"),
        ).also { org.flywaydb.core.Flyway.configure().dataSource(it).load().migrate() }
    }

    private val rolePolicies = listOf(
        1L to """permit(principal in Role::"datasource-admin", action == Action::"admin.datasources", resource);""",
        2L to """permit(principal in Role::"policy-admin", action == Action::"admin.policies", resource);""",
        3L to """permit(principal in Role::"identity-admin", action == Action::"admin.identity", resource);""",
        4L to """permit(principal, action == Action::"audit.read", resource) when { resource is AuditRecord && resource.principal == principal };""",
        5L to """permit(principal in Role::"auditor", action == Action::"audit.read", resource);""",
    )

    private val principalRoles = mapOf(
        "datasource-only" to setOf("datasource-admin"),
        "policy-only" to setOf("policy-admin"),
        "identity-only" to setOf("identity-admin"),
        "auditor-only" to setOf("auditor"),
    )

    private fun authz(): Authz = Authz(
        CedarEngine(rolePolicies),
        CedarPolicyStore(dataSource),
        RoleSource { principal -> principalRoles[principal] ?: emptySet() },
    )

    private fun config(authDebug: Boolean, trustedProxies: Set<String> = emptySet()) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = authDebug,
        secretToken = null,
        sessionSecret = "test-session-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
        trustedProxies = trustedProxies,
    )

    // An IP-gated admin.datasources permit: `isAdmin` is true ONLY when requester_ip is in the documentation
    // range 203.0.113.0/24 — so the /api/me/permissions decision is observably sensitive to the context arg.
    private fun ipGatedAdminAuthz(): Authz = Authz(
        CedarEngine(
            listOf(
                1L to """permit(principal in Role::"system:admin", action == Action::"admin.datasources", resource)
                    when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };""",
            ),
        ),
        CedarPolicyStore(MePermissionsUnusedDataSource),
        RoleSource { p -> if (p == "edge-admin") setOf("system:admin") else emptySet() },
    )

    private fun isAdmin(body: String): Boolean =
        Json.parseToJsonElement(body).jsonObject.getValue("isAdmin").jsonPrimitive.boolean

    @Test
    fun `non-debug requests require a session`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)

        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/me/permissions").status)
    }

    @Test
    fun `auth debug returns all capabilities without a session`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = true), authz(), dataSource)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        val payload = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertEquals(setOf("isAdmin", "canReadAllAudit", "canApprove"), payload.keys)
        assertEquals(true, payload.getValue("isAdmin").jsonPrimitive.boolean)
        assertEquals(true, payload.getValue("canReadAllAudit").jsonPrimitive.boolean)
        assertEquals(true, payload.getValue("canApprove").jsonPrimitive.boolean)
    }

    @Test
    fun `each independent admin action grants admin and approval but not audit collection access`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)

        for (principal in listOf("datasource-only", "policy-only", "identity-only")) {
            assertEquals(HttpStatusCode.NoContent, client.post("/test/session/$principal").status)
            val response = client.get("/api/me/permissions")
            assertEquals(HttpStatusCode.OK, response.status)
            assertEquals(
                MePermissions(isAdmin = true, canReadAllAudit = false, canApprove = true),
                response.body(),
            )
        }
    }

    @Test
    fun `auditor can read the audit collection without admin or approval capabilities`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/auditor-only").status)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            MePermissions(isAdmin = false, canReadAllAudit = true, canApprove = false),
            response.body(),
        )
    }

    @Test
    fun `requester_ip from a trusted edge reaches the me-permissions admin decision`() = testApplication {
        // With a trusted edge configured, X-Forwarded-For is honored, so requester_ip is the forwarded IP —
        // and the ip-gated admin permit fires (or not) accordingly. This pins the computeMePermissions context
        // argument as load-bearing at the actual route: drop it and the in-range case would no longer be admin.
        val client = wirePermissionsApp(config(authDebug = false, trustedProxies = setOf("localhost")), ipGatedAdminAuthz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/edge-admin").status)

        val inRange = client.get("/api/me/permissions") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.OK, inRange.status)
        assertEquals(true, isAdmin(inRange.bodyAsText()), "requester_ip in range -> the ip-gated admin permit fires")

        val outOfRange = client.get("/api/me/permissions") { header("X-Forwarded-For", "198.51.100.10") }
        assertEquals(false, isAdmin(outOfRange.bodyAsText()), "requester_ip out of range -> not admin")
    }

    @Test
    fun `an untrusted peer cannot spoof requester_ip via X-Forwarded-For at the me-permissions route`() = testApplication {
        // No trusted edge -> XFF is never honored -> requester_ip stays absent (the test-host peer 'localhost'
        // is not a valid IP either) -> the ip-gated admin permit never fires, even with a spoofed header.
        val client = wirePermissionsApp(config(authDebug = false, trustedProxies = emptySet()), ipGatedAdminAuthz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/edge-admin").status)

        val spoofed = client.get("/api/me/permissions") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(false, isAdmin(spoofed.bodyAsText()), "an untrusted caller cannot spoof requester_ip via X-Forwarded-For")
    }

    @Test
    fun `ordinary principal has no coarse capabilities`() = testApplication {
        val client = wirePermissionsApp(config(authDebug = false), authz(), dataSource)
        assertEquals(HttpStatusCode.NoContent, client.post("/test/session/ordinary").status)

        val response = client.get("/api/me/permissions")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            MePermissions(isAdmin = false, canReadAllAudit = false, canApprove = false),
            response.body(),
        )
    }
}

private fun ApplicationTestBuilder.wirePermissionsApp(config: Config, authz: Authz, dataSource: DataSource): HttpClient {
    application { installPermissionsTestApp(config, authz, dataSource) }
    return createClient {
        expectSuccess = false
        install(HttpCookies)
        install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    }
}

private fun Application.installPermissionsTestApp(config: Config, authz: Authz, dataSource: DataSource) {
    val sessionStore = PrincipalSessionStore(dataSource, null)
    attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
    install(Sessions) {
        webSessionCookie(sessionStore, config.sessionSecret)
    }
    routing {
        post("/test/session/{principal}") {
            val principal = requireNotNull(call.parameters["principal"])
            val deviceId = call.ensureDeviceCookie(secure = false)
            call.sessions.set(WebSessionRef(sessionStore.mintWeb(principal, null, config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId)))
            call.respond(HttpStatusCode.NoContent)
        }
        mePermissionsRoute(config, authz)
    }
}

/**
 * A JDBC sentinel for [ipGatedAdminAuthz]: its Cedar policies are supplied inline to the engine, so
 * that authz's [CedarPolicyStore] is never queried. Any connection attempt is a bug in the fixture.
 */
private object MePermissionsUnusedDataSource : DataSource {
    private fun boom(): Nothing = error("ipGatedAdminAuthz must not query its Cedar policy store")

    override fun getConnection(): Connection = boom()
    override fun getConnection(username: String?, password: String?): Connection = boom()
    override fun getLogWriter() = boom()
    override fun setLogWriter(out: java.io.PrintWriter?) = boom()
    override fun setLoginTimeout(seconds: Int) = boom()
    override fun getLoginTimeout() = boom()
    override fun getParentLogger(): Logger = boom()
    override fun <T : Any?> unwrap(iface: Class<T>?): T = boom()
    override fun isWrapperFor(iface: Class<*>?): Boolean = false
}
