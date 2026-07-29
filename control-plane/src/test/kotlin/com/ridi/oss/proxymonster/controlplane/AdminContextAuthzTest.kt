package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.CedarEngine
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyStore
import com.ridi.oss.proxymonster.controlplane.authz.RoleSource
import com.ridi.oss.proxymonster.controlplane.authz.requireAdmin
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.get
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
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [com.ridi.oss.proxymonster.controlplane.authz.requireAdmin] (docs/authz-context.md) is the
 * single choke point every admin route funnels through — proving `requester_ip` reaches Cedar HERE, once,
 * stands in for all ~35 admin call sites (CedarPolicyStore.kt, Users.kt, Policies.kt, Datasources.kt) with
 * zero call-site churn, per the guide. Also pins the anti-spoof invariant end-to-end: an arbitrary
 * caller supplying `X-Forwarded-For` gains NOTHING unless the socket peer (Ktor test-host's fixed
 * `"localhost"`) is itself a configured trusted proxy.
 */
class AdminContextAuthzTest {
    private val dataSource: DataSource by lazy {
        com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip()
        com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.hikari(
            com.ridi.oss.proxymonster.controlplane.support.SharedPostgres.freshDatabase("pm_admin_context"),
        ).also { org.flywaydb.core.Flyway.configure().dataSource(it).load().migrate() }
    }

    private object UnusedDataSource : DataSource {
        override fun getConnection(): Connection = error("not used by this test")
        override fun getConnection(username: String?, password: String?): Connection = error("not used by this test")
        override fun getLogWriter() = error("not used by this test")
        override fun setLogWriter(out: java.io.PrintWriter?) = error("not used by this test")
        override fun setLoginTimeout(seconds: Int) = error("not used by this test")
        override fun getLoginTimeout() = error("not used by this test")
        override fun getParentLogger(): Logger = error("not used by this test")
        override fun <T : Any?> unwrap(iface: Class<T>?): T = error("not used by this test")
        override fun isWrapperFor(iface: Class<*>?): Boolean = false
    }

    // Gates admin.datasources on a requester_ip inside the documentation range 203.0.113.0/24 (RFC 5737).
    private val ipGatedAdminPolicy = 1L to """permit(
        principal in Role::"system:admin", action == Action::"admin.datasources", resource
    ) when { context has requester_ip && context.requester_ip.isInRange(ip("203.0.113.0/24")) };"""

    private fun authz(): Authz = Authz(
        CedarEngine(listOf(ipGatedAdminPolicy)),
        CedarPolicyStore(UnusedDataSource),
        RoleSource { principal -> if (principal == "admin@example.com") setOf("system:admin") else emptySet() },
    )

    private fun config(trustedProxies: Set<String>) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = false,
        secretToken = null,
        sessionSecret = "admin-context-test-secret",
        oidc = null,
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = true,
        trustedProxies = trustedProxies,
    )

    private fun ApplicationTestBuilder.wireApp(config: Config, authz: Authz, dataSource: DataSource): HttpClient {
        application { installAdminTestApp(config, authz, dataSource) }
        return createClient {
            expectSuccess = false
            install(HttpCookies)
        }
    }

    private fun Application.installAdminTestApp(config: Config, authz: Authz, dataSource: DataSource) {
        val sessionStore = PrincipalSessionStore(dataSource, null)
        attributes.put(PRINCIPAL_SESSION_STORE, sessionStore)
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) {
            webSessionCookie(sessionStore, config.sessionSecret)
        }
        routing {
            post("/test/session/{principal}") {
                val deviceId = call.ensureDeviceCookie(secure = false)
                call.sessions.set(
                    WebSessionRef(
                        sessionStore.mintWeb(
                            requireNotNull(call.parameters["principal"]),
                            null,
                            config.webSessionAbsoluteSeconds,
                            config.webSessionIdleSeconds,
                            deviceId,
                        ),
                    ),
                )
                call.respond(HttpStatusCode.NoContent)
            }
            get("/admin/datasources") {
                if (!call.requireAdmin(config, authz, AuthzAction.ADMIN_DATASOURCES)) return@get
                call.respond(HttpStatusCode.OK)
            }
        }
    }

    @Test
    fun `an admin session with no trusted edge is denied even though the policy would allow with the right ip`() = testApplication {
        val client = wireApp(config(trustedProxies = emptySet()), authz(), dataSource)
        client.post("/test/session/admin@example.com")

        // No trusted proxy configured -> X-Forwarded-For is never honored -> requester_ip absent (the
        // test-host's raw peer "localhost" isn't a valid IP either) -> the ip-gated policy never fires.
        val response = client.get("/admin/datasources") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.Forbidden, response.status, "an untrusted caller cannot spoof requester_ip via X-Forwarded-For")
    }

    @Test
    fun `a trusted edge's forwarded ip reaches Cedar and satisfies the ip-gated admin policy`() = testApplication {
        val client = wireApp(config(trustedProxies = setOf("localhost")), authz(), dataSource)
        client.post("/test/session/admin@example.com")

        val allowed = client.get("/admin/datasources") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.OK, allowed.status, "requester_ip from the trusted edge's XFF must satisfy the ip-gated permit")

        val outsideRange = client.get("/admin/datasources") { header("X-Forwarded-For", "198.51.100.10") }
        assertEquals(HttpStatusCode.Forbidden, outsideRange.status, "an ip outside the granted range must still deny")
    }

    @Test
    fun `no session is unauthenticated regardless of ip`() = testApplication {
        val client = wireApp(config(trustedProxies = setOf("localhost")), authz(), dataSource)
        val response = client.get("/admin/datasources") { header("X-Forwarded-For", "203.0.113.10") }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }
}
