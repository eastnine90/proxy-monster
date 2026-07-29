package com.ridi.oss.proxymonster.controlplane

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.call
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [requireScimAuth]'s bearer+TLS gate, exercised through a real Ktor test host (not a plain call) so
 * the scheme/header plumbing is proven end to end (docs/auth-model.md "SCIM 2.0 provisioning" —
 * "bearer-token auth, constant-time compare, TLS-only; reject over plaintext"). A tiny probe route
 * stands in for [scimRoutes] here — this file is about the gate itself, not the store-backed routes
 * (see ScimUsersDbTest/ScimGroupsDbTest for those).
 */
class ScimAuthTest {
    private val scimToken = "s3cret-scim-token"

    private fun Route.probeRoute(config: Config) {
        get("/probe") {
            if (!call.requireScimAuth(config)) return@get
            call.respond(HttpStatusCode.OK)
        }
    }

    @Test
    fun `plaintext request is rejected regardless of the bearer token`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = scimToken)) } }
        val response = client.get("/probe") { header("Authorization", "Bearer $scimToken") }
        assertEquals(HttpStatusCode.Forbidden, response.status)
    }

    /**
     * The spoof path, end to end: `X-Forwarded-Proto` is only meaningful from a trusted edge, so with no
     * `PM_TRUSTED_PROXIES` configured a caller asserting `https` about itself must still be refused —
     * otherwise one header would carry the standing bearer over plaintext. [ScimTlsGateTest] covers the
     * resolver; this proves the route rejects it with a real request.
     */
    @Test
    fun `forwarded proto from an untrusted peer does not satisfy the TLS gate`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = scimToken)) } }
        val response = client.get("/probe") {
            header("X-Forwarded-Proto", "https")
            header("Authorization", "Bearer $scimToken")
        }
        assertEquals(
            HttpStatusCode.Forbidden,
            response.status,
            "an untrusted peer must not assert its own transport — even with the correct bearer",
        )
    }

    @Test
    fun `https-asserted request with the wrong bearer is unauthorized`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = scimToken, trustedProxies = setOf("localhost"))) } }
        val response = client.get("/probe") {
            header("X-Forwarded-Proto", "https")
            header("Authorization", "Bearer wrong-token")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `https-asserted request with no bearer header is unauthorized`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = scimToken, trustedProxies = setOf("localhost"))) } }
        val response = client.get("/probe") { header("X-Forwarded-Proto", "https") }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `https-asserted request with the correct bearer succeeds`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = scimToken, trustedProxies = setOf("localhost"))) } }
        val response = client.get("/probe") {
            header("X-Forwarded-Proto", "https")
            header("Authorization", "Bearer $scimToken")
        }
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `an unconfigured SCIM token disables the endpoint fail-closed`() = testApplication {
        install(ContentNegotiation) { json() }
        application { routing { probeRoute(testScimConfig(scimToken = null)) } }
        val response = client.get("/probe") {
            header("X-Forwarded-Proto", "https")
            header("Authorization", "Bearer $scimToken")
        }
        assertEquals(HttpStatusCode.NotImplemented, response.status)
    }
}

/** A minimal but complete [Config] for SCIM-gate tests — every field but [Config.scimToken] is inert. */
internal fun testScimConfig(scimToken: String?, trustedProxies: Set<String> = emptySet()): Config = Config(
    httpPort = 0,
    dbUrl = "jdbc:postgresql://localhost/unused",
    dbUser = "unused",
    dbPassword = "unused",
    authDebug = true,
    secretToken = null,
    sessionSecret = "test-only-session-secret",
    oidc = null,
    resultKey = null,
    scimToken = scimToken,
    trustedProxies = trustedProxies,
    sessionWindowSeconds = 3600,
    idpRecheckIntervalSeconds = 600,
    devMarker = true,
)
