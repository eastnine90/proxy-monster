package com.ridi.oss.proxymonster.controlplane

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.parseQueryString
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.get as serverGet
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.cookie
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertNull

private const val TEST_SESSION_SECRET = "oidc-callback-test-secret-not-for-prod"

/**
 * Syntactically-invalid `id_token` — [IdTokenValidator.validate] fails to even parse it, so it
 * returns `null` **without ever fetching `jwks_uri`**. That's exactly what lets this suite exercise
 * the real [OidcDiscovery] + [IdTokenValidator] (not stand-ins) with zero real-network/signing
 * infrastructure: real JWKS/signature integration is verified manually against Okta
 * (docs/auth-model.md), not by this automated suite.
 */
private const val UNPARSEABLE_ID_TOKEN = "not-a-real-jwt"

/**
 * [oidcRoutes] exercised through a real Ktor test host: the CSRF `state` + `nonce` cookies'
 * one-time-use, callback errors, and the allowlisted co-hosted OAuth continuation. The IdP side
 * (discovery document + token endpoint) is a tiny double colocated in the same test application so
 * it's reachable via relative URLs through the in-process test client — no real sockets, and no real
 * signing keys needed since every scenario here fails validation/CSRF *before* JIT provisioning
 * would run (so [UserGroupStore] is backed by a [DataSource] that must never actually be touched).
 */
class OidcCallbackTest {
    private val log = LoggerFactory.getLogger(OidcCallbackTest::class.java)
    private val userGroupStore = UserGroupStore(UnusedDataSource)
    private val roleResolver = RoleResolver(UnusedDataSource, userGroupStore, AccessStore(UnusedDataSource))

    private fun testConfig(oidcConfigured: Boolean = true): Config = Config(
        httpPort = 0,
        dbUrl = "unused",
        dbUser = "unused",
        dbPassword = "unused",
        authDebug = false,
        secretToken = null,
        sessionSecret = TEST_SESSION_SECRET,
        oidc = if (oidcConfigured) {
            OidcConfig(
                issuer = "",
                clientId = "test-client",
                clientSecret = "test-secret",
                redirectUri = "https://cp.example.test/auth/oidc/callback",
                scopes = "openid profile email groups offline_access",
                groupMapping = OidcGroupMapping(emptyMap(), null),
            )
        } else {
            null
        },
        resultKey = null,
        scimToken = null,
        sessionWindowSeconds = 12 * 3600,
        idpRecheckIntervalSeconds = 600,
        devMarker = false,
    )

    /**
     * Wires the real [oidcRoutes] plus a fake-IdP double (discovery + token endpoint, both relative
     * paths served by this SAME test app) and returns a cookie-jar-aware client with redirects
     * disabled, so the 3xx responses under test are inspectable directly instead of being silently
     * followed.
     */
    private fun ApplicationTestBuilder.wireOidc(config: Config): HttpClient {
        // The client oidcRoutes/OidcDiscovery use for their OWN outbound calls (discovery fetch +
        // token exchange) — bound to this test app's in-process engine, so "/.well-known/..." and
        // "/token" below resolve without a real socket.
        val internalHttp = createClient {
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        }
        val discovery = config.oidc?.let { OidcDiscovery(internalHttp, it.issuer) }
        val validator = discovery?.let { IdTokenValidator(it, config.oidc!!.issuer, config.oidc!!.clientId) }

        // A top-level `Application.()` extension (below) rather than inlined here: nested directly in
        // this `ApplicationTestBuilder` extension function, plain `install(...)` calls are ambiguous
        // between `Application.install` and `TestApplicationBuilder.install` (both are implicit
        // receivers in scope) — pulling the app setup out to its own receiver scope, matching how
        // Application.module itself is structured, resolves it unambiguously.
        application { installOidcTestApp(config, discovery, validator, internalHttp, userGroupStore, roleResolver, log) }

        return createClient {
            expectSuccess = false
            followRedirects = false
            install(HttpCookies)
        }
    }

    @Test
    fun `OIDC continuation accepts only the co-hosted resume and reauth routes`() {
        assertEquals("/oauth/resume", oidcReturnTarget("/oauth/resume"))
        assertEquals("/auth/reauth-complete", oidcReturnTarget("/auth/reauth-complete"))
        assertNull(oidcReturnTarget("https://evil.example/callback"))
        assertNull(oidcReturnTarget("//evil.example/callback"))
        assertNull(oidcReturnTarget("/other"))
        assertNull(oidcReturnTarget("/"))
    }

    @Test
    fun `unconfigured oidc degrades both routes to 501`() = testApplication {
        val client = wireOidc(testConfig(oidcConfigured = false))

        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/login").status)
        assertEquals(HttpStatusCode.NotImplemented, client.get("/auth/oidc/callback").status)
    }

    @Test
    fun `provider error param redirects to error=oidc`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=oidc", resp.headers[HttpHeaders.Location])
    }

    @Test
    fun `provider error preserves the popup reauth continuation`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=oidc&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `state failure preserves the popup reauth continuation`() = testApplication {
        val client = wireOidc(testConfig())

        client.get("/auth/oidc/login?return_to=%2Fauth%2Freauth-complete")
        val resp = client.get("/auth/oidc/callback?code=abc&state=wrong-state")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals(
            "/login?error=state&callbackUrl=%2Fauth%2Freauth-complete",
            resp.headers[HttpHeaders.Location],
        )
    }

    @Test
    fun `provider error returns to the co-hosted OAuth resume route`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login?return_to=%2Foauth%2Fresume")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!
        val resp = client.get("/auth/oidc/callback?error=access_denied&state=$realState")

        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/oauth/resume?error=access_denied", resp.headers[HttpHeaders.Location])
    }

    @Test
    fun `state mismatch redirects to error=state, and the state cookie is one-time-use`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        assertEquals(HttpStatusCode.Found, loginResp.status)
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!

        // Wrong state -> rejected; per the clear-regardless idiom, the cookie is burned either way.
        val wrongResp = client.get("/auth/oidc/callback?code=abc&state=not-the-real-state")
        assertEquals(HttpStatusCode.Found, wrongResp.status)
        assertEquals("/login?error=state", wrongResp.headers[HttpHeaders.Location])

        // Replaying with the ORIGINAL, correct state now also fails — proves one-time-use (the
        // cookie is gone), not just that the string comparison rejects a bad value.
        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }

    @Test
    fun `invalid id_token redirects to error=nonce, and the nonce cookie is one-time-use`() = testApplication {
        val client = wireOidc(testConfig())

        val loginResp = client.get("/auth/oidc/login")
        val realState = parseQueryString(loginResp.headers[HttpHeaders.Location]!!.substringAfter('?'))["state"]!!

        val resp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals(HttpStatusCode.Found, resp.status)
        assertEquals("/login?error=nonce", resp.headers[HttpHeaders.Location])

        // The state (and nonce) cookies were cleared on this first attempt regardless of outcome —
        // a replay of the same, originally-valid state now hits the (now-empty) state guard.
        val replayResp = client.get("/auth/oidc/callback?code=abc&state=$realState")
        assertEquals("/login?error=state", replayResp.headers[HttpHeaders.Location])
    }
}

/**
 * Sessions/content-negotiation + the fake IdP double (discovery + token) + the real [oidcRoutes]
 * under test, all in one [Application] extension so `install(...)` inside it resolves unambiguously
 * (see the comment at its call site in [OidcCallbackTest.wireOidc]).
 */
private fun Application.installOidcTestApp(
    config: Config,
    discovery: OidcDiscovery?,
    validator: IdTokenValidator?,
    http: HttpClient,
    userGroupStore: UserGroupStore,
    roleResolver: RoleResolver,
    log: Logger,
) {
    install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
    install(Sessions) {
        cookie<OAuthStateSession>(OAUTH_STATE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
        cookie<OAuthNonceSession>(OAUTH_NONCE_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
        cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
            cookie.path = "/"
            cookie.httpOnly = true
            serializer = jsonSessionSerializer()
            transform(SessionTransportTransformerMessageAuthentication(TEST_SESSION_SECRET.toByteArray()))
        }
    }
    routing {
        // Fake IdP double: a discovery document + token endpoint, just enough for oidcRoutes' own
        // round-trips. jwks_uri is deliberately unreachable — never hit (see UNPARSEABLE_ID_TOKEN).
        serverGet("/.well-known/openid-configuration") {
            call.respond(
                OidcDiscoveryDocument(
                    issuer = config.oidc?.issuer ?: "",
                    authorization_endpoint = "/authorize",
                    token_endpoint = "/token",
                    jwks_uri = "http://jwks.invalid/keys",
                ),
            )
        }
        post("/token") {
            call.respond(mapOf("id_token" to UNPARSEABLE_ID_TOKEN))
        }
        oidcRoutes(config, discovery, validator, http, userGroupStore, roleResolver, PrincipalSessionStore(UnusedDataSource, null), log)
    }
}

/**
 * A [DataSource] that must never be touched. Every scenario in [OidcCallbackTest] fails CSRF/id_token
 * validation before `UserGroupStore.provisionFromOidc` would ever run — real JIT-provisioning-on-login
 * behavior belongs to [UserGroupStore]'s own (DB-backed) tests, not here.
 */
private object UnusedDataSource : DataSource {
    private fun boom(): Nothing = error("OidcCallbackTest: UserGroupStore should not be queried by any scenario here")

    override fun getConnection() = boom()
    override fun getConnection(username: String?, password: String?) = boom()
    override fun <T : Any?> unwrap(iface: Class<T>?): T = boom()
    override fun isWrapperFor(iface: Class<*>?): Boolean = false
    override fun getLogWriter(): java.io.PrintWriter? = null
    override fun setLogWriter(out: java.io.PrintWriter?) {}
    override fun setLoginTimeout(seconds: Int) {}
    override fun getLoginTimeout(): Int = 0
    override fun getParentLogger(): java.util.logging.Logger = boom()
}
