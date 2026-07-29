package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import com.ridi.oss.proxymonster.controlplane.support.webSessionCookie
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation as ClientContentNegotiation
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.server.sessions.set
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.slf4j.LoggerFactory
import java.time.Instant
import javax.sql.DataSource
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * DB-backed store round-trips for [DeviceLoginStore] (docs/auth-model.md "CLI / daemon login")
 * + a route-level proof that `PM_AUTH_DEBUG` mints a wire token end-to-end through
 * `/auth/device/start` + `/auth/device/poll` **without ever configuring an IdP** — `discovery`/
 * `validator` are both null and nothing here makes an outbound HTTP call.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DeviceLoginStoreDbTest {
    private lateinit var ds: DataSource
    private lateinit var store: DeviceLoginStore

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        ds = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_device_login"))
        Flyway.configure().dataSource(ds).load().migrate()
        store = DeviceLoginStore(ds)
    }

    @Test
    fun `create then get round-trips a pending row`() {
        val handle = store.newHandle()
        val row = store.create(handle, deviceCode = "dc-1", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        assertEquals(handle, row.handle)
        assertEquals("dc-1", row.deviceCode)
        assertEquals("PENDING", row.status)
        assertNull(row.principal)

        val fetched = store.get(handle)!!
        assertEquals(row.id, fetched.id)
        assertEquals(5, fetched.intervalSec)
        assertEquals(3600L, fetched.ttlSeconds)
    }

    @Test
    fun `unknown handle is absent`() {
        assertNull(store.get("no-such-handle"))
    }

    @Test
    fun `a login is retrievable by its user_code and a fresh one is well-formed`() {
        val handle = store.newHandle()
        val userCode = store.newUserCode()
        assertTrue(userCode.matches(Regex("[A-Z0-9]{4}-[A-Z0-9]{4}")), "user_code is XXXX-XXXX from the unambiguous alphabet, got $userCode")
        store.create(handle, deviceCode = null, intervalSec = 2, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600), userCode = userCode)

        val byCode = store.getByUserCode(userCode)!!
        assertEquals(handle, byCode.handle, "the page looks the handle up by the human user_code")
        assertEquals(userCode, byCode.userCode)
        assertNull(store.getByUserCode("NOPE-NOPE"), "an unknown user_code is absent")
    }

    @Test
    fun `markApproved sets status and principal, only once`() {
        val handle = store.newHandle()
        store.create(handle, deviceCode = "dc-2", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        assertTrue(store.markApproved(handle, "alice@example.com"))
        val row = store.get(handle)!!
        assertEquals("APPROVED", row.status)
        assertEquals("alice@example.com", row.principal)

        // Re-approving an already-approved row is a no-op (it's no longer PENDING) — a second IdP
        // exchange for the same handle must not silently switch the winning principal.
        assertFalse(store.markApproved(handle, "mallory@example.com"))
        assertEquals("alice@example.com", store.get(handle)!!.principal)
    }

    @Test
    fun `markApproved refuses an expired handle`() {
        val handle = store.newHandle()
        store.create(handle, deviceCode = "dc-3", intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().minusSeconds(1))
        assertFalse(store.markApproved(handle, "alice@example.com"))
        assertEquals("PENDING", store.get(handle)!!.status)
    }

    @Test
    fun `purgeExpired removes only expired rows`() {
        val live = store.newHandle()
        val dead = store.newHandle()
        store.create(live, deviceCode = null, intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().plusSeconds(600))
        store.create(dead, deviceCode = null, intervalSec = 5, ttlSeconds = 3600, expiresAt = Instant.now().minusSeconds(1))
        assertTrue(store.purgeExpired() >= 1)
        assertNull(store.get(dead))
        assertNotNull(store.get(live))
    }

    /** The daemon session store the device routes minted into — so a test can inspect what was minted. */
    private lateinit var lastPrincipalSessionStore: PrincipalSessionStore
    private lateinit var lastTokenStore: TokenStore

    /**
     * Stand up the device-login API surface (the verification PAGE itself is the web app's /device; the CP
     * owns start/confirm/authorize/poll). The web-session cookie is installed too, so a test can drive the
     * "already logged in → approve with that session" path. Redirects are NOT auto-followed so a test can
     * assert where authorize sends the browser.
     */
    private fun ApplicationTestBuilder.installDeviceRoutes(): io.ktor.client.HttpClient {
        val config = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "test-secret-at-least-32-chars-long!!", oidc = null, resultKey = ByteArray(32) { it.toByte() },
            scimToken = null, sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        lastTokenStore = TokenStore(ds)
        val userGroupStore = UserGroupStore(ds)
        lastPrincipalSessionStore = PrincipalSessionStore(ds, ResultCrypto(config.resultKey!!))
        val log = LoggerFactory.getLogger("DeviceLoginStoreDbTest")

        // webSession() resolves the cookie through this application attribute — without it every request
        // reads as unauthenticated and the authorize route would always bounce to /login.
        application { attributes.put(PRINCIPAL_SESSION_STORE, lastPrincipalSessionStore) }
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true; encodeDefaults = true }) }
        install(Sessions) {
            webSessionCookie(lastPrincipalSessionStore, config.sessionSecret) {
                cookie.maxAgeInSeconds = config.webSessionAbsoluteSeconds
            }
            cookie<DeviceVerifySession>(DEVICE_VERIFY_COOKIE) {
                serializer = jsonSessionSerializer()
                transform(SessionTransportTransformerMessageAuthentication(config.sessionSecret.toByteArray()))
            }
        }
        routing {
            deviceSessionRoutes(config, store, lastPrincipalSessionStore, lastTokenStore, userGroupStore, log)
            // Stands in for the web console's own login: mints a web session so the "already logged in" path
            // can be exercised without dragging the whole OIDC flow into this test.
            get("/test/login-as/{principal}") {
                // Bind the session to this browser's device cookie exactly as the real OIDC callback does —
                // resolveWeb refuses a session whose stored device_id doesn't match the request's cookie.
                val deviceId = call.ensureDeviceCookie(secure = false)
                val sessionId = lastPrincipalSessionStore.mintWeb(
                    call.parameters["principal"]!!, null, config.webSessionAbsoluteSeconds, config.webSessionIdleSeconds, deviceId,
                )
                call.sessions.set(WebSessionRef(sessionId))
                call.respond(HttpStatusCode.OK, "ok")
            }
        }
        return createClient {
            install(ClientContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
            install(HttpCookies)
            followRedirects = false
        }
    }

    private suspend fun io.ktor.client.HttpClient.startLogin(): DeviceStartResponse {
        val start = post("/auth/device/start") { contentType(ContentType.Application.Json); setBody("{}") }
        assertEquals(HttpStatusCode.OK, start.status)
        return start.body<DeviceStartResponse>().also {
            assertTrue(it.handle.isNotBlank())
            assertTrue(it.userCode.isNotBlank())
            assertTrue(it.verificationUriComplete.endsWith("/device?user_code=${it.userCode}"), "start points at the web /device page")
        }
    }

    /** What the web /device page POSTs when the human confirms the code it shows. */
    private suspend fun io.ktor.client.HttpClient.confirm(userCode: String) =
        post("/auth/device/confirm") { contentType(ContentType.Application.Json); setBody("""{"userCode":"$userCode"}""") }

    /** Where the web page sends the browser after a successful confirm. */
    private suspend fun io.ktor.client.HttpClient.authorize(userCode: String) = get("/auth/device/authorize?user_code=$userCode")

    private suspend fun io.ktor.client.HttpClient.poll(handle: String) =
        post("/auth/device/poll") { contentType(ContentType.Application.Json); setBody("""{"handle":"$handle"}""") }

    @Test
    fun `the verification URL points at the web console origin, not the control plane`() {
        // /device is a WEB route, so the URL pmon prints must be the console's origin. Blank PM_WEB_ORIGIN
        // means "same origin" (the usual single-edge deployment); set, it wins — otherwise a split-origin
        // deployment would send the browser to the control plane, which serves no such page.
        val sameOrigin = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = true, secretToken = null,
            sessionSecret = "s".repeat(32), oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
            mcpResource = "https://console.example/mcp",
        )
        assertEquals("https://console.example", sameOrigin.webBaseUrl)
        assertEquals("http://127.0.0.1:41300", sameOrigin.copy(webOrigin = "http://127.0.0.1:41300/").webBaseUrl)
    }

    @Test
    fun `confirm accepts a real pending code and rejects an unknown one`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()

        assertEquals(HttpStatusCode.OK, client.confirm(started.userCode).status)
        assertEquals(HttpStatusCode.BadRequest, client.confirm("NOPE-NOPE").status, "an unknown code must not be confirmable")
    }

    @Test
    fun `authorize without a prior confirm approves nothing and bounces back to the device page`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.get("/test/login-as/alice@example.com") // logged in, but never confirmed the code on /device

        // The device-phishing gate: a direct authorize link (no /device confirm in THIS browser) can't approve.
        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "an unconfirmed authorize must bounce to the device page, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", store.get(started.handle)!!.status, "no approval without a confirm")
    }

    @Test
    fun `a confirm for one code cannot authorize a different code`() = testApplication {
        val client = installDeviceRoutes()
        val mine = client.startLogin()
        val other = client.startLogin() // e.g. an attacker's own pending login
        client.get("/test/login-as/alice@example.com")

        // Confirming MY code must not become a blanket approval capability: the verify cookie is bound to that
        // exact code, so authorizing a different one is refused even though this browser is confirmed + signed in.
        assertEquals(HttpStatusCode.OK, client.confirm(mine.userCode).status)
        val res = client.authorize(other.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertTrue(
            res.headers[HttpHeaders.Location]!!.startsWith("/device"),
            "authorizing a code this browser did not confirm must bounce, got ${res.headers[HttpHeaders.Location]}",
        )
        assertEquals("PENDING", store.get(other.handle)!!.status, "the other login must NOT be approved")
        // …and my own code still authorizes normally.
        assertEquals("/device/success", client.authorize(mine.userCode).headers[HttpHeaders.Location])
    }

    @Test
    fun `authorize with no session sends the user to login and approves nothing yet`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.confirm(started.userCode)

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        val location = res.headers[HttpHeaders.Location]!!
        assertTrue(location.startsWith("/login?return_to="), "no console session → go log in first, got $location")
        assertTrue(location.contains("device"), "login must return to the device authorize URL, got $location")
        assertEquals("PENDING", store.get(started.handle)!!.status, "still pending until a session exists")
    }

    @Test
    fun `an existing console session approves the login without re-authenticating`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.confirm(started.userCode)
        client.get("/test/login-as/alice@example.com")

        val res = client.authorize(started.userCode)
        assertEquals(HttpStatusCode.Found, res.status)
        assertEquals("/device/success", res.headers[HttpHeaders.Location], "an existing session approves straight through")

        val row = store.get(started.handle)!!
        assertEquals("APPROVED", row.status)
        assertEquals("alice@example.com", row.principal, "approved as the logged-in principal, never a debug default")
    }

    @Test
    fun `a login mints a wire token end-to-end via start, confirm, authorize, then poll`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()

        // Until the browser approves, pmon's poll is pending — start never auto-approves.
        assertEquals(HttpStatusCode.Accepted, client.poll(started.handle).status, "poll is pending until the browser approves")

        client.confirm(started.userCode)
        client.get("/test/login-as/alice@example.com")
        assertEquals(HttpStatusCode.Found, client.authorize(started.userCode).status)

        val poll = client.poll(started.handle)
        assertEquals(HttpStatusCode.OK, poll.status)
        val result: DevicePollResult = poll.body()
        assertEquals("alice@example.com", result.principal)
        assertTrue(result.token.isNotBlank())
        assertNotNull(lastTokenStore.validate(result.token))
        assertTrue(result.renewalToken.startsWith("pmr_"), "renewalToken must be the mint-once bearer renewal secret")
    }

    @Test
    fun `a device handle mints exactly once — a replayed poll is refused and mints no second session`() = testApplication {
        val client = installDeviceRoutes()
        val started = client.startLogin()
        client.confirm(started.userCode)
        client.get("/test/login-as/alice@example.com")
        client.authorize(started.userCode)

        // First poll completes the login and mints the one session + renewal secret.
        assertEquals(HttpStatusCode.OK, client.poll(started.handle).status)

        // A second poll on the SAME (now-consumed) handle must be refused, not mint again — otherwise
        // the short-lived login handle becomes an unbounded renewal-secret-minting handle.
        assertEquals(HttpStatusCode.BadRequest, client.poll(started.handle).status, "a replayed poll on a consumed handle must be refused")

        // Exactly one daemon session (one renewal secret) exists for this handle.
        val count = ds.connection.use { c ->
            c.prepareStatement("SELECT count(*) FROM principal_session WHERE handle = ? AND kind = 'DAEMON'").use { ps ->
                ps.setString(1, started.handle)
                ps.executeQuery().use { rs -> rs.next(); rs.getInt(1) }
            }
        }
        assertEquals(1, count, "a replayed poll must not mint a second session/renewal secret")
    }
}
