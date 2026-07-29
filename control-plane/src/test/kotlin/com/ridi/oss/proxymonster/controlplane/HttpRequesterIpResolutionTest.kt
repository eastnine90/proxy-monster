package com.ridi.oss.proxymonster.controlplane

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * [resolveHttpRequesterIp] (docs/authz-context.md, docs/backlog.md) — the trusted-edge-gated
 * HTTP counterpart of [parseRequesterIp] (which resolves the wire proxy's client_addr). The core invariant
 * under test is the anti-spoof one (authz-context.md "Server-attested, never client-asserted"): `X-Forwarded-
 * For` is honored ONLY when the socket peer matches a configured trusted-proxy entry, and even then only the
 * RIGHTMOST entry (the one the trusted edge itself appended) is trusted — never falling back to the edge's own
 * address on a malformed/unparseable candidate. Never throws.
 */
class HttpRequesterIpResolutionTest {
    private val trustedEdge = setOf("10.0.0.9")

    @Test
    fun `an untrusted peer's X-Forwarded-For is ignored entirely — the peer itself is used`() {
        assertEquals(
            "192.0.2.10",
            resolveHttpRequesterIp(peerAddress = "192.0.2.10", xff = "203.0.113.5", trustedProxies = emptySet()),
            "no trusted-proxies configured -> XFF is never honored, even from a would-be-trusted-looking peer",
        )
        assertEquals(
            "192.0.2.10",
            resolveHttpRequesterIp(peerAddress = "192.0.2.10", xff = "203.0.113.5", trustedProxies = trustedEdge),
            "peer 192.0.2.10 is not in trustedProxies -> XFF ignored, peer used instead",
        )
    }

    @Test
    fun `a trusted peer's rightmost XFF entry is honored`() {
        assertEquals(
            "203.0.113.5",
            resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = "203.0.113.5", trustedProxies = trustedEdge),
        )
    }

    @Test
    fun `multi-hop XFF takes the RIGHTMOST entry — the one the trusted edge itself appended`() {
        // By X-Forwarded-For convention, everything left of the rightmost entry was supplied by whatever
        // sits upstream of the trusted edge (the client, or another untrusted hop) — not attested here.
        assertEquals(
            "198.51.100.7",
            resolveHttpRequesterIp(
                peerAddress = "10.0.0.9",
                xff = "203.0.113.5, 198.51.100.7",
                trustedProxies = trustedEdge,
            ),
        )
    }

    @Test
    fun `whitespace around a multi-hop XFF entry is trimmed`() {
        assertEquals(
            "198.51.100.7",
            resolveHttpRequesterIp(
                peerAddress = "10.0.0.9",
                xff = "203.0.113.5 ,  198.51.100.7  ",
                trustedProxies = trustedEdge,
            ),
        )
    }

    @Test
    fun `an invalid rightmost XFF entry from a trusted peer resolves to null — never falls back to the edge's own IP`() {
        assertNull(
            resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = "not-an-ip", trustedProxies = trustedEdge),
            "the edge is not the requester — an unparseable XFF must not silently substitute the peer address",
        )
        assertNull(
            resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = "203.0.113.5, garbage", trustedProxies = trustedEdge),
        )
    }

    @Test
    fun `a malformed rightmost XFF entry is not salvaged into a valid IP — it resolves to null`() {
        // The strict stripper must reject a candidate whose port/bracket form is malformed rather than silently
        // truncating it to a valid-looking IP (the permissive wire-path stripper would salvage these).
        listOf(
            "[203.0.113.5",        // unclosed bracket
            "[203.0.113.5]junk",   // trailing garbage after the closing bracket
            "203.0.113.5:not-a-port", // non-numeric port
            "203.0.113.5:",        // empty port
            "[2001:db8::1]:junk",  // non-numeric port on a bracketed v6
        ).forEach { malformed ->
            assertNull(
                resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = malformed, trustedProxies = trustedEdge),
                "malformed XFF entry '$malformed' must resolve to null, not a salvaged IP",
            )
        }
    }

    @Test
    fun `a blank or absent XFF from a trusted peer resolves to null — the edge's own address is not the requester`() {
        // Once the peer is known to be a trusted edge, its socket address is the EDGE, not the end client. With
        // no attested client in X-Forwarded-For, requester_ip must be absent (fail-closed) — never the edge's IP.
        assertNull(resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = null, trustedProxies = trustedEdge))
        assertNull(resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = "   ", trustedProxies = trustedEdge))
    }

    @Test
    fun `a null or unparseable peer resolves to null — fail closed, never throws`() {
        assertNull(resolveHttpRequesterIp(peerAddress = null, xff = null, trustedProxies = trustedEdge))
        assertNull(resolveHttpRequesterIp(peerAddress = "not-an-ip", xff = null, trustedProxies = emptySet()))
    }

    @Test
    fun `a peer or XFF entry carrying a well-formed port is stripped to the bare address`() {
        // The strict stripper accepts a well-formed [host]:port / [v6]:port (numeric port) — so an LB config
        // that appends a port doesn't spuriously fail IP validation — while rejecting malformed forms (covered
        // above). A well-formed candidate is still validated through cedar-java's IpAddress.
        assertEquals("192.0.2.10", resolveHttpRequesterIp(peerAddress = "192.0.2.10:54321", xff = null, trustedProxies = emptySet()))
        assertEquals(
            "2001:db8::1",
            resolveHttpRequesterIp(peerAddress = "10.0.0.9", xff = "[2001:db8::1]:443", trustedProxies = trustedEdge),
        )
    }

    @Test
    fun `an untrusted peer that happens to equal an entry after cleaning does not match on the raw (uncleaned) form`() {
        // trustedProxies match is on the RAW peerAddress string (pre-clean) — matches the guide's "exact
        // socket-peer string match." A peer carrying a port never matches an entry configured without one, so
        // the XFF header is ignored — this falls through to the (port-stripped) peer address itself, NOT the
        // (untrusted) XFF value.
        assertEquals(
            "10.0.0.9",
            resolveHttpRequesterIp(peerAddress = "10.0.0.9:12345", xff = "203.0.113.5", trustedProxies = trustedEdge),
        )
    }

    // ---- ApplicationCall wiring (Ktor test-host's socket peer is the fixed literal "localhost") ----

    @Test
    fun `httpRequesterIp honors X-Forwarded-For only when the test-host peer is configured as trusted`() = testApplication {
        application {
            routing {
                get("/untrusted") { call.respondText(call.httpRequesterIp(config(trustedProxies = emptySet())) ?: "null") }
                get("/trusted") { call.respondText(call.httpRequesterIp(config(trustedProxies = setOf("localhost"))) ?: "null") }
            }
        }
        val client = createClient {}

        val untrusted = client.get("/untrusted") { header("X-Forwarded-For", "203.0.113.5") }
        assertEquals("null", untrusted.bodyAsText(), "peer 'localhost' isn't a configured trusted proxy -> XFF ignored, and 'localhost' itself isn't a valid IP -> null")

        val trusted = client.get("/trusted") { header("X-Forwarded-For", "203.0.113.5") }
        assertEquals("203.0.113.5", trusted.bodyAsText())
    }

    private fun config(trustedProxies: Set<String>) = Config(
        httpPort = 0,
        dbUrl = "",
        dbUser = "",
        dbPassword = "",
        authDebug = true,
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
}
