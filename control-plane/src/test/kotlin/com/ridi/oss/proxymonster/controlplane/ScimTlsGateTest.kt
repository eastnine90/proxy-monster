package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [resolveScimTls] — SCIM's "requires TLS" gate (docs/auth-model.md). The invariant is the same
 * anti-spoof one [resolveHttpRequesterIp] enforces for `X-Forwarded-For`: a client-settable header may
 * speak for the transport ONLY when the socket peer is a configured trusted edge. The case that matters
 * most is [forwardedProtoFromUntrustedPeerIsIgnored]: without that gate a direct plaintext caller can
 * assert `https` about itself and pass the gate, sending the standing `PM_SCIM_TOKEN` bearer in the clear.
 */
class ScimTlsGateTest {
    private val edge = setOf("10.0.0.1")

    @Test
    fun `direct https is TLS regardless of the trusted-edge set`() {
        assertTrue(resolveScimTls("https", "203.0.113.9", null, emptySet()))
        assertTrue(resolveScimTls("HTTPS", null, null, emptySet()), "scheme compare is case-insensitive")
    }

    @Test
    fun `direct http with no forwarded header is not TLS`() {
        assertFalse(resolveScimTls("http", "10.0.0.1", null, edge))
    }

    @Test
    fun `forwarded proto from a trusted edge is honored`() {
        assertTrue(resolveScimTls("http", "10.0.0.1", "https", edge))
        assertTrue(resolveScimTls("http", "10.0.0.1", "HTTPS", edge), "header compare is case-insensitive")
    }

    /** The vulnerability this gate exists to close: an untrusted peer asserting https about itself. */
    @Test
    fun forwardedProtoFromUntrustedPeerIsIgnored() {
        assertFalse(
            resolveScimTls("http", "203.0.113.9", "https", edge),
            "a direct plaintext caller must not pass the gate by setting its own X-Forwarded-Proto",
        )
    }

    @Test
    fun `an empty trusted-edge set trusts no peer`() {
        assertFalse(
            resolveScimTls("http", "10.0.0.1", "https", emptySet()),
            "PM_TRUSTED_PROXIES unset means no edge may assert the transport (fail-closed)",
        )
    }

    @Test
    fun `a multi-hop value takes the rightmost entry`() {
        // Only the last hop was appended by the trusted edge; everything left of it is client-supplied.
        assertTrue(resolveScimTls("http", "10.0.0.1", "http, https", edge))
        assertFalse(
            resolveScimTls("http", "10.0.0.1", "https, http", edge),
            "a client-supplied leading https must not override the edge's own http",
        )
    }

    @Test
    fun `absent or blank forwarded proto is not TLS`() {
        assertFalse(resolveScimTls("http", "10.0.0.1", null, edge))
        assertFalse(resolveScimTls("http", "10.0.0.1", "", edge))
        assertFalse(resolveScimTls("http", "10.0.0.1", "   ", edge))
    }

    @Test
    fun `a null peer never passes on a header alone`() {
        assertFalse(resolveScimTls("http", null, "https", edge))
    }
}
