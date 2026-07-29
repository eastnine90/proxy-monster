package com.ridi.oss.proxymonster.controlplane

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.ContentType
import io.ktor.server.application.call
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.net.ServerSocket
import java.util.Date
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * `id_token` validation (docs/auth-model.md "id_token fully validated") against a REAL local
 * HTTP server + an in-memory RSA-signed JWT — [IdTokenValidator] delegates the JWKS fetch to
 * Nimbus's own `RemoteJWKSet`, which does its own raw HTTP call (not through the injected
 * `HttpClient`), so a genuine (loopback) server is needed rather than a mocked client.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IdTokenValidatorTest {
    private val issuer: String get() = "http://127.0.0.1:$port"

    private var port: Int = 0
    private lateinit var rsaKey: RSAKey
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>
    private lateinit var discovery: OidcDiscovery
    private lateinit var validator: IdTokenValidator

    private val clientId = "test-client"
    private val kid = "test-kid"

    @BeforeAll
    fun setup() {
        rsaKey = RSAKeyGenerator(2048).keyID(kid).generate()
        port = ServerSocket(0).use { it.localPort }

        server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            routing {
                get("/.well-known/openid-configuration") {
                    call.respondText(
                        contentType = ContentType.Application.Json,
                        text = """
                            {"issuer":"$issuer","authorization_endpoint":"$issuer/authorize",
                             "token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks"}
                        """.trimIndent(),
                    )
                }
                get("/jwks") {
                    call.respondText(
                        contentType = ContentType.Application.Json,
                        text = com.nimbusds.jose.jwk.JWKSet(rsaKey.toPublicJWK()).toString(),
                    )
                }
            }
        }.start(wait = false)

        val http = oidcHttpClient()
        discovery = OidcDiscovery(http, issuer)
        validator = IdTokenValidator(discovery, issuer, clientId)
    }

    @AfterAll
    fun teardown() {
        server.stop(gracePeriodMillis = 0, timeoutMillis = 500)
    }

    private fun claims(
        subject: String = "user-123",
        audience: String = clientId,
        issuerClaim: String = issuer,
        expiresInSeconds: Long = 300,
        nonce: String? = "the-nonce",
        email: String? = "alice@example.com",
        groups: List<String>? = listOf("engineering", "eng-leads"),
    ): JWTClaimsSet {
        val builder = JWTClaimsSet.Builder()
            .issuer(issuerClaim)
            .subject(subject)
            .audience(audience)
            .expirationTime(Date(System.currentTimeMillis() + expiresInSeconds * 1000))
        if (nonce != null) builder.claim("nonce", nonce)
        if (email != null) builder.claim("email", email)
        if (groups != null) builder.claim("groups", groups)
        return builder.build()
    }

    private fun sign(claimsSet: JWTClaimsSet, key: RSAKey = rsaKey): String {
        val header = JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build()
        val jwt = SignedJWT(header, claimsSet)
        jwt.sign(RSASSASigner(key))
        return jwt.serialize()
    }

    @Test
    fun `a correctly signed, matching id_token validates and surfaces claims`() = runBlocking {
        val token = sign(claims())
        val result = validator.validate(token, expectedNonce = "the-nonce")
        assertEquals("user-123", result?.subject)
        assertEquals("alice@example.com", result?.email)
        assertEquals(listOf("engineering", "eng-leads"), result?.groups)
        assertEquals("the-nonce", result?.nonce)
    }

    @Test
    fun `a nonce mismatch fails closed`() = runBlocking {
        val token = sign(claims(nonce = "the-nonce"))
        assertNull(validator.validate(token, expectedNonce = "a-different-nonce"))
    }

    @Test
    fun `the nonce check is skipped when the caller expects none (device flow)`() = runBlocking {
        val token = sign(claims(nonce = null))
        val result = validator.validate(token, expectedNonce = null)
        assertEquals("user-123", result?.subject)
        assertNull(result?.nonce)
    }

    @Test
    fun `a wrong audience fails closed`() = runBlocking {
        val token = sign(claims(audience = "some-other-client"))
        assertNull(validator.validate(token, expectedNonce = "the-nonce"))
    }

    @Test
    fun `a wrong issuer fails closed`() = runBlocking {
        val token = sign(claims(issuerClaim = "http://not-the-real-issuer"))
        assertNull(validator.validate(token, expectedNonce = "the-nonce"))
    }

    @Test
    fun `an expired token fails closed`() = runBlocking {
        val token = sign(claims(expiresInSeconds = -60))
        assertNull(validator.validate(token, expectedNonce = "the-nonce"))
    }

    @Test
    fun `a token signed by an untrusted key fails closed (bad signature)`() = runBlocking {
        val otherKey = RSAKeyGenerator(2048).keyID(kid).generate() // same kid, different key material
        val token = sign(claims(), key = otherKey)
        assertNull(validator.validate(token, expectedNonce = "the-nonce"))
    }

    @Test
    fun `a missing groups claim resolves to an empty list, not a failure`() = runBlocking {
        val token = sign(claims(groups = null))
        val result = validator.validate(token, expectedNonce = "the-nonce")
        assertEquals(emptyList(), result?.groups)
    }
}
