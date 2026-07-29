package com.ridi.oss.proxymonster.controlplane.oauth

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.utils.io.readRemaining
import kotlinx.io.readByteArray
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.InetAddress
import java.net.URI
import okhttp3.Dns

@Serializable
data class CimdClientMetadata(
    val client_id: String,
    val client_name: String,
    val redirect_uris: List<String>,
    val grant_types: List<String> = listOf("authorization_code"),
    val response_types: List<String> = listOf("code"),
    val token_endpoint_auth_method: String = "none",
    val scope: String = "",
)

fun interface CimdResolver {
    suspend fun resolve(clientId: String): CimdClientMetadata
}

class HttpCimdResolver(
    private val productionChecks: Boolean,
    private val clientFactory: ((String, List<InetAddress>) -> HttpClient)? = null,
) : CimdResolver {
    override suspend fun resolve(clientId: String): CimdClientMetadata {
        val uri = URI(clientId)
        require(
            uri.scheme == "https" && uri.host != null && uri.path.isNotBlank() && uri.userInfo == null &&
                uri.fragment == null && uri.path.split('/').none { it == "." || it == ".." },
        ) {
            "client_id must be an HTTPS metadata-document URL with a path and no userinfo, dot segments, or fragment"
        }
        val addresses = InetAddress.getAllByName(uri.host).toList()
        require(addresses.isNotEmpty()) { "client metadata host did not resolve" }
        if (productionChecks) {
            require(addresses.none(::isSpecialUse)) { "client metadata resolves to a special-use address" }
        }
        // Pin this request to the addresses that passed the special-use check. Leaving DNS resolution to
        // the HTTP engine would create a check/use gap in which a rebinding answer could reach localhost.
        val http = clientFactory?.invoke(uri.host, addresses) ?: pinnedClient(uri.host, addresses)
        return http.use { client ->
            val response = client.get(clientId)
            val contentType = response.contentType()
            require(
                contentType != null && contentType.contentType == ContentType.Application.Any.contentType &&
                    (contentType.contentSubtype == "json" || contentType.contentSubtype.endsWith("+json")),
            ) { "client metadata must be JSON" }
            response.headers["Content-Length"]?.toLongOrNull()?.let {
                require(it <= MAX_DOCUMENT_BYTES) { "client metadata is too large" }
            }
            val bytes = response.bodyAsChannel().readRemaining(MAX_DOCUMENT_BYTES + 1L).readByteArray()
            require(bytes.size <= MAX_DOCUMENT_BYTES) { "client metadata is too large" }
            val metadata = CIMD_JSON.decodeFromString(CimdClientMetadata.serializer(), bytes.toString(Charsets.UTF_8))
            require(metadata.client_id == clientId) { "client metadata client_id mismatch" }
            require(metadata.client_name.isNotBlank()) { "client metadata client_name is required" }
            require(metadata.redirect_uris.isNotEmpty() && metadata.redirect_uris.none(String::isBlank)) {
                "client metadata redirect_uris is required"
            }
            metadata.redirect_uris.forEach(::validatedRedirectUri)
            metadata
        }
    }

    private fun pinnedClient(host: String, addresses: List<InetAddress>) = HttpClient(OkHttp) {
        followRedirects = false
        expectSuccess = true
        install(HttpTimeout) {
            connectTimeoutMillis = 2_000
            requestTimeoutMillis = 5_000
            socketTimeoutMillis = 5_000
        }
        engine {
            config {
                followRedirects(false)
                followSslRedirects(false)
                dns(
                    object : Dns {
                        override fun lookup(hostname: String): List<InetAddress> =
                            if (hostname.equals(host, ignoreCase = true)) addresses else Dns.SYSTEM.lookup(hostname)
                    },
                )
            }
        }
    }

    private fun isSpecialUse(address: InetAddress): Boolean =
        address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress || SPECIAL_USE_CIDRS.any { it.contains(address.address) }

    private companion object {
        const val MAX_DOCUMENT_BYTES = 5 * 1024
        val CIMD_JSON = Json { ignoreUnknownKeys = true }
        val SPECIAL_USE_CIDRS = listOf(
            "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
            "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
            "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
            "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
            "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
            "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8",
        ).map(Cidr::parse)
    }
}

private data class Cidr(val network: ByteArray, val prefixBits: Int) {
    fun contains(address: ByteArray): Boolean {
        if (address.size != network.size) return false
        val wholeBytes = prefixBits / 8
        val remainingBits = prefixBits % 8
        for (index in 0 until wholeBytes) if (address[index] != network[index]) return false
        if (remainingBits == 0) return true
        val mask = (0xff shl (8 - remainingBits)) and 0xff
        return (address[wholeBytes].toInt() and mask) == (network[wholeBytes].toInt() and mask)
    }

    companion object {
        fun parse(value: String): Cidr {
            val address = InetAddress.getByName(value.substringBefore('/')).address
            return Cidr(address, value.substringAfter('/').toInt())
        }
    }
}

fun CimdClientMetadata.validateRequest(redirectUri: String, requestedScopes: Set<String>) {
    require(redirect_uris.any { loopbackAwareRedirectUriMatch(redirectUri, it) }) { "redirect_uri is not registered" }
    validatedRedirectUri(redirectUri)
    require("code" in response_types) { "client does not support response_type=code" }
    require("authorization_code" in grant_types) { "client does not support authorization_code" }
    require(token_endpoint_auth_method == "none") { "only public clients are supported" }
    val declaredScopes = scope.split(' ').filter(String::isNotBlank).toSet()
    if (declaredScopes.isNotEmpty()) {
        require(requestedScopes.all { it in declaredScopes }) { "requested scope is not declared by client metadata" }
    }
}

/** OAuth 2.1 permits HTTPS redirects plus HTTP loopback redirects for native/local clients. */
internal fun validatedRedirectUri(value: String): URI {
    val uri = runCatching { URI(value) }.getOrElse { throw IllegalArgumentException("redirect_uri is invalid", it) }
    require(uri.isAbsolute && uri.host != null && uri.userInfo == null && uri.fragment == null) {
        "redirect_uri must be an absolute URI with a host and no userinfo or fragment"
    }
    val https = uri.scheme.equals("https", ignoreCase = true)
    val loopbackHttp = uri.scheme.equals("http", ignoreCase = true) && isLoopbackRedirectHost(uri.host)
    require(https || loopbackHttp) { "redirect_uri must use HTTPS unless it targets localhost" }
    return uri
}

internal fun isLoopbackRedirectHost(host: String): Boolean {
    if (host.equals("localhost", ignoreCase = true) || host == "::1" || host == "[::1]") return true
    val octets = host.split('.')
    return octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 } && octets.first() == "127"
}

/**
 * RFC 8252 section 7.3: a native/CLI client binds its loopback redirect listener to a port chosen at
 * launch, so a CIMD document that wants to support this can only ever declare a **portless**
 * loopback redirect_uri — an authorization server MUST then match it against the actual request
 * while ignoring the port. Claude Code's own published metadata
 * (`https://claude.ai/oauth/claude-code-client-metadata`) declares exactly `http://localhost/callback`
 * / `http://127.0.0.1/callback` for this reason; a plain `requested == declared` string check rejects
 * every real login (`claude mcp login`), since the request always carries an explicit ephemeral port.
 * A declared loopback redirect_uri that DOES specify a port is left exact-match — nothing forces a
 * client to omit it, and relaxing a deliberately fixed port would let a request substitute an
 * arbitrary one. Every non-loopback redirect_uri (HTTPS, per [validatedRedirectUri]) is likewise
 * always exact-match — a fixed HTTPS endpoint has no ephemeral-port excuse to relax against.
 */
private fun loopbackAwareRedirectUriMatch(requested: String, declared: String): Boolean {
    if (requested == declared) return true
    val requestedUri = runCatching { URI(requested) }.getOrNull() ?: return false
    val declaredUri = runCatching { URI(declared) }.getOrNull() ?: return false
    if (!declaredUri.scheme.equals("http", ignoreCase = true) || declaredUri.host == null ||
        declaredUri.port != -1 || !isLoopbackRedirectHost(declaredUri.host)
    ) {
        return false
    }
    return requestedUri.scheme.equals("http", ignoreCase = true) &&
        requestedUri.host.equals(declaredUri.host, ignoreCase = true) &&
        requestedUri.path == declaredUri.path &&
        requestedUri.query == declaredUri.query
}
