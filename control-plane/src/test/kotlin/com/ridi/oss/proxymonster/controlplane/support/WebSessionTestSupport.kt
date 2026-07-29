package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStorage
import com.ridi.oss.proxymonster.controlplane.PrincipalSessionStore
import com.ridi.oss.proxymonster.controlplane.SESSION_COOKIE
import com.ridi.oss.proxymonster.controlplane.WebSessionRef
import com.ridi.oss.proxymonster.controlplane.jsonSessionSerializer
import io.ktor.server.sessions.CookieIdSessionBuilder
import io.ktor.server.sessions.SessionTransportTransformerMessageAuthentication
import io.ktor.server.sessions.SessionsConfig
import io.ktor.server.sessions.cookie

fun SessionsConfig.webSessionCookie(
    store: PrincipalSessionStore,
    secret: String,
    configure: CookieIdSessionBuilder<WebSessionRef>.() -> Unit = {},
) {
    val serializer = jsonSessionSerializer<WebSessionRef>()
    cookie<WebSessionRef>(SESSION_COOKIE, PrincipalSessionStorage(store, serializer)) {
        cookie.path = "/"
        cookie.httpOnly = true
        this.serializer = serializer
        transform(SessionTransportTransformerMessageAuthentication(secret.toByteArray()))
        configure()
    }
}
