package com.ridi.oss.proxymonster.controlplane

import io.ktor.server.sessions.SessionSerializer
import io.ktor.server.sessions.SessionStorage

/**
 * Links Ktor's opaque tracker id to a WEB row. Writing can move a reused key to a newly minted row;
 * reading returns refs for live or ended rows without sliding idle time, because request-time
 * resolution owns liveness, device binding, and the ended-reason surface; invalidation ends only an
 * active row and preserves a prior terminal reason.
 */
class PrincipalSessionStorage(
    private val store: PrincipalSessionStore,
    private val serializer: SessionSerializer<WebSessionRef>,
) : SessionStorage {
    override suspend fun write(id: String, value: String) {
        val ref = serializer.deserialize(value)
        store.linkWebSessionKey(ref.sessionId, id)
    }

    override suspend fun read(id: String): String = store.webIdBySessionKey(id)
        ?.let { serializer.serialize(WebSessionRef(it)) }
        ?: throw NoSuchElementException("Unknown web session key")

    override suspend fun invalidate(id: String) {
        store.endWebBySessionKey(id, ENDED_SIGNED_OUT)
    }
}
