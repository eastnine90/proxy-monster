package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.Authz
import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

// Denied and missing are deliberately indistinguishable (both respond notFound("audit record")) —
// a caller must not be able to tell "exists but you can't see it" from "doesn't exist".
private suspend fun ApplicationCall.respondAuditNotFound() {
    notFound("audit record")
}

internal fun Route.auditRoutes(config: Config, store: AuditStore, authz: Authz) {
    get("/api/audit") {
        // authDebug is authoritative and short-circuits before any session resolution (mirrors requireApi).
        if (!call.requireApi(config)) return@get

        val limit = (call.request.queryParameters["limit"]?.toIntOrNull() ?: 100)
            .coerceIn(1, 500)
        if (config.authDebug) {
            call.respond(store.recent(limit))
            return@get
        }

        val principal = requireNotNull(call.userSession()) {
            "audit list admitted a non-debug request without a UserSession"
        }.principal
        val decision = authz.authorize(principal, AuthzAction.AUDIT_READ, AuthzResource.AuditLog, call.httpAuthzContext(config))
        val records = if (decision == AuthzDecision.Allow) {
            store.recent(limit)
        } else {
            store.recent(limit, principal)
        }
        call.respond(records)
    }

    get("/api/audit/{id}") {
        if (!call.requireApi(config)) return@get
        val id = call.idParam() ?: return@get call.badId()
        val record = store.get(id) ?: return@get call.respondAuditNotFound()

        if (config.authDebug) {
            call.respond(record)
            return@get
        }

        val session = requireNotNull(call.userSession()) {
            "audit detail admitted a non-debug request without a UserSession"
        }
        val decision = authz.authorize(
            session.principal,
            AuthzAction.AUDIT_READ,
            AuthzResource.AuditRecord(record.principal),
            call.httpAuthzContext(config),
        )
        if (decision == AuthzDecision.Allow) {
            call.respond(record)
        } else {
            call.respondAuditNotFound()
        }
    }
}
