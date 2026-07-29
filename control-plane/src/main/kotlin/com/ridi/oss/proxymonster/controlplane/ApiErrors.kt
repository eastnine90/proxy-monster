package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.response.respond
import kotlinx.serialization.Serializable

/**
 * User-facing API error envelope (docs/l10n.md): a stable, dot-namespaced `code` the web UI looks
 * up directly as an i18n message key, plus the `params` it interpolates into that message. Unlike an
 * ad-hoc `mapOf("error" to "<English sentence>")` response, this keeps English prose out of the wire
 * contract, so messages can be localized and deduplicated across routes.
 *
 * `code` is either a shared `common.*` code (see the extension functions below — reused across many
 * routes for the same *kind* of failure) or a route-specific `<feature>.*` code for a message that's
 * genuinely unique to one workflow. SCIM (`Scim.kt`) is exempt: its error body follows the SCIM 2.0
 * spec for the IdP, not this envelope.
 */
@Serializable
data class ApiError(val code: String, val params: Map<String, String> = emptyMap())

suspend fun ApplicationCall.respondError(status: HttpStatusCode, code: String, params: Map<String, String> = emptyMap()) {
    respond(status, ApiError(code, params))
}

// ---- Common, cross-cutting codes -----------------------------------------------------------
// The single biggest de-duplication win (docs/l10n.md): "bad id" / "not found" / "X required" /
// "already exists" were each repeated near-verbatim across a dozen-plus routes. One shared code per
// *kind* of failure, parameterized with which resource/field it was about, instead of a bespoke
// English sentence (and a bespoke i18n key) per call site.

/** A path param that failed to parse as an id (was blank or non-numeric). */
suspend fun ApplicationCall.badId() = respondError(HttpStatusCode.BadRequest, "common.bad_id")

/** No row matching the given id/name for `resource` (e.g. "datasource", "group", "role"). */
suspend fun ApplicationCall.notFound(resource: String) =
    respondError(HttpStatusCode.NotFound, "common.not_found", mapOf("resource" to resource))

/** One or more required body fields were missing/blank. */
suspend fun ApplicationCall.fieldRequired(vararg fields: String) =
    respondError(HttpStatusCode.BadRequest, "common.field_required", mapOf("fields" to fields.joinToString(", ")))

/** A create/rename would collide with an existing `resource` (optionally naming which one, `name`). */
suspend fun ApplicationCall.alreadyExists(resource: String, name: String? = null) = respondError(
    HttpStatusCode.Conflict,
    "common.already_exists",
    buildMap { put("resource", resource); name?.let { put("name", it) } },
)

/** No session and `PM_AUTH_DEBUG` is off — the request carries no usable identity at all. */
suspend fun ApplicationCall.unauthenticated() = respondError(HttpStatusCode.Unauthorized, "common.unauthenticated")

/** A bearer/wire/ingest credential was missing, malformed, or expired. `kind` names which one. */
suspend fun ApplicationCall.invalidToken(kind: String? = null) = respondError(
    HttpStatusCode.Unauthorized,
    "common.invalid_token",
    kind?.let { mapOf("kind" to it) } ?: emptyMap(),
)
