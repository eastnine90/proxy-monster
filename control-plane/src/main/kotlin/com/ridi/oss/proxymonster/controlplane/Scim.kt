package com.ridi.oss.proxymonster.controlplane

import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.plugins.origin
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.patch
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.security.MessageDigest
import java.sql.SQLException
import org.slf4j.Logger

// ---- SCIM DTOs (docs/auth-model.md "SCIM 2.0 provisioning"; RFC 7643/7644) --------------------

private const val SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
private const val SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
private const val SCIM_LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
private const val SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
private const val SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

@Serializable data class ScimName(val formatted: String? = null)
@Serializable data class ScimEmail(val value: String? = null, val primary: Boolean? = null, val type: String? = null)
@Serializable data class ScimUserGroupRef(val value: String, val display: String? = null)
@Serializable data class ScimMemberRef(val value: String, val display: String? = null)

@Serializable
data class ScimUser(
    val schemas: List<String> = listOf(SCIM_USER_SCHEMA),
    val id: String? = null,
    val externalId: String? = null,
    val userName: String = "",
    val name: ScimName? = null,
    val emails: List<ScimEmail> = emptyList(),
    val active: Boolean = true,
    val groups: List<ScimUserGroupRef> = emptyList(),
) {
    fun primaryEmail(): String? = emails.firstOrNull { it.primary == true }?.value ?: emails.firstOrNull()?.value
}

@Serializable
data class ScimGroup(
    val schemas: List<String> = listOf(SCIM_GROUP_SCHEMA),
    val id: String? = null,
    val externalId: String? = null,
    val displayName: String = "",
    val members: List<ScimMemberRef> = emptyList(),
)

@Serializable
data class ScimListResponse<T>(
    val schemas: List<String> = listOf(SCIM_LIST_RESPONSE_SCHEMA),
    val totalResults: Int,
    @SerialName("Resources") val resources: List<T>,
)

@Serializable
data class ScimError(
    val schemas: List<String> = listOf(SCIM_ERROR_SCHEMA),
    val status: String,
    val scimType: String? = null,
    val detail: String? = null,
)

// ---- PATCH — the CORE SUBSET only (docs/auth-model.md) ----------------------------------------
// Supported shapes: {op:replace, path:active, value:<bool>} (Users) and {op:add|remove,
// path:members, value:[{value:<id>}, ...]} (Groups). No filter-path grammar
// (`members[value eq "..."]`) — anything outside the two shapes is rejected with a proper SCIM 400.

@Serializable
data class ScimPatchOperation(val op: String, val path: String? = null, val value: JsonElement? = null)

@Serializable
data class ScimPatchOp(
    val schemas: List<String> = emptyList(),
    @SerialName("Operations") val operations: List<ScimPatchOperation> = emptyList(),
)

/** Thrown by [ScimPatchValidator.validate] for anything outside the core PATCH subset. */
class ScimPatchInvalidException(val scimType: String, val detailMessage: String) : RuntimeException(detailMessage)

sealed interface ScimPatchAction {
    data class SetActive(val active: Boolean) : ScimPatchAction
    /** [op] is always "add" or "remove"; [values] are the target resources' SCIM `id`s. */
    data class MemberOp(val op: String, val values: List<String>) : ScimPatchAction
}

/**
 * Validates a SCIM PATCH body against the core provisioning subset (docs/auth-model.md — "PATCH:
 * only the core provisioning subset ... reject anything outside it with a proper SCIM 400"). A pure
 * function: no I/O, no store access — routes apply the returned [ScimPatchAction] themselves.
 */
object ScimPatchValidator {
    fun validate(operations: List<ScimPatchOperation>): ScimPatchAction {
        if (operations.size != 1) {
            throw ScimPatchInvalidException("invalidPath", "exactly one Operations entry is supported")
        }
        val op = operations.single()
        val path = op.path?.trim()
        return when {
            op.op.equals("replace", ignoreCase = true) && path == "active" -> {
                val active = (op.value as? JsonPrimitive)?.booleanOrNull
                    ?: throw ScimPatchInvalidException("invalidValue", "path 'active' requires a boolean value")
                ScimPatchAction.SetActive(active)
            }
            (op.op.equals("add", ignoreCase = true) || op.op.equals("remove", ignoreCase = true)) && path == "members" -> {
                val values = (op.value as? JsonArray)?.mapNotNull { el ->
                    (el as? JsonObject)?.get("value")?.let { (it as? JsonPrimitive)?.contentOrNull }
                } ?: throw ScimPatchInvalidException("invalidValue", "path 'members' requires a value array of {value}")
                ScimPatchAction.MemberOp(op.op.lowercase(), values)
            }
            else -> throw ScimPatchInvalidException(
                "invalidPath",
                "unsupported PATCH op/path '${op.op}'/'${op.path}' — only replace:active (Users) and add|remove:members (Groups) are supported",
            )
        }
    }
}

// ---- Bearer + TLS gate --------------------------------------------------------------------------

/**
 * SCIM's auth gate (docs/auth-model.md "SCIM 2.0 provisioning"): a standing bearer secret
 * (`PM_SCIM_TOKEN`), constant-time compared, TLS-only — deliberately NOT `requireAdmin`/Cedar
 * (there is no user session here, this is an IdP-to-CP service integration). Fail-closed at every
 * step: unconfigured token -> 501 (no provisioning surface at all), plaintext -> 403, missing/wrong
 * bearer -> 401. The TLS check is [resolveScimTls]: direct HTTPS, or an `X-Forwarded-Proto` from a
 * trusted edge — never a header a direct caller asserted about itself. So a deployment terminating
 * TLS at an edge must list that edge in `PM_TRUSTED_PROXIES`, or SCIM stays 403.
 */
suspend fun ApplicationCall.requireScimAuth(config: Config): Boolean {
    val expected = config.scimToken
    if (expected == null) {
        respond(HttpStatusCode.NotImplemented, ScimError(status = "501", detail = "SCIM provisioning is not configured"))
        return false
    }
    if (!isScimTls(config)) {
        respond(HttpStatusCode.Forbidden, ScimError(status = "403", detail = "SCIM requires TLS"))
        return false
    }
    val provided = request.headers[HttpHeaders.Authorization]?.removePrefix("Bearer ")?.trim()
    if (provided == null || !constantTimeEquals(provided, expected)) {
        respond(HttpStatusCode.Unauthorized, ScimError(status = "401", detail = "invalid bearer token"))
        return false
    }
    return true
}

/**
 * `request.local.remoteAddress` is the raw socket peer (the same source [httpRequesterIp] uses, and the
 * reason it is not `origin.remoteAddress`: origin is header-influenced, so it is not the TCP-level fact
 * the trusted-edge test needs).
 */
private fun ApplicationCall.isScimTls(config: Config): Boolean =
    resolveScimTls(
        directScheme = request.origin.scheme,
        peerAddress = request.local.remoteAddress,
        forwardedProto = request.headers.getAll("X-Forwarded-Proto")?.lastOrNull(),
        trustedProxies = config.trustedProxies,
    )

/**
 * True when the request demonstrably arrived over TLS. Direct HTTPS is a fact of the connection.
 * `X-Forwarded-Proto` is client-settable, so it is honored ONLY when the socket peer is a configured
 * trusted edge — [isTrustedEdge], the same server-attested-never-client-asserted invariant
 * [resolveHttpRequesterIp] enforces for `X-Forwarded-For`. Without that gate any direct plaintext
 * caller could assert `https` about itself and send the standing bearer in the clear.
 *
 * A multi-hop value takes the RIGHTMOST entry — the one THIS edge appended; everything left of it is
 * client-supplied. Absent, blank, or non-`https` is not TLS (fail-closed). Note the practical
 * consequence of the empty default: with `PM_TRUSTED_PROXIES` unset NO peer is trusted, so a
 * TLS-terminating edge must be listed there or SCIM stays 403.
 */
internal fun resolveScimTls(
    directScheme: String?,
    peerAddress: String?,
    forwardedProto: String?,
    trustedProxies: Set<String>,
): Boolean {
    if (directScheme.equals("https", ignoreCase = true)) return true
    if (!isTrustedEdge(peerAddress, trustedProxies)) return false
    val asserted = forwardedProto?.split(',')?.lastOrNull()?.trim()
    return asserted.equals("https", ignoreCase = true)
}

/** Constant-time bearer compare — do NOT replace with `==`/`!=` (see Tokens.kt's ingest-token check
 *  for the naive version this deliberately avoids; a standing SCIM secret is a juicier timing target). */
private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

// ---- mapping helpers -----------------------------------------------------------------------------

private fun AppUser.toScim(): ScimUser = ScimUser(
    id = id.toString(),
    externalId = externalId,
    userName = principal,
    name = displayName?.let { ScimName(formatted = it) },
    emails = email?.let { listOf(ScimEmail(value = it, primary = true)) } ?: emptyList(),
    active = active,
    groups = groups.map { ScimUserGroupRef(value = it.id.toString(), display = it.name) },
)

private fun AppGroup.toScim(members: List<GroupMemberEntry>): ScimGroup = ScimGroup(
    id = id.toString(),
    externalId = externalId,
    displayName = name,
    members = members.map { ScimMemberRef(value = it.userId.toString(), display = it.principal) },
)

private suspend fun ApplicationCall.respondScimError(status: HttpStatusCode, scimType: String?, detail: String) {
    respond(status, ScimError(status = status.value.toString(), scimType = scimType, detail = detail))
}

// ---- static discovery documents ------------------------------------------------------------------

private val SERVICE_PROVIDER_CONFIG: JsonObject = buildJsonObject {
    putJsonArray("schemas") { add(SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA) }
    putJsonObject("patch") { put("supported", true) }
    putJsonObject("bulk") { put("supported", false); put("maxOperations", 0); put("maxPayloadSize", 0) }
    // No filter-path grammar (docs/auth-model.md) — the PATCH core subset only, and list endpoints
    // don't support `filter=`.
    putJsonObject("filter") { put("supported", false); put("maxResults", 0) }
    putJsonObject("changePassword") { put("supported", false) }
    putJsonObject("sort") { put("supported", false) }
    putJsonObject("etag") { put("supported", false) }
    putJsonArray("authenticationSchemes") {
        add(
            buildJsonObject {
                put("type", "oauthbearertoken")
                put("name", "OAuth Bearer Token")
                put("description", "Authentication via a standing PM_SCIM_TOKEN bearer credential, TLS-only")
                put("primary", true)
            },
        )
    }
}

private val RESOURCE_TYPES: JsonArray = buildJsonArray {
    add(
        buildJsonObject {
            putJsonArray("schemas") { add("urn:ietf:params:scim:schemas:core:2.0:ResourceType") }
            put("id", "User")
            put("name", "User")
            put("endpoint", "/Users")
            put("schema", SCIM_USER_SCHEMA)
        },
    )
    add(
        buildJsonObject {
            putJsonArray("schemas") { add("urn:ietf:params:scim:schemas:core:2.0:ResourceType") }
            put("id", "Group")
            put("name", "Group")
            put("endpoint", "/Groups")
            put("schema", SCIM_GROUP_SCHEMA)
        },
    )
}

private val SCHEMAS: JsonArray = buildJsonArray {
    add(
        buildJsonObject {
            put("id", SCIM_USER_SCHEMA)
            put("name", "User")
            putJsonArray("attributes") {
                add(buildJsonObject { put("name", "userName"); put("type", "string"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "externalId"); put("type", "string"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "name"); put("type", "complex"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "emails"); put("type", "complex"); put("multiValued", true); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "active"); put("type", "boolean"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "groups"); put("type", "complex"); put("multiValued", true); put("mutability", "readOnly") })
            }
        },
    )
    add(
        buildJsonObject {
            put("id", SCIM_GROUP_SCHEMA)
            put("name", "Group")
            putJsonArray("attributes") {
                add(buildJsonObject { put("name", "displayName"); put("type", "string"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "externalId"); put("type", "string"); put("mutability", "readWrite") })
                add(buildJsonObject { put("name", "members"); put("type", "complex"); put("multiValued", true); put("mutability", "readWrite") })
            }
        },
    )
}

// ---- Routes ----------------------------------------------------------------------------------

/**
 * SCIM 2.0 provisioning (docs/auth-model.md "SCIM 2.0 provisioning — IdP -> local directory"): the
 * IdP (Okta or any SCIM 2.0 client) pushes users/groups/membership into the local directory tables
 * (`app_user`/`app_group`/`group_member`, `source=SCIM`). Bearer+TLS gated ([requireScimAuth]) —
 * never `requireAdmin`/Cedar, this is a standing service-to-service integration, not a user session.
 * `active=false` (deactivate) and DELETE both soft-deprovision (never hard-delete a user — audit
 * history holds) and revoke that principal's standing wire tokens + JIT grants + daemon-session
 * windows ATOMICALLY with the `app_user` write — every deactivate/delete/rename path runs its mutation
 * and its credential teardown as ONE committed transaction under the per-principal advisory lock,
 * via [UserGroupStore.upsertScimUser] (POST/PUT) / [UserGroupStore.setActiveById]
 * (PATCH SetActive / DELETE — id-addressed, re-reading the current principal under the lock).
 */
fun Route.scimRoutes(
    config: Config,
    userGroupStore: UserGroupStore,
    tokenStore: TokenStore,
    accessStore: AccessStore,
    daemonSessionStore: PrincipalSessionStore,
    log: Logger,
) {
    get("/api/scim/v2/ServiceProviderConfig") {
        if (!call.requireScimAuth(config)) return@get
        call.respond(SERVICE_PROVIDER_CONFIG)
    }
    get("/api/scim/v2/ResourceTypes") {
        if (!call.requireScimAuth(config)) return@get
        call.respond(RESOURCE_TYPES)
    }
    get("/api/scim/v2/Schemas") {
        if (!call.requireScimAuth(config)) return@get
        call.respond(SCHEMAS)
    }

    // ---- Users ----

    get("/api/scim/v2/Users") {
        if (!call.requireScimAuth(config)) return@get
        val users = userGroupStore.listUsers()
        call.respond(ScimListResponse(totalResults = users.size, resources = users.map { it.toScim() }))
    }
    post("/api/scim/v2/Users") {
        if (!call.requireScimAuth(config)) return@post
        val body = call.receive<ScimUser>()
        val externalId = body.externalId
        if (externalId.isNullOrBlank()) {
            return@post call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "externalId is required")
        }
        val principal = body.userName.ifBlank { body.primaryEmail().orEmpty() }
        if (principal.isBlank()) {
            return@post call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "userName is required")
        }
        // upsertScimUser's stores-threaded overload atomically tears down BOTH a matched-but-renamed
        // row's OLD principal (app_user UPDATE + tombstone + credential revoke) AND, when
        // the resolved state is active=false, the CURRENT principal's credentials, each
        // in ONE transaction under the per-principal lock. A POST can legitimately hit either case: Okta
        // may reconcile an existing user (matched by external_id/email) via a full-resource POST, incl.
        // deprovisioning it down to active=false — so no separate, non-atomic follow-up revoke is needed.
        val user = try {
            userGroupStore.upsertScimUser(
                externalId = externalId,
                principal = principal,
                email = body.primaryEmail(),
                displayName = body.name?.formatted,
                active = body.active,
                tokenStore = tokenStore,
                accessStore = accessStore,
                daemonSessionStore = daemonSessionStore,
            )
        } catch (e: SQLException) {
            // externalId is a partial UNIQUE index (V14) — a POST whose externalId
            // is new but whose email/principal match resolves to a row already owning a DIFFERENT
            // external_id collides here rather than silently producing a split-brain external_id.
            if (e.isUniqueViolation()) {
                return@post call.respondScimError(HttpStatusCode.Conflict, "uniqueness", "principal or externalId already in use")
            }
            throw e
        }
        log.info("SCIM: provisioned user principal={} externalId={}", user.principal, externalId)
        call.respond(HttpStatusCode.Created, user.toScim())
    }
    get("/api/scim/v2/Users/{id}") {
        if (!call.requireScimAuth(config)) return@get
        val id = call.parameters["id"]?.toLongOrNull()
        val user = id?.let { userGroupStore.getUser(it) }
            ?: return@get call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        call.respond(user.toScim())
    }
    put("/api/scim/v2/Users/{id}") {
        if (!call.requireScimAuth(config)) return@put
        val id = call.parameters["id"]?.toLongOrNull()
        if (id == null) return@put call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        val existing = userGroupStore.getUser(id)
            ?: return@put call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        val body = call.receive<ScimUser>()
        val externalId = body.externalId ?: existing.externalId
        if (externalId.isNullOrBlank()) {
            return@put call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "externalId is required")
        }
        val principal = body.userName.ifBlank { existing.principal }
        // PUT replaces the resource AT THIS id — replaceScimUserById resolves/mutates
        // the row addressed by [id] directly, never re-discovering a different row by
        // externalId/email/principal the way upsertScimUser (POST) does. Both the rename teardown of
        // the OLD principal and the active=false revoke of the CURRENT principal
        // still happen atomically inside it — one committed transaction under the
        // per-principal lock, no separate follow-up revoke that a crash could skip.
        val user = try {
            userGroupStore.replaceScimUserById(
                id = id,
                principal = principal,
                email = body.primaryEmail() ?: existing.email,
                displayName = body.name?.formatted ?: existing.displayName,
                externalId = externalId,
                active = body.active,
                tokenStore = tokenStore,
                accessStore = accessStore,
                daemonSessionStore = daemonSessionStore,
            ) ?: return@put call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        } catch (e: SQLException) {
            // externalId is a partial UNIQUE index (V14) — an externalId already
            // owned by a DIFFERENT row collides here instead of producing a split-brain external_id.
            if (e.isUniqueViolation()) {
                return@put call.respondScimError(HttpStatusCode.Conflict, "uniqueness", "externalId already belongs to a different user")
            }
            throw e
        }
        call.respond(user.toScim())
    }
    patch("/api/scim/v2/Users/{id}") {
        if (!call.requireScimAuth(config)) return@patch
        val id = call.parameters["id"]?.toLongOrNull()
        if (id == null || userGroupStore.getUser(id) == null) {
            return@patch call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        }
        val body = call.receive<ScimPatchOp>()
        val action = try {
            ScimPatchValidator.validate(body.operations)
        } catch (e: ScimPatchInvalidException) {
            return@patch call.respondScimError(HttpStatusCode.BadRequest, e.scimType, e.detailMessage)
        }
        when (action) {
            is ScimPatchAction.SetActive -> {
                // Deactivate/reactivate BY ID: [setActiveById] re-reads the row's CURRENT principal
                // under the per-principal advisory lock — so a concurrent rename can't
                // make this act on a stale pre-lock snapshot — and, on active=false, revokes that
                // principal's credentials in the SAME committed transaction, not a
                // mutate-then-revoke pair a crash could leave half-applied.
                val updated = userGroupStore.setActiveById(id, action.active, tokenStore, accessStore, daemonSessionStore)
                    ?: return@patch call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
                if (!action.active) log.info("SCIM: deactivated user principal={}", updated.principal)
                call.respond(updated.toScim())
            }
            is ScimPatchAction.MemberOp -> {
                call.respondScimError(HttpStatusCode.BadRequest, "invalidPath", "path 'members' is only valid on Groups")
            }
        }
    }
    delete("/api/scim/v2/Users/{id}") {
        if (!call.requireScimAuth(config)) return@delete
        val id = call.parameters["id"]?.toLongOrNull()
        // Deactivate, don't delete (docs/auth-model.md) — audit history holds. BY ID: [setActiveById]
        // re-reads the current principal under the per-principal advisory lock and revokes
        // its credentials in the SAME committed transaction, so a concurrent rename can't
        // leave the row's real identity credentialed while we tombstone a stale one.
        val deprovisioned = id?.let { userGroupStore.setActiveById(it, false, tokenStore, accessStore, daemonSessionStore) }
            ?: return@delete call.respondScimError(HttpStatusCode.NotFound, null, "no such user")
        log.info("SCIM: deprovisioned user principal={}", deprovisioned.principal)
        call.respond(HttpStatusCode.NoContent)
    }

    // ---- Groups ----

    get("/api/scim/v2/Groups") {
        if (!call.requireScimAuth(config)) return@get
        val groups = userGroupStore.listGroups()
        call.respond(ScimListResponse(totalResults = groups.size, resources = groups.map { it.toScim(userGroupStore.listMembers(it.id)) }))
    }
    post("/api/scim/v2/Groups") {
        if (!call.requireScimAuth(config)) return@post
        val body = call.receive<ScimGroup>()
        val externalId = body.externalId
        if (externalId.isNullOrBlank()) {
            return@post call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "externalId is required")
        }
        if (body.displayName.isBlank()) {
            return@post call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "displayName is required")
        }
        // The SYSTEM-group guard lives INSIDE upsertScimGroup, atomic with the mutation (it resolves,
        // FOR UPDATE-checks, and writes the one resolved row in a single transaction). A route-level
        // pre-check on a separate connection was defeatable by a concurrent PUT that re-pointed an
        // external_id between the check and the write — so the store throws instead.
        val group = try {
            userGroupStore.upsertScimGroup(externalId = externalId, displayName = body.displayName)
        } catch (e: SystemGroupImmutableException) {
            return@post call.respondScimError(HttpStatusCode.Conflict, "mutability", "system-managed group is immutable")
        } catch (e: SQLException) {
            if (e.isUniqueViolation()) {
                return@post call.respondScimError(HttpStatusCode.Conflict, "uniqueness", "name or externalId already in use")
            }
            throw e
        }
        body.members.forEach { m -> m.value.toLongOrNull()?.let { userGroupStore.addMember(group.id, it) } }
        log.info("SCIM: provisioned group name={} externalId={}", group.name, externalId)
        call.respond(HttpStatusCode.Created, group.toScim(userGroupStore.listMembers(group.id)))
    }
    get("/api/scim/v2/Groups/{id}") {
        if (!call.requireScimAuth(config)) return@get
        val id = call.parameters["id"]?.toLongOrNull()
        val group = id?.let { userGroupStore.getGroup(it) }
            ?: return@get call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        call.respond(group.toScim(userGroupStore.listMembers(group.id)))
    }
    put("/api/scim/v2/Groups/{id}") {
        if (!call.requireScimAuth(config)) return@put
        val id = call.parameters["id"]?.toLongOrNull()
        val existing = id?.let { userGroupStore.getGroup(it) }
            ?: return@put call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        if (userGroupStore.isSystemGroup(existing.id)) {
            return@put call.respondScimError(HttpStatusCode.Conflict, "mutability", "system-managed group is immutable")
        }
        val body = call.receive<ScimGroup>()
        val externalId = body.externalId ?: existing.externalId
        if (externalId.isNullOrBlank()) {
            return@put call.respondScimError(HttpStatusCode.BadRequest, "invalidValue", "externalId is required")
        }
        val displayName = body.displayName.ifBlank { existing.name }
        // PUT replaces the resource AT THIS id (same class of bug fixed for
        // Users' PUT): replaceScimGroupById mutates the row at [id] directly, never re-discovering a
        // different row by externalId/displayName the way upsertScimGroup (POST) does.
        val group = try {
            userGroupStore.replaceScimGroupById(id, externalId = externalId, displayName = displayName)
                ?: return@put call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        } catch (e: SQLException) {
            if (e.isUniqueViolation()) {
                return@put call.respondScimError(HttpStatusCode.Conflict, "uniqueness", "externalId already belongs to a different group")
            }
            throw e
        }
        // PUT is a full replace: reconcile membership to exactly the submitted set.
        val desired = body.members.mapNotNull { it.value.toLongOrNull() }.toSet()
        val current = userGroupStore.listMembers(group.id).map { it.userId }.toSet()
        (desired - current).forEach { userGroupStore.addMember(group.id, it) }
        (current - desired).forEach { userGroupStore.removeMember(group.id, it) }
        call.respond(group.toScim(userGroupStore.listMembers(group.id)))
    }
    patch("/api/scim/v2/Groups/{id}") {
        if (!call.requireScimAuth(config)) return@patch
        val id = call.parameters["id"]?.toLongOrNull()
        val existing = id?.let { userGroupStore.getGroup(it) }
            ?: return@patch call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        if (userGroupStore.isSystemGroup(existing.id)) {
            return@patch call.respondScimError(HttpStatusCode.Conflict, "mutability", "system-managed group is immutable")
        }
        val body = call.receive<ScimPatchOp>()
        val action = try {
            ScimPatchValidator.validate(body.operations)
        } catch (e: ScimPatchInvalidException) {
            return@patch call.respondScimError(HttpStatusCode.BadRequest, e.scimType, e.detailMessage)
        }
        when (action) {
            is ScimPatchAction.MemberOp -> {
                val userIds = action.values.mapNotNull { it.toLongOrNull() }
                if (action.op == "add") {
                    userIds.forEach { userGroupStore.addMember(existing.id, it) }
                } else {
                    userIds.forEach { userGroupStore.removeMember(existing.id, it) }
                }
                call.respond(existing.toScim(userGroupStore.listMembers(existing.id)))
            }
            is ScimPatchAction.SetActive -> {
                call.respondScimError(HttpStatusCode.BadRequest, "invalidPath", "path 'active' is only valid on Users")
            }
        }
    }
    delete("/api/scim/v2/Groups/{id}") {
        if (!call.requireScimAuth(config)) return@delete
        val id = call.parameters["id"]?.toLongOrNull()
            ?: return@delete call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        if (userGroupStore.isSystemGroup(id)) {
            return@delete call.respondScimError(HttpStatusCode.Conflict, null, "system-managed group is immutable")
        }
        if (userGroupStore.deleteGroup(id)) {
            call.respond(HttpStatusCode.NoContent)
        } else {
            call.respondScimError(HttpStatusCode.NotFound, null, "no such group")
        }
    }
}
