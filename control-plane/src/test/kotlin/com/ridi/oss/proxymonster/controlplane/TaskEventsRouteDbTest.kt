package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.SharedPostgres
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import javax.sql.DataSource
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Direct tests of the two authorization/session gates the task-event SSE stream enforces so the push cannot
 * outlive the poll's guarantees ([taskReadableForPush] = the live `task.read` filter, [sessionStillLive] =
 * the web-session re-validation). The route's SSE transport itself is exercised by inspection — the Ktor
 * client SSE plugin is not on the classpath — so these cover the logic that filters/terminates the stream.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TaskEventsRouteDbTest {
    private lateinit var dataSource: DataSource
    private lateinit var core: ControlPlaneCore
    private lateinit var datasource: Datasource
    private lateinit var sessionStore: PrincipalSessionStore
    private lateinit var prod: Config
    private lateinit var debug: Config
    private val caller = "alice@example.com"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        dataSource = SharedPostgres.hikari(SharedPostgres.freshDatabase("pm_task_events"))
        Flyway.configure().dataSource(dataSource).load().migrate()
        core = ControlPlaneCore(dataSource)
        sessionStore = PrincipalSessionStore(dataSource, null)
        datasource = core.datasourceStore.create(
            DatasourceInput(name = "task-events-ds", engine = "postgres", host = "h", port = 5432, dbName = "d"),
        )
        core.userGroupStore.createUser(AppUserInput(principal = caller), core.tokenStore, core.accessStore, sessionStore)
        val roleId = core.policyStore.createRole(RoleInput("editor-analyst")).id
        core.policyStore.createAssignment(RoleAssignmentInput(caller, roleId))
        prod = Config(
            httpPort = 0, dbUrl = "", dbUser = "", dbPassword = "", authDebug = false, secretToken = null,
            sessionSecret = "task-events-test", oidc = null, resultKey = null, scimToken = null,
            sessionWindowSeconds = 3600, idpRecheckIntervalSeconds = 600, devMarker = true,
        )
        debug = prod.copy(authDebug = true)
    }

    private fun newTask(): Long =
        core.accessStore.createEditorTask(caller, datasource.id, "select 1", listOf("editor-analyst"), caller).id

    private fun readable(taskId: Long, config: Config = prod) =
        taskReadableForPush(config, caller, taskId, AuthzContext(), core.accessStore, core.authz, core.datasourceStore)

    @Test
    fun `the push task_read filter mirrors the poll - owner allowed, a forbid suppresses, absent denied`() {
        val task = newTask()
        // Baseline: the owner's self-read permit lets the push through, exactly like the poll.
        assertTrue(readable(task), "owner may task.read its own task → push allowed")

        val forbidId = core.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "sse-push-task-read-forbid",
                cedarSrc = """forbid(principal, action == Action::"task.read", resource) when { principal == User::"$caller" };""",
            ),
            updatedBy = "test-fixture",
        ).id
        try {
            assertFalse(readable(task), "a task.read forbid must suppress the push, matching the poll's 404")
        } finally {
            core.cedarPolicyStore.delete(forbidId)
        }
        assertTrue(readable(task), "with the forbid gone the push is allowed again")

        // An absent task is never pushable (no oracle), and authDebug bypasses the gate (dev parity with routes).
        assertFalse(readable(-999_999L), "a missing task is not readable")
        assertTrue(readable(-999_999L, debug), "authDebug bypasses the gate")
    }

    @Test
    fun `session liveness tracks minting and revocation`() {
        val sessionId = sessionStore.mintWeb(caller, null, 7200, 900, "device-1")
        assertTrue(sessionStillLive(prod, sessionId, "device-1", sessionStore), "a freshly minted session is live")

        assertTrue(sessionStore.endWeb(sessionId, "test-logout"))
        assertFalse(sessionStillLive(prod, sessionId, "device-1", sessionStore), "a revoked session is not live → stream ends")

        // authDebug has no session and is always live; a null session id is never live.
        assertTrue(sessionStillLive(debug, null, null, sessionStore))
        assertFalse(sessionStillLive(prod, null, "device-1", sessionStore))
    }
}
