package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.controlplane.authz.AuthzAction
import com.ridi.oss.proxymonster.controlplane.authz.AuthzContext
import com.ridi.oss.proxymonster.controlplane.authz.AuthzDecision
import com.ridi.oss.proxymonster.controlplane.authz.AuthzResource
import com.ridi.oss.proxymonster.controlplane.authz.CedarPolicyInput
import com.ridi.oss.proxymonster.controlplane.support.EnforcementFixture
import com.ridi.oss.proxymonster.grpc.EnfAction
import com.ridi.oss.proxymonster.controlplane.support.requireDockerOrSkip
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** MySQL-leading proof that saved workflow results hold R's execution-enforced output and task.assume exposes R's live view. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApprovalResultAssumeMysqlDbTest {
    private lateinit var fx: EnforcementFixture
    private lateinit var datasource: Datasource
    private var roleId = 0L

    private val requester = "requester@example.com"
    private val approver = "approver@example.com"
    private val roleName = "system:production-pii-accessor"
    private val rawRrn = "900101-1234567"
    private val maskedRrn = "**********4567"

    @BeforeAll
    fun setup() {
        requireDockerOrSkip()
        fx = EnforcementFixture.mysql()
        roleId = fx.policyStore.listRoles().first { it.name == roleName }.id
        fx.dataSource.connection.use { c ->
            c.prepareStatement("UPDATE datasource SET tags = ?::jsonb WHERE id = ?").use { ps ->
                ps.setString(1, "[\"system:production\"]")
                ps.setLong(2, fx.datasource.id)
                ps.executeUpdate()
            }
        }
        listOf(-250L, -251L, -256L, -257L, -258L).forEach {
            checkNotNull(fx.cedarPolicyStore.setEnabled(it, true, "test-enable-production"))
        }
        fx.cedarPolicyStore.create(
            CedarPolicyInput(
                name = "trusted-network-test",
                cedarSrc = """permit(principal, action == Action::"context.tag::trusted-network", resource) when { context has requester_ip && context.requester_ip.isInRange(ip("100.100.0.0/16")) };""",
            ),
            updatedBy = "test-fixture",
        )
        datasource = checkNotNull(fx.datasourceStore.get(fx.datasource.id))
        assertTrue(fx.roleResolver.resolve(requester).isEmpty(), "the requester has no ambient PII role")
    }

    private fun decide(channel: Channel, ip: String): DecisionContext = decideQuery(
        principal = requester,
        ds = datasource,
        sql = "SELECT rrn FROM users",
        channel = channel,
        catalog = fx.datasourceStore.catalog(datasource.id),
        policyStore = fx.policyStore,
        accessStore = fx.accessStore,
        userGroupStore = fx.userGroupStore,
        roleResolver = fx.roleResolver,
        authz = fx.authz,
        providedRoles = setOf(roleName),
        context = AuthzContext(requesterIp = ip),
    )

    private fun request() = AccessRequest(
        id = 1,
        principal = requester,
        roleId = roleId,
        roleName = roleName,
        datasourceId = datasource.id,
        datasourceName = datasource.name,
        requestedDurationSec = 3600,
        status = "EXECUTED",
        decidedBy = approver,
        executedBy = approver,
        createdAt = "2026-07-23T00:00:00Z",
        kind = "QUERY",
        sql = "SELECT rrn FROM users",
        executeAs = listOf(roleName),
        creatorKind = "WORKFLOW",
    )

    @Test
    fun `requester assumes R and sees the shipped production view for their live network`() {
        assertEquals(
            AuthzDecision.Allow,
            fx.authz.authorize(
                requester,
                AuthzAction.TASK_ASSUME,
                AuthzResource.ApprovalRequest(
                    requester = requester,
                    approver = approver,
                    executedBy = approver,
                    datasourceName = datasource.name,
                    roleName = roleName,
                ),
            ),
        )
        val decrypted = DecryptedResult(listOf("rrn"), listOf(listOf(rawRrn)))

        val trusted = decideResultView(
            viewer = requester,
            req = request(),
            childSql = request().sql,
            ds = datasource,
            decrypted = decrypted,
            callerContext = AuthzContext(requesterIp = "100.100.1.10"),
            datasourceStore = fx.datasourceStore,
            policyStore = fx.policyStore,
            accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore,
            roleResolver = fx.roleResolver,
            authz = fx.authz,
            systemClassification = null,
        )
        assertEquals(rawRrn, assertIs<ResultViewDecision.Allowed>(trusted).rows.single().single())

        val outside = decideResultView(
            viewer = requester,
            req = request(),
            childSql = request().sql,
            ds = datasource,
            decrypted = decrypted,
            callerContext = AuthzContext(requesterIp = "100.99.1.10"),
            datasourceStore = fx.datasourceStore,
            policyStore = fx.policyStore,
            accessStore = fx.accessStore,
            userGroupStore = fx.userGroupStore,
            roleResolver = fx.roleResolver,
            authz = fx.authz,
            systemClassification = null,
        )
        assertEquals(maskedRrn, assertIs<ResultViewDecision.Allowed>(outside).rows.single().single())
    }

    @Test
    fun `workflow executor stores R's execution-enforced masks and the viewer re-decides per context`() {
        // Off the trusted network R (a production PII accessor) cannot unmask rrn, so the stored result is
        // R's execution-enforced masked form — storage is never widened to what some other context reveals.
        val storedOffNetwork = decide(Channel.WORKFLOW_EXECUTOR, "100.99.1.10")
        assertEquals(EnfAction.MASK, storedOffNetwork.action, "off-network execution masks rrn")
        assertEquals(
            listOf("rrn"), storedOffNetwork.masks.map { it.column },
            "storage holds R's execution-context mask plan, never widened",
        )

        // Executing ON the trusted network unmasks rrn, so R stores it cleartext.
        assertEquals(
            EnfAction.ALLOW, decide(Channel.WORKFLOW_EXECUTOR, "100.100.1.10").action,
            "on the trusted network R stores rrn cleartext",
        )

        // The viewer re-decides under exactly {R} in the viewer's own context: masked off-network, unmasked on it.
        val viewedOffNetwork = decide(Channel.WORKFLOW_VIEWER, "100.99.1.10")
        assertEquals(EnfAction.MASK, viewedOffNetwork.action)
        assertEquals("rrn", viewedOffNetwork.masks.single().column)
        assertEquals(EnfAction.ALLOW, decide(Channel.WORKFLOW_VIEWER, "100.100.1.10").action)
    }
}
