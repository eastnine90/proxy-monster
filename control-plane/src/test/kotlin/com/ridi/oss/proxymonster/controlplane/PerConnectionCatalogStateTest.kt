package com.ridi.oss.proxymonster.controlplane

import com.google.protobuf.ByteString
import com.ridi.oss.proxymonster.grpc.Engine
import com.ridi.oss.proxymonster.grpc.column
import com.ridi.oss.proxymonster.grpc.schemaFragmentPush
import io.grpc.Status
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PerConnectionCatalogStateTest {
    private val ds = Datasource(
        1, "ds", Engine.MYSQL, "", 0, "app", defaultSchemas = listOf("app"),
        mysqlLowerCaseTableNames = 0, engineVersion = "8.4.0",
    )

    private fun push(
        opened: OpenConnection,
        schema: String,
        hash: String,
        generation: Long = 1,
        unchanged: Boolean = false,
        columnName: String = "id",
    ) = schemaFragmentPush {
        connectionId = opened.connectionId
        datasourceName = ds.name
        this.schema = schema
        contentHash = ByteString.copyFromUtf8(hash)
        this.unchanged = unchanged
        backendGeneration = generation
        if (!unchanged) {
            columns.add(column {
                this.schema = schema; table = "users"; column = columnName
                dataType = "bigint"; ordinal = 1; nullable = false
            })
        }
    }

    @Test
    fun `minted ids are 16 bytes and collisions retry`() {
        val values = ArrayDeque(listOf(ByteArray(16), ByteArray(16), ByteArray(16) { 1 }))
        val random = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                values.removeFirst().copyInto(bytes)
            }
        }
        val registry = ConnectionCatalogRegistry(secureRandom = random)
        val first = registry.open(Binding("ds", "a", "USER"), listOf("app"))
        val second = registry.open(Binding("ds", "b", "USER"), listOf("app"))
        assertEquals(16, first.connectionId.size())
        assertEquals(16, second.connectionId.size())
        assertNotEquals(first.connectionId, second.connectionId)
    }

    @Test
    fun `pending is the push CAS and replay cannot regress authoritative`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "p", "USER"), listOf("app"))
        assertEquals(1, (registry.applyPush(push(opened, "app", "z"), ds) as CatalogMutationResult.Applied).generation)
        val replay = registry.applyPush(push(opened, "app", "a"), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, replay.code)
        assertEquals("z", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
    }

    @Test
    fun `backend generation binds and old pushes reject`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "p", "USER"), listOf("app"))
        registry.applyPush(push(opened, "app", "h1", generation = 5), ds)
        val connection = registry.find(opened.connectionId)!!
        registry.markAfterStatement(connection, listOf("app"))
        val rejected = registry.applyPush(push(opened, "app", "h2", generation = 4), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, rejected.code)
        assertEquals("h1", connection.held.getValue("app").hash.bytes.toStringUtf8())
    }

    @Test
    fun `authoritative ordering follows accepted observation order including revert`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val one = registry.open(Binding(ds.name, "one", "USER"), listOf("app"))
        registry.applyPush(push(one, "app", "z"), ds)
        val epoch1 = registry.authoritativeFor(ds.name, "app")!!.epoch
        val two = registry.open(Binding(ds.name, "two", "USER"), listOf("app"))
        registry.applyPush(push(two, "app", "a"), ds)
        val epoch2 = registry.authoritativeFor(ds.name, "app")!!.epoch
        val three = registry.open(Binding(ds.name, "three", "USER"), listOf("app"))
        registry.applyPush(push(three, "app", "z"), ds)
        assertTrue(epoch2 > epoch1)
        assertEquals("z", registry.authoritativeFor(ds.name, "app")!!.hash.bytes.toStringUtf8())
        assertTrue(registry.authoritativeFor(ds.name, "app")!!.epoch > epoch2)
    }

    @Test
    fun `a hash marker quiets one authoritative version and retriggers on the next`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val held = registry.open(Binding(ds.name, "held", "USER"), listOf("app"))
        registry.applyPush(push(held, "app", "h1"), ds)
        val sibling = registry.open(Binding(ds.name, "sibling", "USER"), listOf("app"))
        registry.applyPush(push(sibling, "app", "h2"), ds)

        val connection = registry.find(held.connectionId)!!
        assertEquals(setOf("app"), registry.freshnessGate(connection, listOf("app")))
        registry.markBeforeDecide(connection, listOf("app"))
        registry.applyPush(push(held, "app", "h1", unchanged = true), ds)
        assertTrue(registry.freshnessGate(connection, listOf("app")).isEmpty())

        val third = registry.open(Binding(ds.name, "third", "USER"), listOf("app"))
        registry.applyPush(push(third, "app", "h3"), ds)
        assertEquals(setOf("app"), registry.freshnessGate(connection, listOf("app")))
    }

    @Test
    fun `unchanged adoption shares pooled fragment and refreshes staleness clock`() = runBlocking {
        var now = 0L
        val registry = ConnectionCatalogRegistry(clockNanos = { now }, stalenessNanos = 10)
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1"), ds)
        val key = registry.find(first.connectionId)!!.held.getValue("app").pooledRef
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"))
        now = 20
        registry.applyPush(push(second, "app", "h1", unchanged = true), ds)
        assertEquals(3, registry.pooledFor(key)!!.refCount) // authoritative + two connections
        assertTrue(registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")).isEmpty())
        now = 31
        assertEquals(setOf("app"), registry.freshnessGate(registry.find(second.connectionId)!!, listOf("app")))
    }

    @Test
    fun `unchanged on-open cannot no-op an unconditional first fetch`() = runBlocking {
        // A fresh connection whose schema has no authoritative hash yet is issued an UNCONDITIONAL refetch
        // (pending.expectedHash == null). A proxy that replies unchanged=true has nothing to adopt — this
        // must fail closed, never silently establish a held reference with no structure behind it.
        val registry = ConnectionCatalogRegistry()
        val opened = registry.open(Binding(ds.name, "fresh", "USER"), listOf("app"))
        val rejected = registry.applyPush(push(opened, "app", "h1", unchanged = true), ds) as CatalogMutationResult.Rejected
        assertEquals(Status.Code.FAILED_PRECONDITION, rejected.code)
        val connection = registry.find(opened.connectionId)!!
        assertTrue(connection.held["app"] == null)
        assertTrue(connection.pending.containsKey("app")) // still pending: the fetch was not satisfied
    }

    @Test
    fun `system schema fragments dedup across datasources on the same engine version`() = runBlocking {
        // Two distinct datasources on the SAME engine version share one pooled fragment for a system schema
        // (PoolKey scope "engine:<version>"), so the shared catalog build is stored once. A ds-scoped schema
        // would never collide like this.
        val registry = ConnectionCatalogRegistry()
        val dsA = ds.copy(id = 1, name = "dsA")
        val dsB = ds.copy(id = 2, name = "dsB")
        val a = registry.openPushSystem(dsA, "information_schema", "sys-h1")
        registry.openPushSystem(dsB, "information_schema", "sys-h1")
        val key = registry.find(a.connectionId)!!.held.getValue("information_schema").pooledRef
        assertEquals(1, registry.poolSize())
        // dsA held + dsA authoritative + dsB held + dsB authoritative all reference the one pooled fragment.
        assertEquals(4, registry.pooledFor(key)!!.refCount)
    }

    /** Open a connection on [ds] scoped to one system [schema] and push a single-column fragment for it. */
    private suspend fun ConnectionCatalogRegistry.openPushSystem(ds: Datasource, schema: String, hash: String): OpenConnection {
        val opened = open(Binding(ds.name, "p", "USER"), listOf(schema))
        val result = applyPush(
            schemaFragmentPush {
                connectionId = opened.connectionId
                datasourceName = ds.name
                this.schema = schema
                contentHash = ByteString.copyFromUtf8(hash)
                backendGeneration = 1
                columns.add(column {
                    this.schema = schema; table = "t"; column = "c"
                    dataType = "bigint"; ordinal = 1; nullable = false
                })
            },
            ds,
        )
        check(result is CatalogMutationResult.Applied) { "openPushSystem rejected: $result" }
        return opened
    }

    @Test
    fun `same hash with different columns rejects and close is idempotently fail-closed`() = runBlocking {
        val registry = ConnectionCatalogRegistry()
        val first = registry.open(Binding(ds.name, "first", "USER"), listOf("app"))
        registry.applyPush(push(first, "app", "h1", columnName = "id"), ds)
        val second = registry.open(Binding(ds.name, "second", "USER"), listOf("app"))
        val alias = registry.applyPush(push(second, "app", "h1", columnName = "email"), ds)
        assertTrue(alias is CatalogMutationResult.Rejected)
        assertTrue(registry.close(first.connectionId, ds.name) is CatalogMutationResult.Applied)
        assertEquals(Status.Code.NOT_FOUND, (registry.close(first.connectionId, ds.name) as CatalogMutationResult.Rejected).code)
        assertNotNull(registry.authoritativeFor(ds.name, "app"))
        Unit
    }
}
