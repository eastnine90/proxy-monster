package com.ridi.oss.proxymonster.controlplane

import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TaskCompletionHubTest {
    @Test
    fun `a subscriber receives an event published to its principal`() = runBlocking {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        hub.publish("alice", TaskEvent(7, "EXECUTED"))
        val got = withTimeout(1000) { events.receive() }
        assertEquals(TaskEvent(7, "EXECUTED"), got)
    }

    @Test
    fun `publish to a principal with no subscribers is a no-op`() {
        val hub = TaskCompletionHub()
        // Must not throw even though nobody is listening.
        hub.publish("nobody", TaskEvent(1, "FAILED"))
    }

    @Test
    fun `an event reaches every open stream of the same principal`() = runBlocking {
        val hub = TaskCompletionHub()
        val tabA = hub.subscribe("alice")
        val tabB = hub.subscribe("alice")
        hub.publish("alice", TaskEvent(9, "CANCELLED"))
        assertEquals(TaskEvent(9, "CANCELLED"), withTimeout(1000) { tabA.receive() })
        assertEquals(TaskEvent(9, "CANCELLED"), withTimeout(1000) { tabB.receive() })
    }

    @Test
    fun `a principal only receives its own events`() = runBlocking {
        val hub = TaskCompletionHub()
        val alice = hub.subscribe("alice")
        val bob = hub.subscribe("bob")
        hub.publish("alice", TaskEvent(3, "EXECUTED"))
        assertEquals(TaskEvent(3, "EXECUTED"), withTimeout(1000) { alice.receive() })
        // Bob's channel stays empty — no cross-principal leak.
        assertNull(bob.tryReceive().getOrNull())
    }

    @Test
    fun `publish to a party set delivers once per principal even when a principal repeats`() = runBlocking {
        val hub = TaskCompletionHub()
        val requester = hub.subscribe("carol")
        // carol is both requester and approver of a self-approved task: she must get exactly one event.
        hub.publish(listOf("carol", "carol"), TaskEvent(5, "EXECUTED"))
        assertEquals(TaskEvent(5, "EXECUTED"), withTimeout(1000) { requester.receive() })
        assertNull(requester.tryReceive().getOrNull())
    }

    @Test
    fun `unsubscribe removes and closes the channel`() = runBlocking<Unit> {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        hub.unsubscribe("alice", events)
        // The closed channel yields no more events; a publish after unsubscribe reaches nobody.
        hub.publish("alice", TaskEvent(2, "EXECUTED"))
        assertFailsWith<ClosedReceiveChannelException> { events.receive() }
    }

    @Test
    fun `a full subscriber buffer drops oldest and never blocks the publisher, keeping the newest event`() = runBlocking {
        val hub = TaskCompletionHub()
        val events = hub.subscribe("alice")
        // Far more than the 64-slot buffer, with nobody draining: every publish must return without suspending
        // (DROP_OLDEST), so the run coroutine is never blocked by a stuck client.
        withTimeout(1000) {
            for (i in 1..500) hub.publish("alice", TaskEvent(i.toLong(), "EXECUTED"))
        }
        val drained = buildList { while (true) { add(events.tryReceive().getOrNull() ?: break) } }
        assertTrue(drained.size <= 64, "buffer must stay bounded, got ${drained.size}")
        assertTrue(drained.isNotEmpty())
        // The most recent event is always retained; the oldest are the ones dropped.
        assertEquals(500L, drained.last().taskId)
    }
}
