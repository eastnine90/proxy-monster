package com.ridi.oss.proxymonster.controlplane

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** A terminal transition of one task, pushed to the parties watching it so their web tab updates without
 *  waiting for the next poll. [status] is the task's new state (EXECUTED / FAILED / CANCELLED). */
@Serializable
data class TaskEvent(val taskId: Long, val status: String)

/**
 * In-process per-principal fan-out of task terminal transitions, so a watching web tab is pushed the state
 * change instead of discovering it on its next poll. Single-replica by design: the run coroutine that
 * terminalizes a task and the SSE stream that serves the principal live in the same process, so a plain
 * in-memory map suffices. A multi-replica LISTEN/NOTIFY fan-out is a separate follow-up (docs/backlog.md).
 *
 * The push is a pure accelerator: the web still polls the task to a terminal state, so a dropped or missed
 * event only delays the update to the next poll — it is never the source of truth. Accordingly [publish] is
 * non-blocking (a full subscriber buffer drops the oldest event rather than suspending the run coroutine),
 * and delivery is best-effort.
 */
class TaskCompletionHub {
    private val log = LoggerFactory.getLogger(TaskCompletionHub::class.java)

    // principal -> its open SSE subscriber channels (one per browser tab/connection). CopyOnWriteArrayList so
    // publish iterates without locking against concurrent subscribe/unsubscribe.
    private val subscribers = ConcurrentHashMap<String, CopyOnWriteArrayList<Channel<TaskEvent>>>()

    /** Open a subscription for [principal]; the caller must [unsubscribe] it (a `finally`) when the stream ends. */
    fun subscribe(principal: String): ReceiveChannel<TaskEvent> {
        // Bounded + DROP_OLDEST: a slow/stuck client can never make publish() suspend or grow memory unbounded;
        // it just loses the oldest pushes and catches up on its next poll.
        val channel = Channel<TaskEvent>(capacity = 64, onBufferOverflow = BufferOverflow.DROP_OLDEST)
        subscribers.compute(principal) { _, list -> (list ?: CopyOnWriteArrayList()).apply { add(channel) } }
        return channel
    }

    fun unsubscribe(principal: String, channel: ReceiveChannel<TaskEvent>) {
        subscribers.computeIfPresent(principal) { _, list ->
            list.remove(channel)
            list.ifEmpty { null }
        }
        (channel as? Channel<TaskEvent>)?.close()
    }

    /** Best-effort push of [event] to every open stream of [principal]. Never blocks the caller. */
    fun publish(principal: String, event: TaskEvent) {
        val channels = subscribers[principal] ?: return
        for (channel in channels) channel.trySend(event)
    }

    /** Push [event] to a set of parties (e.g. a workflow task's requester + approver), de-duplicated. */
    fun publish(principals: Collection<String>, event: TaskEvent) {
        for (principal in principals.toSet()) publish(principal, event)
    }
}
