package net.portswigger.mcp.security

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.Serializable

@Serializable
data class ActivityEvent(
    val timestamp: String,
    val action: String,
    val outcome: String,
    val detail: String
)

/** In-memory, payload-free MCP audit log. It deliberately never stores tool arguments or HTTP content. */
object ActivityLog {
    private const val MAX_EVENTS = 100
    private val formatter = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
    private val events = ArrayDeque<ActivityEvent>()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    @Synchronized
    fun record(action: String, outcome: String, detail: String = "") {
        events.addFirst(
            ActivityEvent(
                timestamp = formatter.format(Instant.now()),
                action = action.take(80),
                outcome = outcome.take(24),
                detail = SafeContent.redactInlineSecrets(detail).take(160)
            )
        )
        while (events.size > MAX_EVENTS) events.removeLast()
        listeners.forEach { listener -> runCatching { listener() } }
    }

    @Synchronized
    fun snapshot(): List<ActivityEvent> = events.toList()

    fun addListener(listener: () -> Unit): () -> Unit {
        listeners.add(listener)
        return { listeners.remove(listener) }
    }

    @Synchronized
    fun clear() {
        events.clear()
        listeners.forEach { listener -> runCatching { listener() } }
    }
}
