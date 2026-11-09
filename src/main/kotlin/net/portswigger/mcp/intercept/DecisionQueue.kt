package net.portswigger.mcp.intercept

import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import net.portswigger.mcp.security.ActivityLog

/** No lock is held while a Proxy callback waits, or while a human reviews a decision. */
class DecisionQueue<T : Any>(private val capacity: Int = 8) {
    data class Ticket<T>(val id: String, val kind: String, val original: T, val deadline: Long,
        var proposed: T? = null, var revision: Int = 0, var approvedRevision: Int? = null, var disclosedRevision: Int? = null,
        var disclosureRequestedRevision: Int? = null, var disclosureStatus: String = "NOT_REQUESTED",
        var approvedBy: String? = null, val result: CompletableFuture<T?> = CompletableFuture())
    data class DisclosureRequest(val status: String, val shouldPrompt: Boolean)
    private val pending = linkedMapOf<String, Ticket<T>>()
    private val completed = linkedMapOf<String, String>()

    @Synchronized fun offer(kind: String, value: T, timeoutMillis: Long): Ticket<T>? {
        require(timeoutMillis in 1..120_000)
        if (pending.size >= capacity) return null
        val ticket = Ticket(UUID.randomUUID().toString(), kind, value, System.nanoTime() + timeoutMillis * 1_000_000)
        pending[ticket.id] = ticket
        ActivityLog.record("intercept_capture", "pending", "${ticket.kind} ${ticket.id}")
        return ticket
    }

    fun await(ticket: Ticket<T>): T? {
        try {
            return ticket.result.get((ticket.deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS)
        } catch (_: TimeoutException) {
            synchronized(this) { if (pending.containsKey(ticket.id)) finish(ticket, "EXPIRED", null) }
        } catch (_: InterruptedException) {
            synchronized(this) { if (pending.containsKey(ticket.id)) finish(ticket, "CANCELLED", null) }
            Thread.currentThread().interrupt()
        }
        // A decision may have won the race with the timed get. Never substitute an original message.
        return ticket.result.getNow(null)
    }

    @Synchronized fun get(id: String): Ticket<T> {
        val ticket = pending[id] ?: error("Message is ${completed[id] ?: "unknown"}; it cannot be processed again")
        if (System.nanoTime() >= ticket.deadline) {
            finish(ticket, "EXPIRED", null)
            error("Message $id has expired")
        }
        return ticket.copy()
    }
    @Synchronized fun list(kind: String): List<Ticket<T>> {
        expire()
        return pending.values.filter { it.kind == kind }.map { it.copy() }
    }
    @Synchronized fun propose(id: String, revision: Int, value: T): Int {
        get(id)
        val ticket = pending.getValue(id)
        check(ticket.revision == revision) { "Revision changed; retrieve the message again" }
        ticket.proposed = value
        ticket.revision++
        ticket.approvedRevision = null
        ticket.approvedBy = null
        ticket.disclosedRevision = null
        ticket.disclosureRequestedRevision = null
        ticket.disclosureStatus = "NOT_REQUESTED"
        ActivityLog.record("intercept_propose", "proposed", "$id revision=${ticket.revision}")
        return ticket.revision
    }
    @Synchronized fun approve(id: String, revision: Int, approvedBy: String = "HUMAN") {
        get(id)
        val ticket = pending.getValue(id)
        check(ticket.revision == revision) { "Revision changed during human review" }
        ticket.approvedRevision = revision
        ticket.approvedBy = approvedBy
        ActivityLog.record("intercept_approve", if (approvedBy == "HUMAN") "approved" else "auto_approved", "$id revision=$revision source=$approvedBy")
    }

    @Synchronized fun revokeApprovals(approvedBy: String): Int {
        var revoked = 0
        pending.values.forEach { ticket ->
            if (ticket.approvedBy == approvedBy) {
                ticket.approvedRevision = null
                ticket.approvedBy = null
                revoked++
                ActivityLog.record("intercept_approve", "revoked", "${ticket.kind} ${ticket.id} revision=${ticket.revision}; source=$approvedBy")
            }
        }
        return revoked
    }
    @Synchronized fun disclose(id: String, revision: Int) {
        get(id)
        val ticket=pending.getValue(id)
        check(ticket.revision==revision) { "Revision changed during disclosure review" }
        ticket.disclosedRevision=revision
        ticket.disclosureRequestedRevision=revision
        ticket.disclosureStatus="APPROVED"
        ActivityLog.record("intercept_disclosure", "approved", "$id revision=$revision")
    }

    /** Marks one exact revision for local disclosure review without blocking the MCP caller. */
    @Synchronized fun beginDisclosureRequest(id: String, revision: Int): DisclosureRequest {
        get(id)
        val ticket = pending.getValue(id)
        check(ticket.revision == revision) { "Revision changed; retrieve the message again" }
        if (ticket.disclosedRevision == revision) return DisclosureRequest("APPROVED", false)
        if (ticket.disclosureRequestedRevision == revision && ticket.disclosureStatus == "PENDING") {
            return DisclosureRequest("PENDING", false)
        }
        ticket.disclosureRequestedRevision = revision
        ticket.disclosureStatus = "PENDING"
        ActivityLog.record("intercept_disclosure", "requested", "$id revision=$revision")
        return DisclosureRequest("PENDING", true)
    }

    /** Completes local disclosure review while keeping the request ID stable in the pending queue. */
    @Synchronized fun completeDisclosureRequest(id: String, revision: Int, status: String): Boolean {
        val ticket = pending[id] ?: return false
        if (ticket.revision != revision || ticket.disclosureRequestedRevision != revision) return false
        require(status in setOf("APPROVED", "DENIED", "BUSY", "CANCELLED", "ERROR", "EXPIRED"))
        ticket.disclosureStatus = status
        if (status == "APPROVED") ticket.disclosedRevision = revision
        ActivityLog.record("intercept_disclosure", status.lowercase(), "$id revision=$revision")
        return true
    }
    @Synchronized fun forward(id: String, revision: Int) {
        get(id)
        val ticket = pending.getValue(id)
        check(ticket.revision == revision && ticket.approvedRevision == revision) { "This exact revision needs human approval" }
        finish(ticket, "FORWARDED", ticket.proposed ?: ticket.original)
    }
    @Synchronized fun drop(id: String) {
        get(id)
        finish(pending.getValue(id), "DROPPED", null)
    }
    @Synchronized fun cancelAll(reason: String = "CANCELLED") {
        pending.values.toList().forEach { finish(it, reason, null) }
    }
    @Synchronized fun expire() {
        pending.values.filter { System.nanoTime() >= it.deadline }.toList().forEach { finish(it, "EXPIRED", null) }
    }
    private fun finish(ticket: Ticket<T>, status: String, value: T?) {
        pending.remove(ticket.id)
        completed[ticket.id] = status
        while (completed.size > 128) completed.remove(completed.keys.first())
        val action = when (status) {
            "FORWARDED" -> "intercept_forward"
            "DROPPED" -> "intercept_drop"
            "EXPIRED" -> "intercept_expiration"
            else -> "intercept_cancellation"
        }
        ActivityLog.record(action, status.lowercase(), "${ticket.kind} ${ticket.id} revision=${ticket.revision}")
        ticket.result.complete(value)
    }
}
