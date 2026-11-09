package net.portswigger.mcp.intercept

import kotlinx.serialization.Serializable
import java.net.URI
import java.util.UUID
import java.util.concurrent.TimeUnit

@Serializable
data class TargetRuleGrant(val id: String, val urls: List<String>, val remainingMillis: Long)

/** In-memory preparation grants plus explicit session/rule bindings. A grant alone authorizes no traffic or disclosure. */
internal class TargetRuleAuthorization(
    private val eligible: (String) -> Boolean,
    private val nanoTime: () -> Long = System::nanoTime,
    private val policyRevision: () -> Long = { 0L }
) {
    private data class Grant(val id: String, val urls: List<String>, val deadline: Long, val policyRevision: Long)
    private val grants = linkedMapOf<String, Grant>()
    private var generation = 0L
    private data class Binding(val sessionId: String, val rules: Map<String, InterceptionRuleSpec>)
    private val bindings = linkedMapOf<String, Binding>()

    @Synchronized fun approvalEpoch(): Long = generation

    @Synchronized fun bind(grantId: String, sessionId: String, rules: Map<String, InterceptionRuleSpec>, epoch: Long) {
        expire()
        check(epoch == generation && sessionId.isNotBlank() && rules.isNotEmpty()) { "Stale target session approval" }
        check(grantId !in bindings) { "Grant already bound to a session" }
        check(rules.values.all { it.authorizationReference == grantId && permits(it) && it.action != RuleAction.DROP }) { "Unapproved target or operation" }
        bindings[grantId] = Binding(sessionId, rules.toMap())
    }

    @Synchronized fun permitsExecution(ruleId: String, spec: InterceptionRuleSpec, sessionId: String?): Boolean {
        if (!permits(spec)) return false
        val binding = bindings[spec.authorizationReference] ?: return false
        return binding.sessionId == sessionId && binding.rules[ruleId] == spec && spec.action != RuleAction.DROP
    }

    @Synchronized fun remainingMillis(grantId: String): Long {
        expire()
        return grants[grantId]?.let { TimeUnit.NANOSECONDS.toMillis(it.deadline - nanoTime()).coerceAtLeast(0) } ?: 0
    }

    @Synchronized fun <T> commit(ruleSpecs: Map<String, InterceptionRuleSpec>, sessionId: String?, action: () -> T): T {
        val policy = policyRevision()
        check(ruleSpecs.isNotEmpty() && ruleSpecs.all { (id, spec) -> permitsExecution(id, spec, sessionId) } && policy == policyRevision()) { "Target permission expired or revoked" }
        return action()
    }

    companion object {
        fun validateUrls(urls: List<String>) {
            require(urls.size in 1..16 && urls.toSet().size == urls.size) { "Supply 1..16 unique exact paths" }
            val parsed = urls.map { url ->
                require(url.length <= 2048 && url.all { it.code in 33..126 }) { "Invalid target URL" }
                val u = URI(url)
                require(u.scheme in setOf("http", "https") && u.host != null &&
                    u.host.matches(Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*")) &&
                    u.host.length <= 253 && u.port in 1..65535 && u.rawUserInfo == null &&
                    u.rawQuery == null && u.rawFragment == null) { "Use an exact lowercase HTTP(S) host and explicit port without credentials, query or fragment" }
                require(u.rawPath.startsWith("/") && u.rawPath != "/" &&
                    u.rawPath.matches(Regex("/[A-Za-z0-9_./~-]+")) &&
                    !u.rawPath.contains("//") && u.rawPath.split('/').none { it == "." || it == ".." }) {
                    "Use a non-root exact path without wildcards, encoding or traversal"
                }
                require(url == "${u.scheme}://${u.host}:${u.port}${u.rawPath}") { "Target must be canonical" }
                u
            }
            require(parsed.map { "${it.scheme}://${it.host}:${it.port}" }.toSet().size == 1) { "One exact destination per approval" }
        }
    }

    /** Recheck policy on both sides of human approval; do not hold a monitor while prompting. */
    suspend fun request(urls: List<String>, seconds: Int, approve: suspend (String) -> Boolean): TargetRuleGrant {
        val targets = urls.toList()
        validateUrls(targets)
        require(seconds in 1..300) { "Authorization duration must be 1..300 seconds" }
        val policy = policyRevision()
        val epoch = synchronized(this) {
            expire()
            check(grants.size < 16) { "Authorization limit reached" }
            check(targets.all(eligible)) { "Every path must already be in Burp scope and the exact host:port allowlist" }
            generation
        }
        check(approve("Prepare disabled interception rules only.\nExact paths:\n${targets.joinToString("\n")}\nDuration: ${seconds}s; no automatic renewal. Capture, disclosure and execution remain disabled.")) { "Target authorization denied or expired" }
        return synchronized(this) {
            check(epoch == generation && policy == policyRevision()) { "Authorization invalidated during approval" }
            check(grants.size < 16 && targets.all(eligible)) { "Target policy changed during approval" }
            val id = UUID.randomUUID().toString()
            grants[id] = Grant(id, targets, nanoTime() + TimeUnit.SECONDS.toNanos(seconds.toLong()), policy)
            TargetRuleGrant(id, targets.toList(), seconds * 1000L)
        }
    }

    @Synchronized fun permits(spec: InterceptionRuleSpec): Boolean {
        expire()
        val grant = grants[spec.authorizationReference] ?: return false
        return spec.targetUrl in grant.urls && eligible(spec.targetUrl)
    }

    @Synchronized fun list(): List<TargetRuleGrant> {
        expire()
        return grants.values.map { TargetRuleGrant(it.id, it.urls.toList(), TimeUnit.NANOSECONDS.toMillis(it.deadline - nanoTime()).coerceAtLeast(0)) }
    }

    @Synchronized fun revokeAll() { generation++; grants.clear(); bindings.clear() }

    private fun expire() {
        grants.values.removeIf { nanoTime() >= it.deadline || it.policyRevision != policyRevision() || !it.urls.all(eligible) }
        bindings.keys.retainAll(grants.keys)
    }
}
