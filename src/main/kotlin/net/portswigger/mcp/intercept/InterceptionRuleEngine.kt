package net.portswigger.mcp.intercept

import kotlinx.serialization.Serializable
import net.portswigger.mcp.config.LocalTestTargets
import java.net.URI
import java.util.ArrayDeque
import java.util.Collections
import java.util.LinkedHashMap
import java.util.UUID
import java.util.concurrent.TimeUnit

@Serializable enum class RuleDirection { REQUEST, RESPONSE, BOTH }
@Serializable enum class RuleAction { MODIFY_AND_FORWARD, FORWARD_UNCHANGED, DROP }
@Serializable enum class RuleTransformType {
    SET_JSON_FIELD, REMOVE_JSON_FIELD, SET_QUERY_PARAMETER, REMOVE_QUERY_PARAMETER,
    SET_FORM_FIELD, REMOVE_FORM_FIELD, SET_REQUEST_HEADER, REMOVE_REQUEST_HEADER,
    SET_RESPONSE_HEADER, REMOVE_RESPONSE_HEADER, REPLACE_EXACT_TEXT
}
@Serializable enum class InterceptionRuleState { DISABLED, ACTIVE, PAUSED, EXPIRED, MAX_MATCHES, MAX_MODIFICATIONS, AUTHORIZATION_ENDED, EMERGENCY_STOPPED }

@Serializable
data class RuleMatchConditions(
    val method: String? = null,
    val path: String? = null,
    val pathPrefix: String? = null,
    val queryParameterName: String? = null,
    val queryParameterValue: String? = null,
    val headerName: String? = null,
    val headerValue: String? = null,
    val contentType: String? = null,
    val jsonPath: String? = null,
    val jsonValueJson: String? = null,
    val formFieldName: String? = null,
    val formFieldValue: String? = null,
    val responseStatus: Int? = null
)

/** Transformation values are literal data: scripts, regexes and expressions are never evaluated. */
@Serializable
data class RuleTransformation(
    val type: RuleTransformType,
    val name: String? = null,
    val path: String? = null,
    val value: String? = null,
    val valueJson: String? = null,
    val search: String? = null,
    val replacement: String? = null
)

@Serializable
data class InterceptionRuleSpec(
    val name: String,
    /** Exact test URL, or the fixed local authority when conditions constrain it to approved test paths. */
    val targetUrl: String,
    val authorizationReference: String,
    val direction: RuleDirection,
    val conditions: RuleMatchConditions = RuleMatchConditions(),
    val transformations: List<RuleTransformation> = emptyList(),
    val action: RuleAction = RuleAction.MODIFY_AND_FORWARD,
    /** Higher values run first. */
    val priority: Int = 100,
    val maximumMatches: Int = 32,
    /** Maximum actual message changes, reserved atomically across concurrent evaluations. */
    val maximumModifications: Int = 32,
    val durationSeconds: Int = 120
)

@Serializable
data class InterceptionRuleStats(
    val ruleId: String,
    val name: String,
    val targetUrl: String,
    val direction: RuleDirection,
    val state: InterceptionRuleState,
    val matchedRequests: Long,
    val matchedResponses: Long,
    val modified: Long,
    val forwarded: Long,
    val dropped: Long,
    val skipped: Long,
    val failed: Long,
    val remainingMatches: Int,
    val remainingModifications: Int,
    val expiresAtEpochMillis: Long?,
    val lastExecutionEpochMillis: Long?,
    val lastErrorCode: String?
)

@Serializable
data class InterceptionRuleView(
    val id: String,
    val spec: InterceptionRuleSpec,
    val state: InterceptionRuleState,
    val expiresAtEpochMillis: Long?,
    val remainingMillis: Long,
    val stats: InterceptionRuleStats
)

@Serializable
data class InterceptionRuleEvent(
    val timestampEpochMillis: Long,
    val ruleId: String,
    val messageId: String?,
    val direction: String,
    val outcome: String,
    val approvalMode: String,
    val code: String?
)

@Serializable
data class InterceptionRuleEngineStatus(
    val enabledRules: Int,
    val configuredRules: Int,
    val emergencyStopped: Boolean,
    val maximumRules: Int,
    val maximumMatchesPerRule: Int,
    val maximumModificationsPerRule: Int,
    val maximumRuleTtlSeconds: Int,
    val eventCapacity: Int
)

@Serializable
data class InterceptionRulePreviewResult(
    val status: String,
    val action: RuleAction,
    val wouldModify: Boolean,
    val wouldDrop: Boolean,
    val changedUrl: Boolean,
    val changedHeaderNames: List<String>,
    val inputBodyBytes: Int,
    val outputBodyBytes: Int,
    val code: String?
)

internal data class RuleHeader(val name: String, val value: String)
internal data class RuleHttpMessage(
    val direction: RuleDirection,
    val targetUrl: String,
    val url: String,
    val method: String,
    val headers: List<RuleHeader>,
    val body: ByteArray,
    val statusCode: Int? = null,
    val messageId: String? = null
)

internal enum class RuleEvaluationStatus { READY, MANUAL_REQUIRED, CONFLICT, STALE_RULES }
internal class RuleAuthorizationRequired(val code: String) : IllegalStateException(code)
internal data class RuleEvaluation(
    val status: RuleEvaluationStatus,
    val code: String?,
    val action: RuleAction,
    val input: RuleHttpMessage,
    val output: RuleHttpMessage,
    val matchedRuleIds: List<String>,
    val contributingRuleIds: Set<String>,
    val modifiedRuleIds: Set<String>,
    val changed: Boolean,
    internal val generations: Map<String, Long>,
    internal val reservationId: String
)

/** In-memory, bounded evaluator. Network authorization remains exclusively in LiveInterception. */
internal class InterceptionRuleEngine(
    private val nanoTime: () -> Long = System::nanoTime,
    private val currentTimeMillis: () -> Long = System::currentTimeMillis,
    private val approvedPreparationTarget: (InterceptionRuleSpec) -> Boolean = { false },
    private val approvedExecutionTarget: (String, InterceptionRuleSpec) -> Boolean = { _, _ -> false }
) {
    companion object {
        const val MAX_RULES = 64
        const val MAX_MATCHES = 32
        const val MAX_MODIFICATIONS = 32
        const val MAX_TTL_SECONDS = 300
        const val MAX_TRANSFORMATIONS = 8
        const val MAX_EVENTS = 500
        const val MAX_MESSAGE_BYTES = 65_536
        const val MAX_PENDING_EVALUATIONS = 8
    }

    private data class MutableRule(
        val id: String,
        var spec: InterceptionRuleSpec,
        var state: InterceptionRuleState = InterceptionRuleState.DISABLED,
        var generation: Long = 0,
        var deadlineNanos: Long? = null,
        var expiresAtEpochMillis: Long? = null,
        var reserved: Int = 0,
        var reservedModifications: Int = 0,
        /** Enforcement budgets are separate from clearable observability counters. */
        var matchBudgetConsumed: Long = 0,
        var modificationBudgetConsumed: Long = 0,
        var matchedRequests: Long = 0,
        var matchedResponses: Long = 0,
        var modified: Long = 0,
        var forwarded: Long = 0,
        var dropped: Long = 0,
        var skipped: Long = 0,
        var failed: Long = 0,
        var lastExecutionEpochMillis: Long? = null,
        var lastErrorCode: String? = null
    )
    private data class Candidate(val id: String, val spec: InterceptionRuleSpec, val generation: Long, val used: Long)
    private data class PendingReservation(
        val generations: Map<String, Long>,
        val messageId: String?,
        val direction: RuleDirection,
        val modificationRuleIds: Set<String> = emptySet()
    )

    private val rules = linkedMapOf<String, MutableRule>()
    private val events = ArrayDeque<InterceptionRuleEvent>()
    private val pendingReservations = LinkedHashMap<String, PendingReservation>()
    private var emergencyStopped = false

    @Synchronized fun create(spec: InterceptionRuleSpec): InterceptionRuleView {
        validateRuleSpec(spec)
        require(rules.size < MAX_RULES) { "Rule limit reached ($MAX_RULES)" }
        val id = UUID.randomUUID().toString()
        rules[id] = MutableRule(id, freezeSpec(spec))
        event(id, null, "CONFIG", "CREATED", "NONE", null)
        return view(rules.getValue(id))
    }

    fun validateForAuthorization(spec: InterceptionRuleSpec) = validateRuleSpec(spec)

    @Synchronized fun authorizationRevision(id: String): Long = (rules[id] ?: error("Unknown interception rule")).generation

    @Synchronized fun get(id: String): InterceptionRuleView { expireDueLocked(); return view(rules[id] ?: error("Unknown interception rule")) }
    @Synchronized fun list(): List<InterceptionRuleView> {
        expireDueLocked()
        return rules.values.sortedWith(compareByDescending<MutableRule> { it.spec.priority }.thenBy { it.id }).map(::view)
    }

    @Synchronized fun update(id: String, spec: InterceptionRuleSpec): InterceptionRuleView {
        validateRuleSpec(spec)
        val rule = rules[id] ?: error("Unknown interception rule")
        invalidateReservationsFor(id, "RULE_UPDATED")
        rule.generation++; rule.spec = freezeSpec(spec); rule.state = InterceptionRuleState.DISABLED
        rule.deadlineNanos = null; rule.expiresAtEpochMillis = null; rule.reserved = 0; rule.reservedModifications = 0; rule.lastErrorCode = null
        event(id, null, "CONFIG", "UPDATED_DISABLED", "NONE", null)
        return view(rule)
    }

    @Synchronized fun enable(id: String, effectiveDurationMillis: Long): InterceptionRuleView {
        expireDueLocked()
        check(!emergencyStopped) { "Rule engine is emergency-stopped; activate fresh local authorization in Burp first" }
        require(effectiveDurationMillis in 1..TimeUnit.SECONDS.toMillis(MAX_TTL_SECONDS.toLong())) { "Rule duration is outside the bounded limit" }
        val rule = rules[id] ?: error("Unknown interception rule")
        check(isLocalTarget(rule.spec) || approvedExecutionTarget(id, rule.spec)) { "Target rule lacks an approved session binding" }
        check(rule.state != InterceptionRuleState.ACTIVE) { "Rule is already active" }
        check(rule.matchBudgetConsumed < rule.spec.maximumMatches) { "Rule reached its maximum match count" }
        check(rule.spec.action != RuleAction.MODIFY_AND_FORWARD || rule.modificationBudgetConsumed < rule.spec.maximumModifications) { "Rule reached its maximum modification count" }
        rule.generation++
        val now = nanoTime()
        rule.deadlineNanos = now + TimeUnit.MILLISECONDS.toNanos(effectiveDurationMillis)
        rule.expiresAtEpochMillis = currentTimeMillis() + effectiveDurationMillis
        rule.state = InterceptionRuleState.ACTIVE
        event(id, null, "CONFIG", "ENABLED", "NONE", null)
        return view(rule)
    }

    @Synchronized fun disable(id: String, state: InterceptionRuleState = InterceptionRuleState.PAUSED): InterceptionRuleView {
        require(state in setOf(InterceptionRuleState.PAUSED, InterceptionRuleState.DISABLED))
        val rule = rules[id] ?: error("Unknown interception rule")
        invalidateReservationsFor(id, "RULE_DISABLED")
        rule.generation++; rule.state = state; rule.deadlineNanos = null; rule.expiresAtEpochMillis = null; rule.reserved = 0; rule.reservedModifications = 0
        event(id, null, "CONFIG", state.name, "NONE", null)
        return view(rule)
    }

    @Synchronized fun delete(id: String): Boolean {
        invalidateReservationsFor(id, "RULE_DELETED")
        val rule = rules.remove(id) ?: return false
        rule.generation++; event(id, null, "CONFIG", "DELETED", "NONE", null)
        return true
    }
    @Synchronized fun clear(): Int {
        val count = rules.size
        invalidateAllReservations("RULES_CLEARED")
        rules.values.forEach { it.generation++; event(it.id, null, "CONFIG", "DELETED", "NONE", null) }
        rules.clear()
        return count
    }
    @Synchronized fun clearStats(id: String? = null) {
        val selected = if (id == null) rules.values else listOf(rules[id] ?: error("Unknown interception rule"))
        selected.forEach {
            it.matchedRequests=0; it.matchedResponses=0; it.modified=0; it.forwarded=0; it.dropped=0; it.skipped=0; it.failed=0
            it.lastExecutionEpochMillis=null; it.lastErrorCode=null
        }
        event(id ?: "*", null, "CONFIG", "STATS_CLEARED", "NONE", null)
    }
    @Synchronized fun emergencyStop() {
        emergencyStopped = true
        invalidateAllReservations("EMERGENCY_STOP")
        rules.values.forEach {
            it.generation++; it.state=InterceptionRuleState.EMERGENCY_STOPPED; it.deadlineNanos=null; it.expiresAtEpochMillis=null; it.reserved=0; it.reservedModifications=0
            event(it.id, null, "ENGINE", "EMERGENCY_STOPPED", "NONE", null)
        }
    }
    /** Only LiveInterception's human-visible activation control may call this. */
    @Synchronized fun freshHumanActivation() {
        emergencyStopped = false
        rules.values.filter { it.state == InterceptionRuleState.EMERGENCY_STOPPED }.forEach {
            it.generation++; it.state=InterceptionRuleState.PAUSED
        }
    }
    @Synchronized fun pauseAll(reason: String) {
        val next = if (reason == "AUTHORIZATION_EXPIRED") InterceptionRuleState.AUTHORIZATION_ENDED else InterceptionRuleState.PAUSED
        val active = rules.values.filter { it.state == InterceptionRuleState.ACTIVE }
        active.forEach { invalidateReservationsFor(it.id, reason.take(48)) }
        active.forEach {
            it.generation++; it.state=next; it.deadlineNanos=null; it.expiresAtEpochMillis=null; it.reserved=0; it.reservedModifications=0
            event(it.id, null, "ENGINE", next.name, "NONE", reason.take(48))
        }
    }
    @Synchronized fun tick() { expireDueLocked() }
    @Synchronized fun status(): InterceptionRuleEngineStatus {
        expireDueLocked()
        return InterceptionRuleEngineStatus(rules.values.count { it.state == InterceptionRuleState.ACTIVE }, rules.size,
            emergencyStopped, MAX_RULES, MAX_MATCHES, MAX_MODIFICATIONS, MAX_TTL_SECONDS, MAX_EVENTS)
    }
    @Synchronized fun eventHistory(count: Int): List<InterceptionRuleEvent> {
        require(count in 1..100); expireDueLocked(); return events.toList().takeLast(count).asReversed()
    }

    fun evaluate(inputMessage: RuleHttpMessage): RuleEvaluation? {
        val message = freezeMessage(inputMessage)
        if (message.body.size > MAX_MESSAGE_BYTES) return null
        val snapshot = synchronized(this) {
            expireDueLocked()
            if (emergencyStopped) return null
            rules.values.filter { it.state == InterceptionRuleState.ACTIVE }
                .map { Candidate(it.id, it.spec, it.generation, it.matchBudgetConsumed) }
        }
        val matched = mutableListOf<Candidate>()
        val skipped = mutableListOf<Pair<Candidate,String>>()
        snapshot.forEach { candidate ->
            if ((!isLocalTarget(candidate.spec) && !approvedExecutionTarget(candidate.id, candidate.spec)) || candidate.used >= candidate.spec.maximumMatches || !targetMatches(candidate.spec.targetUrl, message.targetUrl) ||
                !directionMatches(candidate.spec.direction, message.direction)) return@forEach
            when (val result = RuleTransformations.matches(candidate.spec.conditions, message)) {
                MatchResult.MATCH -> matched += candidate
                MatchResult.NO_MATCH -> Unit
                is MatchResult.UNSUPPORTED -> skipped += candidate to result.code
            }
        }
        if (matched.isEmpty()) {
            skipped.forEach { (c, code) -> recordSkipped(c, code, message.messageId, message.direction) }
            return null
        }
        if (skipped.isNotEmpty()) {
            // A rule whose conditions cannot be evaluated may match this message.
            // Do not allow another rule to mutate or release it as if that rule did not exist.
            skipped.forEach { (c, code) -> recordSkipped(c, code, message.messageId, message.direction) }
            matched.forEach { c -> recordSkipped(c, "CO_MATCHED_RULE_UNSUPPORTED", message.messageId, message.direction) }
            return null
        }
        val reservation = UUID.randomUUID().toString()
        val generations = linkedMapOf<String,Long>()
        synchronized(this) {
            expireDueLocked()
            if (emergencyStopped) return null
            if (pendingReservations.size >= MAX_PENDING_EVALUATIONS) {
                matched.forEach { recordSkippedLocked(rules[it.id], "RULE_ENGINE_BUSY", message.messageId, message.direction) }
                return null
            }
            for (candidate in matched) {
                val current = rules[candidate.id]
                if (current == null || current.state != InterceptionRuleState.ACTIVE || current.generation != candidate.generation ||
                    current.matchBudgetConsumed >= current.spec.maximumMatches) {
                    matched.forEach { recordSkippedLocked(rules[it.id], "STALE_OR_LIMIT", message.messageId, message.direction) }
                    return null
                }
            }
            matched.forEach {
                val rule = rules.getValue(it.id); rule.reserved++
                rule.matchBudgetConsumed++
                if (message.direction == RuleDirection.REQUEST) rule.matchedRequests++ else rule.matchedResponses++
                generations[it.id] = rule.generation
            }
            pendingReservations[reservation] = PendingReservation(generations.toMap(), message.messageId, message.direction)
            skipped.forEach { (c, code) -> recordSkippedLocked(rules[c.id], code, message.messageId, message.direction) }
        }
        val ordered = matched.sortedWith(compareByDescending<Candidate> { it.spec.priority }.thenBy { it.id })
        val (action, actionConflict, highestPriority) = resolveActions(ordered)
        if (actionConflict != null) return plan(RuleEvaluationStatus.CONFLICT, actionConflict, RuleAction.FORWARD_UNCHANGED,
            message, message, matched, emptySet(), emptySet(), false, generations, reservation)
        if (action == RuleAction.DROP) return plan(RuleEvaluationStatus.READY, null, action, message, message, matched,
            ordered.filter { it.spec.priority == highestPriority && it.spec.action == RuleAction.DROP }.map { it.id }.toSet(), emptySet(), false, generations, reservation)
        if (action == RuleAction.FORWARD_UNCHANGED) return plan(RuleEvaluationStatus.READY, null, action, message, message, matched,
            ordered.filter { it.spec.priority == highestPriority && it.spec.action == RuleAction.FORWARD_UNCHANGED }.map { it.id }.toSet(), emptySet(), false, generations, reservation)
        val transformRules = ordered.filter { it.spec.action == RuleAction.MODIFY_AND_FORWARD }
        val (transformations, transformConflict) = resolveTransformations(transformRules)
        if (transformConflict != null) return plan(RuleEvaluationStatus.CONFLICT, transformConflict, action, message, message, matched, emptySet(), emptySet(), false, generations, reservation)
        return try {
            var output = message
            val modifiedRules = linkedSetOf<String>()
            transformations.forEach { (candidate, t) ->
                if (!isLocalTarget(candidate.spec) && !approvedExecutionTarget(candidate.id, candidate.spec)) throw RuleAuthorizationRequired("TARGET_AUTHORIZATION_ENDED")
                val next = RuleTransformations.apply(output, t)
                if (!RuleTransformations.byteAndMetadataEqual(output, next)) modifiedRules += candidate.id
                output = next
            }
            val contributors = transformations.map { it.first.id }.toSet()
            val changed = !RuleTransformations.byteAndMetadataEqual(message, output)
            if (!changed) plan(RuleEvaluationStatus.READY, "NO_CHANGE", RuleAction.FORWARD_UNCHANGED, message, output, matched, contributors, emptySet(), false, generations, reservation)
            else {
                val evaluation = plan(RuleEvaluationStatus.READY, null, RuleAction.MODIFY_AND_FORWARD,
                    message, output, matched, contributors, modifiedRules, true, generations, reservation)
                if (reserveModificationBudget(evaluation)) evaluation else null
            }
        } catch (e: RuleTransformations.UnsupportedRuleMessage) {
            plan(RuleEvaluationStatus.MANUAL_REQUIRED, e.code, action, message, message, matched, emptySet(), emptySet(), false, generations, reservation)
        } catch (_: Exception) {
            plan(RuleEvaluationStatus.MANUAL_REQUIRED, "TRANSFORMATION_FAILED", action, message, message, matched, emptySet(), emptySet(), false, generations, reservation)
        }
    }

    /** Rule edits cannot race with disable/delete or Emergency Stop between the policy check and release. */
    fun <T> commit(evaluation: RuleEvaluation, action: () -> T): T? = synchronized(this) {
        expireDueLocked()
        if (pendingReservations[evaluation.reservationId]?.generations != evaluation.generations) return@synchronized null
        val valid = !emergencyStopped && evaluation.generations.all { (id,generation) ->
            rules[id]?.let { it.state == InterceptionRuleState.ACTIVE && it.generation == generation } == true
        }
        if (!valid || evaluation.status != RuleEvaluationStatus.READY) {
            finishLocked(evaluation, "SKIPPED", "MANUAL", evaluation.code ?: "RULE_STATE_CHANGED")
            return@synchronized null
        }
        try {
            val released = action()
            val outcome = when (evaluation.action) { RuleAction.DROP -> "DROPPED"; else -> if (evaluation.changed) "MODIFIED_AND_FORWARDED" else "FORWARDED_UNCHANGED" }
            finishLocked(evaluation, outcome, "AUTOMATIC", evaluation.code)
            released
        } catch (e: RuleAuthorizationRequired) {
            finishLocked(evaluation, "SKIPPED", "MANUAL", e.code)
            null
        } catch (_: Exception) {
            finishLocked(evaluation, "FAILED", "AUTOMATIC", "POLICY_OR_RELEASE_FAILED")
            null
        }
    }

    @Synchronized fun finish(evaluation: RuleEvaluation, outcome: String, approvalMode: String, code: String? = null) = finishLocked(evaluation, outcome, approvalMode, code)

    @Synchronized fun preview(spec: InterceptionRuleSpec, message: RuleHttpMessage): RuleEvaluationStatus {
        validateRuleSpec(spec)
        if (!targetMatches(spec.targetUrl, message.targetUrl) || !directionMatches(spec.direction, message.direction)) return RuleEvaluationStatus.MANUAL_REQUIRED
        return when (RuleTransformations.matches(spec.conditions, message)) {
            MatchResult.NO_MATCH, is MatchResult.UNSUPPORTED -> RuleEvaluationStatus.MANUAL_REQUIRED
            MatchResult.MATCH -> runCatching { RuleTransformations.applyAll(spec, message); RuleEvaluationStatus.READY }.getOrElse { RuleEvaluationStatus.MANUAL_REQUIRED }
        }
    }

    @Synchronized fun previewDetailed(spec: InterceptionRuleSpec, message: RuleHttpMessage): InterceptionRulePreviewResult {
        validateRuleSpec(spec)
        val match = targetMatches(spec.targetUrl, message.targetUrl) && directionMatches(spec.direction, message.direction)
        if (!match) return InterceptionRulePreviewResult("NO_MATCH", spec.action, false, false, false, emptyList(), message.body.size, message.body.size, null)
        when (val condition = RuleTransformations.matches(spec.conditions, message)) {
            MatchResult.NO_MATCH -> return InterceptionRulePreviewResult("NO_MATCH", spec.action, false, false, false, emptyList(), message.body.size, message.body.size, null)
            is MatchResult.UNSUPPORTED -> return InterceptionRulePreviewResult("UNSUPPORTED", spec.action, false, false, false, emptyList(), message.body.size, message.body.size, condition.code)
            MatchResult.MATCH -> Unit
        }
        if (spec.action == RuleAction.DROP) return InterceptionRulePreviewResult("MATCH", spec.action, false, true, false, emptyList(), message.body.size, message.body.size, null)
        return try {
            val output = if (spec.action == RuleAction.MODIFY_AND_FORWARD) RuleTransformations.applyAll(spec, message) else message
            val names = (message.headers.map { it.name } + output.headers.map { it.name }).distinctBy { it.lowercase() }
                .filter { name -> message.headers.filter { it.name.equals(name,true) }.map { it.value } != output.headers.filter { it.name.equals(name,true) }.map { it.value } }
            InterceptionRulePreviewResult("MATCH", spec.action, !RuleTransformations.byteAndMetadataEqual(message,output), false,
                message.url != output.url, names, message.body.size, output.body.size, null)
        } catch (error: RuleTransformations.UnsupportedRuleMessage) {
            InterceptionRulePreviewResult("UNSUPPORTED", spec.action, false, false, false, emptyList(), message.body.size, message.body.size, error.code)
        } catch (_: Exception) {
            InterceptionRulePreviewResult("INVALID", spec.action, false, false, false, emptyList(), message.body.size, message.body.size, "TRANSFORMATION_FAILED")
        }
    }

    private fun resolveActions(ordered: List<Candidate>): Triple<RuleAction,String?,Int> {
        val priority = ordered.first().spec.priority
        if (ordered.filter { it.spec.priority == priority }.map { it.spec.action }.toSet().size > 1)
            return Triple(RuleAction.FORWARD_UNCHANGED, "ACTION_CONFLICT", priority)
        return Triple(ordered.first().spec.action, null, priority)
    }
    private fun resolveTransformations(candidates: List<Candidate>): Pair<List<Pair<Candidate,RuleTransformation>>,String?> {
        val winners = mutableListOf<Pair<Candidate,RuleTransformation>>()
        candidates.forEach { candidate -> candidate.spec.transformations.forEach { t ->
            val index = winners.indexOfFirst { RuleTransformations.overlaps(it.second, t) }
            if (index < 0) winners += candidate to t
            else {
                val old = winners[index]
                if (old.second == t) Unit
                else if (old.first.spec.priority == candidate.spec.priority) return emptyList<Pair<Candidate,RuleTransformation>>() to "TRANSFORMATION_CONFLICT"
                else if (candidate.spec.priority > old.first.spec.priority) winners[index] = candidate to t
            }
        } }
        return winners.toList() to null
    }
    private fun plan(status: RuleEvaluationStatus, code: String?, action: RuleAction, input: RuleHttpMessage, output: RuleHttpMessage,
                     matched: List<Candidate>, contributors: Set<String>, modified: Set<String>, changed: Boolean,
                     generations: Map<String,Long>, reservation: String) =
        RuleEvaluation(status, code, action, input, output, matched.map { it.id }, contributors, modified, changed, generations, reservation)

    /** Reserve actual modifications after transformation, so no-op forwards do not consume this budget. */
    private fun reserveModificationBudget(evaluation: RuleEvaluation): Boolean = synchronized(this) {
        val pending = pendingReservations[evaluation.reservationId]
        if (pending?.generations != evaluation.generations) return@synchronized false
        val valid = !emergencyStopped && evaluation.generations.all { (id, generation) ->
            rules[id]?.let { it.state == InterceptionRuleState.ACTIVE && it.generation == generation } == true
        }
        if (!valid) {
            finishLocked(evaluation, "SKIPPED", "MANUAL", "RULE_STATE_CHANGED")
            return@synchronized false
        }
        val exhausted = evaluation.modifiedRuleIds.any { id ->
            rules[id]?.let { it.modificationBudgetConsumed + it.reservedModifications >= it.spec.maximumModifications } ?: true
        }
        if (exhausted) {
            finishLocked(evaluation, "SKIPPED", "MANUAL", "MAX_MODIFICATIONS")
            return@synchronized false
        }
        evaluation.modifiedRuleIds.forEach { id -> rules.getValue(id).reservedModifications++ }
        pendingReservations[evaluation.reservationId] = pending.copy(modificationRuleIds = evaluation.modifiedRuleIds)
        true
    }

    private fun finishLocked(e: RuleEvaluation, outcome: String, approval: String, code: String?) {
        val reservation = pendingReservations.remove(e.reservationId) ?: return
        if (reservation.generations != e.generations) return
        val now = currentTimeMillis()
        e.matchedRuleIds.forEach { id ->
            val rule = rules[id] ?: return@forEach
            if (e.generations[id] != rule.generation) return@forEach
            rule.reserved = (rule.reserved - 1).coerceAtLeast(0); rule.lastExecutionEpochMillis = now; rule.lastErrorCode = code?.take(64)
            if (id in reservation.modificationRuleIds) {
                rule.reservedModifications = (rule.reservedModifications - 1).coerceAtLeast(0)
            }
            when (outcome) {
                "MODIFIED_AND_FORWARDED" -> if (id in e.contributingRuleIds) {
                    rule.forwarded++; if (id in e.modifiedRuleIds) {
                        rule.modified++
                        rule.modificationBudgetConsumed++
                    }
                } else rule.skipped++
                "FORWARDED_UNCHANGED" -> if (id in e.contributingRuleIds) rule.forwarded++ else rule.skipped++
                "DROPPED" -> if (id in e.contributingRuleIds) rule.dropped++ else rule.skipped++
                "SKIPPED" -> rule.skipped++
                "FAILED" -> rule.failed++
            }
            if (rule.state == InterceptionRuleState.ACTIVE && rule.reserved == 0 &&
                rule.matchBudgetConsumed >= rule.spec.maximumMatches) {
                rule.state=InterceptionRuleState.MAX_MATCHES; rule.deadlineNanos=null; rule.expiresAtEpochMillis=null
            } else if (rule.state == InterceptionRuleState.ACTIVE && rule.spec.action == RuleAction.MODIFY_AND_FORWARD &&
                rule.modificationBudgetConsumed >= rule.spec.maximumModifications && rule.reservedModifications == 0) {
                rule.state=InterceptionRuleState.MAX_MODIFICATIONS; rule.deadlineNanos=null; rule.expiresAtEpochMillis=null
            }
            event(id, e.input.messageId, e.input.direction.name, outcome, approval, code)
        }
    }
    private fun recordSkipped(candidate: Candidate, code: String, messageId: String?, direction: RuleDirection) = synchronized(this) {
        recordSkippedLocked(rules[candidate.id], code, messageId, direction)
    }
    private fun recordSkippedLocked(rule: MutableRule?, code: String, messageId: String?, direction: RuleDirection) {
        if (rule == null) return
        rule.skipped++; rule.lastExecutionEpochMillis=currentTimeMillis(); rule.lastErrorCode=code.take(64)
        event(rule.id, messageId, direction.name, "SKIPPED", "MANUAL", code)
    }
    private fun view(rule: MutableRule): InterceptionRuleView {
        expireRuleIfDue(rule)
        return InterceptionRuleView(rule.id, rule.spec, rule.state, rule.expiresAtEpochMillis,
            rule.deadlineNanos?.let { TimeUnit.NANOSECONDS.toMillis((it - nanoTime()).coerceAtLeast(0)) } ?: 0, stats(rule))
    }
    private fun stats(r: MutableRule) = InterceptionRuleStats(r.id,r.spec.name,r.spec.targetUrl,r.spec.direction,r.state,
        r.matchedRequests,r.matchedResponses,r.modified,r.forwarded,r.dropped,r.skipped,r.failed,
        (r.spec.maximumMatches.toLong()-r.matchBudgetConsumed).coerceAtLeast(0).toInt(),
        (r.spec.maximumModifications.toLong()-r.modificationBudgetConsumed-r.reservedModifications).coerceAtLeast(0).toInt(),
        r.expiresAtEpochMillis,r.lastExecutionEpochMillis,r.lastErrorCode)
    private fun expireDueLocked() = rules.values.forEach(::expireRuleIfDue)
    private fun expireRuleIfDue(rule: MutableRule) {
        if (rule.spec.targetUrl !in LocalTestTargets.urls && rule.spec.targetUrl != LocalTestTargets.RULE_AUTHORITY_URL &&
            (!approvedPreparationTarget(rule.spec) || (rule.state == InterceptionRuleState.ACTIVE && !approvedExecutionTarget(rule.id, rule.spec))) && rule.state !in setOf(InterceptionRuleState.AUTHORIZATION_ENDED, InterceptionRuleState.EMERGENCY_STOPPED)) {
            invalidateReservationsFor(rule.id, "TARGET_AUTHORIZATION_ENDED")
            rule.generation++; rule.state = InterceptionRuleState.AUTHORIZATION_ENDED
            rule.deadlineNanos = null; rule.expiresAtEpochMillis = null
        }
        val deadline = rule.deadlineNanos ?: return
        if (nanoTime() < deadline) return
        invalidateReservationsFor(rule.id, "RULE_EXPIRED")
        rule.generation++; rule.state=InterceptionRuleState.EXPIRED; rule.deadlineNanos=null; rule.expiresAtEpochMillis=null; rule.reserved=0; rule.reservedModifications=0
        event(rule.id,null,"ENGINE","EXPIRED","NONE","RULE_TTL")
    }
    private fun event(ruleId: String, messageId: String?, direction: String, outcome: String, approval: String, code: String?) {
        events.addLast(InterceptionRuleEvent(currentTimeMillis(),ruleId.take(64),messageId?.take(64),direction.take(16),outcome.take(40),approval.take(24),code?.take(64)))
        while (events.size > MAX_EVENTS) events.removeFirst()
    }
    private fun invalidateReservationsFor(ruleId: String, code: String) {
        val ids = pendingReservations.filterValues { ruleId in it.generations }.keys.toList()
        ids.forEach { id ->
            val reservation = pendingReservations.remove(id) ?: return@forEach
            reservation.generations.forEach { (reservedRuleId, generation) ->
                rules[reservedRuleId]?.takeIf { it.generation == generation }?.let { rule ->
                    rule.reserved = (rule.reserved - 1).coerceAtLeast(0)
                    if (reservedRuleId in reservation.modificationRuleIds) rule.reservedModifications = (rule.reservedModifications - 1).coerceAtLeast(0)
                    recordSkippedLocked(rule, code, reservation.messageId, reservation.direction)
                }
            }
        }
    }
    private fun invalidateAllReservations(code: String) {
        pendingReservations.keys.toList().forEach { id ->
            val reservation = pendingReservations.remove(id) ?: return@forEach
            reservation.generations.forEach { (reservedRuleId, generation) ->
                rules[reservedRuleId]?.takeIf { it.generation == generation }?.let { rule ->
                    rule.reserved = (rule.reserved - 1).coerceAtLeast(0)
                    if (reservedRuleId in reservation.modificationRuleIds) rule.reservedModifications = (rule.reservedModifications - 1).coerceAtLeast(0)
                    recordSkippedLocked(rule, code, reservation.messageId, reservation.direction)
                }
            }
        }
    }
    private fun freezeSpec(spec: InterceptionRuleSpec) = spec.copy(
        conditions = spec.conditions.copy(),
        transformations = Collections.unmodifiableList(spec.transformations.map { it.copy() })
    )
    private fun freezeMessage(message: RuleHttpMessage) = message.copy(
        headers = Collections.unmodifiableList(message.headers.map { it.copy() }),
        body = message.body.copyOf()
    )
    private fun isLocalTarget(spec: InterceptionRuleSpec) = spec.targetUrl in LocalTestTargets.urls || spec.targetUrl == LocalTestTargets.RULE_AUTHORITY_URL
    private fun targetMatches(ruleTarget: String, actual: String): Boolean {
        if (ruleTarget !in LocalTestTargets.urls && ruleTarget != LocalTestTargets.RULE_AUTHORITY_URL) {
            return runCatching { TargetRuleAuthorization.validateUrls(listOf(actual)); ruleTarget == actual }.getOrDefault(false)
        }
        val uri = runCatching { URI(actual) }.getOrNull() ?: return false
        if (uri.userInfo != null || uri.rawFragment != null || uri.scheme != "http" || uri.host != LocalTestTargets.HOST || uri.port != LocalTestTargets.PORT) return false
        val path = uri.rawPath.ifBlank { "/" }
        if (path !in LocalTestTargets.paths) return false
        return if (ruleTarget == LocalTestTargets.RULE_AUTHORITY_URL) true
            else ruleTarget == "${uri.scheme}://${uri.host}:${uri.port}$path"
    }
    private fun directionMatches(rule: RuleDirection, actual: RuleDirection) = rule == RuleDirection.BOTH || rule == actual

    private fun validateRuleSpec(s: InterceptionRuleSpec) {
        require(s.name.length in 1..80 && s.name.none { it.isISOControl() }) { "Rule name must be 1–80 printable characters" }
        val exactTarget = s.targetUrl in LocalTestTargets.urls || approvedPreparationTarget(s)
        val authorityTarget = s.targetUrl == LocalTestTargets.RULE_AUTHORITY_URL
        require(exactTarget || authorityTarget) { "Rule target requires current exact-path human authorization" }
        require(s.authorizationReference.matches(Regex("^[a-f0-9-]{36}$"))) { "Authorization reference must be a test-run or target-grant ID" }
        require(s.priority in -1_000..1_000) { "Priority must be between -1000 and 1000" }
        require(s.maximumMatches in 1..MAX_MATCHES) { "Maximum matches must be 1..$MAX_MATCHES" }
        require(s.maximumModifications in 0..MAX_MODIFICATIONS) { "Maximum modifications must be 0..$MAX_MODIFICATIONS" }
        require(s.action != RuleAction.MODIFY_AND_FORWARD || s.maximumModifications >= 1) { "MODIFY_AND_FORWARD needs at least one allowed modification" }
        require(s.durationSeconds in 1..MAX_TTL_SECONDS) { "Duration must be 1..$MAX_TTL_SECONDS seconds" }
        require(s.transformations.size <= MAX_TRANSFORMATIONS) { "At most $MAX_TRANSFORMATIONS transformations are supported" }
        require(s.action != RuleAction.MODIFY_AND_FORWARD || s.transformations.isNotEmpty()) { "MODIFY_AND_FORWARD needs transformations" }
        require(s.action == RuleAction.MODIFY_AND_FORWARD || s.transformations.isEmpty()) { "Only MODIFY_AND_FORWARD accepts transformations" }
        val c=s.conditions
        require(listOf(c.method,c.path,c.pathPrefix,c.queryParameterName,c.queryParameterValue,c.headerName,c.headerValue,c.contentType,c.jsonPath,c.jsonValueJson,c.formFieldName,c.formFieldValue,c.responseStatus?.toString()).count { it != null } <= 16) { "At most 16 match conditions are allowed" }
        require(c.path == null || (c.path.startsWith("/") && !c.path.startsWith("//") && c.path.length<=512 && '?' !in c.path && '#' !in c.path)) { "path must be an exact absolute path" }
        require(c.pathPrefix == null || (c.pathPrefix.startsWith("/") && !c.pathPrefix.startsWith("//") && c.pathPrefix.length<=256 && '?' !in c.pathPrefix && '#' !in c.pathPrefix)) { "pathPrefix must be an absolute safe prefix" }
        require(c.path == null || c.pathPrefix == null) { "Specify path or pathPrefix, not both" }
        require(s.action != RuleAction.DROP || s.direction == RuleDirection.REQUEST) { "Automatic DROP rules are limited to request direction" }
        if (s.direction == RuleDirection.REQUEST) require(c.responseStatus == null) { "responseStatus requires RESPONSE or BOTH direction" }
        if (s.direction == RuleDirection.RESPONSE) require(s.transformations.none {
            it.type in setOf(RuleTransformType.SET_REQUEST_HEADER, RuleTransformType.REMOVE_REQUEST_HEADER,
                RuleTransformType.SET_QUERY_PARAMETER, RuleTransformType.REMOVE_QUERY_PARAMETER,
                RuleTransformType.SET_FORM_FIELD, RuleTransformType.REMOVE_FORM_FIELD)
        }) { "Request-only transformations require REQUEST or BOTH direction" }
        if (s.direction == RuleDirection.REQUEST) require(s.transformations.none {
            it.type in setOf(RuleTransformType.SET_RESPONSE_HEADER, RuleTransformType.REMOVE_RESPONSE_HEADER)
        }) { "Response-only header transformations require RESPONSE or BOTH direction" }
        if (exactTarget) {
            val targetPath = URI(s.targetUrl).rawPath
            require(c.path == null || c.path == targetPath) { "An exact URL target cannot use a different exact path condition" }
            require(c.pathPrefix == null || targetPath.startsWith(c.pathPrefix)) { "An exact URL target must start with its configured path prefix" }
        }
        if (authorityTarget) {
            require(c.path != null || c.pathPrefix != null) { "An authority target must be constrained by an exact path or safe prefix" }
            require(c.path == null || c.path in LocalTestTargets.paths) { "Rule path is not one of the predefined local test paths" }
            require(c.pathPrefix == null || LocalTestTargets.paths.any { it.startsWith(c.pathPrefix) }) { "Path prefix does not select a predefined local test path" }
        }
        require(c.method == null || c.method.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$"))) { "Invalid method condition" }
        require(c.responseStatus == null || c.responseStatus in 100..599) { "Invalid response status" }
        require(c.headerName == null || c.headerName.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$"))) { "Invalid header-name condition" }
        require(c.queryParameterName == null || c.queryParameterName.length in 1..128) { "Invalid query-parameter condition" }
        require(c.formFieldName == null || c.formFieldName.length in 1..128) { "Invalid form-field condition" }
        require(c.contentType == null || c.contentType.substringBefore(';').trim().matches(Regex("^[A-Za-z0-9!#$&^_.+-]{1,127}/[A-Za-z0-9!#$&^_.+-]{1,127}$"))) {
            "Content-Type condition must name one exact media type"
        }
        listOf(c.queryParameterName,c.queryParameterValue,c.headerName,c.headerValue,c.contentType,c.jsonPath,c.jsonValueJson,c.formFieldName,c.formFieldValue).filterNotNull().forEach {
            require(it.length<=2048 && it.none(Char::isISOControl)) { "Condition value is too long or contains control characters" }
        }
        if (c.jsonPath != null) {
            require(c.jsonValueJson != null) { "jsonPath requires typed jsonValueJson" }
            RuleTransformations.validateJsonLiteral(c.jsonValueJson, 2_048)
            RuleTransformations.parseJsonPath(c.jsonPath)
        } else require(c.jsonValueJson == null) { "jsonValueJson requires jsonPath" }
        s.transformations.forEach(RuleTransformations::validate)
    }
}
