package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.*
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.*
import net.portswigger.mcp.tools.isAuthorizedRequest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import javax.swing.SwingUtilities
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.util.concurrent.Semaphore
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.UUID

data class HeldMessage(val message: HttpMessage, val request: HttpRequest)
private data class CaptureSkip(val reason: String, val mustDrop: Boolean)

data class InterceptionHealth(
    val enabled: Boolean,
    val heartbeatHealth: String,
    val sessionLifetimeSeconds: Int,
    val heartbeatIntervalSeconds: Int,
    val sessionRemainingMillis: Long,
    val sessionExpiresAtEpochMillis: Long?,
    val leaseRemainingMillis: Long,
    val leaseExpiresAtEpochMillis: Long?,
    val lastHeartbeatAtEpochMillis: Long?,
    val sessionEndReason: String,
    val pendingRequests: Int,
    val pendingResponses: Int,
    val queueCapacity: Int
)

class LiveInterception(private val api: MontoyaApi, val config: McpConfig, private val nanoTime: () -> Long = System::nanoTime) : AutoCloseable {
    companion object {
        const val CLIENT_LEASE_SECONDS = 15
        const val HEARTBEAT_INTERVAL_SECONDS = 3
        const val DEFAULT_SESSION_LIFETIME_SECONDS = 300
        const val MIN_SESSION_LIFETIME_SECONDS = 60
        const val MAX_SESSION_LIFETIME_SECONDS = 600
        const val DEFAULT_MESSAGE_TIMEOUT_SECONDS = 60
        const val MIN_MESSAGE_TIMEOUT_SECONDS = 5
        const val MAX_MESSAGE_TIMEOUT_SECONDS = 120
        const val QUEUE_CAPACITY = 8
    }

    val queue = DecisionQueue<HeldMessage>()
    private val targetPolicyRevision = java.util.concurrent.atomic.AtomicLong()
    private val targetPolicyChanged: () -> Unit = { targetPolicyRevision.incrementAndGet() }
    private val targetPolicyListener = config.addTargetsChangeListener(targetPolicyChanged)
    internal val targetRuleAuthorizations = TargetRuleAuthorization(::targetPreparationEligible, nanoTime, targetPolicyRevision::get)
    internal val ruleEngine = InterceptionRuleEngine(nanoTime = nanoTime, approvedPreparationTarget = targetRuleAuthorizations::permits, approvedExecutionTarget = ::targetExecutionEligible)

    private fun targetPreparationEligible(url: String): Boolean = runCatching {
        val uri = URI(url)
        !closed && config.requireBearerToken && !config.readOnlyMode &&
            config.getAutoApproveTargetsList().any { it.equals("${uri.host}:${uri.port}", ignoreCase = true) } &&
            api.scope().isInScope(url)
    }.getOrDefault(false)

    suspend fun requestTargetRuleAuthorization(urls: List<String>, seconds: Int): TargetRuleGrant {
        check(!enabled) { "Stop interception before requesting target authorization" }
        return targetRuleAuthorizations.request(urls, seconds) { details ->
            StateChangeSecurity.confirm(api, config, "Authorize exact rule preparation target", details)
        }
    }

    fun targetRuleAuthorizationStatus(): List<TargetRuleGrant> = targetRuleAuthorizations.list()
    @Volatile private var targetSession = false
    private val targetSlots = Semaphore(2)
    private data class TargetAssociation(val session: String, val target: String, val fingerprint: String, val revisions: Map<String, Long>)
    private val targetAssociations = linkedMapOf<Int, TargetAssociation>()

    private fun targetSessionHealthy(): Boolean {
        val now = nanoTime()
        return targetSession && enabled && !closed && heartbeatHealth == "HEALTHY" &&
            (sessionDeadlineNanos ?: 0) > now &&
            lastHeartbeatNanos?.let { now - it < TimeUnit.SECONDS.toNanos(CLIENT_LEASE_SECONDS.toLong()) } == true &&
            config.requireBearerToken && !config.readOnlyMode
    }

    private fun targetExecutionEligible(id: String, spec: InterceptionRuleSpec): Boolean =
        targetSessionHealthy() &&
            (allowEdits || spec.action != RuleAction.MODIFY_AND_FORWARD) &&
            targetRuleAuthorizations.permitsExecution(id, spec, currentSessionId)

    /** The second approval names immutable rule revisions and operations; preparation alone cannot execute. */
    suspend fun startTargetRuleSession(grantId: String, ruleIds: List<String>, seconds: Int): InterceptionHealth {
        require(ruleIds.size in 1..16 && ruleIds.distinct().size == ruleIds.size)
        require(seconds in MIN_SESSION_LIFETIME_SECONDS..300)
        val epoch = targetRuleAuthorizations.approvalEpoch()
        val revisions = ruleIds.associateWith { ruleEngine.authorizationRevision(it) }
        val specs = synchronized(this) {
            check(!enabled && !closed && !unattendedMode.snapshot().active)
            check(queue.list("request").isEmpty() && queue.list("response").isEmpty())
            ruleIds.associateWith { id -> ruleEngine.get(id).also { check(it.state != InterceptionRuleState.ACTIVE) }.spec }
        }
        check(specs.values.all { it.authorizationReference == grantId && targetRuleAuthorizations.permits(it) &&
            it.targetUrl !in LocalTestTargets.urls && it.action != RuleAction.DROP }) { "Invalid target session rules or operations" }
        check(targetRuleAuthorizations.remainingMillis(grantId) >= seconds * 1000L)
        val details = "Start automatic target rule session for ${seconds}s. No renewal or automatic disclosure. " +
            "Unrelated, sensitive or revoked traffic continues unchanged.\n" + specs.entries.joinToString("\n") {
                "Rule ${it.key}: ${it.value.targetUrl}; ${it.value.direction}; ${it.value.action}; transforms=${it.value.transformations}"
            }
        check(details.length <= 16_000) { "Approval details exceed the review limit" }
        check(StateChangeSecurity.confirm(api, config, "Approve bounded target rule execution", details)) { "Target session denied" }
        return synchronized(this) {
            check(!enabled && !closed && !unattendedMode.snapshot().active)
            check(queue.list("request").isEmpty() && queue.list("response").isEmpty())
            check(epoch == targetRuleAuthorizations.approvalEpoch()) { "Stale session approval" }
            check(revisions.all { (id, revision) -> ruleEngine.authorizationRevision(id) == revision }) { "Rule revision changed during approval" }
            check(specs.all { (id, spec) -> ruleEngine.get(id).let { it.spec == spec && it.state != InterceptionRuleState.ACTIVE } }) { "Rule changed during approval" }
            check(specs.values.all { targetRuleAuthorizations.permits(it) && (allowEdits || it.action != RuleAction.MODIFY_AND_FORWARD) })
            check(targetRuleAuthorizations.remainingMillis(grantId) >= seconds * 1000L) { "Insufficient grant lifetime" }
            startApprovedSession(seconds)
            try {
                targetRuleAuthorizations.bind(grantId, currentSessionId!!, specs, epoch)
                targetSession = true
                ruleEngine.freshHumanActivation()
                specs.keys.forEach { enableInterceptionRule(it) }
                health()
            } catch (error: Exception) {
                endSession("TARGET_BINDING_FAILED")
                throw error
            }
        }
    }

    private fun exactTarget(request: HttpRequest): String? = runCatching {
        val u = URI(request.url())
        require(u.rawUserInfo == null && u.rawFragment == null)
        val port = if (u.port == -1) when (u.scheme) { "http" -> 80; "https" -> 443; else -> -1 } else u.port
        val target = "${u.scheme}://${u.host}:$port${u.rawPath}"
        TargetRuleAuthorization.validateUrls(listOf(target))
        val service = request.httpService()
        require(service.host() == u.host && service.port() == port && service.secure() == (u.scheme == "https"))
        val hosts = request.headers().filter { it.name().equals("Host", true) }.map { it.value() }
        require(hosts.size == 1 && (hosts.single() == "${u.host}:$port" ||
            (port == (if (u.scheme == "https") 443 else 80) && hosts.single() == u.host)))
        require(request.path() == u.rawPath + (u.rawQuery?.let { "?$it" } ?: ""))
        require(api.scope().isInScope(request.url()) && targetPreparationEligible(target))
        target
    }.getOrNull()

    private fun targetFingerprint(request: HttpRequest): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(request.toByteArray().getBytes()).joinToString("") { "%02x".format(it) }

    // Budget exhaustion stops evaluation, but does not change the approved revision
    // of an already forwarded request. Keep it in the association identity until
    // pause/delete/expiry/revocation invalidates that identity. The evaluator still
    // selects ACTIVE rules only and enforces every consumed budget.
    private fun targetAssociationState(state: InterceptionRuleState): Boolean =
        state == InterceptionRuleState.ACTIVE || state == InterceptionRuleState.MAX_MATCHES ||
            state == InterceptionRuleState.MAX_MODIFICATIONS

    /** Bounded automatic path: no manual queue, network I/O, disclosure, drop or wait. */
    internal fun processTargetMessage(kind: String, original: HeldMessage, messageId: Int): HeldMessage {
        if (!targetSlots.tryAcquire()) return original
        try {
            if (SwingUtilities.isEventDispatchThread() || kind !in setOf("request", "response")) return original
            if ((kind == "request") != (original.message is HttpRequest)) return original
            if (kind == "response" && original.message !is HttpResponse) return original
            val target = exactTarget(original.request) ?: return original
            if (original.message.toByteArray().length() > InterceptionRuleEngine.MAX_MESSAGE_BYTES ||
                original.request.toByteArray().length() > InterceptionRuleEngine.MAX_MESSAGE_BYTES ||
                hasSensitiveContent(original.request, original.message)) return original
            val fingerprint = targetFingerprint(original.request)
            if (kind == "request" && original.message !== original.request) return original
            if (kind == "response" && original.message is InterceptedResponse &&
                targetFingerprint(original.message.initiatingRequest()) != fingerprint) return original
            val snapshot = synchronized(this) {
                val session = currentSessionId ?: return original
                val specs = ruleEngine.list().filter { targetAssociationState(it.state) && it.spec.targetUrl == target && targetExecutionEligible(it.id, it.spec) }
                    .associate { it.id to it.spec }
                if (specs.isEmpty()) return original
                val revisions = specs.mapValues { ruleEngine.authorizationRevision(it.key) }
                if (kind == "response") {
                    val associated = targetAssociations.remove(messageId) ?: return original
                    if (associated.session != session || associated.target != target || associated.fingerprint != fingerprint ||
                        associated.revisions != revisions) return original
                }
                Triple(session, specs, revisions)
            }
            val input = toRuleHttpMessage(kind, original, "target-$messageId") ?: return original
            val evaluation = ruleEngine.evaluate(input)
            fun release(output: HeldMessage): HeldMessage {
                val outputFingerprint = targetFingerprint(output.request)
                check(exactTarget(output.request) == target && !hasSensitiveContent(output.request, output.message))
                check(output.message.toByteArray().length() <= InterceptionRuleEngine.MAX_MESSAGE_BYTES)
                check(currentSessionId == snapshot.first && snapshot.second.all { (id, spec) ->
                    targetExecutionEligible(id, spec) && ruleEngine.get(id).let { targetAssociationState(it.state) && it.spec == spec } &&
                        ruleEngine.authorizationRevision(id) == snapshot.third[id]
                }) { "Target authorization changed" }
                val releaseRevisions = snapshot.third
                return targetRuleAuthorizations.commit(snapshot.second, snapshot.first) {
                    check(targetSessionHealthy() && currentSessionId == snapshot.first)
                    if (kind == "request") {
                        while (targetAssociations.size >= 128) targetAssociations.remove(targetAssociations.keys.first())
                        targetAssociations[messageId] = TargetAssociation(snapshot.first, target, outputFingerprint,
                            releaseRevisions)
                    }
                    output
                }
            }
            return synchronized(this) {
                if (evaluation == null) {
                    // Response-only rules still need a request association; the request continues unchanged.
                    if (kind == "request") release(original) else original
                } else if (evaluation.status != RuleEvaluationStatus.READY || evaluation.action == RuleAction.DROP) {
                    ruleEngine.finish(evaluation, "SKIPPED", "NONE", "TARGET_ACTION_NOT_AUTHORIZED")
                    original
                } else ruleEngine.commit(evaluation) {
                    check(currentSessionId == snapshot.first && snapshot.second.all { (id, spec) -> targetExecutionEligible(id, spec) })
                    val output = if (evaluation.changed) applyRuleOutput(original, evaluation.output) else original
                    check(RequestRateLimiter.tryAcquire()) { "Request rate limit exceeded" }
                    release(output)
                } ?: original
            }
        } catch (_: Exception) {
            ActivityLog.record("target_rule", "skipped", "TARGET_POLICY_OR_ASSOCIATION_REJECTED")
            return original
        } finally { targetSlots.release() }
    }
    @Volatile var enabled = false; private set
    @Volatile var allowEdits = false
    @Volatile var timeoutSeconds = config.interceptionTimeoutSeconds; private set
    @Volatile var configuredSessionLifetimeSeconds = DEFAULT_SESSION_LIFETIME_SECONDS; private set
    @Volatile private var lastClientNanos = nanoTime()
    @Volatile private var lastHeartbeatNanos: Long? = null
    @Volatile private var nextHeartbeatNanos: Long? = null
    @Volatile private var sessionDeadlineNanos: Long? = null
    @Volatile private var sessionDeadlineEpochMillis: Long? = null
    @Volatile private var lastHeartbeatEpochMillis: Long? = null
    @Volatile private var currentSessionId: String? = null
    @Volatile private var heartbeatHealth = "STOPPED"
    @Volatile private var sessionEndReason = "NONE"
    @Volatile private var closed = false
    private val reviewPermit = Semaphore(1)
    private val unattendedMode = UnattendedLocalTestMode()
    private val reviewJobs = ConcurrentHashMap<String, Job>()
    private val disclosureJobs = ConcurrentHashMap<String, Job>()
    private val disclosureScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val registrations = mutableListOf<Registration>()
    private val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "burp-mcp-interception-expiry").apply { isDaemon = true } }

    fun install() {
        registrations += api.scope().registerScopeChangeHandler { targetPolicyChanged() }
        registrations += api.proxy().registerRequestHandler(object : ProxyRequestHandler {
            override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction {
                val mode = callbackMode()
                if (mode != 1) {
                    val result = if (mode == 2) processTargetMessage("request", HeldMessage(request, request), request.messageId()) else HeldMessage(request, request)
                    return ProxyRequestReceivedAction.continueWith(result.message as HttpRequest)
                }
                val skip = captureSkipReason(request, request)
                if (skip != null) {
                    logCaptureSkip("request", request, skip)
                    return if (skip.mustDrop) ProxyRequestReceivedAction.drop()
                        else ProxyRequestReceivedAction.continueWith(request)
                }
                val result = runCatching { hold("request", HeldMessage(request, request)) }.getOrElse {
                    ActivityLog.record("intercept_request", "dropped", it.javaClass.simpleName); null
                }
                return if (result == null) ProxyRequestReceivedAction.drop()
                    else ProxyRequestReceivedAction.doNotIntercept(result.message as HttpRequest)
            }
            override fun handleRequestToBeSent(request: InterceptedRequest) = ProxyRequestToBeSentAction.continueWith(request)
        })
        registrations += api.proxy().registerResponseHandler(object : ProxyResponseHandler {
            override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
                val request = response.initiatingRequest()
                val mode = callbackMode()
                if (mode != 1) {
                    val result = if (mode == 2) processTargetMessage("response", HeldMessage(response, request), response.messageId()) else HeldMessage(response, request)
                    return ProxyResponseReceivedAction.continueWith(result.message as HttpResponse)
                }
                val skip = captureSkipReason(response, request)
                if (skip != null) {
                    logCaptureSkip("response", request, skip)
                    return if (skip.mustDrop) ProxyResponseReceivedAction.drop()
                        else ProxyResponseReceivedAction.continueWith(response)
                }
                val result = runCatching { hold("response", HeldMessage(response, request)) }.getOrElse {
                    ActivityLog.record("intercept_response", "dropped", it.javaClass.simpleName); null
                }
                return if (result == null) ProxyResponseReceivedAction.drop()
                    else ProxyResponseReceivedAction.doNotIntercept(result.message as HttpResponse)
            }
            override fun handleResponseToBeSent(response: InterceptedResponse) = ProxyResponseToBeSentAction.continueWith(response)
        })
        timer.scheduleAtFixedRate({
            runCatching {
                synchronized(this) { expireUnattendedModeLocked() }
                queue.expire()
                ruleEngine.tick()
                heartbeatTick()
            }.onFailure { ActivityLog.record("intercept_expiry", "error", it.javaClass.simpleName) }
        }, 1, 1, TimeUnit.SECONDS)
    }

    @Synchronized fun touch() { lastClientNanos = nanoTime() }

    @Synchronized fun setConfiguredSessionLifetime(seconds: Int) {
        require(seconds in MIN_SESSION_LIFETIME_SECONDS..MAX_SESSION_LIFETIME_SECONDS) {
            "Session lifetime must be between $MIN_SESSION_LIFETIME_SECONDS and $MAX_SESSION_LIFETIME_SECONDS seconds"
        }
        configuredSessionLifetimeSeconds = seconds
    }

    fun validateSessionLifetime(seconds: Int) {
        require(seconds in MIN_SESSION_LIFETIME_SECONDS..MAX_SESSION_LIFETIME_SECONDS) {
            "Session lifetime must be between $MIN_SESSION_LIFETIME_SECONDS and $MAX_SESSION_LIFETIME_SECONDS seconds"
        }
    }

    /** Call only after a local Burp confirmation or an explicit local UI confirmation. */
    @Synchronized fun startApprovedSession(seconds: Int = configuredSessionLifetimeSeconds) {
        check(!closed) { "Extension has unloaded" }
        check(config.requireBearerToken) { "Enable MCP bearer authentication before live interception" }
        validateSessionLifetime(seconds)
        if (enabled) endSession("SESSION_REPLACED")
        targetSession = false
        targetAssociations.clear()
        val nowNanos = nanoTime()
        val nowMillis = System.currentTimeMillis()
        val durationNanos = TimeUnit.SECONDS.toNanos(seconds.toLong())
        configuredSessionLifetimeSeconds = seconds
        enabled = true
        currentSessionId = UUID.randomUUID().toString()
        unattendedMode.bindSession(currentSessionId!!)
        sessionDeadlineNanos = nowNanos + durationNanos
        sessionDeadlineEpochMillis = nowMillis + TimeUnit.NANOSECONDS.toMillis(durationNanos)
        lastHeartbeatNanos = nowNanos
        nextHeartbeatNanos = nowNanos + TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS.toLong())
        lastHeartbeatEpochMillis = nowMillis
        lastClientNanos = nowNanos
        heartbeatHealth = "HEALTHY"
        sessionEndReason = "NONE"
        ActivityLog.record("intercept_session", "approved", "lifetime=${seconds}s; heartbeat=${HEARTBEAT_INTERVAL_SECONDS}s")
    }

    fun setTimeout(seconds: Int) {
        require(seconds in MIN_MESSAGE_TIMEOUT_SECONDS..MAX_MESSAGE_TIMEOUT_SECONDS) {
            "Per-message timeout must be between $MIN_MESSAGE_TIMEOUT_SECONDS and $MAX_MESSAGE_TIMEOUT_SECONDS seconds"
        }
        config.interceptionTimeoutSeconds = seconds
        timeoutSeconds = seconds
    }

    @Synchronized fun disable(reason: String = "DISABLED") { endSession(reason) }

    @Synchronized fun cancel(reason: String = "CANCELLED") {
        endSession(reason)
    }

    @Synchronized internal fun heartbeatTick(nowNanos: Long = nanoTime()) {
        if (!enabled) return
        if (!config.requireBearerToken) { endSession("AUTHENTICATION_DISABLED"); return }
        val deadline = sessionDeadlineNanos
        if (deadline == null || nowNanos >= deadline) { endSession("SESSION_EXPIRED"); return }

        val last = lastHeartbeatNanos ?: nowNanos
        if (nowNanos - last >= TimeUnit.SECONDS.toNanos(CLIENT_LEASE_SECONDS.toLong())) {
            endSession("HEARTBEAT_MISSED")
            return
        }
        val next = nextHeartbeatNanos ?: nowNanos
        if (nowNanos >= next) {
            lastHeartbeatNanos = nowNanos
            lastHeartbeatEpochMillis = System.currentTimeMillis()
            lastClientNanos = nowNanos
            nextHeartbeatNanos = nowNanos + TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS.toLong())
            heartbeatHealth = "HEALTHY"
        } else if (nowNanos - last > TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS * 2L)) {
            heartbeatHealth = "DEGRADED"
        }
    }

    @Synchronized fun health(nowNanos: Long = nanoTime()): InterceptionHealth {
        expireUnattendedModeLocked()
        val sessionDeadline = sessionDeadlineNanos
        val leaseExpiry = if (enabled) lastClientNanos + TimeUnit.SECONDS.toNanos(CLIENT_LEASE_SECONDS.toLong()) else null
        val sessionRemaining = sessionDeadline?.let { (it - nowNanos).coerceAtLeast(0) / 1_000_000 } ?: 0L
        val leaseRemaining = leaseExpiry?.let { (it - nowNanos).coerceAtLeast(0) / 1_000_000 } ?: 0L
        val nowMillis = System.currentTimeMillis()
        fun epochFor(deadline: Long?): Long? = deadline?.let { nowMillis + ((it - nowNanos) / 1_000_000).coerceAtLeast(0) }
        return InterceptionHealth(
            enabled = enabled,
            heartbeatHealth = heartbeatHealth,
            sessionLifetimeSeconds = configuredSessionLifetimeSeconds,
            heartbeatIntervalSeconds = HEARTBEAT_INTERVAL_SECONDS,
            sessionRemainingMillis = sessionRemaining,
            sessionExpiresAtEpochMillis = if (enabled) sessionDeadlineEpochMillis else null,
            leaseRemainingMillis = leaseRemaining,
            leaseExpiresAtEpochMillis = epochFor(leaseExpiry),
            lastHeartbeatAtEpochMillis = if (enabled) lastHeartbeatEpochMillis else null,
            sessionEndReason = sessionEndReason,
            pendingRequests = queue.list("request").size,
            pendingResponses = queue.list("response").size,
            queueCapacity = QUEUE_CAPACITY
        )
    }

    private fun endSession(reason: String) {
        val wasActive = enabled
        enabled = false
        targetSession = false
        targetAssociations.clear()
        targetRuleAuthorizations.revokeAll()
        heartbeatHealth = when (reason) {
            "SESSION_EXPIRED", "HEARTBEAT_MISSED" -> "EXPIRED"
            else -> "STOPPED"
        }
        sessionEndReason = reason
        sessionDeadlineNanos = null
        sessionDeadlineEpochMillis = null
        unattendedMode.clearSessionBinding(currentSessionId)
        currentSessionId = null
        lastHeartbeatNanos = null
        nextHeartbeatNanos = null
        lastHeartbeatEpochMillis = null
        queue.cancelAll(reason)
        reviewJobs.values.toList().forEach { it.cancel(CancellationException("Interception session ended: $reason")) }
        reviewJobs.clear()
        disclosureJobs.values.toList().forEach { it.cancel(CancellationException("Interception session ended: $reason")) }
        disclosureJobs.clear()
        ruleEngine.pauseAll(if (reason == "UNATTENDED_EXPIRED") "AUTHORIZATION_EXPIRED" else reason)
        if (wasActive) ActivityLog.record("intercept_session", "ended", reason)
    }
    fun authorized(request: HttpRequest) = runCatching { isAuthorizedRequest(request, api, config) }.getOrDefault(false)

    // Read mode under the same monitor as start/stop/bind, never observing a half-bound session.
    private fun callbackMode(): Int = synchronized(this) {
        when { !enabled || closed -> 0; targetSession -> 2; else -> 1 }
    }

    private fun captureSkipReason(message: HttpMessage, request: HttpRequest): CaptureSkip? {
        if (!enabled) return CaptureSkip("live interception session is disabled", mustDrop = false)
        if (closed) return CaptureSkip("extension is unloading", mustDrop = false)
        authorizationSkipReason(request)?.let { return CaptureSkip(it, mustDrop = false) }
        if (SwingUtilities.isEventDispatchThread()) return CaptureSkip("Proxy callback is on Burp's UI thread; dropped to avoid bypassing local review", mustDrop = true)
        val messageBytes = runCatching { message.toByteArray().length() }.getOrNull()
            ?: return CaptureSkip("message size could not be read safely; dropped because it cannot enter bounded review", mustDrop = true)
        if (messageBytes > SafeContent.MAX_REQUEST_BYTES) {
            return CaptureSkip("message exceeds the ${SafeContent.MAX_REQUEST_BYTES}-byte interception limit; dropped because it cannot enter bounded review", mustDrop = true)
        }
        return null
    }

    private fun authorizationSkipReason(request: HttpRequest): String? {
        val service = runCatching { request.httpService() }.getOrNull()
            ?: return "HTTP service unavailable"
        if (!HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config)) return "host is not in the explicit allowlist"
        val url = runCatching { request.url() }.getOrNull()
            ?: return "request URL unavailable"
        if (!urlMatchesHttpService(url, service.host(), service.port())) return "URL does not match the HTTP service"
        if (!runCatching { api.scope().isInScope(url) }.getOrDefault(false)) return "target is outside Burp scope"
        return null
    }

    private fun logCaptureSkip(kind: String, request: HttpRequest, skip: CaptureSkip) {
        val metadata = requestMetadata(request)
        ActivityLog.record("intercept_$kind", if (skip.mustDrop) "dropped" else "skipped",
            "${metadata.method} ${metadata.hostname}${metadata.urlPath}; ${skip.reason}")
    }

    private fun hold(kind: String, value: HeldMessage): HeldMessage? {
        val ticket = synchronized(this) {
            // A callback selected under the former manual session must not enter its queue
            // after a newly approved target session has replaced that session.
            if (targetSession) return value
            if (!enabled || closed) {
                ActivityLog.record("intercept_capture", "dropped", "session ended before queue capture")
                return null
            }
            queue.offer(kind, value, timeoutSeconds * 1000L)
        }
        if (ticket == null) { ActivityLog.record("intercept_capture", "dropped", "queue capacity reached"); return null }
        val metadata = requestMetadata(value.request)
        ActivityLog.record("intercept_$kind", "captured", "id=${ticket.id} ${metadata.method} ${metadata.hostname}${metadata.urlPath}")
        runCatching { processMatchingRule(ticket) }.onFailure {
            ActivityLog.record("intercept_rule", "failed", it.javaClass.simpleName)
        }
        val result = queue.await(ticket) ?: return null
        // Scope and allowlist can change while the callback is waiting.
        if (!enabled || closed || !authorized(result.request) || (result.message !== value.message && (config.readOnlyMode || !allowEdits))) {
            ActivityLog.record("intercept_release", "dropped", "authorization or interception policy changed"); return null
        }
        return result
    }

    private data class AutoRuleRelease(val message: HeldMessage?, val dropped: Boolean)

    private fun processMatchingRule(ticket: DecisionQueue.Ticket<HeldMessage>) {
        val input = toRuleHttpMessage(ticket.kind, ticket.original, ticket.id) ?: return
        val evaluation = ruleEngine.evaluate(input) ?: return
        if (evaluation.status != RuleEvaluationStatus.READY) {
            ruleEngine.finish(evaluation, "SKIPPED", "MANUAL", evaluation.code ?: evaluation.status.name)
            ActivityLog.record("intercept_rule", "manual_required", evaluation.code ?: evaluation.status.name)
            return
        }
        synchronized(this) {
            ruleEngine.commit(evaluation) {
                expireUnattendedModeLocked()
                if (!enabled || closed || !config.requireBearerToken) throw RuleAuthorizationRequired("SESSION_AUTHORIZATION_INACTIVE")
                val authorization = unattendedMode.snapshot()
                if (!authorization.active || !unattendedMode.isBoundToSession(currentSessionId)) {
                    throw RuleAuthorizationRequired("LOCAL_AUTHORIZATION_INACTIVE")
                }
                if (config.readOnlyMode) throw RuleAuthorizationRequired("READ_ONLY_MODE")
                val current = runCatching { queue.get(ticket.id) }.getOrElse { throw RuleAuthorizationRequired("MESSAGE_NO_LONGER_PENDING") }
                if (current.kind != ticket.kind || current.revision != ticket.revision || current.proposed != null) {
                    throw RuleAuthorizationRequired("MESSAGE_REVISION_CHANGED")
                }
                if (hasSensitiveContent(current.original.request, current.original.message)) {
                    throw RuleAuthorizationRequired("SENSITIVE_CONTENT_REQUIRES_MANUAL_REVIEW")
                }
                if (evaluation.action == RuleAction.DROP) {
                    if (ticket.kind != "request") throw RuleAuthorizationRequired("RESPONSE_DROP_REQUIRES_LOCAL_REVIEW")
                    val decision = unattendedMode.decideAndCommit(policyContext(current, LocalTestOperation.DROP_REQUEST)) {
                        queue.drop(ticket.id)
                    }
                    if (decision.policy.decision != LocalTestPolicyDecision.AUTO_APPROVE) throw RuleAuthorizationRequired("DROP_NOT_AUTHORIZED")
                    AutoRuleRelease(null, dropped = true)
                } else {
                    var releaseTicket = current
                    if (evaluation.changed) {
                        if (!allowEdits) throw RuleAuthorizationRequired("LIVE_EDITS_DISABLED")
                        val edited = applyRuleOutput(current.original, evaluation.output)
                        if (hasSensitiveContent(if (edited.message is HttpRequest) edited.message else edited.request, edited.message)) {
                            throw RuleAuthorizationRequired("SENSITIVE_OUTPUT_REQUIRES_MANUAL_REVIEW")
                        }
                        val proposed = current.copy(
                            proposed = edited,
                            revision = current.revision + 1,
                            approvedRevision = null,
                            approvedBy = null
                        )
                        val proposalCommit = unattendedMode.decideAndCommit(policyContext(proposed, LocalTestOperation.PROPOSE_EDIT)) {
                            queue.propose(ticket.id, current.revision, edited)
                        }
                        if (proposalCommit.policy.decision != LocalTestPolicyDecision.AUTO_APPROVE) {
                            throw RuleAuthorizationRequired("MODIFICATION_NOT_AUTHORIZED")
                        }
                        val newRevision = proposalCommit.value ?: throw RuleAuthorizationRequired("PROPOSAL_NOT_COMMITTED")
                        releaseTicket = runCatching { queue.get(ticket.id) }.getOrElse { throw RuleAuthorizationRequired("MESSAGE_EXPIRED_AFTER_EDIT") }
                        check(newRevision == releaseTicket.revision)
                    }
                    val approval = unattendedMode.decideAndCommit(policyContext(releaseTicket, LocalTestOperation.APPROVE_REVISION)) {
                        queue.approve(ticket.id, releaseTicket.revision, UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
                    }
                    if (approval.policy.decision != LocalTestPolicyDecision.AUTO_APPROVE) throw RuleAuthorizationRequired("FORWARD_NOT_AUTHORIZED")
                    releaseTicket = runCatching { queue.get(ticket.id) }.getOrElse { throw RuleAuthorizationRequired("MESSAGE_EXPIRED_BEFORE_FORWARD") }
                    val operation = if (ticket.kind == "request") LocalTestOperation.FORWARD_REQUEST else LocalTestOperation.FORWARD_RESPONSE
                    val forwarding = unattendedMode.decideAndCommit(policyContext(releaseTicket, operation)) {
                        if (!RequestRateLimiter.tryAcquire()) {
                            queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
                            throw RuleAuthorizationRequired("REQUEST_RATE_LIMIT")
                        }
                        try { queue.forward(ticket.id, releaseTicket.revision) }
                        catch (error: Exception) {
                            queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
                            throw error
                        }
                    }
                    if (forwarding.policy.decision != LocalTestPolicyDecision.AUTO_APPROVE) {
                        queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
                        throw RuleAuthorizationRequired("FORWARD_AUTHORIZATION_EXPIRED")
                    }
                    AutoRuleRelease(releaseTicket.proposed ?: releaseTicket.original, dropped = false)
                }
            }
        }
    }

    private fun toRuleHttpMessage(kind: String, held: HeldMessage, messageId: String): RuleHttpMessage? = runCatching {
        val uri = URI(held.request.url())
        val path = uri.rawPath.ifBlank { "/" }
        val target = if (targetSession) exactTarget(held.request) ?: error("Target identity changed") else "${uri.scheme}://${uri.host}:${uri.port}$path"
        val message = held.message
        RuleHttpMessage(
            direction = if (kind == "request") RuleDirection.REQUEST else RuleDirection.RESPONSE,
            targetUrl = target,
            url = held.request.url(),
            method = held.request.method(),
            headers = message.headers().map { RuleHeader(it.name(), it.value()) },
            body = message.body().getBytes(),
            statusCode = (message as? HttpResponse)?.statusCode()?.toInt(),
            messageId = messageId
        )
    }.getOrNull()

    private fun applyRuleOutput(original: HeldMessage, output: RuleHttpMessage): HeldMessage {
        val before = original.message.headers().map { RuleHeader(it.name(), it.value()) }
        val changedNames = (before.map { it.name } + output.headers.map { it.name }).distinctBy { it.lowercase() }
            .filter { name -> before.filter { it.name.equals(name, true) }.map { it.value } != output.headers.filter { it.name.equals(name, true) }.map { it.value } }
        var request = original.request
        var message: HttpMessage = original.message
        if (message is HttpRequest) {
            val uri = URI(output.url)
            val pathAndQuery = uri.rawPath.ifBlank { "/" } + (uri.rawQuery?.let { "?$it" } ?: "")
            if (message.url() != output.url) message = message.withPath(pathAndQuery)
            var edited: HttpRequest = message
            if (!message.body().getBytes().contentEquals(output.body)) {
                val text = decodeRuleUtf8(output.body)
                edited = edited.withBody(text)
            }
            changedNames.forEach { name ->
                val values = output.headers.filter { it.name.equals(name, true) }.map { it.value }
                edited = edited.withRemovedHeader(name)
                values.forEach { value -> edited = edited.withAddedHeader(name, value) }
            }
            require(edited.httpService().host() == original.request.httpService().host() &&
                edited.httpService().port() == original.request.httpService().port() &&
                edited.httpService().secure() == original.request.httpService().secure()) { "Rule output changed the actual destination" }
            check(authorized(edited)) { "Rule output is no longer in Burp scope and the MCP allowlist" }
            check(edited.toByteArray().length() <= SafeContent.MAX_REQUEST_BYTES) { "Rule output exceeds the bounded message size" }
            validateMaterializedFraming(edited)
            request = edited
            message = edited
        } else if (message is HttpResponse) {
            var edited: HttpResponse = message
            if (!message.body().getBytes().contentEquals(output.body)) edited = edited.withBody(decodeRuleUtf8(output.body))
            changedNames.forEach { name ->
                val values = output.headers.filter { it.name.equals(name, true) }.map { it.value }
                edited = edited.withRemovedHeader(name)
                values.forEach { value -> edited = edited.withAddedHeader(name, value) }
            }
            check(edited.toByteArray().length() <= SafeContent.MAX_REQUEST_BYTES) { "Rule output exceeds the bounded message size" }
            validateMaterializedFraming(edited)
            message = edited
        }
        return HeldMessage(message, request)
    }

    private fun validateMaterializedFraming(message: HttpMessage) {
        val lengths = message.headers().filter { it.name().equals("Content-Length", true) }
        check(lengths.size <= 1) { "Rule output has ambiguous Content-Length framing" }
        if (lengths.isNotEmpty()) {
            val declared = lengths.single().value().toLongOrNull()
            check(declared != null && declared == message.body().getBytes().size.toLong()) { "Rule output Content-Length does not match its body" }
        }
        check(message.headers().none { it.name().equals("Transfer-Encoding", true) }) {
            "Rule output with unsupported Transfer-Encoding must remain under manual review"
        }
    }

    private fun decodeRuleUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        .decode(java.nio.ByteBuffer.wrap(bytes)).toString()

    fun snapshot(id: String, kind: String): DecisionQueue.Ticket<HeldMessage> {
        if (!config.requireBearerToken) { cancel("AUTHENTICATION_DISABLED"); error("Live interception requires bearer authentication") }
        val ticket = queue.get(id)
        check(ticket.kind == kind) { "Message has the wrong direction" }
        if (!authorized(ticket.original.request)) { queue.drop(id); error("Target authorization changed; message dropped") }
        return ticket
    }

    @Synchronized
    fun unattendedSnapshot(): UnattendedLocalTestSnapshot {
        expireUnattendedModeLocked()
        return unattendedMode.snapshot()
    }

    @Synchronized
    fun activateUnattendedLocalTestMode(seconds: Int = UnattendedLocalTestMode.DEFAULT_DURATION_SECONDS) {
        check(!closed) { "Extension has unloaded" }
        check(config.requireBearerToken) { "Enable MCP bearer authentication before unattended mode" }
        check(!config.readOnlyMode) { "Read-only mode must remain disabled for this local synthetic test action policy" }
        check(!enabled && queue.list("request").isEmpty() && queue.list("response").isEmpty()) {
            "Unattended mode can only be activated with interception stopped and both queues empty"
        }
        unattendedMode.activate(seconds)
        ruleEngine.freshHumanActivation()
        ActivityLog.record("unattended_local_test", "visible", "UI activation; duration=${seconds}s")
    }

    @Synchronized
    fun deactivateUnattendedLocalTestMode(reason: String = "USER_DISABLED"): Boolean {
        val wasActive = unattendedMode.deactivate(reason)
        queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
        if (wasActive) ruleEngine.pauseAll("AUTHORIZATION_DISABLED")
        return wasActive
    }

    @Synchronized
    fun emergencyStopUnattendedLocalTestMode() {
        deactivateUnattendedLocalTestMode("EMERGENCY_STOP")
        endSession("UNATTENDED_EMERGENCY_STOP")
        ruleEngine.emergencyStop()
    }

    @Synchronized
    fun unattendedManagementDecision(
        operation: LocalTestManagementOperation,
        requestedSessionLifetimeSeconds: Int? = null
    ): LocalTestPolicyResult {
        expireUnattendedModeLocked()
        val snapshot = unattendedMode.snapshot()
        val exactAllowlistOnly = config.getAutoApproveTargetsList().map { it.lowercase() } ==
            listOf(LocalTestTargets.ALLOWLIST_ENTRY.lowercase())
        val allLocalUrlsEligible = LocalTestTargets.urls.all { url ->
            val allowed = HttpRequestSecurity.isAllowedByHostAllowlist(LocalTestTargets.HOST, LocalTestTargets.PORT, config)
            allowed && runCatching { api.scope().isInScope(url) }.getOrDefault(false)
        }
        val health = health()
        return unattendedMode.decideManagement(
            LocalTestManagementContext(
                operation = operation,
                bearerAuthenticationEnabled = config.requireBearerToken,
                readOnlyMode = config.readOnlyMode,
                queuesEmpty = health.pendingRequests == 0 && health.pendingResponses == 0,
                sessionActive = health.enabled,
                sessionBoundToMode = unattendedMode.isBoundToSession(currentSessionId),
                exactLocalAllowlistOnly = exactAllowlistOnly,
                allLocalTestUrlsEligible = allLocalUrlsEligible && snapshot.active,
                requestedSessionLifetimeFitsMode = requestedSessionLifetimeSeconds == null ||
                    requestedSessionLifetimeSeconds * 1000L <= snapshot.remainingMillis
            )
        )
    }

    @Synchronized fun createInterceptionRule(spec: InterceptionRuleSpec): InterceptionRuleView {
        checkRuleBearerAndMode(spec)
        check(!enabled) { "Create or edit rules before starting the bounded interception session" }
        require(queue.list("request").isEmpty() && queue.list("response").isEmpty()) { "Both interception queues must be empty" }
        if (spec.targetUrl !in LocalTestTargets.urls && spec.targetUrl != LocalTestTargets.RULE_AUTHORITY_URL) {
            check(targetRuleAuthorizations.permits(spec)) { "Target authorization expired or changed" }
            return ruleEngine.create(spec)
        }
        val decision = unattendedManagementDecision(LocalTestManagementOperation.CONFIGURE_RULE)
        check(decision.decision == LocalTestPolicyDecision.AUTO_APPROVE) { "Rule configuration is not authorized: ${decision.reason}" }
        return ruleEngine.create(spec)
    }

    @Synchronized fun updateInterceptionRule(id: String, spec: InterceptionRuleSpec): InterceptionRuleView {
        checkRuleBearerAndMode(spec)
        check(!enabled) { "Rule configuration is allowed only before the session starts" }
        require(queue.list("request").isEmpty() && queue.list("response").isEmpty()) { "Both interception queues must be empty" }
        check(ruleEngine.get(id).state != InterceptionRuleState.ACTIVE) { "Pause a rule before updating it" }
        if (spec.targetUrl !in LocalTestTargets.urls && spec.targetUrl != LocalTestTargets.RULE_AUTHORITY_URL) {
            check(targetRuleAuthorizations.permits(spec)) { "Target authorization expired or changed" }
            return ruleEngine.update(id, spec)
        }
        val decision = unattendedManagementDecision(LocalTestManagementOperation.CONFIGURE_RULE)
        check(decision.decision == LocalTestPolicyDecision.AUTO_APPROVE) { "Rule configuration is not authorized: ${decision.reason}" }
        return ruleEngine.update(id, spec)
    }

    @Synchronized fun enableInterceptionRule(id: String): InterceptionRuleView {
        check(config.requireBearerToken && !config.readOnlyMode) { "Authenticated write access is required to enable a rule" }
        expireUnattendedModeLocked()
        val rule = ruleEngine.get(id)
        if (rule.spec.targetUrl !in LocalTestTargets.urls && rule.spec.targetUrl != LocalTestTargets.RULE_AUTHORITY_URL) {
            check(targetExecutionEligible(id, rule.spec)) { "Target rule lacks an approved session binding" }
            val duration = minOf(rule.spec.durationSeconds * 1000L, targetRuleAuthorizations.remainingMillis(rule.spec.authorizationReference),
                ((sessionDeadlineNanos ?: 0) - nanoTime()) / 1_000_000)
            check(duration > 0 && (allowEdits || rule.spec.action != RuleAction.MODIFY_AND_FORWARD))
            return ruleEngine.enable(id, duration)
        }
        val mode = unattendedMode.snapshot()
        check(mode.active && mode.testRunId == rule.spec.authorizationReference) { "Rule authorization reference does not match the active test run" }
        ruleEngine.validateForAuthorization(rule.spec)
        check(enabled && heartbeatHealth == "HEALTHY") { "A healthy approved interception session is required" }
        check(allowEdits || rule.spec.action != RuleAction.MODIFY_AND_FORWARD) { "Enable the existing local live-edit control before enabling a modification rule" }
        val health = health()
        check(health.pendingRequests == 0 && health.pendingResponses == 0) { "Both queues must be empty before enabling a rule" }
        val durationMillis = minOf(rule.spec.durationSeconds * 1000L, mode.remainingMillis, health.sessionRemainingMillis)
        check(durationMillis >= 1_000) { "Less than one second of session and authorization time remains" }
        val requestedSeconds = (durationMillis / 1000L).toInt().coerceAtLeast(1)
        val decision = unattendedManagementDecision(LocalTestManagementOperation.ENABLE_RULE, requestedSeconds)
        check(decision.decision == LocalTestPolicyDecision.AUTO_APPROVE) { "Rule activation is not authorized: ${decision.reason}" }
        return ruleEngine.enable(id, durationMillis)
    }

    fun disableInterceptionRule(id: String): InterceptionRuleView = ruleEngine.disable(id)
    fun deleteInterceptionRule(id: String): Boolean = ruleEngine.delete(id)
    fun clearInterceptionRules(): Int = ruleEngine.clear()
    fun clearInterceptionRuleStats(id: String? = null) = ruleEngine.clearStats(id)
    fun pauseAllInterceptionRules() = ruleEngine.pauseAll("USER_STOP")

    @Synchronized internal fun previewInterceptionRule(spec: InterceptionRuleSpec, message: RuleHttpMessage): InterceptionRulePreviewResult {
        check(config.requireBearerToken) { "Bearer authentication is required" }
        val mode = unattendedMode.snapshot()
        check(mode.active && mode.testRunId == spec.authorizationReference) { "Preview requires the current synthetic test-run identity" }
        ruleEngine.validateForAuthorization(spec)
        check(message.body.size <= UnattendedLocalTestMode.MAX_PAYLOAD_BYTES) { "Preview body exceeds the bounded local test size" }
        if (ruleMessageContainsSensitiveData(message)) throw IllegalArgumentException("Preview refuses credential-like or sensitive content")
        return ruleEngine.previewDetailed(spec, message)
    }

    private fun checkRuleBearerAndMode(spec: InterceptionRuleSpec) {
        check(config.requireBearerToken && !config.readOnlyMode) { "Authenticated write access with read-only mode disabled is required" }
        ruleEngine.validateForAuthorization(spec)
        if (spec.targetUrl !in LocalTestTargets.urls && spec.targetUrl != LocalTestTargets.RULE_AUTHORITY_URL) {
            check(targetRuleAuthorizations.permits(spec)) { "Target authorization missing or expired" }
            return
        }
        val mode = unattendedMode.snapshot()
        check(mode.active && mode.testRunId == spec.authorizationReference) { "Rule must reference the currently active synthetic test run" }
    }

    private fun ruleMessageContainsSensitiveData(message: RuleHttpMessage): Boolean {
        val sensitiveNames = Regex("(?i)(authorization|cookie|token|password|passwd|secret|session|credential|api[_-]?key)")
        val sensitiveValues = Regex("(?i)(bearer\\s+[A-Za-z0-9._~+/-]{8,}|basic\\s+[A-Za-z0-9+/=]{8,}|[\\\"']?(?:authorization|password|passwd|access[_-]?token|refresh[_-]?token|session[_-]?id|secret|cookie|credential|api[_-]?key)[\\\"']?\\s*[:=])")
        if (message.headers.any { sensitiveNames.containsMatchIn(it.name) || sensitiveValues.containsMatchIn(it.value) }) return true
        if (message.headers.any { it.name.equals("Content-Encoding", true) && !it.value.equals("identity", true) }) return true
        if (message.direction == RuleDirection.RESPONSE && (message.statusCode in 300..399 || message.headers.any { it.name.equals("Location", true) })) return true
        val urlQuery = runCatching { URI(message.url).rawQuery.orEmpty() }.getOrElse { return true }
        if (Regex("(?i)(^|[&;])(authorization|cookie|token|password|passwd|secret|session|credential|api[_-]?key)(=|&|;|$)")
                .containsMatchIn(runCatching { java.net.URLDecoder.decode(urlQuery, StandardCharsets.UTF_8) }.getOrElse { return true })) return true
        val body = runCatching { decodeRuleUtf8(message.body) }.getOrElse { return true }
        return sensitiveValues.containsMatchIn(body) || Regex("(?i)\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b").containsMatchIn(body)
    }

    private fun expireUnattendedModeLocked() {
        if (unattendedMode.expireIfDue()) {
            queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
            ruleEngine.pauseAll("AUTHORIZATION_EXPIRED")
        }
    }

    fun propose(id: String, kind: String, revision: Int, headers: Map<String, String>, removeHeaders: List<String>, body: String?, path: String?): Int {
        check(allowEdits && !config.readOnlyMode) { "Enable live edits locally and disable read-only mode first" }
        val ticket = snapshot(id, kind)
        require(headers.size + removeHeaders.size <= 50)
        val forbidden = setOf(
            "host", "content-length", "transfer-encoding", "connection", "upgrade",
            "authorization", "proxy-authorization", "cookie", "cookie2", "set-cookie"
        )
        (headers.keys + removeHeaders).forEach {
            require(it.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")) && it.lowercase() !in forbidden) { "Invalid or protected header" }
        }
        require(headers.values.all { it.length <= 8192 && '\r' !in it && '\n' !in it })
        require(body == null || body.toByteArray().size <= 65_536)
        val encoding=ticket.original.message.headerValue("Content-Encoding").orEmpty()
        require(body==null || encoding.isBlank() || encoding.equals("identity",true)) { "Text body replacement of compressed messages is unsupported" }
        require(path == null || (kind == "request" && path.startsWith("/") && !path.startsWith("//") && path.length <= 8192 && path.none { it.isWhitespace() }))
        // Patches always start from the original so omitted/redacted credentials are preserved locally.
        var message = ticket.original.message
        when (message) {
            is HttpRequest -> {
                var edited: HttpRequest = message
                removeHeaders.forEach { edited = edited.withRemovedHeader(it) }
                headers.forEach { (k,v) -> edited = edited.withHeader(k,v) }
                if (body != null) edited = edited.withBody(body)
                if (path != null) edited = edited.withPath(path)
                check(authorized(edited)) { "Proposed request is outside scope or its authorized service" }
                message = edited
            }
            is HttpResponse -> {
                var edited: HttpResponse = message
                removeHeaders.forEach { edited = edited.withRemovedHeader(it) }
                headers.forEach { (k,v) -> edited = if (edited.hasHeader(k)) edited.withUpdatedHeader(k,v) else edited.withAddedHeader(k,v) }
                if (body != null) edited = edited.withBody(body)
                message = edited
            }
        }
        require(message.toByteArray().length() <= SafeContent.MAX_REQUEST_BYTES)
        val proposed = HeldMessage(message, if (message is HttpRequest) message else ticket.original.request)
        return synchronized(this) {
            expireUnattendedModeLocked()
            if (unattendedMode.snapshot().active) {
                // When unattended mode is on, reject proposals that cannot be classified as
                // harmless exact-local test edits. The regular manually enabled edit workflow
                // is unchanged while the mode is off.
                val prospectiveRevision = ticket.copy(
                    proposed = proposed,
                    revision = ticket.revision + 1,
                    approvedRevision = null,
                    approvedBy = null
                )
                val decision = unattendedMode.decide(policyContext(prospectiveRevision, LocalTestOperation.PROPOSE_EDIT))
                check(decision.decision == LocalTestPolicyDecision.AUTO_APPROVE) {
                    "Unattended policy requires a manually supervised edit for this message: ${decision.reason}"
                }
            }
            queue.propose(id, revision, proposed)
        }
    }

    fun localReview(ticket: DecisionQueue.Ticket<HeldMessage>): String =
        "Message ${ticket.id}, ${ticket.kind}, revision ${ticket.revision}\n\nORIGINAL (local sensitive data)\n${ticket.original.message}\n\nPROPOSED\n${(ticket.proposed ?: ticket.original).message}"

    private suspend fun review(
        ticket: DecisionQueue.Ticket<HeldMessage>,
        message: String,
        options: Array<String>,
        title: String,
        requestContent: String? = localReview(ticket)
    ): Boolean {
        check(reviewPermit.tryAcquire()) { "Another live message is already under human review" }
        val job = currentCoroutineContext()[Job]
        if (job != null) reviewJobs[ticket.id] = job
        try {
            return withTimeout(((ticket.deadline-nanoTime())/1_000_000).coerceAtLeast(1)) {
                check(enabled && !closed) { "Interception was cancelled" }
                // Plain text preserves both messages exactly; do not parse the combined review as a request editor.
                Dialogs.requestOption(findBurpFrame(),message,options,requestContent,title=title)==0
            }
        } finally {
            if (job != null) reviewJobs.remove(ticket.id, job)
            reviewPermit.release()
        }
    }

    suspend fun requestApproval(id: String, kind: String, revision: Int) {
        check(!config.readOnlyMode) { "Read-only mode blocks forwarding approvals" }
        val ticket = snapshot(id, kind)
        check(ticket.revision == revision)
        val autoDecision = synchronized(this) {
            expireUnattendedModeLocked()
            val current = snapshot(id, kind)
            check(current.revision == revision)
            val result = unattendedMode.decide(policyContext(current, LocalTestOperation.APPROVE_REVISION))
            if (result.decision == LocalTestPolicyDecision.AUTO_APPROVE) {
                approveLocally(id, kind, revision, UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
            }
            result
        }
        if (autoDecision.decision == LocalTestPolicyDecision.AUTO_APPROVE) return
        if (autoDecision.decision == LocalTestPolicyDecision.DENY) error("Unattended policy denied this exact message revision: ${autoDecision.reason}")
        ActivityLog.record("intercept_approval", "prompted", "${ticket.kind} ${ticket.id} revision=$revision")
        val metadata = requestMetadata(ticket.original.request)
        val approved = review(ticket,
            "Review this exact live ${ticket.kind} revision locally. Approve forwarding once? The AI cannot approve it.\n\n" +
                "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                "${((ticket.deadline - nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000}s hold time remains.",
            arrayOf("Approve once", "Deny"),
            "Approve live request forwarding")
        if (!approved) { ActivityLog.record("intercept_approve", "denied", id); error("User denied approval") }
        approveLocally(id, kind, revision)
    }
    suspend fun dropWithLocalApproval(id: String, kind: String) {
        check(!config.readOnlyMode) { "Read-only mode blocks dropping intercepted messages" }
        val ticket = snapshot(id, kind)
        val autoDecision = synchronized(this) {
            expireUnattendedModeLocked()
            val current = snapshot(id, kind)
            val operation = if (kind == "request") LocalTestOperation.DROP_REQUEST else null
            val result = unattendedMode.decide(policyContext(current, operation))
            if (result.decision == LocalTestPolicyDecision.AUTO_APPROVE) {
                check(current.revision == ticket.revision) { "Message revision changed during unattended drop decision" }
                queue.drop(id)
            }
            result
        }
        if (autoDecision.decision == LocalTestPolicyDecision.AUTO_APPROVE) return
        if (autoDecision.decision == LocalTestPolicyDecision.DENY) error("Unattended policy denied this message drop: ${autoDecision.reason}")
        val metadata = requestMetadata(ticket.original.request)
        val remaining = ((ticket.deadline - nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000
        ActivityLog.record("intercept_drop_approval", "prompted", "${ticket.kind} ${ticket.id} revision=${ticket.revision}")
        val approved = review(
            ticket,
            "An MCP client requested that this held ${ticket.kind} be dropped. Confirm this exact message?\n\n" +
                "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                "$remaining seconds hold time remain. Dropping a response cannot undo the upstream request.",
            arrayOf("Drop this message", "Keep pending"),
            "Approve intercepted message drop",
            requestContent = null
        )
        if (!approved) {
            ActivityLog.record("intercept_drop_approval", "denied", "${ticket.kind} ${ticket.id} revision=${ticket.revision}")
            error("User denied dropping intercepted message")
        }
        val current = snapshot(id, kind)
        check(current.revision == ticket.revision) { "Message revision changed during drop approval" }
        queue.drop(id)
    }
    fun requestDisclosure(id:String,kind:String,revision:Int): String {
        val ticket=snapshot(id,kind)
        check(ticket.revision==revision)
        val autoDecision = synchronized(this) {
            expireUnattendedModeLocked()
            val current = snapshot(id, kind)
            check(current.revision == revision)
            val result = unattendedMode.decide(policyContext(current, LocalTestOperation.READ_DISCLOSURE))
            if (result.decision == LocalTestPolicyDecision.AUTO_APPROVE) queue.disclose(id, revision)
            result
        }
        if (autoDecision.decision == LocalTestPolicyDecision.AUTO_APPROVE) return "APPROVED"
        if (autoDecision.decision == LocalTestPolicyDecision.DENY) error("Unattended policy denied this disclosure: ${autoDecision.reason}")
        val request = queue.beginDisclosureRequest(id, revision)
        if (!request.shouldPrompt) return request.status

        val job = disclosureScope.launch(start = CoroutineStart.LAZY) {
            try {
                val metadata = requestMetadata(ticket.original.request)
                val approved = review(
                    ticket,
                    "Allow this exact request revision to be sent to the external model as a redacted preview?\n\n" +
                        "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                        "The preview includes headers and a bounded body. Common credentials are redacted, but application-specific secrets may remain. Review the LOCAL raw content first.",
                    arrayOf("Share redacted preview once", "Deny"),
                    "Approve request disclosure"
                )
                if (approved) {
                    snapshot(id, kind)
                    queue.completeDisclosureRequest(id, revision, "APPROVED")
                } else {
                    queue.completeDisclosureRequest(id, revision, "DENIED")
                }
            } catch (_: TimeoutCancellationException) {
                queue.completeDisclosureRequest(id, revision, "EXPIRED")
                ActivityLog.record("intercept_disclosure", "expired", "$id revision=$revision")
            } catch (error: CancellationException) {
                queue.completeDisclosureRequest(id, revision, "CANCELLED")
                throw error
            } catch (error: Exception) {
                val busy = error.message?.contains("already under human review", ignoreCase = true) == true
                queue.completeDisclosureRequest(id, revision, if (busy) "BUSY" else "ERROR")
                if (!busy) ActivityLog.record("intercept_disclosure", "error", "$id ${error.javaClass.simpleName}")
            }
        }
        disclosureJobs[id] = job
        job.invokeOnCompletion { disclosureJobs.remove(id, job) }
        job.start()
        return "PENDING"
    }
    fun approveLocally(id: String, kind: String, revision: Int, approvedBy: String = "HUMAN") {
        val ticket = snapshot(id, kind)
        check(!config.readOnlyMode && (ticket.proposed == null || allowEdits)) { "Read-only mode or edit policy blocks approval" }
        queue.approve(id, revision, approvedBy)
    }
    @Synchronized fun forward(id: String, kind: String, revision: Int) {
        expireUnattendedModeLocked()
        val ticket = snapshot(id, kind)
        check(!config.readOnlyMode && (ticket.proposed == null || allowEdits))
        check(authorized((ticket.proposed ?: ticket.original).request))
        check(RequestRateLimiter.tryAcquire()) { "Request rate limit exceeded" }
        if (ticket.approvedBy == UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE) {
            val operation = if (kind == "request") LocalTestOperation.FORWARD_REQUEST else LocalTestOperation.FORWARD_RESPONSE
            val decision = unattendedMode.decide(policyContext(ticket, operation))
            if (decision.decision != LocalTestPolicyDecision.AUTO_APPROVE) {
                queue.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
                error("Unattended forwarding authorization expired or no longer matches policy")
            }
        }
        queue.forward(id, revision)
    }

    private fun policyContext(
        ticket: DecisionQueue.Ticket<HeldMessage>,
        operation: LocalTestOperation?
    ): LocalTestPolicyContext {
        val heldRequest = ticket.original.request
        val message = ticket.proposed?.message ?: ticket.original.message
        // Authorization must classify the exact message revision that may be forwarded.
        // For requests, a proposed path or header change must never inherit the original URL's eligibility.
        val effectiveRequest = (message as? HttpRequest) ?: heldRequest
        val service = runCatching { heldRequest.httpService() }.getOrNull()
        val effectiveService = runCatching { effectiveRequest.httpService() }.getOrNull()
        val destinationIdentityConsistent = service != null && effectiveService != null &&
            runCatching {
                service.host() == effectiveService.host() &&
                    service.port() == effectiveService.port() &&
                    service.secure() == effectiveService.secure()
            }.getOrDefault(false)
        val hostHeaders = runCatching { effectiveRequest.headers().filter { it.name().equals("Host", true) }.map { it.value() } }.getOrNull()
        val health = health()
        val runIdValues = runCatching { effectiveRequest.headers().filter { it.name().equals("X-MCP-Test-Run", true) }.map { it.value() } }.getOrNull()
        val serverIdentityValues = runCatching { effectiveRequest.headers().filter { it.name().equals("X-MCP-Server-Identity", true) }.map { it.value() } }.getOrNull()
        val testCaseValues = runCatching { effectiveRequest.headers().filter { it.name().equals("X-MCP-Test-ID", true) }.map { it.value() } }.getOrNull()
        val state = when {
            ticket.approvedRevision == ticket.revision -> "APPROVED"
            ticket.proposed != null -> "PROPOSED"
            else -> "PENDING"
        }
        val bodyBytes = runCatching { message.toByteArray().length() }.getOrNull()
        return LocalTestPolicyContext(
            operation = operation,
            sessionId = currentSessionId,
            sessionActive = health.enabled,
            heartbeatHealthy = health.heartbeatHealth == "HEALTHY",
            sessionRemainingMillis = health.sessionRemainingMillis,
            messageId = ticket.id,
            revision = ticket.revision,
            messageState = state,
            messageApproved = ticket.approvedRevision == ticket.revision,
            messageRemainingMillis = ((ticket.deadline - nanoTime()).coerceAtLeast(0) / 1_000_000),
            pendingMessageCount = health.pendingRequests + health.pendingResponses,
            destinationHost = service?.host(),
            destinationPort = service?.port(),
            secure = service?.secure(),
            destinationIdentityConsistent = destinationIdentityConsistent,
            url = runCatching { effectiveRequest.url() }.getOrNull(),
            hostHeaderValues = hostHeaders,
            method = runCatching { effectiveRequest.method() }.getOrNull(),
            messageKind = ticket.kind,
            testRunId = runIdValues?.singleOrNull(),
            serverIdentity = serverIdentityValues?.singleOrNull(),
            testCaseId = testCaseValues?.singleOrNull(),
            burpScopeEligible = runCatching { api.scope().isInScope(effectiveRequest.url()) }.getOrDefault(false),
            mcpAllowlistEligible = service?.let { HttpRequestSecurity.isAllowedByHostAllowlist(it.host(), it.port(), config) } == true &&
                effectiveService?.let { HttpRequestSecurity.isAllowedByHostAllowlist(it.host(), it.port(), config) } == true,
            containsCredentials = hasSensitiveContent(effectiveRequest, message),
            payloadBytes = bodyBytes
        )
    }

    internal fun hasSensitiveContent(request: HttpRequest, message: HttpMessage): Boolean {
        val sensitiveName = Regex("(?i)(authorization|cookie|token|password|passwd|secret|session|credential|api[_-]?key)")
        val sensitiveValue = Regex("(?i)(bearer\\s+[A-Za-z0-9._~+/-]{8,}|basic\\s+[A-Za-z0-9+/=]{8,}|[\\\"']?(?:authorization|password|passwd|access[_-]?token|refresh[_-]?token|session[_-]?id|secret|cookie|credential|api[_-]?key|client[_-]?secret)[\\\"']?\\s*[:=])")
        val jwtValue = Regex("(?i)\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b")
        fun containsSensitiveValue(value: String) = sensitiveValue.containsMatchIn(value) || jwtValue.containsMatchIn(value)
        val requestHeaders = runCatching { request.headers() }.getOrElse { return true }
        val messageHeaders = if (message !== request) {
            runCatching { message.headers() }.getOrElse { return true }
        } else emptyList()
        val allHeaders = requestHeaders + messageHeaders
        if (allHeaders.any { sensitiveName.containsMatchIn(it.name()) }) return true
        if (allHeaders.any { containsSensitiveValue(it.value()) }) return true
        if (allHeaders.any {
                it.name().equals("Content-Encoding", true) &&
                    it.value().split(',').any { encoding -> encoding.isNotBlank() && !encoding.trim().equals("identity", true) }
            }) return true
        val query = runCatching { URI(request.url()).rawQuery }.getOrElse { return true }.orEmpty()
        val decodedQuery = runCatching { java.net.URLDecoder.decode(query, StandardCharsets.UTF_8) }.getOrElse { return true }
        if (Regex("(?i)(^|[&;])(authorization|cookie|token|password|passwd|secret|session|credential|api[_-]?key)(=|&|;|$)")
                .containsMatchIn(decodedQuery)) return true
        if (containsSensitiveValue(decodedQuery)) return true
        if (message is HttpResponse && (message.statusCode().toInt() in 300..399 || message.hasHeader("Location"))) return true
        val bytes = runCatching { message.body().getBytes() }.getOrNull() ?: return true
        val asciiView = String(bytes, StandardCharsets.ISO_8859_1)
        return containsSensitiveValue(asciiView)
    }
    override fun close() {
        synchronized(this) { closed = true; endSession("UNLOADED") }
        disclosureScope.cancel()
        timer.shutdownNow()
        targetPolicyListener.remove()
        registrations.forEach { runCatching { it.deregister() } }
        registrations.clear()
    }
}
