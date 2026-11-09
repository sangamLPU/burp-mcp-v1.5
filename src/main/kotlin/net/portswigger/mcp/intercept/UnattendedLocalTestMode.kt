package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.security.ActivityLog
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

enum class LocalTestPolicyDecision { AUTO_APPROVE, REQUIRE_MANUAL_APPROVAL, DENY }

enum class LocalTestOperation {
    APPROVE_REVISION,
    FORWARD_REQUEST,
    FORWARD_RESPONSE,
    DROP_REQUEST,
    READ_DISCLOSURE,
    PROPOSE_EDIT
}

enum class LocalTestManagementOperation { START_SESSION, STOP_SESSION, CONFIGURE_LOCAL_SCOPE, CONFIGURE_RULE, ENABLE_RULE }

data class LocalTestPolicyContext(
    val operation: LocalTestOperation?,
    val sessionId: String?,
    val sessionActive: Boolean,
    val heartbeatHealthy: Boolean,
    val sessionRemainingMillis: Long,
    val messageId: String?,
    val revision: Int?,
    val messageState: String?,
    val messageApproved: Boolean,
    val messageRemainingMillis: Long,
    val pendingMessageCount: Int,
    val destinationHost: String?,
    val destinationPort: Int?,
    val secure: Boolean?,
    val destinationIdentityConsistent: Boolean,
    val url: String?,
    val hostHeaderValues: List<String>?,
    val method: String?,
    val messageKind: String?,
    val testRunId: String?,
    val serverIdentity: String?,
    val testCaseId: String?,
    val burpScopeEligible: Boolean,
    val mcpAllowlistEligible: Boolean,
    val containsCredentials: Boolean,
    val payloadBytes: Int?
)

data class LocalTestManagementContext(
    val operation: LocalTestManagementOperation,
    val bearerAuthenticationEnabled: Boolean,
    val readOnlyMode: Boolean,
    val queuesEmpty: Boolean,
    val sessionActive: Boolean,
    val sessionBoundToMode: Boolean,
    val exactLocalAllowlistOnly: Boolean,
    val allLocalTestUrlsEligible: Boolean,
    val requestedSessionLifetimeFitsMode: Boolean
)

data class LocalTestPolicyResult(val decision: LocalTestPolicyDecision, val reason: String)
data class LocalTestPolicyCommit<T>(val policy: LocalTestPolicyResult, val value: T?)

@Serializable
data class UnattendedLocalTestSnapshot(
    val active: Boolean,
    val configuredDurationSeconds: Int,
    val remainingMillis: Long,
    val testRunId: String?,
    val serverIdentity: String?,
    val maximumConcurrentMessages: Int,
    val maximumRequestsPerRun: Int,
    val maximumPayloadBytes: Int
)

/**
 * Process-local, fail-closed approval policy for synthetic loopback tests.
 * Activation data is deliberately never persisted and is discarded on expiry,
 * deactivation, or extension reload.
 */
class UnattendedLocalTestMode(
    private val nanoTime: () -> Long = System::nanoTime,
    private val identityFactory: () -> Pair<String, String> = ::newIdentities
) {
    companion object {
        const val DEFAULT_DURATION_SECONDS = 120
        const val MIN_DURATION_SECONDS = 60
        const val MAX_DURATION_SECONDS = 300
        const val MAX_CONCURRENT_MESSAGES = 2
        const val MAX_PENDING_MESSAGES = 8
        const val MAX_REQUESTS_PER_RUN = 32
        const val MAX_PAYLOAD_BYTES = 65_536
        const val AUTO_APPROVAL_SOURCE = "UNATTENDED_LOCAL_TEST"
        private val allowedMethods = setOf("GET", "POST", "PUT", "PATCH", "DELETE")
        private val allowedOperations = setOf(
            LocalTestOperation.APPROVE_REVISION,
            LocalTestOperation.FORWARD_REQUEST,
            LocalTestOperation.FORWARD_RESPONSE,
            LocalTestOperation.DROP_REQUEST,
            LocalTestOperation.READ_DISCLOSURE,
            LocalTestOperation.PROPOSE_EDIT
        )
        private val testCasePattern = Regex("^[A-Za-z0-9_-]{1,64}$")
    }

    private data class Activation(
        val runId: String,
        val serverIdentity: String,
        val durationSeconds: Int,
        val deadlineNanos: Long
    )

    private var activation: Activation? = null
    private var boundSessionId: String? = null
    private val approvedOperationKeys = linkedSetOf<String>()
    private val testCaseIds = linkedSetOf<String>()
    private val requestMessageByTestCase = linkedMapOf<String, String>()

    @Synchronized
    fun activate(durationSeconds: Int = DEFAULT_DURATION_SECONDS) {
        require(durationSeconds in MIN_DURATION_SECONDS..MAX_DURATION_SECONDS) {
            "Unattended local test mode duration must be between $MIN_DURATION_SECONDS and $MAX_DURATION_SECONDS seconds"
        }
        expireIfDueLocked()
        check(activation == null) { "Unattended local test mode is already active" }
        val (runId, serverIdentity) = identityFactory()
        require(runId.matches(Regex("^[a-f0-9-]{36}$")) && serverIdentity.matches(Regex("^[A-Za-z0-9_-]{43}$"))) {
            "Ephemeral test identity generation failed"
        }
        activation = Activation(
            runId = runId,
            serverIdentity = serverIdentity,
            durationSeconds = durationSeconds,
            deadlineNanos = nanoTime() + TimeUnit.SECONDS.toNanos(durationSeconds.toLong())
        )
        boundSessionId = null
        approvedOperationKeys.clear()
        testCaseIds.clear()
        requestMessageByTestCase.clear()
        ActivityLog.record("unattended_local_test", "activated", "duration=${durationSeconds}s")
    }

    @Synchronized
    fun deactivate(reason: String = "USER_DISABLED"): Boolean {
        expireIfDueLocked()
        if (activation == null) return false
        activation = null
        boundSessionId = null
        approvedOperationKeys.clear()
        testCaseIds.clear()
        requestMessageByTestCase.clear()
        ActivityLog.record("unattended_local_test", "disabled", "reason=$reason")
        return true
    }

    @Synchronized
    fun bindSession(sessionId: String) {
        expireIfDueLocked()
        if (activation != null && sessionId.isNotBlank()) boundSessionId = sessionId
    }

    @Synchronized
    fun clearSessionBinding(sessionId: String? = null) {
        if (sessionId == null || boundSessionId == sessionId) boundSessionId = null
    }

    @Synchronized
    fun isBoundToSession(sessionId: String?): Boolean {
        expireIfDueLocked()
        return sessionId != null && boundSessionId == sessionId
    }

    /** Called from the bounded once-per-second lifecycle tick. Returns true only on expiry. */
    @Synchronized
    fun expireIfDue(): Boolean = expireIfDueLocked()

    @Synchronized
    fun snapshot(): UnattendedLocalTestSnapshot {
        expireIfDueLocked()
        val current = activation
        val remaining = current?.let { (it.deadlineNanos - nanoTime()).coerceAtLeast(0) / 1_000_000 } ?: 0L
        return UnattendedLocalTestSnapshot(
            active = current != null,
            configuredDurationSeconds = current?.durationSeconds ?: DEFAULT_DURATION_SECONDS,
            remainingMillis = remaining,
            testRunId = current?.runId,
            serverIdentity = current?.serverIdentity,
            maximumConcurrentMessages = MAX_CONCURRENT_MESSAGES,
            maximumRequestsPerRun = MAX_REQUESTS_PER_RUN,
            maximumPayloadBytes = MAX_PAYLOAD_BYTES
        )
    }

    @Synchronized
    fun decide(context: LocalTestPolicyContext): LocalTestPolicyResult {
        expireIfDueLocked()
        val current = activation ?: return LocalTestPolicyResult(
            LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, "unattended mode is disabled or expired"
        )
        val reason = ineligibilityReason(current, context)
        if (reason != null) return audit(context, LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, reason)

        val operation = context.operation!!
        val messageId = context.messageId!!
        val revision = context.revision!!
        val testCaseId = context.testCaseId!!
        val key = "${operation.name}:$messageId:$revision"
        if (key in approvedOperationKeys) {
            return audit(context, LocalTestPolicyDecision.DENY, "duplicate automatic decision")
        }
        if (context.messageKind == "request") {
            val priorRequest = requestMessageByTestCase[testCaseId]
            if (priorRequest != null && priorRequest != messageId) {
                return audit(context, LocalTestPolicyDecision.DENY, "duplicate test-case request identity")
            }
            requestMessageByTestCase[testCaseId] = messageId
        } else if (context.messageKind == "response" && testCaseId !in requestMessageByTestCase) {
            return audit(context, LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, "response is not associated with an automatic test request")
        }
        if (testCaseId !in testCaseIds && testCaseIds.size >= MAX_REQUESTS_PER_RUN) {
            return audit(context, LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, "per-run request limit reached")
        }
        approvedOperationKeys += key
        testCaseIds += testCaseId
        while (approvedOperationKeys.size > MAX_REQUESTS_PER_RUN * 4) approvedOperationKeys.remove(approvedOperationKeys.first())
        return audit(context, LocalTestPolicyDecision.AUTO_APPROVE, "all synthetic-local policy checks passed")
    }

    /** Atomically evaluates and commits one short local queue mutation before the authorization lease can expire. */
    @Synchronized
    fun <T> decideAndCommit(context: LocalTestPolicyContext, action: () -> T): LocalTestPolicyCommit<T> {
        val decision = decide(context)
        if (decision.decision != LocalTestPolicyDecision.AUTO_APPROVE) return LocalTestPolicyCommit(decision, null)
        return LocalTestPolicyCommit(decision, action())
    }

    @Synchronized
    fun decideManagement(context: LocalTestManagementContext): LocalTestPolicyResult {
        expireIfDueLocked()
        val current = activation ?: return LocalTestPolicyResult(
            LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, "unattended mode is disabled or expired"
        )
        val commonFailure = when {
            !context.bearerAuthenticationEnabled -> "bearer authentication is disabled"
            context.readOnlyMode -> "read-only mode is enabled"
            !context.queuesEmpty -> "interception queues are not empty"
            else -> null
        }
        val reason = commonFailure ?: when (context.operation) {
            LocalTestManagementOperation.CONFIGURE_LOCAL_SCOPE -> if (context.sessionActive) {
                "scope setup requires an inactive interception session"
            } else null
            LocalTestManagementOperation.CONFIGURE_RULE -> when {
                context.sessionActive -> "rule configuration requires an inactive interception session"
                !context.exactLocalAllowlistOnly -> "the MCP allowlist is not restricted to the local test target"
                !context.allLocalTestUrlsEligible -> "the nine predefined localhost URLs are not all eligible"
                else -> null
            }
            LocalTestManagementOperation.ENABLE_RULE -> when {
                !context.sessionActive -> "an approved interception session is required to enable a rule"
                !context.sessionBoundToMode -> "the active interception session is not bound to this local authorization"
                !context.exactLocalAllowlistOnly -> "the MCP allowlist is not restricted to the local test target"
                !context.allLocalTestUrlsEligible -> "the nine predefined localhost URLs are not all eligible"
                !context.requestedSessionLifetimeFitsMode -> "rule duration exceeds remaining local authorization"
                else -> null
            }
            LocalTestManagementOperation.START_SESSION -> when {
                context.sessionActive -> "an interception session is already active"
                !context.exactLocalAllowlistOnly -> "the MCP allowlist is not restricted to the local test target"
                !context.allLocalTestUrlsEligible -> "the nine predefined localhost URLs are not all eligible"
                !context.requestedSessionLifetimeFitsMode -> "requested interception duration exceeds remaining unattended authorization"
                else -> null
            }
            LocalTestManagementOperation.STOP_SESSION -> when {
                !context.sessionActive -> "there is no active interception session"
                !context.sessionBoundToMode -> "the active session is not associated with this mode activation"
                else -> null
            }
        }
        if (reason != null) return ActivityLog.record(
            "unattended_local_test", "manual_required",
            "operation=${context.operation.name} sessionActive=${context.sessionActive}; $reason"
        ).let { LocalTestPolicyResult(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, reason) }
        ActivityLog.record(
            "unattended_local_test", "auto_approved",
            "operation=${context.operation.name} sessionActive=${context.sessionActive}; policy passed"
        )
        return LocalTestPolicyResult(LocalTestPolicyDecision.AUTO_APPROVE, "management policy passed")
    }

    private fun ineligibilityReason(current: Activation, context: LocalTestPolicyContext): String? {
        val operation = context.operation ?: return "operation is missing"
        if (operation !in allowedOperations) return "operation is not eligible for unattended approval"
        if (context.messageId.isNullOrBlank() || context.messageId.length > 64 || context.revision == null || context.revision < 0) {
            return "message identity or revision is missing"
        }
        if (context.sessionId.isNullOrBlank() || context.sessionId != boundSessionId || !context.sessionActive) {
            return "message is not attached to the active mode session"
        }
        if (!context.heartbeatHealthy || context.sessionRemainingMillis <= 0 || context.messageRemainingMillis <= 0) {
            return "session heartbeat or message deadline is not healthy"
        }
        if (context.pendingMessageCount !in 1..MAX_PENDING_MESSAGES || context.pendingMessageCount > MAX_CONCURRENT_MESSAGES) {
            return "pending-message or concurrency limit exceeded"
        }
        if (context.messageState !in setOf("PENDING", "PROPOSED", "APPROVED")) {
            return "message is not in a decision-eligible state"
        }
        if (context.messageApproved && operation == LocalTestOperation.APPROVE_REVISION) {
            return "message revision is already approved"
        }
        if (operation in setOf(LocalTestOperation.DROP_REQUEST, LocalTestOperation.READ_DISCLOSURE) &&
            context.messageState == "APPROVED") {
            return "message is already approved for forwarding"
        }
        if (operation == LocalTestOperation.FORWARD_REQUEST || operation == LocalTestOperation.FORWARD_RESPONSE) {
            if (context.messageState != "APPROVED" || !context.messageApproved) {
                return "exact message revision is not approved"
            }
        } else if (context.messageState == "APPROVED") {
            return "message is already approved for forwarding"
        }
        if (context.destinationHost != LocalTestTargets.HOST || context.destinationPort != LocalTestTargets.PORT || context.secure != false) {
            return "actual Burp destination is not the approved HTTP loopback target"
        }
        if (!context.destinationIdentityConsistent) return "effective request destination does not match the actual Burp destination"
        val path = canonicalAllowedPath(context.url) ?: return "URL is not a canonical predefined localhost test URL"
        if (context.hostHeaderValues != listOf("${LocalTestTargets.HOST}:${LocalTestTargets.PORT}")) {
            return "Host header is missing, duplicated, or inconsistent"
        }
        if (context.method !in allowedMethods) return "HTTP method is not allowed by unattended mode"
        if (context.messageKind !in setOf("request", "response")) return "message direction is missing"
        if (operation == LocalTestOperation.DROP_REQUEST && context.messageKind != "request") {
            return "only synthetic requests can be automatically dropped"
        }
        if (operation == LocalTestOperation.FORWARD_REQUEST && context.messageKind != "request") return "request operation has the wrong message direction"
        if (operation == LocalTestOperation.FORWARD_RESPONSE && context.messageKind != "response") return "response operation has the wrong message direction"
        if (context.testRunId != current.runId || context.serverIdentity != current.serverIdentity) {
            return "test-run or ephemeral server identity does not match this activation"
        }
        if (context.testCaseId.isNullOrBlank() || !testCasePattern.matches(context.testCaseId)) {
            return "synthetic test-case identity is missing or malformed"
        }
        if (!context.burpScopeEligible || !context.mcpAllowlistEligible) return "Burp scope or MCP allowlist check failed"
        if (context.containsCredentials) return "credential or session data detected"
        if (context.payloadBytes == null || context.payloadBytes !in 0..MAX_PAYLOAD_BYTES) {
            return "payload exceeds the unattended-mode size limit or is unmeasurable"
        }
        return null
    }

    private fun canonicalAllowedPath(url: String?): String? {
        if (url.isNullOrBlank() || url.length > 8_192) return null
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        if (uri.scheme != "http" || uri.userInfo != null || uri.rawFragment != null ||
            uri.host != LocalTestTargets.HOST || uri.port != LocalTestTargets.PORT ||
            uri.rawPath != uri.path || uri.rawPath !in LocalTestTargets.paths) return null
        val query = uri.rawQuery
        if (query != null) {
            val decoded = runCatching { URLDecoder.decode(query, StandardCharsets.UTF_8) }.getOrNull() ?: return null
            if (Regex("(?i)(^|[&;])(authorization|cookie|token|password|passwd|secret|session|credential|api[_-]?key)(=|&|;|$)")
                    .containsMatchIn(decoded)) return null
        }
        return uri.rawPath
    }

    private fun audit(
        context: LocalTestPolicyContext,
        decision: LocalTestPolicyDecision,
        reason: String
    ): LocalTestPolicyResult {
        val path = canonicalAllowedPath(context.url) ?: "[out-of-policy]"
        ActivityLog.record(
            "unattended_local_test",
            when (decision) {
                LocalTestPolicyDecision.AUTO_APPROVE -> "auto_approved"
                LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL -> "manual_required"
                LocalTestPolicyDecision.DENY -> "denied"
            },
            "operation=${context.operation?.name ?: "UNKNOWN"} path=$path " +
                "message=${context.messageId ?: "missing"} revision=${context.revision ?: -1} " +
                "sessionActive=${context.sessionActive}; $reason"
        )
        return LocalTestPolicyResult(decision, reason)
    }

    private fun expireIfDueLocked(): Boolean {
        val current = activation ?: return false
        if (nanoTime() < current.deadlineNanos) return false
        activation = null
        boundSessionId = null
        approvedOperationKeys.clear()
        testCaseIds.clear()
        requestMessageByTestCase.clear()
        ActivityLog.record("unattended_local_test", "expired", "authorization expired")
        return true
    }
}

private fun newIdentities(): Pair<String, String> {
    val bytes = ByteArray(32)
    SecureRandom().nextBytes(bytes)
    return UUID.randomUUID().toString() to Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
