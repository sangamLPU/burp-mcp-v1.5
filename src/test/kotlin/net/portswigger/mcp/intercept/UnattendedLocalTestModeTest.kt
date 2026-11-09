package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.security.ActivityLog
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class UnattendedLocalTestModeTest {
    private val now = AtomicLong(1_000_000_000L)
    private val mode = UnattendedLocalTestMode(
        nanoTime = now::get,
        identityFactory = { "11111111-2222-3333-4444-555555555555" to "A".repeat(43) }
    )

    @AfterEach
    fun cleanup() {
        mode.deactivate("TEST_CLEANUP")
        ActivityLog.clear()
    }

    private fun start() {
        mode.activate()
        mode.bindSession("session-1")
    }

    private fun context(
        operation: LocalTestOperation? = LocalTestOperation.APPROVE_REVISION,
        testCaseId: String = "phase4a-case-1",
        messageId: String = "message-1",
        revision: Int? = 0,
        state: String? = "PENDING",
        approved: Boolean = false,
        url: String = "http://127.0.0.1:8000/test-cancel",
        host: String? = "127.0.0.1",
        port: Int? = 8000,
        secure: Boolean? = false,
        destinationIdentityConsistent: Boolean = true,
        hostHeaders: List<String>? = listOf("127.0.0.1:8000"),
        method: String? = "GET",
        kind: String? = "request",
        pending: Int = 1,
        sessionId: String? = "session-1",
        sessionActive: Boolean = true,
        heartbeat: Boolean = true,
        sessionRemaining: Long = 90_000,
        messageRemaining: Long = 30_000,
        runId: String? = mode.snapshot().testRunId,
        serverIdentity: String? = mode.snapshot().serverIdentity,
        scoped: Boolean = true,
        allowlisted: Boolean = true,
        credentials: Boolean = false,
        payloadBytes: Int? = 20
    ) = LocalTestPolicyContext(
        operation = operation,
        sessionId = sessionId,
        sessionActive = sessionActive,
        heartbeatHealthy = heartbeat,
        sessionRemainingMillis = sessionRemaining,
        messageId = messageId,
        revision = revision,
        messageState = state,
        messageApproved = approved,
        messageRemainingMillis = messageRemaining,
        pendingMessageCount = pending,
        destinationHost = host,
        destinationPort = port,
        secure = secure,
        destinationIdentityConsistent = destinationIdentityConsistent,
        url = url,
        hostHeaderValues = hostHeaders,
        method = method,
        messageKind = kind,
        testRunId = runId,
        serverIdentity = serverIdentity,
        testCaseId = testCaseId,
        burpScopeEligible = scoped,
        mcpAllowlistEligible = allowlisted,
        containsCredentials = credentials,
        payloadBytes = payloadBytes
    )

    @Test
    fun `mode is off by default and manual approval remains required`() {
        assertFalse(mode.snapshot().active)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context()).decision)
    }

    @Test
    fun `atomic policy commit does not run when authorization expires`() {
        start()
        val authorizedContext = context()
        var committed = false
        now.addAndGet(TimeUnit.SECONDS.toNanos(UnattendedLocalTestMode.MAX_DURATION_SECONDS.toLong() + 1))
        val result = mode.decideAndCommit(authorizedContext) { committed = true; "committed" }
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, result.policy.decision)
        assertNull(result.value)
        assertFalse(committed)
    }

    @Test
    fun `each activation receives fresh run and server identities`() {
        var generation = 0
        val freshMode = UnattendedLocalTestMode(
            nanoTime = now::get,
            identityFactory = {
                generation += 1
                "11111111-2222-3333-4444-${generation.toString().padStart(12, '0')}" to
                    (('A'.code + generation - 1).toChar().toString().repeat(43))
            }
        )
        try {
            freshMode.activate(60)
            val first = freshMode.snapshot()
            freshMode.deactivate("TEST_REACTIVATE")
            freshMode.activate(60)
            val second = freshMode.snapshot()

            assertNotEquals(first.testRunId, second.testRunId)
            assertNotEquals(first.serverIdentity, second.serverIdentity)
        } finally {
            freshMode.deactivate("TEST_CLEANUP")
        }
    }

    @Test
    fun `unattended activity log never records run or server identities`() {
        ActivityLog.clear()
        start()
        val snapshot = mode.snapshot()
        mode.decide(context())
        mode.decideManagement(LocalTestManagementContext(
            operation = LocalTestManagementOperation.START_SESSION,
            bearerAuthenticationEnabled = true,
            readOnlyMode = false,
            queuesEmpty = true,
            sessionActive = true,
            sessionBoundToMode = true,
            exactLocalAllowlistOnly = true,
            allLocalTestUrlsEligible = true,
            requestedSessionLifetimeFitsMode = true
        ))
        mode.deactivate("TEST_DISABLE")
        mode.activate(60)
        now.addAndGet(TimeUnit.SECONDS.toNanos(61))
        mode.snapshot()

        val details = ActivityLog.snapshot().joinToString("\n") { it.detail }
        assertFalse(details.contains(snapshot.testRunId.orEmpty()))
        assertFalse(details.contains(snapshot.serverIdentity.orEmpty()))
    }

    @Test
    fun `manual activation creates ephemeral run and server identities`() {
        mode.activate()
        val snapshot = mode.snapshot()
        assertTrue(snapshot.active)
        assertEquals(120_000, snapshot.remainingMillis)
        assertEquals("11111111-2222-3333-4444-555555555555", snapshot.testRunId)
        assertEquals("A".repeat(43), snapshot.serverIdentity)
        assertNull(mode.snapshot().let { if (it.active) null else it.testRunId })
    }

    @Test
    fun `unattended approvals require exact synthetic loopback context`() {
        start()
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context()).decision)
    }

    @Test
    fun `all nine exact synthetic URLs can qualify`() {
        start()
        LocalTestTargets.urls.forEachIndexed { index, url ->
            assertEquals(
                LocalTestPolicyDecision.AUTO_APPROVE,
                mode.decide(context(testCaseId = "case-$index", messageId = "message-$index", url = url)).decision,
                url
            )
        }
    }

    @Test
    fun `all permitted methods are accepted but wrong operation is not`() {
        start()
        listOf("GET", "POST", "PUT", "PATCH", "DELETE").forEachIndexed { index, method ->
            assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(
                testCaseId = "method-$index", messageId = "method-message-$index", method = method
            )).decision)
        }
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(
            testCaseId = "safe-edit", messageId = "safe-edit-message",
            operation = LocalTestOperation.PROPOSE_EDIT, state = "PROPOSED"
        )).decision)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context(
            testCaseId = "missing-op", messageId = "missing-op-message", operation = null
        )).decision)
    }

    @Test
    fun `outside host port scheme path aliases and host headers require manual approval`() {
        start()
        val invalid = listOf(
            context(testCaseId = "external", messageId = "external", host = "example.test"),
            context(testCaseId = "wrong-port", messageId = "wrong-port", port = 8080),
            context(testCaseId = "secure", messageId = "secure", secure = true),
            context(testCaseId = "mismatched-effective-destination", messageId = "mismatched-effective-destination", destinationIdentityConsistent = false),
            context(testCaseId = "wrong-host", messageId = "wrong-host", hostHeaders = listOf("localhost:8000")),
            context(testCaseId = "dup-host", messageId = "dup-host", hostHeaders = listOf("127.0.0.1:8000", "127.0.0.1:8000")),
            context(testCaseId = "alias", messageId = "alias", url = "http://localhost:8000/test-cancel"),
            context(testCaseId = "path", messageId = "path", url = "http://127.0.0.1:8000/test-cancel/"),
            context(testCaseId = "encoded", messageId = "encoded", url = "http://127.0.0.1:8000/test-cancel%2f.."),
            context(testCaseId = "userinfo", messageId = "userinfo", url = "http://user@127.0.0.1:8000/test-cancel"),
            context(testCaseId = "fragment", messageId = "fragment", url = "http://127.0.0.1:8000/test-cancel#x"),
            context(testCaseId = "scope", messageId = "scope", scoped = false),
            context(testCaseId = "allowlist", messageId = "allowlist", allowlisted = false)
        )
        invalid.forEach { assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(it).decision) }
    }

    @Test
    fun `invalid run identity credentials and oversized payload require manual approval`() {
        start()
        val invalid = listOf(
            context(testCaseId = "bad-run", messageId = "bad-run", runId = "other-run"),
            context(testCaseId = "bad-server", messageId = "bad-server", serverIdentity = "B".repeat(43)),
            context(testCaseId = "outside-edit", messageId = "outside-edit", operation = LocalTestOperation.PROPOSE_EDIT,
                state = "PROPOSED", url = "http://127.0.0.1:8000/outside"),
            context(testCaseId = "creds", messageId = "creds", credentials = true),
            context(testCaseId = "large", messageId = "large", payloadBytes = 65_537),
            context(testCaseId = "unknown-size", messageId = "unknown-size", payloadBytes = null),
            context(testCaseId = "contains space", messageId = "bad-case"),
            context(testCaseId = "bad-method", messageId = "bad-method", method = "CONNECT")
        )
        invalid.forEach { assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(it).decision) }
    }

    @Test
    fun `session heartbeat queue capacity deadlines and revisions are required`() {
        start()
        val invalid = listOf(
            context(testCaseId = "no-session", messageId = "no-session", sessionActive = false),
            context(testCaseId = "wrong-session", messageId = "wrong-session", sessionId = "old-session"),
            context(testCaseId = "heartbeat", messageId = "heartbeat", heartbeat = false),
            context(testCaseId = "session-expired", messageId = "session-expired", sessionRemaining = 0),
            context(testCaseId = "message-expired", messageId = "message-expired", messageRemaining = 0),
            context(testCaseId = "over-concurrent", messageId = "over-concurrent", pending = 3),
            context(testCaseId = "missing-id", messageId = "", revision = 0),
            context(testCaseId = "missing-revision", messageId = "missing-revision", revision = null),
            context(testCaseId = "stale-state", messageId = "stale-state", state = "DROPPED")
        )
        invalid.forEach { assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(it).decision) }
    }

    @Test
    fun `response forwarding requires an approved exact revision`() {
        start()
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context(
            operation = LocalTestOperation.FORWARD_RESPONSE,
            testCaseId = "response-unapproved", messageId = "response-unapproved", state = "PENDING"
        )).decision)
        val responseCase = "response-approved"
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(
            testCaseId = responseCase, messageId = "origin-request"
        )).decision)
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(
            operation = LocalTestOperation.FORWARD_RESPONSE,
            testCaseId = responseCase, messageId = "response-approved", state = "APPROVED", approved = true,
            kind = "response"
        )).decision)
    }

    @Test
    fun `duplicate decisions and duplicate forwarding are denied`() {
        start()
        val request = context()
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(request).decision)
        assertEquals(LocalTestPolicyDecision.DENY, mode.decide(request).decision)
        val forward = context(operation = LocalTestOperation.FORWARD_REQUEST, state = "APPROVED", approved = true)
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(forward).decision)
        assertEquals(LocalTestPolicyDecision.DENY, mode.decide(forward).decision)
    }

    @Test
    fun `mode expires and explicit deactivation revoke future automatic decisions`() {
        start()
        now.addAndGet(TimeUnit.SECONDS.toNanos(UnattendedLocalTestMode.DEFAULT_DURATION_SECONDS.toLong()))
        assertFalse(mode.snapshot().active)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context()).decision)
        mode.activate()
        mode.bindSession("session-1")
        assertTrue(mode.deactivate("EMERGENCY_STOP"))
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context()).decision)
    }

    @Test
    fun `request count cap and simultaneous duplicate decisions fail closed`() {
        start()
        repeat(UnattendedLocalTestMode.MAX_REQUESTS_PER_RUN) { index ->
            assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(
                testCaseId = "case-$index", messageId = "message-$index"
            )).decision)
        }
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decide(context(
            testCaseId = "case-over-cap", messageId = "message-over-cap"
        )).decision)

        mode.deactivate("TEST_RESET")
        mode.activate()
        mode.bindSession("session-1")
        val pool = Executors.newFixedThreadPool(4)
        try {
            val input = context(testCaseId = "race", messageId = "race")
            val results = (1..8).map { pool.submit<LocalTestPolicyDecision> { mode.decide(input).decision } }
                .map { it.get(2, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it == LocalTestPolicyDecision.AUTO_APPROVE })
            assertEquals(7, results.count { it == LocalTestPolicyDecision.DENY })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `duplicate request test case identity cannot be replayed under a new message ID`() {
        start()
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decide(context(messageId = "first-message")).decision)
        assertEquals(LocalTestPolicyDecision.DENY, mode.decide(context(messageId = "second-message")).decision)
    }

    @Test
    fun `management actions auto approve only under restricted mode policy`() {
        start()
        val startSession = LocalTestManagementContext(
            operation = LocalTestManagementOperation.START_SESSION,
            bearerAuthenticationEnabled = true,
            readOnlyMode = false,
            queuesEmpty = true,
            sessionActive = false,
            sessionBoundToMode = false,
            exactLocalAllowlistOnly = true,
            allLocalTestUrlsEligible = true,
            requestedSessionLifetimeFitsMode = true
        )
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decideManagement(startSession).decision)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decideManagement(startSession.copy(
            exactLocalAllowlistOnly = false
        )).decision)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decideManagement(startSession.copy(
            requestedSessionLifetimeFitsMode = false
        )).decision)
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decideManagement(startSession.copy(
            operation = LocalTestManagementOperation.CONFIGURE_LOCAL_SCOPE
        )).decision)
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE, mode.decideManagement(startSession.copy(
            operation = LocalTestManagementOperation.STOP_SESSION,
            sessionActive = true,
            sessionBoundToMode = true
        )).decision)
        assertEquals(LocalTestPolicyDecision.REQUIRE_MANUAL_APPROVAL, mode.decideManagement(startSession.copy(
            operation = LocalTestManagementOperation.STOP_SESSION,
            sessionActive = true,
            sessionBoundToMode = false
        )).decision)
    }
}
