package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.yield
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ApprovalTimeoutTest {
    @AfterEach
    fun cleanup() {
        unmockkObject(Dialogs)
    }

    @Test
    fun `an unanswered state change approval times out and cancels its prompt`() = runBlocking {
        ActivityLog.clear()
        val api = mockk<MontoyaApi>(relaxed = true)
        val config = mockk<McpConfig>()
        every { config.readOnlyMode } returns false
        mockkObject(Dialogs)
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } coAnswers {
            awaitCancellation()
        }

        val allowed = StateChangeSecurity.confirm(
            api, config, "test state change", "Synthetic test details", approvalTimeoutMillis = 50
        )

        assertFalse(allowed, "A timed-out approval must fail closed")
        coVerify(exactly = 1) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
        assertTrue(ActivityLog.snapshot().any { it.action == "approval" && it.outcome == "timed_out" })
    }

    @Test
    fun `caller cancellation is not converted into an approval denial`() = runBlocking {
        val request = async {
            ApprovalTimeout.await("synthetic cancellation", 5_000) { awaitCancellation() }
        }
        yield()
        request.cancelAndJoin()

        assertTrue(request.isCancelled)
    }

    @Test
    fun `caller's outer timeout propagates without being logged as approval timeout`() = runBlocking {
        ActivityLog.clear()
        var propagated = false
        try {
            withTimeout(25) {
                ApprovalTimeout.await("synthetic outer timeout", 5_000) { awaitCancellation() }
            }
        } catch (_: TimeoutCancellationException) {
            propagated = true
        }

        assertTrue(propagated)
        assertFalse(ActivityLog.snapshot().any { it.action == "approval" && it.outcome == "timed_out" })
    }
}
