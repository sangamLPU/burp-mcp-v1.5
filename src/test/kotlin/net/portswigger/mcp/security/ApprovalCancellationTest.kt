package net.portswigger.mcp.security

import io.mockk.*
import kotlinx.coroutines.*
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.awt.Frame
import java.awt.Window
import javax.swing.JDialog
import javax.swing.JPanel
import javax.swing.SwingUtilities
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

@Timeout(10)
class ApprovalCancellationTest {
    @AfterEach
    fun cleanup() = unmockkAll()

    @Test
    fun `null parent uses the Burp frame when available and permits an unowned dialog otherwise`() {
        mockkStatic(::findBurpFrame)
        val frame = mockk<Frame>()
        every { findBurpFrame() } returnsMany listOf(frame, null)

        SwingUtilities.invokeAndWait {
            assertSame(frame, Dialogs.resolveDialogOwner(null))
            assertNull(Dialogs.resolveDialogOwner(null))
        }
    }

    @Test
    fun `explicit window and nested component retain their owner`() {
        val frame = mockk<Frame>()
        val panel = mockk<JPanel> { every { parent } returns frame }
        val dialog = mockk<JDialog>()
        val nestedPanel = mockk<JPanel> { every { parent } returns dialog }

        SwingUtilities.invokeAndWait {
            assertSame(frame, Dialogs.resolveDialogOwner(frame))
            assertSame(frame, Dialogs.resolveDialogOwner(panel))
            assertSame(dialog, Dialogs.resolveDialogOwner(dialog))
            assertSame(dialog, Dialogs.resolveDialogOwner(nestedPanel))
        }
    }

    @Test
    fun `unsupported window uses its supported owner and a detached component has no ancestor`() {
        mockkStatic(::findBurpFrame)
        every { findBurpFrame() } returns null
        val frame = mockk<Frame>()
        val window = mockk<Window> { every { owner } returns frame }

        SwingUtilities.invokeAndWait {
            assertSame(frame, Dialogs.resolveDialogOwner(window))
            assertNull(Dialogs.resolveDialogOwner(JPanel()))
        }
    }

    @Test
    fun `cancel before queued dialog opens does not show it`() = runBlocking {
        mockkObject(Dialogs)
        val edtBlocked = CountDownLatch(1)
        val releaseEdt = CountDownLatch(1)
        SwingUtilities.invokeLater {
            edtBlocked.countDown()
            check(releaseEdt.await(5, TimeUnit.SECONDS))
        }
        try {
            assertTrue(edtBlocked.await(5, TimeUnit.SECONDS))
            val job = launch(start = CoroutineStart.UNDISPATCHED) {
                Dialogs.requestOption(null, "approval", arrayOf("Allow", "Deny"))
                error("Cancelled approval resumed")
            }
            job.cancelAndJoin()
        } finally {
            releaseEdt.countDown()
            SwingUtilities.invokeAndWait {}
        }
        verify(exactly = 0) { Dialogs.showOptionDialog(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `late always allow after cancellation neither resumes nor persists permission`() = runBlocking {
        mockkObject(Dialogs)
        val config = mockk<McpConfig>(relaxed = true)
        val shown = CompletableDeferred<Unit>()
        val releaseDialog = CountDownLatch(1)
        val dialog = mockk<JDialog>(relaxed = true)
        every { dialog.dispose() } answers { check(SwingUtilities.isEventDispatchThread()) }
        every { Dialogs.showOptionDialog(any(), any(), any(), any(), any(), any()) } answers {
            val onShow = arg<(JDialog) -> Boolean>(5)
            check(onShow(dialog))
            shown.complete(Unit)
            check(releaseDialog.await(5, TimeUnit.SECONDS))
            1 // A stale Always Allow click.
        }
        var sent = false
        val job = launch(start = CoroutineStart.UNDISPATCHED) {
            if (SwingUserApprovalHandler().requestApproval("example.com", 80, config, null, null)) sent = true
        }
        try {
            withTimeout(5000) { shown.await() }
            job.cancelAndJoin()
        } finally {
            releaseDialog.countDown()
            SwingUtilities.invokeAndWait {}
        }
        assertTrue(job.isCancelled)
        assertEquals(false, sent)
        verify(exactly = 0) { config.addAutoApproveTarget(any()) }
        verify { dialog.dispose() }
    }

    @Test
    fun `active approval still allows and persists permission`() = runBlocking {
        mockkObject(Dialogs)
        val config = mockk<McpConfig>(relaxed = true)
        every { Dialogs.showOptionDialog(any(), any(), any(), any(), any(), any()) } returns 2
        assertTrue(SwingUserApprovalHandler().requestApproval("example.com", 443, config, null, null))
        verify(exactly = 1) { config.addAutoApproveTarget("example.com:443") }
    }

    @Test
    fun `approval rejection and dismissal are reported without persisting permission on the EDT path`() = runBlocking {
        mockkObject(Dialogs)
        val config = mockk<McpConfig>(relaxed = true)
        val http = SwingUserApprovalHandler()
        val data = SwingDataAccessApprovalHandler()
        for (answer in listOf(0, 3, -1)) {
            every { Dialogs.showOptionDialog(null, any(), any(), any(), any(), any()) } answers {
                check(SwingUtilities.isEventDispatchThread())
                answer
            }
            assertEquals(answer == 0, http.requestApproval("127.0.0.1", 18080, config))
        }
        for (answer in listOf(0, 2, -1)) {
            every { Dialogs.showOptionDialog(null, any(), any(), any(), any(), any()) } answers {
                check(SwingUtilities.isEventDispatchThread())
                answer
            }
            assertEquals(answer == 0, data.requestDataAccess(DataAccessType.HTTP_HISTORY, config))
        }
        verify(exactly = 0) { config.addAutoApproveTarget(any()) }
        verify(exactly = 0) { config.alwaysAllowHttpHistory = any() }
    }
}
