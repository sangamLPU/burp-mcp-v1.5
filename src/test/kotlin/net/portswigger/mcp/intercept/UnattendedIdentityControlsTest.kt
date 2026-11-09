package net.portswigger.mcp.intercept

import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.Transferable
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class UnattendedIdentityControlsTest {
    private val runId = "11111111-2222-3333-4444-555555555555"
    private val serverIdentity = "A".repeat(43)

    @Test
    fun `copy buttons expose current IDs while fields stay read only and server ID stays masked`() {
        val clipboard = Clipboard("ui-test")
        val controls = onEdt { UnattendedIdentityControls(ConditionalClipboard(clipboard, 60_000)) }
        try {
            onEdt { controls.update(activeSnapshot()) }

            assertFalse(controls.runIdField.isEditable)
            assertTrue(controls.runIdField.isFocusable)
            assertEquals(runId, controls.runIdField.text)
            assertFalse(controls.serverIdentityField.isEditable)
            assertTrue(controls.serverIdentityField.echoChar != '\u0000')
            assertTrue(controls.copyRunIdButton.isEnabled)
            assertTrue(controls.copyServerIdentityButton.isEnabled)

            onEdt { controls.copyRunIdButton.doClick() }
            assertEquals(runId, clipboardText(clipboard))
            assertTrue(controls.feedbackLabel.text.contains("Run ID copied"))

            onEdt { controls.copyServerIdentityButton.doClick() }
            assertEquals(serverIdentity, clipboardText(clipboard))
            assertTrue(controls.feedbackLabel.text.contains("Server identity copied"))
        } finally {
            onEdt { controls.cleanup() }
        }
    }

    @Test
    fun `setup copy includes current IDs and safer test command prompts without embedding them`() {
        val clipboard = Clipboard("ui-test")
        val controls = onEdt { UnattendedIdentityControls(ConditionalClipboard(clipboard, 60_000)) }
        try {
            onEdt { controls.update(activeSnapshot()) }
            onEdt { controls.copyPowerShellSetupButton.doClick() }
            val setup = clipboardText(clipboard).orEmpty()
            assertTrue(setup.contains(runId))
            assertTrue(setup.contains(serverIdentity))
            assertTrue(setup.contains("prepare-cancel-test-server.ps1"))

            onEdt { controls.copyTestCommandsButton.doClick() }
            val safeCommands = clipboardText(clipboard).orEmpty()
            assertFalse(safeCommands.contains(runId))
            assertFalse(safeCommands.contains(serverIdentity))
            assertTrue(safeCommands.contains("Read-Host -Prompt 'Paste the active Burp Run ID (hidden)' -AsSecureString"))
            assertTrue(safeCommands.contains("Read-Host -Prompt 'Paste the active Burp Server Identity (hidden)' -AsSecureString"))
            assertTrue(safeCommands.contains("prepare-cancel-test-server.ps1"))
            assertTrue(safeCommands.contains("run-cancel-test.ps1 -PromptForMcpToken -WaitForLiveSession"))
            assertFalse(safeCommands.contains("After Burp confirms the bounded session is active"))
        } finally {
            onEdt { controls.cleanup() }
        }
    }

    @Test
    fun `deactivation clears fields disables copying and conditionally clears our clipboard content`() {
        val clipboard = Clipboard("ui-test")
        val controls = onEdt { UnattendedIdentityControls(ConditionalClipboard(clipboard, 60_000)) }
        try {
            onEdt {
                controls.update(activeSnapshot())
                controls.copyServerIdentityButton.doClick()
            }
            assertEquals(serverIdentity, clipboardText(clipboard))

            onEdt { controls.update(inactiveSnapshot()) }

            assertEquals("", controls.runIdField.text)
            assertTrue(controls.serverIdentityField.password.isEmpty())
            assertFalse(controls.copyRunIdButton.isEnabled)
            assertFalse(controls.copyServerIdentityButton.isEnabled)
            assertFalse(controls.copyPowerShellSetupButton.isEnabled)
            assertFalse(controls.copyTestCommandsButton.isEnabled)
            assertTrue(clipboardText(clipboard).isNullOrEmpty())
        } finally {
            onEdt { controls.cleanup() }
        }
    }

    @Test
    fun `copy action rechecks live mode instead of using a stale displayed snapshot`() {
        val clipboard = Clipboard("ui-test")
        var current = activeSnapshot()
        val controls = onEdt {
            UnattendedIdentityControls(
                ConditionalClipboard(clipboard, 60_000),
                snapshotProvider = { current }
            )
        }
        try {
            onEdt { controls.update(current) }
            current = inactiveSnapshot()

            onEdt { controls.copyServerIdentityButton.doClick() }

            assertTrue(clipboardText(clipboard).isNullOrEmpty())
            assertFalse(controls.copyServerIdentityButton.isEnabled)
            assertEquals("Copy failed: unattended mode is not active.", controls.feedbackLabel.text)
        } finally {
            onEdt { controls.cleanup() }
        }
    }

    @Test
    fun `clipboard failure gives brief feedback without exposing values`() {
        val failingClipboard = object : Clipboard("failure") {
            override fun setContents(contents: Transferable?, owner: ClipboardOwner?) {
                throw IllegalStateException("synthetic clipboard failure")
            }
        }
        val controls = onEdt { UnattendedIdentityControls(ConditionalClipboard(failingClipboard, 60_000)) }
        try {
            onEdt {
                controls.update(activeSnapshot())
                controls.copyServerIdentityButton.doClick()
            }

            assertEquals("Copy failed. Check clipboard access and try again.", controls.feedbackLabel.text)
            assertFalse(controls.feedbackLabel.text.contains(serverIdentity))
        } finally {
            onEdt { controls.cleanup() }
        }
    }

    private fun activeSnapshot() = UnattendedLocalTestSnapshot(
        active = true,
        configuredDurationSeconds = 300,
        remainingMillis = 300_000,
        testRunId = runId,
        serverIdentity = serverIdentity,
        maximumConcurrentMessages = 2,
        maximumRequestsPerRun = 32,
        maximumPayloadBytes = 65_536
    )

    private fun inactiveSnapshot() = activeSnapshot().copy(
        active = false,
        remainingMillis = 0,
        testRunId = null,
        serverIdentity = null
    )

    private fun clipboardText(clipboard: Clipboard): String? =
        clipboard.getContents(null)?.getTransferData(DataFlavor.stringFlavor) as? String

    private fun <T> onEdt(block: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return block()
        val result = AtomicReference<T>()
        SwingUtilities.invokeAndWait { result.set(block()) }
        return result.get()
    }
}
