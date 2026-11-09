package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.Design
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JTextField
import javax.swing.Timer

internal class UnattendedIdentityControls(
    clipboardOverride: ConditionalClipboard? = null,
    private val snapshotProvider: (() -> UnattendedLocalTestSnapshot)? = null
) : JPanel(GridBagLayout()) {
    private var clipboard: ConditionalClipboard? = clipboardOverride
    internal val runIdField = JTextField(36).apply {
        isEditable = false
        isFocusable = true
        toolTipText = "Read-only Run ID. Selectable for manual copying."
        accessibleContext.accessibleName = "Unattended test Run ID"
    }
    internal val serverIdentityField = JPasswordField(43).apply {
        isEditable = false
        isFocusable = true
        echoChar = '\u2022'
        toolTipText = "Read-only masked server identity. Use Copy Server Identity to copy it."
        accessibleContext.accessibleName = "Masked ephemeral server identity"
    }
    internal val copyRunIdButton = JButton("Copy Run ID")
    internal val copyServerIdentityButton = JButton("Copy Server Identity")
    internal val copyPowerShellSetupButton = JButton("Copy PowerShell Setup").apply {
        toolTipText = "Includes the active identities. Use Copy Test Commands to keep them out of PowerShell history and terminal input."
    }
    internal val copyTestCommandsButton = JButton("Copy Test Commands").apply {
        toolTipText = "Uses hidden PowerShell prompts for both identities and the MCP token."
    }
    internal val feedbackLabel = JLabel(" ")

    private var displayedRunId: String? = null
    private var displayedServerIdentity: String? = null
    private var activeSnapshot: UnattendedLocalTestSnapshot? = null
    private val feedbackTimer = Timer(FEEDBACK_DURATION_MILLIS) { feedbackLabel.text = " " }.apply {
        isRepeats = false
    }

    init {
        isOpaque = false
        val c = GridBagConstraints().apply {
            insets = Insets(0, 0, Design.Spacing.SM / 2, Design.Spacing.SM)
            anchor = GridBagConstraints.WEST
            fill = GridBagConstraints.HORIZONTAL
        }
        c.gridx = 0
        c.gridy = 0
        add(JLabel("Run ID:"), c)
        c.gridx = 1
        c.weightx = 1.0
        add(runIdField, c)
        c.gridx = 2
        c.weightx = 0.0
        c.insets = Insets(0, 0, Design.Spacing.SM / 2, 0)
        add(copyRunIdButton, c)

        c.gridx = 0
        c.gridy = 1
        c.insets = Insets(0, 0, Design.Spacing.SM / 2, Design.Spacing.SM)
        add(JLabel("Server identity:"), c)
        c.gridx = 1
        c.weightx = 1.0
        add(serverIdentityField, c)
        c.gridx = 2
        c.weightx = 0.0
        c.insets = Insets(0, 0, Design.Spacing.SM / 2, 0)
        add(copyServerIdentityButton, c)

        c.gridx = 1
        c.gridy = 2
        c.gridwidth = 2
        c.insets = Insets(0, 0, Design.Spacing.SM / 2, 0)
        add(JPanel(FlowLayout(FlowLayout.LEFT, Design.Spacing.SM, 0)).apply {
            isOpaque = false
            add(copyPowerShellSetupButton)
            add(copyTestCommandsButton)
        }, c)

        c.gridx = 0
        c.gridy = 3
        c.gridwidth = 3
        c.weightx = 1.0
        c.insets = Insets(0, 0, 0, 0)
        add(feedbackLabel, c)

        copyRunIdButton.addActionListener { copyFromActiveSnapshot("Run ID") { it.testRunId } }
        copyServerIdentityButton.addActionListener { copyFromActiveSnapshot("Server identity") { it.serverIdentity } }
        copyPowerShellSetupButton.addActionListener {
            val snapshot = currentActiveSnapshot()
            if (snapshot == null) {
                showFailure("Copy failed: unattended mode is not active.")
            } else {
                copy(snapshot.testRunId, "PowerShell setup") { id ->
                    LocalTestPowerShellCommands.setup(id, snapshot.serverIdentity.orEmpty())
                }
            }
        }
        copyTestCommandsButton.addActionListener {
            if (currentActiveSnapshot() == null) showFailure("Copy failed: unattended mode is not active.")
            else copy(LocalTestPowerShellCommands.testCommands(), "Test commands") { it }
        }
    }

    fun update(snapshot: UnattendedLocalTestSnapshot) {
        val isActive = snapshot.active && !snapshot.testRunId.isNullOrBlank() && !snapshot.serverIdentity.isNullOrBlank()
        activeSnapshot = snapshot.takeIf { isActive }
        val nextRunId = activeSnapshot?.testRunId
        val nextServerIdentity = activeSnapshot?.serverIdentity
        if (nextRunId != displayedRunId || nextServerIdentity != displayedServerIdentity) {
            runIdField.text = nextRunId.orEmpty()
            serverIdentityField.text = nextServerIdentity.orEmpty()
            displayedRunId = nextRunId
            displayedServerIdentity = nextServerIdentity
        }
        copyRunIdButton.isEnabled = isActive
        copyServerIdentityButton.isEnabled = isActive
        copyPowerShellSetupButton.isEnabled = isActive
        copyTestCommandsButton.isEnabled = isActive
        if (!isActive) clipboard?.clearCurrentIfUnchanged()
    }

    private fun copyFromActiveSnapshot(label: String, value: (UnattendedLocalTestSnapshot) -> String?) {
        val snapshot = currentActiveSnapshot()
        val current = snapshot?.let(value)
        if (current.isNullOrBlank()) {
            showFailure("Copy failed: unattended mode is not active.")
            return
        }
        copy(current, label) { it }
    }

    private fun currentActiveSnapshot(): UnattendedLocalTestSnapshot? {
        val newest = snapshotProvider?.invoke()
        if (newest != null) update(newest)
        return activeSnapshot
    }

    private fun copy(value: String?, label: String, transform: (String) -> String) {
        if (value.isNullOrBlank()) {
            showFailure("Copy failed: unattended mode is not active.")
            return
        }
        try {
            systemClipboard().copy(transform(value))
            feedbackLabel.text = "$label copied. Clipboard clears in 30 seconds if unchanged."
            feedbackTimer.restart()
        } catch (_: Exception) {
            showFailure("Copy failed. Check clipboard access and try again.")
        }
    }

    private fun showFailure(message: String) {
        feedbackLabel.text = message
        feedbackTimer.restart()
    }

    fun cleanup() {
        feedbackTimer.stop()
        activeSnapshot = null
        runIdField.text = ""
        serverIdentityField.text = ""
        displayedRunId = null
        displayedServerIdentity = null
        clipboard?.close()
        clipboard = null
    }

    private fun systemClipboard(): ConditionalClipboard = clipboard ?: ConditionalClipboard(
        Toolkit.getDefaultToolkit().systemClipboard
    ).also { clipboard = it }

    companion object {
        private const val FEEDBACK_DURATION_MILLIS = 4_000
    }
}
