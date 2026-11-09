package net.portswigger.mcp.config.components

import net.portswigger.mcp.McpServerRuntime
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.config.Design
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JPanel

/** Compact connection status card used by the Server Settings tab. */
class ServerDetailsPanel : JPanel(BorderLayout(Design.Spacing.SM, Design.Spacing.SM)) {
    private val status = JLabel()
    private val endpoint = JLabel()

    init {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
        add(Design.createSectionLabel("Server Status"), BorderLayout.NORTH)

        val details = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val row = GridBagConstraints().apply {
                gridx = 0
                gridy = 0
                weightx = 1.0
                fill = GridBagConstraints.HORIZONTAL
                anchor = GridBagConstraints.WEST
                insets = Insets(0, 0, Design.Spacing.SM, 0)
            }
            add(status.apply { font = Design.Typography.bodyLarge }, row)
            row.gridy = 1
            row.insets = Insets(0, 0, 0, 0)
            add(endpoint.apply {
                font = Design.Typography.bodyMedium
                foreground = Design.Colors.onSurfaceVariant
            }, row)
        }
        add(details, BorderLayout.CENTER)
        updateState(null)
    }

    fun updateState(state: ServerState?) {
        val current = when (state) {
            ServerState.Starting -> "Starting"
            ServerState.Running -> "Running"
            ServerState.Stopping -> "Stopping"
            ServerState.Stopped -> "Stopped"
            is ServerState.Failed -> "Failed (${state.exception.javaClass.simpleName})"
            null -> McpServerRuntime.state.replaceFirstChar { it.uppercase() }
        }
        status.text = "Status: $current"
        status.foreground = if (current == "Running") Design.Colors.onSurface else Design.Colors.onSurfaceVariant
        endpoint.text = "MCP endpoint: ${McpServerRuntime.endpoint}"
    }

    fun cleanup() = Unit
}
