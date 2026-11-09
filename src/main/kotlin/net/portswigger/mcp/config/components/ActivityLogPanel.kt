package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.security.ActivityLog
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/** Scrollable, payload-free view of recent MCP activity events. */
class ActivityLogPanel : JPanel(BorderLayout(Design.Spacing.MD, Design.Spacing.MD)) {
    private val count = JLabel()
    private val log = JTextArea(12, 60).apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        font = Design.Typography.bodyMedium
        background = Design.Colors.listBackground
        foreground = Design.Colors.onSurface
        border = BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM)
    }
    private val removeListener: () -> Unit

    init {
        border = BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        val header = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val c = GridBagConstraints().apply {
                gridy = 0
                insets = Insets(0, 0, Design.Spacing.SM, Design.Spacing.SM)
                anchor = GridBagConstraints.WEST
            }
            c.gridx = 0
            c.weightx = 1.0
            c.fill = GridBagConstraints.HORIZONTAL
            add(Design.createSectionLabel("Recent Activity"), c)
            c.gridx = 1
            c.weightx = 0.0
            c.fill = GridBagConstraints.NONE
            c.insets = Insets(0, 0, Design.Spacing.SM, 0)
            add(count, c)
            c.gridx = 0
            c.gridy = 1
            c.gridwidth = 2
            c.weightx = 1.0
            c.fill = GridBagConstraints.HORIZONTAL
            c.insets = Insets(0, 0, 0, 0)
            add(JLabel("Payloads and credentials are not recorded; the in-memory log retains up to 100 events.").apply {
                foreground = Design.Colors.onSurfaceVariant
                font = Design.Typography.bodyMedium
            }, c)
        }
        add(header, BorderLayout.NORTH)
        add(JScrollPane(log).apply {
            minimumSize = java.awt.Dimension(0, 120)
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
        }, BorderLayout.CENTER)
        refresh()
        removeListener = ActivityLog.addListener { SwingUtilities.invokeLater { refresh() } }
    }

    private fun refresh() {
        val events = ActivityLog.snapshot()
        count.text = "${events.size} events"
        log.text = if (events.isEmpty()) "No MCP activity yet." else events.joinToString("\n") { event ->
            buildString {
                append(event.timestamp).append("  ").append(event.outcome.uppercase()).append("  ").append(event.action)
                if (event.detail.isNotBlank()) append(" — ").append(event.detail)
            }
        }
        log.caretPosition = 0
    }

    fun cleanup() = removeListener()
}
