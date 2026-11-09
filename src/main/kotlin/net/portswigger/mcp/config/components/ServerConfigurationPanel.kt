package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.McpConfig
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.awt.event.ItemEvent
import javax.swing.*

class SecurityConfigurationPanel(private val config: McpConfig) : JPanel() {

    private lateinit var alwaysAllowHttpHistoryCheckBox: JCheckBox
    private lateinit var alwaysAllowWebSocketHistoryCheckBox: JCheckBox
    private lateinit var alwaysAllowOrganizerCheckBox: JCheckBox

    init {
        layout = GridBagLayout()
        updateColors()
        alignmentX = LEFT_ALIGNMENT

        buildPanel()
    }

    override fun updateUI() {
        super.updateUI()
        updateColors()
    }

    private fun updateColors() {
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        )
    }

    private fun buildPanel() {
        val row = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.NORTHWEST
            insets = Insets(0, 0, Design.Spacing.MD, 0)
        }
        var rowIndex = 0
        fun addRow(component: JComponent, bottomInset: Int = Design.Spacing.MD) {
            row.gridy = rowIndex++
            row.insets = Insets(0, 0, bottomInset, 0)
            add(component, row)
        }

        addRow(Design.createSectionLabel("Security and Permissions"))

        val readOnlyCheckBox = createCheckBoxWithSubtitle(
            "Read-only mode",
            "On by default. Turn off only when you need approved requests or state changes.",
            config.readOnlyMode
        ) { config.readOnlyMode = it }
        addRow(readOnlyCheckBox)

        val bearerCheckBox = createStandardCheckBox(
            "Require bearer token", config.requireBearerToken
        ) { config.requireBearerToken = it }
        addRow(bearerCheckBox, Design.Spacing.SM)
        addRow(createTokenControls())

        val configEditingToolingCheckBox = createCheckBoxWithSubtitle(
            "Enable tools that can edit your config",
            "WARNING: Can execute code",
            config.configEditingTooling
        ) { config.configEditingTooling = it }
        addRow(configEditingToolingCheckBox)

        val httpRequestApprovalCheckBox = createStandardCheckBox(
            "Require approval for HTTP requests", config.requireHttpRequestApproval
        ) { config.requireHttpRequestApproval = it }
        addRow(httpRequestApprovalCheckBox)

        val dataAccessApprovalCheckBox = createDataAccessApprovalCheckBox()
        addRow(dataAccessApprovalCheckBox, Design.Spacing.SM)

        alwaysAllowHttpHistoryCheckBox = createIndentedCheckBox(
            "Always allow HTTP history access", config.alwaysAllowHttpHistory, config.requireDataAccessApproval
        ) { config.alwaysAllowHttpHistory = it }
        addRow(alwaysAllowHttpHistoryCheckBox, Design.Spacing.SM)

        alwaysAllowWebSocketHistoryCheckBox = createIndentedCheckBox(
            "Always allow WebSocket history access",
            config.alwaysAllowWebSocketHistory,
            config.requireDataAccessApproval
        ) { config.alwaysAllowWebSocketHistory = it }
        addRow(alwaysAllowWebSocketHistoryCheckBox, Design.Spacing.SM)

        alwaysAllowOrganizerCheckBox = createIndentedCheckBox(
            "Always allow Organizer access",
            config.alwaysAllowOrganizer,
            config.requireDataAccessApproval
        ) { config.alwaysAllowOrganizer = it }
        addRow(alwaysAllowOrganizerCheckBox)

        val filterConfigCredentialsCheckBox = createCheckBoxWithSubtitle(
            "Filter config credentials",
            "Hides sensitive data in config files (Platform Authentication, socks proxy, etc.)",
            config.filterConfigCredentials
        ) { config.filterConfigCredentials = it }
        addRow(filterConfigCredentialsCheckBox, 0)
    }

    private fun createTokenControls(): JComponent {
        val tokenField = JPasswordField(config.bearerToken, 24).apply {
            toolTipText = "Use this token in the MCP client's Authorization: Bearer header."
            isEditable = false
            echoChar = '\u2022'
            font = Design.Typography.bodyMedium
            minimumSize = java.awt.Dimension(0, preferredSize.height)
        }
        val revealButton = JButton("Show").apply {
            addActionListener {
                val visible = tokenField.echoChar != '\u0000'
                tokenField.echoChar = if (visible) '\u0000' else '\u2022'
                text = if (visible) "Hide" else "Show"
            }
        }
        val copyButton = JButton("Copy").apply {
            addActionListener {
                Toolkit.getDefaultToolkit().systemClipboard.setContents(
                    StringSelection(String(tokenField.password)), null
                )
            }
        }
        val buttons = JPanel().apply {
            isOpaque = false
            add(revealButton)
            add(copyButton)
        }
        val row = JPanel(BorderLayout(Design.Spacing.SM, 0)).apply {
            isOpaque = false
            add(tokenField, BorderLayout.CENTER)
            add(buttons, BorderLayout.EAST)
        }
        val label = JLabel("Bearer token").apply {
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            alignmentX = LEFT_ALIGNMENT
        }
        return JPanel(BorderLayout(0, 4)).apply {
            isOpaque = false
            add(label, BorderLayout.NORTH)
            add(row, BorderLayout.CENTER)
            add(JLabel("Keep this token private. It is stored in Burp extension data.").apply {
                font = Design.Typography.labelMedium
                foreground = Design.Colors.onSurfaceVariant
                alignmentX = LEFT_ALIGNMENT
            }, BorderLayout.SOUTH)
        }
    }

    private fun createDataAccessApprovalCheckBox(): JCheckBox {
        return createStandardCheckBox(
            "Require approval for project data access", config.requireDataAccessApproval
        ) { enabled ->
            config.requireDataAccessApproval = enabled
            if (!enabled) {
                config.alwaysAllowHttpHistory = false
                config.alwaysAllowWebSocketHistory = false
                config.alwaysAllowOrganizer = false
                alwaysAllowHttpHistoryCheckBox.isSelected = false
                alwaysAllowWebSocketHistoryCheckBox.isSelected = false
                alwaysAllowOrganizerCheckBox.isSelected = false
            }
            alwaysAllowHttpHistoryCheckBox.isEnabled = enabled
            alwaysAllowWebSocketHistoryCheckBox.isEnabled = enabled
            alwaysAllowOrganizerCheckBox.isEnabled = enabled
        }
    }

    fun updateDataAccessCheckboxes() {
        SwingUtilities.invokeLater {
            alwaysAllowHttpHistoryCheckBox.isSelected = config.alwaysAllowHttpHistory
            alwaysAllowWebSocketHistoryCheckBox.isSelected = config.alwaysAllowWebSocketHistory
            alwaysAllowOrganizerCheckBox.isSelected = config.alwaysAllowOrganizer
        }
    }

    private fun createStandardCheckBox(
        text: String, initialValue: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createIndentedCheckBox(
        text: String, initialValue: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit
    ): JCheckBox {
        return JCheckBox(text).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            isEnabled = enabled
            font = Design.Typography.bodyMedium
            foreground = Design.Colors.onSurfaceVariant
            border = BorderFactory.createEmptyBorder(0, Design.Spacing.LG, 0, 0)
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }
    }

    private fun createCheckBoxWithSubtitle(
        mainText: String, subtitleText: String, initialValue: Boolean, onChange: (Boolean) -> Unit
    ): JPanel {
        val checkBox = JCheckBox(mainText).apply {
            alignmentX = LEFT_ALIGNMENT
            isSelected = initialValue
            font = Design.Typography.bodyLarge
            foreground = Design.Colors.onSurface
            addItemListener { event ->
                onChange(event.stateChange == ItemEvent.SELECTED)
            }
        }

        val subtitleLabel = JTextArea(subtitleText, 2, 48).apply {
            font = Design.Typography.labelMedium
            foreground = Design.Colors.onSurfaceVariant
            isEditable = false
            isFocusable = false
            lineWrap = true
            wrapStyleWord = true
            isOpaque = false
            border = BorderFactory.createEmptyBorder()
            minimumSize = java.awt.Dimension(0, preferredSize.height)
        }

        val subtitlePanel = JPanel(BorderLayout()).apply {
            isOpaque = false
            alignmentX = LEFT_ALIGNMENT
            border = BorderFactory.createEmptyBorder(0, 20, 0, 0)
            add(subtitleLabel, BorderLayout.CENTER)
        }

        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            alignmentX = LEFT_ALIGNMENT
            isOpaque = false
            add(checkBox)
            add(subtitlePanel)
        }
    }

}
