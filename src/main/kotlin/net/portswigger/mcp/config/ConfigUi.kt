package net.portswigger.mcp.config

import io.ktor.util.network.UnresolvedAddressException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.Swing
import net.portswigger.mcp.config.components.*
import net.portswigger.mcp.intercept.InterceptionPanel
import net.portswigger.mcp.intercept.LiveInterception
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.*
import javax.swing.JOptionPane.ERROR_MESSAGE

/** Main Burp tab. Each work area gets a dedicated, width-tracking, vertically scrollable tab. */
class ConfigUi(private val config: McpConfig, live: LiveInterception? = null) {
    private val panel = JPanel(BorderLayout())
    private val tabs = JTabbedPane()
    val component: JComponent get() = panel

    private val listenerHandles = mutableListOf<ListenerHandle>()
    private val interceptionPanel = live?.let { InterceptionPanel(it) }
    private val validationErrorLabel = WarningLabel()
    private val hostField = JTextField(18)
    private val portField = JTextField(6)
    private val reinstallNotice = WarningLabel("Restart the MCP server for these settings to take effect.")
    private val enabledToggle: ToggleSwitch = Design.createToggleSwitch(false) { enabled -> onServerEnabledChanged(enabled) }

    private lateinit var securityPanel: SecurityConfigurationPanel
    private lateinit var advancedOptionsPanel: AdvancedOptionsPanel
    private lateinit var autoApproveTargetsPanel: AutoApproveTargetsPanel
    private lateinit var serverDetailsPanel: ServerDetailsPanel
    private lateinit var activityLogPanel: ActivityLogPanel
    private lateinit var toolCatalogPanel: ToolCatalogPanel

    private var toggleListener: ((Boolean) -> Unit)? = null
    private var suppressToggleEvents = false

    private val dataAccessRefreshListener: () -> Unit = {
        SwingUtilities.invokeLater {
            if (::securityPanel.isInitialized) securityPanel.updateDataAccessCheckboxes()
        }
    }

    init {
        hostField.text = config.host
        portField.text = config.port.toString()
        enabledToggle.setState(config.enabled, animate = false)
        initializeComponents()
        buildUi()
    }

    private fun initializeComponents() {
        securityPanel = SecurityConfigurationPanel(config)
        advancedOptionsPanel = AdvancedOptionsPanel(hostField, portField, reinstallNotice)
        autoApproveTargetsPanel = AutoApproveTargetsPanel(config)
        serverDetailsPanel = ServerDetailsPanel()
        activityLogPanel = ActivityLogPanel()
        toolCatalogPanel = ToolCatalogPanel()
        listenerHandles += config.addDataAccessChangeListener(dataAccessRefreshListener)
    }

    private fun onServerEnabledChanged(enabled: Boolean) {
        if (suppressToggleEvents) return
        if (enabled) {
            ConfigValidation.validateServerConfig(hostField.text, portField.text)?.let { error ->
                validationErrorLabel.text = error
                validationErrorLabel.isVisible = true
                enabledToggle.setState(false, animate = true)
                return
            }
        }
        validationErrorLabel.isVisible = false
        config.enabled = enabled
        toggleListener?.invoke(enabled)
    }

    fun cleanup() {
        interceptionPanel?.cleanup()
        activityLogPanel.cleanup()
        listenerHandles.forEach { it.remove() }
        listenerHandles.clear()
        autoApproveTargetsPanel.cleanup()
        serverDetailsPanel.cleanup()
    }

    fun onEnabledToggled(listener: (Boolean) -> Unit) { toggleListener = listener }

    fun getConfig(): McpConfig {
        config.host = hostField.text.trim()
        portField.text.trim().toIntOrNull()?.let { config.port = it }
        return config
    }

    fun updateServerState(state: ServerState) {
        CoroutineScope(Dispatchers.Swing).launch {
            suppressToggleEvents = true
            serverDetailsPanel.updateState(state)
            toolCatalogPanel.refreshTools()

            val endpointEditable = state is ServerState.Stopped || state is ServerState.Failed
            advancedOptionsPanel.setFieldsEnabled(endpointEditable)
            when (state) {
                ServerState.Starting, ServerState.Stopping -> enabledToggle.isEnabled = false
                ServerState.Running -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(true, animate = false)
                }
                ServerState.Stopped -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                }
                is ServerState.Failed -> {
                    enabledToggle.isEnabled = true
                    enabledToggle.setState(false, animate = false)
                    val friendlyMessage = when (state.exception) {
                        is UnresolvedAddressException -> "Unable to resolve address"
                        else -> state.exception.message ?: state.exception.javaClass.simpleName
                    }
                    Dialogs.showMessageDialog(panel, "Failed to start Burp MCP Server: $friendlyMessage", ERROR_MESSAGE)
                }
            }
            suppressToggleEvents = false
        }
    }

    private fun buildUi() {
        panel.border = BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM)
        tabs.addTab("Server Settings", createScrollableTab(createServerSettingsTab()))
        tabs.addTab("Security", createScrollableTab(createSecurityTab()))
        tabs.addTab("Live Interception", createScrollableTab(interceptionPanel ?: unavailablePanel("Live interception is not available.")))
        tabs.addTab("MCP Tools", toolCatalogPanel)
        tabs.addTab("Activity Logs", activityLogPanel)
        panel.add(tabs, BorderLayout.CENTER)
    }

    private fun createServerSettingsTab(): JPanel {
        val content = JPanel(GridBagLayout()).apply {
            background = Design.Colors.surface
            border = BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        }
        val c = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.NORTHWEST
            insets = Insets(0, 0, Design.Spacing.MD, 0)
        }
        c.gridy = 0
        content.add(serverDetailsPanel, c)

        val controlCard = JPanel(GridBagLayout()).apply {
            background = Design.Colors.surface
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
                BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
            )
            val row = GridBagConstraints().apply {
                gridy = 0
                insets = Insets(0, 0, 0, Design.Spacing.MD)
                anchor = GridBagConstraints.WEST
            }
            row.gridx = 0
            row.weightx = 1.0
            row.fill = GridBagConstraints.HORIZONTAL
            add(JLabel("MCP server").apply {
                font = Design.Typography.titleMedium
                foreground = Design.Colors.onSurface
            }, row)
            row.gridx = 1
            row.weightx = 0.0
            row.fill = GridBagConstraints.NONE
            row.insets = Insets(0, 0, 0, 0)
            add(enabledToggle, row)
        }
        c.gridy = 1
        content.add(controlCard, c)

        c.gridy = 2
        content.add(advancedOptionsPanel, c)

        c.gridy = 3
        c.insets = Insets(0, 0, 0, 0)
        content.add(validationErrorLabel, c)
        c.gridy = 4
        content.add(reinstallNotice, c)
        return content
    }

    private fun createSecurityTab(): JPanel = JPanel(GridBagLayout()).apply {
        background = Design.Colors.surface
        border = BorderFactory.createEmptyBorder(Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD, Design.Spacing.MD)
        val c = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.NORTHWEST
            insets = Insets(0, 0, Design.Spacing.MD, 0)
        }
        c.gridy = 0
        add(securityPanel, c)
        c.gridy = 1
        c.weighty = 1.0
        c.insets = Insets(0, 0, 0, 0)
        add(autoApproveTargetsPanel, c)
    }

    private fun unavailablePanel(message: String) = JPanel(BorderLayout()).apply {
        add(JLabel(message), BorderLayout.NORTH)
    }

    private fun createScrollableTab(content: JComponent): JScrollPane {
        val widthTrackingView = ViewportWidthPanel(content)
        return JScrollPane(widthTrackingView).apply {
            border = BorderFactory.createEmptyBorder()
            background = Design.Colors.surface
            viewport.background = Design.Colors.surface
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBar.unitIncrement = Design.Spacing.MD * 2
        }
    }

    private class ViewportWidthPanel(content: JComponent) : JPanel(BorderLayout()), Scrollable {
        init {
            background = Design.Colors.surface
            add(content, BorderLayout.CENTER)
        }

        override fun getPreferredScrollableViewportSize() = Dimension(720, 520)
        override fun getScrollableUnitIncrement(visibleRect: java.awt.Rectangle, orientation: Int, direction: Int) = Design.Spacing.MD
        override fun getScrollableBlockIncrement(visibleRect: java.awt.Rectangle, orientation: Int, direction: Int) =
            if (orientation == SwingConstants.VERTICAL) visibleRect.height - Design.Spacing.MD else visibleRect.width - Design.Spacing.MD
        override fun getScrollableTracksViewportWidth() = true
        override fun getScrollableTracksViewportHeight(): Boolean {
            val viewport = parent as? JViewport ?: return false
            return preferredSize.height <= viewport.extentSize.height
        }
    }
}
