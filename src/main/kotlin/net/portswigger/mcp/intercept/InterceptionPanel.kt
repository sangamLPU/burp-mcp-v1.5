package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.security.ActivityLog
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.GridLayout
import java.awt.Insets
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.*

class InterceptionPanel(private val live: LiveInterception) : JPanel(BorderLayout(Design.Spacing.SM, Design.Spacing.SM)) {
    private val mode = JCheckBox("Live interception (local approval required)")
    private val edits = JCheckBox("Allow AI edit proposals")
    private val unattendedDuration = JSpinner(SpinnerNumberModel(
        UnattendedLocalTestMode.DEFAULT_DURATION_SECONDS,
        UnattendedLocalTestMode.MIN_DURATION_SECONDS,
        UnattendedLocalTestMode.MAX_DURATION_SECONDS,
        30
    ))
    private val unattendedStatus = JTextArea(6, 54).apply {
        isEditable = false
        isFocusable = false
        lineWrap = true
        wrapStyleWord = true
        isOpaque = false
        font = Design.Typography.bodyMedium
        foreground = Design.Colors.onSurfaceVariant
        border = BorderFactory.createEmptyBorder()
    }
    private val unattendedButton = JButton("Enable Unattended Local Test Mode")
    private val unattendedEmergencyButton = JButton("Emergency stop unattended mode and interception")
    private val identityControls = UnattendedIdentityControls(snapshotProvider = live::unattendedSnapshot)
    private val statusText = JTextArea(4, 54).apply {
        isEditable = false
        isFocusable = false
        lineWrap = true
        wrapStyleWord = true
        isOpaque = false
        font = Design.Typography.bodyMedium
        foreground = Design.Colors.onSurfaceVariant
        border = BorderFactory.createEmptyBorder()
        minimumSize = Dimension(0, getFontMetrics(font).height * 3)
    }
    private val sessionLifetime = JSpinner(SpinnerNumberModel(
        live.configuredSessionLifetimeSeconds,
        LiveInterception.MIN_SESSION_LIFETIME_SECONDS,
        LiveInterception.MAX_SESSION_LIFETIME_SECONDS,
        30
    ))
    private val holdTimeout = JSpinner(SpinnerNumberModel(
        live.timeoutSeconds,
        LiveInterception.MIN_MESSAGE_TIMEOUT_SECONDS,
        LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS,
        5
    ))
    private val model = DefaultListModel<String>()
    private val list = JList(model).apply {
        visibleRowCount = 8
        font = Design.Typography.bodyMedium
    }
    private val preview = JTextArea(8, 40).apply {
        isEditable = false
        lineWrap = false
        font = Design.Typography.bodyMedium
    }
    private val recentActivity = JTextArea(8, 60).apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
        font = Design.Typography.bodyMedium
    }
    private var ids = emptyList<String>()
    private var signature = ""
    private var updatingMode = false
    private val timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
    private val timer = Timer(500) { refresh() }

    init {
        border = BorderFactory.createTitledBorder("Live Interception — local sensitive preview")
        mode.addActionListener {
            if (updatingMode) return@addActionListener
            if (mode.isSelected) {
                val seconds = sessionLifetime.value as Int
                val approved = JOptionPane.showConfirmDialog(
                    this,
                    "Start live interception for $seconds seconds?\n\n" +
                        "Only traffic already in Burp scope and on the explicit host allowlist can be held. " +
                        "A local heartbeat runs automatically. Held messages are dropped when their configured deadline expires. " +
                        "The hard session maximum is ${LiveInterception.MAX_SESSION_LIFETIME_SECONDS} seconds.",
                    "Approve live interception session",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
                ) == JOptionPane.YES_OPTION
                if (approved) {
                    runCatching { live.startApprovedSession(seconds) }.onFailure {
                        JOptionPane.showMessageDialog(this, it.message, "Interception", JOptionPane.ERROR_MESSAGE)
                        syncMode(false)
                    }
                } else {
                    syncMode(false)
                }
            } else {
                live.disable()
            }
            refresh()
        }
        edits.addActionListener { live.allowEdits = edits.isSelected }
        add(createStatusAndControls(), BorderLayout.NORTH)

        unattendedButton.addActionListener {
            runCatching {
                val snapshot = live.unattendedSnapshot()
                if (snapshot.active) {
                    live.deactivateUnattendedLocalTestMode("LOCAL_UI_DISABLED")
                } else {
                    live.activateUnattendedLocalTestMode(unattendedDuration.value as Int)
                }
            }.onFailure { error ->
                JOptionPane.showMessageDialog(this, error.message, "Unattended local test mode", JOptionPane.ERROR_MESSAGE)
            }
            refresh()
        }
        unattendedEmergencyButton.addActionListener {
            live.emergencyStopUnattendedLocalTestMode()
            refresh()
        }

        val queueScroll = JScrollPane(list).apply {
            minimumSize = Dimension(0, 120)
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        }
        val previewScroll = JScrollPane(preview).apply {
            minimumSize = Dimension(0, 120)
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
        }
        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, queueScroll, previewScroll).apply {
            resizeWeight = 0.40
            setContinuousLayout(true)
            minimumSize = Dimension(0, 150)
            border = BorderFactory.createEmptyBorder()
        }
        val tabs = JTabbedPane().apply {
            addTab("Queue and preview", split)
            addTab("Recent decisions", JScrollPane(recentActivity).apply {
                minimumSize = Dimension(0, 150)
                verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
                horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_NEVER
            })
        }
        add(tabs, BorderLayout.CENTER)
        list.addListSelectionListener { if (!it.valueIsAdjusting) render() }

        val controls = JPanel(GridLayout(0, 2, Design.Spacing.SM, Design.Spacing.SM)).apply {
            border = BorderFactory.createEmptyBorder(Design.Spacing.SM, 0, 0, 0)
        }
        fun button(label: String, action: () -> Unit) {
            controls.add(JButton(label).apply {
                addActionListener {
                    runCatching(action).onFailure { e ->
                        JOptionPane.showMessageDialog(this@InterceptionPanel, e.message, "Interception", JOptionPane.ERROR_MESSAGE)
                    }
                    refresh()
                }
            })
        }
        button("Approve forward") { selected()?.let { if (confirm(it)) live.approveLocally(it.id, it.kind, it.revision) } }
        button("Share redacted preview") {
            selected()?.let {
                if (JOptionPane.showConfirmDialog(
                        this,
                        "Share this exact revision's redacted headers and bounded body with the external model?\n" +
                            "Review the local raw preview first; application-specific secrets may remain.",
                        "Approve content disclosure",
                        JOptionPane.YES_NO_OPTION
                    ) == JOptionPane.YES_OPTION
                ) live.queue.disclose(it.id, it.revision)
            }
        }
        button("Forward approved revision") {
            selected()?.let {
                if (it.approvedRevision == it.revision || confirm(it)) {
                    if (it.approvedRevision != it.revision) live.approveLocally(it.id, it.kind, it.revision)
                    live.forward(it.id, it.kind, it.revision)
                }
            }
        }
        button("Drop") { selected()?.let { live.queue.drop(it.id) } }
        button("Stop session") { live.disable("LOCAL_SESSION_STOPPED") }
        button("Emergency cancel") { live.cancel() }
        add(controls, BorderLayout.SOUTH)

        timer.start()
        refresh()
    }

    private fun createStatusAndControls(): JPanel {
        val container = JPanel(GridBagLayout()).apply { isOpaque = false }
        val c = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.WEST
            insets = Insets(0, 0, Design.Spacing.SM, 0)
        }
        c.gridy = 0
        container.add(mode, c)
        c.gridy = 1
        container.add(edits, c)

        c.gridy = 2
        c.insets = Insets(Design.Spacing.SM, 0, Design.Spacing.SM, 0)
        container.add(createUnattendedModePanel(), c)

        val timing = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val pair = GridBagConstraints().apply {
                anchor = GridBagConstraints.WEST
                insets = Insets(0, 0, 0, Design.Spacing.SM)
            }
            pair.gridx = 0
            pair.gridy = 0
            add(JLabel("Session (seconds):"), pair)
            pair.gridx = 1
            pair.weightx = 1.0
            pair.fill = GridBagConstraints.HORIZONTAL
            sessionLifetime.toolTipText = "Approved session duration: 60–600 seconds. It cannot be extended by tool activity."
            add(sessionLifetime, pair)
            pair.gridx = 0
            pair.gridy = 1
            pair.weightx = 0.0
            pair.fill = GridBagConstraints.NONE
            add(JLabel("Message timeout (seconds):"), pair)
            pair.gridx = 1
            pair.gridy = 1
            pair.weightx = 1.0
            pair.fill = GridBagConstraints.HORIZONTAL
            holdTimeout.toolTipText = "Maximum wait for each individual request or response: 5–120 seconds."
            add(holdTimeout, pair)
        }
        sessionLifetime.addChangeListener { live.setConfiguredSessionLifetime(sessionLifetime.value as Int) }
        holdTimeout.addChangeListener { live.setTimeout(holdTimeout.value as Int) }
        c.gridy = 3
        container.add(timing, c)

        c.gridy = 4
        c.insets = Insets(Design.Spacing.SM, 0, 0, 0)
        container.add(statusText, c)
        return container
    }

    private fun createUnattendedModePanel(): JPanel = JPanel(GridBagLayout()).apply {
        isOpaque = true
        background = Design.Colors.surface
        border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Design.Colors.outlineVariant, 1),
            BorderFactory.createEmptyBorder(Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM, Design.Spacing.SM)
        )
        val c = GridBagConstraints().apply {
            gridx = 0
            weightx = 1.0
            fill = GridBagConstraints.HORIZONTAL
            anchor = GridBagConstraints.WEST
            insets = Insets(0, 0, Design.Spacing.SM, 0)
        }
        c.gridy = 0
        add(JLabel("OPT-IN UNATTENDED LOCAL TEST MODE").apply {
            font = Design.Typography.titleMedium
            foreground = Design.Colors.onSurface
        }, c)
        c.gridy = 1
        add(unattendedStatus, c)

        c.gridy = 2
        add(identityControls, c)

        val durationRow = JPanel(GridBagLayout()).apply {
            isOpaque = false
            val d = GridBagConstraints().apply { anchor = GridBagConstraints.WEST; insets = Insets(0, 0, 0, Design.Spacing.SM) }
            d.gridx = 0
            add(JLabel("Authorization duration (seconds):"), d)
            d.gridx = 1
            unattendedDuration.toolTipText = "Defaults to ${UnattendedLocalTestMode.DEFAULT_DURATION_SECONDS}s; never exceeds ${UnattendedLocalTestMode.MAX_DURATION_SECONDS}s and never renews automatically."
            add(unattendedDuration, d)
        }
        c.gridy = 3
        add(durationRow, c)
        c.gridy = 4
        add(unattendedButton, c)
        c.gridy = 5
        add(unattendedEmergencyButton, c)
    }

    private fun syncMode(enabled: Boolean) {
        updatingMode = true
        mode.isSelected = enabled
        updatingMode = false
    }

    private fun selected() = list.selectedIndex.takeIf { it in ids.indices }?.let { live.queue.get(ids[it]) }

    private fun confirm(ticket: DecisionQueue.Ticket<HeldMessage>): Boolean {
        val metadata = requestMetadata(ticket.original.request)
        preview.text = live.localReview(ticket) + "\n\nDIFF\n" +
            redactedDiff(ticket.original.message.toString(), (ticket.proposed ?: ticket.original).message.toString())
        return JOptionPane.showConfirmDialog(
            this,
            "Approve forwarding ${ticket.kind} ${ticket.id} revision ${ticket.revision}?\n" +
                "${metadata.method} ${metadata.hostname}${metadata.urlPath}\n" +
                "${((ticket.deadline - System.nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000}s hold time remains.\n" +
                "Review original and proposed content in the local preview.",
            "Approve exact live revision",
            JOptionPane.YES_NO_OPTION
        ) == JOptionPane.YES_OPTION
    }

    private fun render() {
        preview.text = runCatching {
            selected()?.let {
                live.localReview(it) + "\n\nLINE DIFF\n" +
                    redactedDiff(it.original.message.toString(), (it.proposed ?: it.original).message.toString())
            } ?: "Select a held message. Sensitive content is shown only in this local Burp panel."
        }.getOrDefault("Message expired or processed.")
        preview.caretPosition = 0
    }

    private fun localTime(epochMillis: Long?) = epochMillis?.let { timeFormatter.format(Instant.ofEpochMilli(it)) } ?: "inactive"

    private fun refresh() {
        val health = live.health()
        val unattended = live.unattendedSnapshot()
        val requests = live.queue.list("request")
        val responses = live.queue.list("response")
        val all = requests + responses
        syncMode(health.enabled)
        statusText.text = buildString {
            append("Heartbeat: ${health.heartbeatHealth} (automatic every ${health.heartbeatIntervalSeconds}s)")
            if (health.enabled) {
                append("\nSession expiry: ${localTime(health.sessionExpiresAtEpochMillis)} (${health.sessionRemainingMillis / 1000}s remaining, ${health.sessionLifetimeSeconds}s total)")
                append("\nClient lease expiry: ${localTime(health.leaseExpiresAtEpochMillis)} (${health.leaseRemainingMillis / 1000}s remaining); last heartbeat ${localTime(health.lastHeartbeatAtEpochMillis)}")
            } else {
                append("\nSession inactive (${health.sessionEndReason})")
            }
            append("\nPending: ${requests.size} requests / ${responses.size} responses (${all.size}/${health.queueCapacity} slots); message timeout ${live.timeoutSeconds}s (bounded to ${LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS}s)")
            append("\nCapture is limited to Burp scope and the explicit host allowlist. Changes require exact-revision local approval.")
            ActivityLog.snapshot().firstOrNull()?.let { event ->
                append("\nLast queue event: ${event.timestamp} ${event.action} ${event.outcome} ${event.detail}")
            }
        }

        unattendedButton.text = if (unattended.active) "Disable Unattended Local Test Mode" else "Enable Unattended Local Test Mode"
        unattendedEmergencyButton.isEnabled = unattended.active || health.enabled
        identityControls.update(unattended)
        unattendedStatus.text = buildString {
            if (unattended.active) {
                append("ACTIVE — ${unattended.remainingMillis / 1000}s remain; expires automatically without renewal.")
                append("\nAuthorized destination: http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}")
                append("\nExact paths: ${LocalTestTargets.paths.joinToString(", ")}")
                append("\nMethods: GET, POST, PUT, PATCH, DELETE. Max 2 concurrent messages, 8 queued, 32 test cases per activation, 64 KiB payload.")
                append("\nAutomatic gates: local test session start/stop, predefined scope helper, exact-revision synthetic request/response approval and forwarding, local request drop, and synthetic content disclosure.")
            } else {
                append("DISABLED. No approvals are automatic. Extension reload and expiry leave this mode off.")
                append("\nDestination: http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}")
                append("\nExact paths: ${LocalTestTargets.paths.joinToString(", ")}")
                append("\nMethods: GET, POST, PUT, PATCH, DELETE. Max ${UnattendedLocalTestMode.MAX_CONCURRENT_MESSAGES} concurrent messages, ${UnattendedLocalTestMode.MAX_PENDING_MESSAGES} queued, ${UnattendedLocalTestMode.MAX_REQUESTS_PER_RUN} test cases, ${UnattendedLocalTestMode.MAX_PAYLOAD_BYTES} byte payload.")
                append("\nPermitted automatic gates: start/stop the restricted local interception session, configure only the predefined scope, approve/forward exact synthetic request or response revisions, drop a local synthetic request, and disclose synthetic test content.")
                append("\nSelected duration: ${unattendedDuration.value}s; default ${UnattendedLocalTestMode.DEFAULT_DURATION_SECONDS}s; hard maximum ${UnattendedLocalTestMode.MAX_DURATION_SECONDS}s.")
            }
            append("\nOnly 127.0.0.1:8000 and the nine listed paths may qualify. Requests need matching X-MCP-Test-Run, X-MCP-Server-Identity and X-MCP-Test-ID values, an exact Host header, Burp scope and MCP allowlist. Credential or cookie data always requires manual review.")
            append("\nWarning: while ACTIVE, qualifying local synthetic traffic may be disclosed, edited, forwarded or dropped without individual confirmation. The activation button is the human authorization; emergency stop disables this mode and cancels the interception session.")
        }

        val next = all.joinToString {
            "${it.id}:${it.revision}:${it.approvedRevision}:${it.disclosureStatus}:${((it.deadline-System.nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000}"
        }
        if (next != signature) {
            val selectedId = ids.getOrNull(list.selectedIndex)
            ids = all.map { it.id }
            model.clear()
            all.forEach { ticket ->
                val metadata = requestMetadata(ticket.original.request)
                val remaining = ((ticket.deadline - System.nanoTime()).coerceAtLeast(0) / 1_000_000 + 999) / 1000
                val decision = if (ticket.approvedRevision == ticket.revision) "FORWARD APPROVED" else ticket.statusLabel()
                val entry = "<html><div style='width:280px'>" +
                    "${escapeHtml(ticket.kind.uppercase())} ${escapeHtml(metadata.method)}<br>" +
                    "${escapeHtml(metadata.hostname)}${escapeHtml(metadata.urlPath.take(160))}<br>" +
                    "${remaining}s remaining â€” ${escapeHtml(decision)}<br>ID ${ticket.id}</div></html>"
                model.addElement(entry)
            }
            list.cellRenderer = DefaultListCellRenderer().apply {
                toolTipText = "Rows show safe metadata only. Sensitive content is available only after local disclosure approval."
            }
            if (selectedId != null) list.selectedIndex = ids.indexOf(selectedId)
            signature = next
            render()
        }

        recentActivity.text = ActivityLog.snapshot().take(30).joinToString("\n") { event ->
            buildString {
                append(event.timestamp).append("  ").append(event.action).append("  ").append(event.outcome)
                if (event.detail.isNotBlank()) append("  ").append(event.detail)
            }
        }.ifBlank { "No interception events yet." }
        recentActivity.caretPosition = 0
    }

    private fun DecisionQueue.Ticket<HeldMessage>.statusLabel(): String = when (disclosureStatus) {
        "PENDING" -> "DISCLOSURE APPROVAL PENDING"
        "DENIED" -> "DISCLOSURE DENIED"
        "BUSY" -> "ANOTHER APPROVAL ACTIVE"
        "ERROR" -> "APPROVAL ERROR"
        "CANCELLED" -> "APPROVAL CANCELLED"
        "EXPIRED" -> "DISCLOSURE EXPIRED"
        "APPROVED" -> "DISCLOSURE APPROVED"
        else -> if (proposed != null) "PROPOSED" else "PENDING"
    }

    private fun escapeHtml(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")

    fun cleanup() {
        timer.stop()
        identityControls.cleanup()
    }
}
