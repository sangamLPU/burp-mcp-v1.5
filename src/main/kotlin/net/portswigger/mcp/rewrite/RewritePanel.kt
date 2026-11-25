package net.portswigger.mcp.rewrite

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.GridLayout
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.serialization.json.*
import javax.swing.*
import javax.swing.table.DefaultTableModel

class RewritePanel(private val manager: RewriteManager) : JPanel(BorderLayout(8, 8)) {
    private val targets = JTextArea(2, 45)
    private val status = JLabel()
    private val tableModel = object : DefaultTableModel(arrayOf("ID", "Host", "Method", "Path", "Enabled"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val table = JTable(tableModel)
    private val globalModel = object : DefaultTableModel(arrayOf("ID", "Parameter", "Locations", "Enabled"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val globalTable = JTable(globalModel)
    private val responseStatus = JLabel()
    private val responseModel = object : DefaultTableModel(arrayOf("ID", "Mode", "Host", "Enabled"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val responseTable = JTable(responseModel)
    private val overviewModel = object : DefaultTableModel(arrayOf("ID", "Direction", "Parameter / field", "Replacement type", "Match", "Enabled", "Match count", "Last matched"), 0) {
        override fun isCellEditable(row: Int, column: Int) = false
    }
    private val overviewTable = JTable(overviewModel)
    private val log = JTextArea(3, 60).apply { isEditable = false }
    private val timer = Timer(1500) { refresh() }

    init {
        border = BorderFactory.createEmptyBorder(12, 12, 12, 12)
        targets.text = manager.targets().joinToString("\n")
        val top = JPanel(BorderLayout(4, 4))
        top.add(JLabel("Manual allowlist: exact hostnames, one per line. Burp target scope is also required."), BorderLayout.NORTH)
        top.add(JScrollPane(targets), BorderLayout.CENTER)
        val controls = JPanel()
        controls.add(JButton("Save allowlist").apply { addActionListener { attempt { manager.setTargets(targets.text); refresh() } } })
        controls.add(JButton("Enable rewriting").apply { addActionListener {
            if (JOptionPane.showConfirmDialog(this@RewritePanel, "Enable approved rules for allowlisted hosts in Burp scope until disabled or the extension unloads?", "Approve rewriting", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.activate(); refresh() }
        } })
        controls.add(JButton("EMERGENCY DISABLE").apply { addActionListener { manager.disableAll(); refresh() } })
        controls.add(status)
        val responseControls = JPanel()
        responseControls.add(JButton("Enable response rewriting").apply { addActionListener {
            if (JOptionPane.showConfirmDialog(this@RewritePanel, "Enable approved response rules for allowlisted hosts in Burp scope until disabled or the extension unloads?", "Approve response rewriting", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.activateResponse(); refresh() }
        } })
        responseControls.add(JButton("Disable response rewriting").apply { addActionListener { manager.disableResponseRewriting(); refresh() } })
        responseControls.add(responseStatus)
        top.add(JPanel(GridLayout(0, 1)).apply { add(controls); add(responseControls) }, BorderLayout.SOUTH)
        add(top, BorderLayout.NORTH)

        val center = JPanel(BorderLayout())
        val jsonPanel = JPanel(BorderLayout())
        jsonPanel.add(JScrollPane(table), BorderLayout.CENTER)
        val buttons = JPanel()
        buttons.add(JButton("Create").apply { addActionListener { edit(null) } })
        buttons.add(JButton("View / edit").apply { addActionListener { selected()?.let { edit(it) } } })
        buttons.add(JButton("Enable rule").apply { addActionListener { selected()?.let { rule ->
            val text = JTextArea(approvalText(rule), 12, 65).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }
            if (JOptionPane.showConfirmDialog(this@RewritePanel, JScrollPane(text), "Approve rule", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.enableApproved(rule); refresh() }
        } } })
        buttons.add(JButton("Disable rule").apply { addActionListener { selected()?.let { attempt { manager.disable(it.id); refresh() } } } })
        buttons.add(JButton("Remove rule").apply { addActionListener { selected()?.let { rule ->
            if (JOptionPane.showConfirmDialog(this@RewritePanel, "Remove selected rule?", "Remove", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.remove(rule.id); refresh() }
        } } })
        jsonPanel.add(buttons, BorderLayout.SOUTH)
        val globalPanel = JPanel(BorderLayout())
        globalPanel.add(JScrollPane(globalTable), BorderLayout.CENTER)
        val globalButtons = JPanel()
        globalButtons.add(JButton("Create").apply { addActionListener { editGlobal(null) } })
        globalButtons.add(JButton("View / edit").apply { addActionListener { selectedGlobal()?.let { editGlobal(it) } } })
        globalButtons.add(JButton("Enable rule").apply { addActionListener { selectedGlobal()?.let { rule ->
            val text = JTextArea(globalApprovalText(rule), 12, 65).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }
            if (JOptionPane.showConfirmDialog(this@RewritePanel, JScrollPane(text), "Approve global rule", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.enableGlobalApproved(rule); refresh() }
        } } })
        globalButtons.add(JButton("Disable rule").apply { addActionListener { selectedGlobal()?.let { attempt { manager.disableGlobal(it.id); refresh() } } } })
        globalButtons.add(JButton("Remove rule").apply { addActionListener { selectedGlobal()?.let { rule ->
            if (JOptionPane.showConfirmDialog(this@RewritePanel, "Remove selected global rule?", "Remove", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.removeGlobal(rule.id); refresh() }
        } } })
        globalPanel.add(globalButtons, BorderLayout.SOUTH)
        val responsePanel = JPanel(BorderLayout())
        responsePanel.add(JScrollPane(responseTable), BorderLayout.CENTER)
        val responseButtons = JPanel()
        responseButtons.add(JButton("Create").apply { addActionListener { editResponse(null) } })
        responseButtons.add(JButton("View / edit").apply { addActionListener { selectedResponse()?.let { editResponse(it) } } })
        responseButtons.add(JButton("Enable rule").apply { addActionListener { selectedResponse()?.let { rule ->
            val text = JTextArea(responseApprovalText(rule), 12, 65).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }
            if (JOptionPane.showConfirmDialog(this@RewritePanel, JScrollPane(text), "Approve response rule", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.enableResponseApproved(rule); refresh() }
        } } })
        responseButtons.add(JButton("Disable rule").apply { addActionListener { selectedResponse()?.let { attempt { manager.disableResponse(it.id); refresh() } } } })
        responseButtons.add(JButton("Remove rule").apply { addActionListener { selectedResponse()?.let { rule ->
            if (JOptionPane.showConfirmDialog(this@RewritePanel, "Remove selected response rule?", "Remove", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION)
                attempt { manager.removeResponse(rule.id); refresh() }
        } } })
        responsePanel.add(responseButtons, BorderLayout.SOUTH)
        center.add(JTabbedPane().apply { addTab("Overview", JScrollPane(overviewTable)); addTab("JSON Rules", jsonPanel); addTab("Global Parameter Rules", globalPanel); addTab("Response Rewrite Rules", responsePanel) }, BorderLayout.CENTER)
        val bottom = JPanel(BorderLayout()).apply {
            add(JLabel("Recent events (no request bodies or replacement values)"), BorderLayout.NORTH)
            add(JScrollPane(log), BorderLayout.CENTER)
        }
        center.minimumSize = Dimension(0, 90)
        bottom.minimumSize = Dimension(0, 60)
        add(JSplitPane(JSplitPane.VERTICAL_SPLIT, center, bottom).apply {
            resizeWeight = 0.7
        }, BorderLayout.CENTER)
        refresh()
    }

    override fun addNotify() { super.addNotify(); timer.start() }
    override fun removeNotify() { timer.stop(); super.removeNotify() }
    private fun selected(): RewriteRule? {
        val row = table.selectedRow
        if (row < 0) return null
        val id = tableModel.getValueAt(table.convertRowIndexToModel(row), 0) as String
        return manager.list().firstOrNull { it.id == id }
    }
    private fun refresh() {
        status.text = if (manager.isActive()) "ACTIVE" else "OFF"
        responseStatus.text = if (manager.isResponseActive()) "Response: ACTIVE" else "Response: OFF"
        val selectedId = selected()?.id
        val rules = manager.list()
        // Avoid disrupting table selection when only the log changes.
        val current = (0 until tableModel.rowCount).map { row -> (0 until tableModel.columnCount).map { tableModel.getValueAt(row, it) } }
        if (current != rules.map { listOf<Any>(it.id, it.hostname, it.method, it.path, it.enabled) }) {
            tableModel.rowCount = 0
            rules.forEach { tableModel.addRow(arrayOf<Any>(it.id, it.hostname, it.method, it.path, it.enabled)) }
            val index = rules.indexOfFirst { it.id == selectedId }
            if (index >= 0) table.setRowSelectionInterval(index, index)
        }
        val selectedGlobalId = selectedGlobal()?.id
        val globals = manager.listGlobal()
        val globalCurrent = (0 until globalModel.rowCount).map { row -> (0 until globalModel.columnCount).map { globalModel.getValueAt(row, it) } }
        if (globalCurrent != globals.map { listOf<Any>(it.id, it.name, it.locations.joinToString(", "), it.enabled) }) {
            globalModel.rowCount = 0
            globals.forEach { globalModel.addRow(arrayOf<Any>(it.id, it.name, it.locations.joinToString(", "), it.enabled)) }
            val index = globals.indexOfFirst { it.id == selectedGlobalId }
            if (index >= 0) globalTable.setRowSelectionInterval(index, index)
        }
        val selectedResponseId = selectedResponse()?.id
        val responses = manager.listResponse()
        val responseCurrent = (0 until responseModel.rowCount).map { row -> (0 until responseModel.columnCount).map { responseModel.getValueAt(row, it) } }
        if (responseCurrent != responses.map { listOf<Any>(it.id, it.mode, it.hostname, it.enabled) }) {
            responseModel.rowCount = 0
            responses.forEach { responseModel.addRow(arrayOf<Any>(it.id, it.mode, it.hostname, it.enabled)) }
            val index = responses.indexOfFirst { it.id == selectedResponseId }
            if (index >= 0) responseTable.setRowSelectionInterval(index, index)
        }
        val rows = mutableListOf<List<Any>>()
        fun addOverview(id: String, direction: String, name: String, type: String, global: Boolean, enabled: Boolean) {
            val activity = manager.activityFor(id)
            val last = activity.lastMatched?.atZone(ZoneId.systemDefault())?.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) ?: "—"
            rows.add(listOf(id, direction, name, type, if (global) "Global" else "Filtered", enabled, activity.count, last))
        }
        rules.forEach { addOverview(it.id, "Request", it.fieldName.ifEmpty { it.pointer }, jsonValueType(it.valueJson),
            it.hostname.isEmpty() && it.method.isEmpty() && it.path.isEmpty() && it.contentType.isEmpty(), it.enabled) }
        globals.forEach { addOverview(it.id, "Request", it.name, "String", true, it.enabled) }
        responses.forEach { addOverview(it.id, "Response", it.match, if (it.mode == "text") "Text" else jsonValueType(it.replacement),
            it.hostname.isEmpty() && it.method.isEmpty() && it.path.isEmpty() && it.status == 0 && it.contentType.isEmpty(), it.enabled) }
        val overviewCurrent = (0 until overviewModel.rowCount).map { row -> (0 until overviewModel.columnCount).map { overviewModel.getValueAt(row, it) } }
        if (overviewCurrent != rows) { overviewModel.rowCount = 0; rows.forEach { overviewModel.addRow(it.toTypedArray()) } }
        val recentEvents = manager.logs().joinToString("\n")
        if (log.text != recentEvents) {
            log.text = recentEvents
            log.caretPosition = 0
        }
    }
    private fun jsonValueType(value: String): String = when (val element = Json.parseToJsonElement(value)) {
        JsonNull -> "Null"
        is JsonObject -> "Object"
        is JsonArray -> "Array"
        is JsonPrimitive -> when { element.isString -> "String"; element.content == "true" || element.content == "false" -> "Boolean"; else -> "Number" }
    }
    private fun selectedResponse(): ResponseRewriteRule? {
        val row = responseTable.selectedRow
        if (row < 0) return null
        val id = responseModel.getValueAt(responseTable.convertRowIndexToModel(row), 0) as String
        return manager.listResponse().firstOrNull { it.id == id }
    }
    private fun editResponse(rule: ResponseRewriteRule?) {
        val mode = JComboBox(arrayOf("json_field", "json_pointer", "text")).apply { selectedItem = rule?.mode ?: "json_field" }
        val match = JTextField(rule?.match ?: "")
        val replacement = JTextField(rule?.replacement ?: "")
        val host = JTextField(rule?.hostname ?: "")
        val method = JTextField(rule?.method ?: "")
        val path = JTextField(rule?.path ?: "")
        val statusField = JTextField(rule?.status?.takeIf { it != 0 }?.toString() ?: "")
        val contentType = JTextField(rule?.contentType ?: "")
        val panel = JPanel(GridLayout(0, 2, 4, 4))
        listOf("Mode (text requires separate approval)" to mode, "Field name / JSON Pointer / literal" to match,
            "Replacement (JSON scalar or literal text)" to replacement, "Exact hostname (blank = allowlist)" to host,
            "Request method (optional)" to method, "Exact path (optional)" to path, "Response status (optional)" to statusField,
            "Content-Type (optional)" to contentType).forEach { (label, field) -> panel.add(JLabel(label)); panel.add(field) }
        if (JOptionPane.showConfirmDialog(this, panel, "Response rule (saving disables it)", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) attempt {
            val next = ResponseRewriteRule(id = rule?.id ?: "", mode = mode.selectedItem as String, match = match.text,
                replacement = replacement.text, hostname = host.text, method = method.text, path = path.text,
                status = if (statusField.text.isBlank()) 0 else statusField.text.toInt(), contentType = contentType.text)
            if (rule == null) manager.createResponse(next) else manager.updateResponse(next)
            refresh()
        }
    }
    private fun selectedGlobal(): GlobalParameterRule? {
        val row = globalTable.selectedRow
        if (row < 0) return null
        val id = globalModel.getValueAt(globalTable.convertRowIndexToModel(row), 0) as String
        return manager.listGlobal().firstOrNull { it.id == id }
    }
    private fun editGlobal(rule: GlobalParameterRule?) {
        val name = JTextField(rule?.name ?: "")
        val value = JTextField(rule?.value ?: "")
        val checks = globalLocations.map { JCheckBox(it, rule?.locations?.contains(it) ?: true) }
        val panel = JPanel(GridLayout(0, 2, 4, 4))
        panel.add(JLabel("Exact case-sensitive parameter name")); panel.add(name)
        panel.add(JLabel("Replacement value (JSON string)")); panel.add(value)
        checks.forEach { panel.add(JLabel("Allow location")); panel.add(it) }
        if (JOptionPane.showConfirmDialog(this, panel, "Global rule (saving disables it)", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) attempt {
            val locations = checks.filter { it.isSelected }.map { it.text }
            if (rule == null) manager.createGlobal(name.text, value.text, locations)
            else manager.updateGlobal(rule.id, name.text, value.text, locations)
            refresh()
        }
    }
    private fun edit(rule: RewriteRule?) {
        val fields = listOf(
            JTextField(rule?.hostname ?: ""), JTextField(rule?.method ?: ""), JTextField(rule?.path ?: ""),
            JTextField(rule?.contentType ?: ""), JTextField(rule?.pointer ?: ""), JTextField(rule?.valueJson ?: "\"test\""), JTextField(rule?.fieldName ?: "")
        )
        val panel = JPanel(GridLayout(0, 2, 4, 4))
        listOf("Hostname (blank = allowlist)", "Method (blank = any)", "Path (blank = any)", "JSON content type (blank = any)", "JSON Pointer (or field name)", "Replacement JSON literal", "Field name (or JSON Pointer)").forEachIndexed { i, label ->
            panel.add(JLabel(label)); panel.add(fields[i])
        }
        if (JOptionPane.showConfirmDialog(this, panel, "Rule (saving disables it)", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) attempt {
            val v = fields.map { it.text }
            if (rule == null) manager.create(v[0], v[1], v[2], v[3], v[4], v[5], v[6])
            else manager.update(rule.id, v[0], v[1], v[2], v[3], v[4], v[5], v[6])
            refresh()
        }
    }
    private fun attempt(block: () -> Unit) {
        try { block() } catch (e: Exception) { JOptionPane.showMessageDialog(this, e.message ?: "Operation failed", "Rewrite rules", JOptionPane.ERROR_MESSAGE) }
    }
}
