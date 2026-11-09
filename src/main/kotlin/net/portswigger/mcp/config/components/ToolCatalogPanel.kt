package net.portswigger.mcp.config.components

import net.portswigger.mcp.config.Design
import net.portswigger.mcp.tools.ToolCatalog
import java.awt.BorderLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.BorderFactory
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

/** Searchable view of the registered MCP tool names. */
class ToolCatalogPanel : JPanel(BorderLayout(Design.Spacing.MD, Design.Spacing.MD)) {
    private val filter = JTextField(28)
    private val count = JLabel()
    private val model = DefaultListModel<String>()
    private val list = JList(model).apply {
        selectionMode = ListSelectionModel.SINGLE_SELECTION
        font = Design.Typography.bodyMedium
        cellRenderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: JList<*>, value: Any?, index: Int, selected: Boolean, focus: Boolean
            ): java.awt.Component {
                val cell = super.getListCellRendererComponent(list, value, index, selected, focus)
                toolTipText = value?.toString()
                return cell
            }
        }
    }
    private var allTools = emptyList<String>()

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
            add(JLabel("Search registered MCP tools").apply {
                font = Design.Typography.titleMedium
                foreground = Design.Colors.onSurface
            }, c)
            c.gridx = 1
            c.weightx = 0.0
            c.fill = GridBagConstraints.NONE
            c.insets = Insets(0, 0, Design.Spacing.SM, 0)
            add(count, c)

            c.gridx = 0
            c.gridy = 1
            c.weightx = 1.0
            c.fill = GridBagConstraints.HORIZONTAL
            c.gridwidth = 2
            c.insets = Insets(0, 0, 0, 0)
            filter.toolTipText = "Filter by tool name"
            add(filter, c)
        }
        add(header, BorderLayout.NORTH)

        val scroll = JScrollPane(list).apply {
            minimumSize = java.awt.Dimension(0, 100)
            verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED
            horizontalScrollBarPolicy = JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        }
        add(scroll, BorderLayout.CENTER)
        add(JButton("Copy selected name").apply {
            addActionListener { list.selectedValue?.let { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(it), null) } }
        }, BorderLayout.SOUTH)

        filter.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent?) = applyFilter()
            override fun removeUpdate(e: DocumentEvent?) = applyFilter()
            override fun changedUpdate(e: DocumentEvent?) = applyFilter()
        })
        refreshTools()
    }

    fun refreshTools() {
        allTools = ToolCatalog.names().sorted()
        applyFilter()
    }

    private fun applyFilter() {
        val query = filter.text.trim().lowercase()
        val matches = allTools.filter { query.isEmpty() || it.lowercase().contains(query) }
        model.clear()
        matches.forEach(model::addElement)
        count.text = "${matches.size} / ${allTools.size}"
    }
}
