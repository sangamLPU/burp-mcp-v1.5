package net.portswigger.mcp.rewrite

import burp.api.montoya.persistence.PersistedObject
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Container
import javax.swing.JButton
import javax.swing.JTable
import javax.swing.SwingUtilities
import javax.swing.JTabbedPane

class RewritePanelTest {
    @Test fun `rule controls remain visible in a compact Burp window`() {
        SwingUtilities.invokeAndWait {
            val panel = RewritePanel(RewriteManager(mockk<PersistedObject>(relaxed = true)))
            panel.setSize(760, 355)
            fun layout(container: Container) {
                container.doLayout()
                container.components.filterIsInstance<Container>().forEach(::layout)
            }
            fun descendants(container: Container): List<java.awt.Component> = container.components.flatMap {
                listOf(it) + if (it is Container) descendants(it) else emptyList()
            }
            layout(panel)
            val children = descendants(panel)
            val tabs = children.filterIsInstance<JTabbedPane>().single()
            assertTrue((0 until tabs.tabCount).map { tabs.getTitleAt(it) }.containsAll(listOf("Overview", "JSON Rules", "Global Parameter Rules", "Response Rewrite Rules")))
            for (index in 0 until tabs.tabCount) {
                tabs.selectedIndex = index; layout(panel)
                val selected = descendants(tabs.selectedComponent as Container)
                val table = selected.filterIsInstance<JTable>().single()
                assertTrue(table.parent.height >= 40, "Rule table viewport was squeezed out")
                if (tabs.getTitleAt(index) == "Overview") continue
                listOf("Create", "View / edit", "Enable rule", "Disable rule", "Remove rule").forEach { text ->
                    val button = selected.filterIsInstance<JButton>().single { it.text == text }
                    val bounds = SwingUtilities.convertRectangle(button.parent, button.bounds, panel)
                    assertTrue(button.width > 0 && button.height > 0 && bounds.y >= 0 && bounds.y + bounds.height <= panel.height, "$text is not visible")
                }
            }
        }
    }
}
