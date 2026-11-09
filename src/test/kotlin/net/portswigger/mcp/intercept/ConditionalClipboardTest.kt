package net.portswigger.mcp.intercept

import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit

class ConditionalClipboardTest {
    @Test
    @Timeout(value = 3, unit = TimeUnit.SECONDS)
    fun `clipboard copy expires when its content is still current`() {
        val clipboard = Clipboard("test")
        val conditional = ConditionalClipboard(clipboard, clearAfterMillis = 40)
        try {
            conditional.copy("ephemeral-value")
            assertEquals("ephemeral-value", clipboardText(clipboard))

            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            while (clipboardText(clipboard) != "" && System.nanoTime() < deadline) Thread.sleep(10)

            assertEquals("", clipboardText(clipboard))
        } finally {
            conditional.close()
        }
    }

    @Test
    @Timeout(value = 3, unit = TimeUnit.SECONDS)
    fun `clipboard expiry leaves newer content untouched`() {
        val clipboard = Clipboard("test")
        val conditional = ConditionalClipboard(clipboard, clearAfterMillis = 80)
        try {
            conditional.copy("ephemeral-value")
            clipboard.setContents(StringSelection("newer-user-content"), null)
            Thread.sleep(160)

            assertEquals("newer-user-content", clipboardText(clipboard))
        } finally {
            conditional.close()
        }
    }

    private fun clipboardText(clipboard: Clipboard): String? =
        clipboard.getContents(null)?.getTransferData(DataFlavor.stringFlavor) as? String
}
