package net.portswigger.mcp.intercept

import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.Transferable
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/** Temporarily copies a value and clears it later only while our content is still current. */
internal class ConditionalClipboard(
    private val clipboard: Clipboard,
    private val clearAfterMillis: Long = DEFAULT_CLEAR_AFTER_MILLIS,
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "burp-mcp-clipboard-clear").apply { isDaemon = true }
    }
) : AutoCloseable {
    private class Lease(value: String) : ClipboardOwner {
        @Volatile var value: String? = value
        @Volatile var ownershipLost: Boolean = false

        override fun lostOwnership(clipboard: Clipboard?, contents: Transferable?) {
            ownershipLost = true
            value = null
        }
    }

    private val lock = Any()
    private var currentLease: Lease? = null

    init {
        require(clearAfterMillis >= 0) { "Clipboard clear delay must not be negative" }
    }

    fun copy(value: String) {
        require(value.isNotEmpty()) { "Cannot copy an empty value" }
        val lease = Lease(value)
        synchronized(lock) {
            clipboard.setContents(StringSelection(value), lease)
            currentLease = lease
        }
        scheduler.schedule({ clearIfUnchanged(lease) }, clearAfterMillis, TimeUnit.MILLISECONDS)
    }

    fun clearCurrentIfUnchanged() {
        val lease = synchronized(lock) { currentLease } ?: return
        clearIfUnchanged(lease)
    }

    private fun clearIfUnchanged(lease: Lease) {
        synchronized(lock) {
            if (currentLease !== lease) return
            val copiedValue = lease.value
            if (!lease.ownershipLost && copiedValue != null) {
                val clipboardValue = runCatching {
                    clipboard.getContents(null)?.getTransferData(DataFlavor.stringFlavor) as? String
                }.getOrNull()
                // AWT has no compare-and-swap clipboard operation. Recheck both ownership and
                // exact content immediately before clearing, so normal newer clipboard writes win.
                if (!lease.ownershipLost && clipboardValue == copiedValue) {
                    clipboard.setContents(StringSelection(""), null)
                }
            }
            lease.value = null
            currentLease = null
        }
    }

    override fun close() {
        clearCurrentIfUnchanged()
        scheduler.shutdownNow()
    }

    companion object {
        const val DEFAULT_CLEAR_AFTER_MILLIS = 30_000L
    }
}
