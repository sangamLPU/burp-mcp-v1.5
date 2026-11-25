package net.portswigger.mcp.rewrite

import burp.api.montoya.persistence.PersistedObject
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ResponseSafetyTest {
    @Test fun `only explicit disabled Burp response unpacking is safe`() {
        fun options(value: String) = """{"proxy":{"miscellaneous":{"unpack_gzip_deflate_in_responses":$value}}}"""
        assertTrue(proxyPreservesResponseEncoding(options("false")))
        for (value in listOf("true", "null", "\"false\"", "0", "{}"))
            assertFalse(proxyPreservesResponseEncoding(options(value)))
        assertFalse(proxyPreservesResponseEncoding("{}"))
        assertFalse(proxyPreservesResponseEncoding("not-json"))
    }

    @Test fun `response switch fails closed at activation and after configuration changes`() {
        var safe = false
        val manager = RewriteManager(mockk<PersistedObject>(relaxed = true)) { safe }
        manager.setTargets("example.test")
        manager.createResponse(ResponseRewriteRule(id = "ignored", mode = "json_field", match = "flag", replacement = "true"))
        manager.enableResponseApproved(manager.listResponse().single())
        assertThrows(IllegalArgumentException::class.java) { manager.activateResponse() }
        assertFalse(manager.isResponseActive())
        safe = true
        manager.activateResponse()
        assertEquals(1, manager.responsesFor("example.test", true).size)
        safe = false
        val epoch = manager.responseCheckEpoch("example.test", true)!!
        assertFalse(manager.enforceResponseConfiguration(manager.isResponseConfigurationSafe(), epoch))
        assertTrue(manager.responsesFor("example.test", true).isEmpty())
        assertFalse(manager.isResponseActive())
        assertTrue(manager.listResponse().single().enabled)
        assertTrue(manager.logs().any { "unpacking" in it })
    }

    @Test fun `unreadable configuration fails closed without altering request switch`() {
        val manager = RewriteManager(mockk<PersistedObject>(relaxed = true)) { throw IllegalStateException("not available") }
        manager.setTargets("example.test")
        manager.activate()
        assertThrows(IllegalArgumentException::class.java) { manager.activateResponse() }
        assertTrue(manager.isActive())
        assertFalse(manager.isResponseActive())
    }

    @Test fun `emergency disable cancels a response activation waiting on Burp configuration`() {
        val entered = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        val worker = Executors.newSingleThreadExecutor()
        try {
            val manager = RewriteManager(mockk<PersistedObject>(relaxed = true)) {
                entered.countDown()
                check(proceed.await(3, TimeUnit.SECONDS))
                true
            }
            manager.setTargets("example.test")
            val activation = worker.submit<Boolean> { runCatching { manager.activateResponse() }.isSuccess }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            manager.disableAll()
            proceed.countDown()
            assertFalse(activation.get(3, TimeUnit.SECONDS))
            assertFalse(manager.isResponseActive())
        } finally {
            proceed.countDown()
            worker.shutdownNow()
        }
    }
}
