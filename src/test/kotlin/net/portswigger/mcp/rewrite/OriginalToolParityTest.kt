package net.portswigger.mcp.rewrite

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean

class OriginalToolParityTest {
    @Test fun `original tools and schemas remain identical with rewriting on both transports and editions`() = runBlocking {
        val additions = setOf("create_rewrite_rule", "update_rewrite_rule", "list_rewrite_rules", "enable_rewrite_rule", "disable_rewrite_rule", "remove_rewrite_rule", "create_global_parameter_rule", "update_global_parameter_rule", "list_global_parameter_rules", "enable_global_parameter_rule", "disable_global_parameter_rule", "remove_global_parameter_rule", "create_response_rewrite_rule", "update_response_rewrite_rule", "list_response_rewrite_rules", "enable_response_rewrite_rule", "disable_response_rewrite_rule", "remove_response_rewrite_rule")
        for ((edition, configEditing, legacyTransport) in listOf(
            Triple(BurpSuiteEdition.COMMUNITY_EDITION, false, false),
            Triple(BurpSuiteEdition.COMMUNITY_EDITION, true, true),
            Triple(BurpSuiteEdition.PROFESSIONAL, false, true),
            Triple(BurpSuiteEdition.PROFESSIONAL, true, false)
        )) {
            val port = ServerSocket(0).use { it.localPort }
            val storage = mockk<PersistedObject>(relaxed = true)
            every { storage.getString("host") } returns "127.0.0.1"
            every { storage.getInteger("port") } returns port
            every { storage.getBoolean("configEditingTooling") } returns configEditing
            val api = mockk<MontoyaApi>(relaxed = true)
            every { api.burpSuite().version().edition() } returns edition
            val config = McpConfig(storage, mockk<Logging>(relaxed = true))

            suspend fun listTools(upgraded: Boolean): Map<String, Pair<String?, Any>> {
                val server = KtorServerManager(api, if (upgraded) RewriteManager(storage) else null)
                val client = TestSseMcpClient()
                val started = AtomicBoolean(false)
                try {
                    server.start(config) { if (it is ServerState.Running) started.set(true) }
                    repeat(100) { if (!started.get()) delay(100) }
                    assertTrue(started.get(), "Server failed to start")
                    if (legacyTransport) client.connectToServer("http://127.0.0.1:$port")
                    else client.connectToStreamableHttpServer("http://127.0.0.1:$port/mcp")
                    return client.listTools().associate { it.name to (it.description to it.inputSchema) }
                } finally {
                    if (client.isConnected()) client.close()
                    server.shutdown()
                }
            }

            val original = listTools(false)
            val upgraded = listTools(true)
            assertEquals(original.keys + additions, upgraded.keys, "Tool set changed for $edition")
            assertEquals(original, upgraded.filterKeys { it !in additions }, "Original schema or description changed")
            assertEquals(edition == BurpSuiteEdition.PROFESSIONAL, "get_scanner_issues" in upgraded)
        }
    }
}
