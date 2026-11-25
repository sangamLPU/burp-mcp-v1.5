package net.portswigger.mcp.rewrite

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.verify
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.DataAccessApprovalHandler
import net.portswigger.mcp.security.DataAccessSecurity
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean

class RewriteToolsIntegrationTest {
    @Test fun `active rewrite rules leave original utility and permission checks intact`() = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getString("host") } returns "127.0.0.1"
        every { storage.getInteger("port") } returns port
        every { storage.getBoolean("requireDataAccessApproval") } returns true
        every { storage.getBoolean("_alwaysAllowHttpHistory") } returns false
        every { storage.getBoolean("configEditingTooling") } returns false
        val api = mockk<MontoyaApi>(relaxed = true)
        val burpSuite = api.burpSuite()
        every { api.utilities().urlUtils().encode("audit test") } returns "audit%20test"
        val manager = RewriteManager(storage)
        manager.setTargets("example.test")
        manager.create("example.test", "POST", "/api", "application/json", "/name", "\"test\"")
        manager.enableApproved(manager.list().single())
        manager.activate()
        val server = KtorServerManager(api, manager)
        val client = TestSseMcpClient()
        val started = AtomicBoolean(false)
        val originalApproval = DataAccessSecurity.approvalHandler
        val denial = mockk<DataAccessApprovalHandler>()
        coEvery { denial.requestDataAccess(any(), any()) } returns false
        DataAccessSecurity.approvalHandler = denial
        try {
            server.start(McpConfig(storage, mockk<Logging>(relaxed = true))) { if (it is ServerState.Running) started.set(true) }
            repeat(100) { if (!started.get()) delay(100) }
            assertTrue(started.get())
            client.connectToStreamableHttpServer("http://127.0.0.1:$port/mcp")
            val encoded = client.callTool("url_encode", mapOf("content" to "audit test"))
            assertEquals("audit%20test", (encoded!!.content.first() as TextContent).text)
            val history = client.callTool("get_proxy_http_history", mapOf("count" to 1, "offset" to 0))
            assertEquals("HTTP history access denied by Burp Suite", (history!!.content.first() as TextContent).text)
            verify(exactly = 0) { api.proxy().history() }
            val config = client.callTool("set_project_options", mapOf("json" to "{}"))
            assertTrue((config!!.content.first() as TextContent).text.contains("disabled configuration editing"))
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
            assertTrue(manager.isActive())
        } finally {
            DataAccessSecurity.approvalHandler = originalApproval
            if (client.isConnected()) client.close()
            server.shutdown()
        }
    }

    @Test fun `MCP tools register and never echo replacement values`() = runBlocking {
        val port = ServerSocket(0).use { it.localPort }
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getString("host") } returns "127.0.0.1"
        every { storage.getInteger("port") } returns port
        val api = mockk<MontoyaApi>(relaxed = true)
        val manager = RewriteManager(storage)
        val server = KtorServerManager(api, manager)
        val client = TestSseMcpClient()
        val started = AtomicBoolean(false)
        try {
            server.start(McpConfig(storage, mockk<Logging>(relaxed = true))) { if (it is ServerState.Running) started.set(true) }
            repeat(100) { if (!started.get()) delay(100) }
            assertTrue(started.get())
            client.connectToStreamableHttpServer("http://127.0.0.1:$port/mcp")
            val tools = client.listTools()
            val names = tools.map { it.name }.toSet()
            assertEquals(setOf("replacementJson"), tools.single { it.name == "create_rewrite_rule" }.inputSchema.required?.toSet())
            assertEquals(setOf("mode", "match", "replacement"), tools.single { it.name == "create_response_rewrite_rule" }.inputSchema.required?.toSet())
            assertTrue(names.containsAll(listOf("create_rewrite_rule", "update_rewrite_rule", "list_rewrite_rules", "enable_rewrite_rule", "disable_rewrite_rule", "remove_rewrite_rule")))
            val secret = "private-test-value"
            val args = mapOf("hostname" to "example.test", "method" to "POST", "path" to "/api", "contentType" to "application/json", "jsonPointer" to "/name", "replacementJson" to "\"$secret\"")
            val created = client.callTool("create_rewrite_rule", args)
            assertFalse(created!!.isError ?: false)
            assertFalse(created.toString().contains(secret))
            val listed = client.callTool("list_rewrite_rules", emptyMap())
            assertFalse(listed.toString().contains(secret))
            val failed = client.callTool("create_rewrite_rule", args + ("replacementJson" to "$secret-invalid"))
            assertTrue(failed!!.isError ?: false)
            assertFalse(failed.toString().contains(secret))
            assertTrue(names.containsAll(listOf("create_global_parameter_rule", "update_global_parameter_rule", "list_global_parameter_rules", "enable_global_parameter_rule", "disable_global_parameter_rule", "remove_global_parameter_rule")))
            val global = client.callTool("create_global_parameter_rule", mapOf("parameterName" to "user_id", "replacementValue" to secret))
            assertFalse(global!!.isError ?: false)
            assertFalse(global.toString().contains(secret))
            assertEquals(globalLocations, manager.listGlobal().single().locations)
            assertFalse(manager.listGlobal().single().enabled)
            val globals = client.callTool("list_global_parameter_rules", emptyMap())
            assertFalse(globals.toString().contains(secret))
            assertTrue(names.containsAll(listOf("create_response_rewrite_rule", "update_response_rewrite_rule", "list_response_rewrite_rules", "enable_response_rewrite_rule", "disable_response_rewrite_rule", "remove_response_rewrite_rule")))
            val response = client.callTool("create_response_rewrite_rule", mapOf("mode" to "json_field", "match" to "privateField", "replacement" to "\"$secret\""))
            assertFalse(response!!.isError ?: false)
            assertFalse(response.toString().contains(secret))
            assertFalse(manager.listResponse().single().enabled)
            val responses = client.callTool("list_response_rewrite_rules", emptyMap())
            assertFalse(responses.toString().contains(secret))
            assertFalse(responses.toString().contains("privateField"))
            val filtered = client.callTool("list_response_rewrite_rules", mapOf("fieldName" to "privateField"))
            assertTrue(filtered.toString().contains(manager.listResponse().single().id))
            val noMatch = client.callTool("list_response_rewrite_rules", mapOf("fieldName" to "other"))
            assertFalse(noMatch.toString().contains(manager.listResponse().single().id))
            val globalJson = client.callTool("create_rewrite_rule", mapOf("fieldName" to "isPremium", "replacementJson" to "true"))
            assertFalse(globalJson!!.isError ?: false)
        } finally {
            if (client.isConnected()) client.close()
            server.shutdown()
        }
    }
}
