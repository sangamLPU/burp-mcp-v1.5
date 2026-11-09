package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.ConfigValidation
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class ServerSecurityPolicyTest {
    private fun rejected(host: String, bearerRequired: Boolean) {
        val port = ServerSocket(0).use { it.localPort }
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } returns null
        every { storage.getBoolean("requireBearerToken") } returns bearerRequired
        every { storage.getString(any()) } returns null
        every { storage.getString("host") } returns host
        every { storage.getString("bearerToken") } returns "synthetic-policy-token"
        every { storage.getInteger(any()) } returns null
        every { storage.getInteger("port") } returns port
        val api = mockk<MontoyaApi>(relaxed = true)
        val config = McpConfig(storage, api.logging())
        val manager = KtorServerManager(api)
        val terminal = CompletableFuture<ServerState>()
        try {
            manager.start(config) { state ->
                if (state is ServerState.Running || state is ServerState.Failed) terminal.complete(state)
            }
            assertTrue(terminal.get(10, TimeUnit.SECONDS) is ServerState.Failed,
                "Unsafe configuration must fail before opening a listener: $host bearer=$bearerRequired")
            ServerSocket(port).use { assertEquals(port, it.localPort) }
        } finally { manager.shutdown() }
    }

    @Test fun `disabled bearer authentication cannot open an MCP listener`() = rejected("127.0.0.1", false)

    @Test fun `non loopback MCP binding cannot open a listener`() = rejected("0.0.0.0", true)

    @Test fun `configuration validation restricts listener to loopback addresses`() {
        for (host in listOf("127.0.0.1", "localhost", "::1")) assertNull(ConfigValidation.validateServerConfig(host, "9876"), host)
        for (host in listOf("0.0.0.0", "example.invalid", "192.0.2.1")) assertNotNull(ConfigValidation.validateServerConfig(host, "9876"), host)
    }
}
