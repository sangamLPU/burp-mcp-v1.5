package net.portswigger.mcp

import net.portswigger.mcp.config.McpConfig

sealed class ServerState {
    data object Starting : ServerState()
    data object Running : ServerState()
    data object Stopping : ServerState()
    data object Stopped : ServerState()
    data class Failed(val exception: Throwable) : ServerState()
}

interface ServerManager {
    fun start(config: McpConfig, callback: (ServerState) -> Unit)
    fun stop(callback: (ServerState) -> Unit)
    fun shutdown()
}

object McpServerRuntime {
    @Volatile var state: String = "stopped"
    @Volatile var endpoint: String = "http://127.0.0.1:9876/mcp"
    @Volatile var lastError: String? = null
    @Volatile var bearerAuthenticationEnforced: Boolean = true
}
