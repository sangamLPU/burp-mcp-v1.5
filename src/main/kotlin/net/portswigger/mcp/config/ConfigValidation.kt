package net.portswigger.mcp.config

object ConfigValidation {

    fun validateServerConfig(host: String, portText: String): String? {
        val trimmedHost = host.trim()
        val port = portText.trim().toIntOrNull()

        if (trimmedHost.lowercase().removeSurrounding("[", "]") !in setOf("127.0.0.1", "localhost", "::1")) {
            return "MCP host must be a loopback address (127.0.0.1, localhost or ::1)"
        }

        if (port == null) {
            return "Port must be a valid number"
        }

        if (port < 1024 || port > 65535) {
            return "Port is not within valid range"
        }

        return null
    }
}
