package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStatelessStreamableHttp
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.ActivityLog
import net.portswigger.mcp.tools.registerBurpApiTools
import net.portswigger.mcp.tools.registerTools
import net.portswigger.mcp.intercept.LiveInterception
import net.portswigger.mcp.intercept.registerInterceptionTools
import net.portswigger.mcp.intercept.registerInterceptionRuleTools
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi, private val live: LiveInterception? = null) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        live?.cancel("SERVER_RESTARTED")
        McpServerRuntime.state = "starting"
        McpServerRuntime.endpoint = "http://${config.host}:${config.port}/mcp"
        McpServerRuntime.lastError = null
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                require(isLoopbackBind(config.host)) { "MCP listener must bind to loopback" }
                require(config.requireBearerToken) { "MCP bearer authentication must remain enabled" }
                McpServerRuntime.bearerAuthenticationEnforced = true

                net.portswigger.mcp.tools.ToolCatalog.clear()
                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", BuildInfo.serverVersion), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                mcpServer.registerTools(api, config)
                mcpServer.registerBurpApiTools(api, config, live)
                live?.let {
                    mcpServer.registerInterceptionTools(it, api)
                    mcpServer.registerInterceptionRuleTools(it)
                }

                // Bind numeric loopback even when the UI uses localhost; do not depend on DNS.
                val bindAddress = if (config.host.removeSurrounding("[", "]").equals("::1", true)) "::1" else "127.0.0.1"
                server = embeddedServer(Netty, port = config.port, host = bindAddress) {
                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader(HttpHeaders.Authorization)
                        allowHeader("Last-Event-ID")
                        allowHeader("MCP-Protocol-Version")
                        allowHeader("Mcp-Session-Id")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        if (call.request.httpMethod != HttpMethod.Options &&
                            !isAuthorized(call.request.header(HttpHeaders.Authorization), config)
                        ) {
                            call.respond(HttpStatusCode.Unauthorized)
                            return@intercept
                        }

                        val origin = call.request.header("Origin")
                        val host = call.request.header("Host")
                        val referer = call.request.header("Referer")
                        val userAgent = call.request.header("User-Agent")

                        if (origin != null && !isValidOrigin(origin)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        } else if (origin == null && isBrowserRequest(userAgent)) {
                            api.logging().logToOutput("Blocked browser request without Origin header")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (host != null && !isValidHost(host, config.port, config.host)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (referer != null && !isValidReferer(referer)) {
                            api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        call.response.header("X-Frame-Options", "DENY")
                        call.response.header("X-Content-Type-Options", "nosniff")
                        call.response.header("Referrer-Policy", "same-origin")
                        call.response.header("Content-Security-Policy", "default-src 'none'")
                    }

                    // This server exposes only tools and has no server-initiated notifications or resumable
                    // event streams. Use the SDK's POST-only transport so closing a client session cannot
                    // leave the stateful transport's standalone GET/SSE call alive in the Netty engine.
                    mcpStatelessStreamableHttp(path = "/mcp") {
                        mcpServer
                    }
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                McpServerRuntime.state = "running"
                callback(ServerState.Running)

            } catch (e: Exception) {
                McpServerRuntime.state = "failed"
                McpServerRuntime.lastError = e.javaClass.simpleName
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        live?.cancel("SERVER_STOPPED")
        McpServerRuntime.state = "stopping"
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                McpServerRuntime.state = "stopped"
                McpServerRuntime.lastError = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                McpServerRuntime.state = "failed"
                McpServerRuntime.lastError = e.javaClass.simpleName
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        live?.cancel("SERVER_STOPPED")
        server?.stop(1000, 5000)
        server = null
        McpServerRuntime.state = "stopped"

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private fun isAuthorized(header: String?, config: McpConfig): Boolean {
        val supplied = header?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.substringAfter(' ')
            ?.trim()
            ?: return false
        val expected = config.bearerToken
        if (expected.isBlank()) return false
        return MessageDigest.isEqual(
            supplied.toByteArray(StandardCharsets.UTF_8),
            expected.toByteArray(StandardCharsets.UTF_8)
        )
    }

    private fun isValidOrigin(origin: String): Boolean {
        try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")

            return hostname in allowedHosts
        } catch (_: Exception) {
            return false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false

        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )

        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int, bindHost: String): Boolean {
        try {
            val parsed = URI("http://$host")
            if (parsed.userInfo != null || parsed.host.isNullOrBlank() || parsed.path.isNotEmpty()) return false
            if (parsed.port != -1 && parsed.port != expectedPort) return false
            val hostname = parsed.host.removeSurrounding("[", "]").lowercase()
            val bind = bindHost.removeSurrounding("[", "]").lowercase()
            val loopbackNames = setOf("localhost", "127.0.0.1", "::1")
            return when {
                bind in loopbackNames -> hostname in loopbackNames
                bind in setOf("0.0.0.0", "::") -> hostname.matches(Regex("^[a-zA-Z0-9.:-]+$"))
                else -> hostname.equals(bind, ignoreCase = true)
            }
        } catch (_: Exception) {
            return false
        }
    }

    private fun isLoopbackBind(host: String): Boolean =
        host.removeSurrounding("[", "]").lowercase() in setOf("localhost", "127.0.0.1", "::1")

    private fun isValidReferer(referer: String): Boolean {
        try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase()

            val allowedHosts = setOf("localhost", "127.0.0.1")
            return hostname in allowedHosts

        } catch (_: Exception) {
            return false
        }
    }
}
