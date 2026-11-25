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
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import net.portswigger.mcp.rewrite.RewriteManager
import net.portswigger.mcp.rewrite.registerRewriteTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

const val STREAMABLE_HTTP_PATH = "/mcp"
private const val MCP_SESSION_ID_HEADER = "Mcp-Session-Id"
private const val MCP_PROTOCOL_VERSION_HEADER = "Mcp-Protocol-Version"

class KtorServerManager(private val api: MontoyaApi, private val rewriteManager: RewriteManager? = null) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    @Synchronized
    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        if (executor.isShutdown) return
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)
                        allowMethod(HttpMethod.Delete)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")
                        allowHeader(MCP_SESSION_ID_HEADER)
                        allowHeader(MCP_PROTOCOL_VERSION_HEADER)
                        exposeHeader(MCP_SESSION_ID_HEADER)

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        val origin = call.request.header("Origin")
                        val host = call.request.header("Host")
                        val referer = call.request.header("Referer")
                        val userAgent = call.request.header("User-Agent")

                        if (origin != null && !isValidOrigin(origin)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        } else if (isBrowserRequest(userAgent)) {
                            api.logging().logToOutput("Blocked browser request without Origin header")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (host != null && !isValidHost(host, config.port)) {
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

                    // Legacy HTTP+SSE transport at "/", used by the bundled stdio proxy and existing clients.
                    mcp {
                        mcpServer
                    }

                    // Streamable HTTP transport at "/mcp", for clients that do not speak legacy SSE (e.g. Codex).
                    mcpStreamableHttp(path = STREAMABLE_HTTP_PATH) {
                        mcpServer
                    }

                    mcpServer.registerTools(api, config)
                    rewriteManager?.let { mcpServer.registerRewriteTools(it) }
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    @Synchronized
    override fun stop(callback: (ServerState) -> Unit) {
        if (executor.isShutdown) return
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        synchronized(this) {
            if (!executor.isShutdown) {
                // Stop on the same queue as start/stop. A queued start must not bind
                // a listener after unload has already tried to stop it.
                executor.submit {
                    try {
                        server?.stop(1000, 5000)
                    } catch (e: Exception) {
                        api.logging().logToError(e)
                    } finally {
                        server = null
                    }
                }
                executor.shutdown()
            }
        }
        if (!executor.awaitTermination(15, TimeUnit.SECONDS)) {
            api.logging().logToError("MCP server shutdown is still pending")
        }
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

    private fun isValidHost(host: String, expectedPort: Int): Boolean {
        try {
            val parts = host.split(":")
            val hostname = parts[0].lowercase()
            val port = if (parts.size > 1) parts[1].toIntOrNull() else null

            val allowedHosts = setOf("localhost", "127.0.0.1")
            if (hostname !in allowedHosts) {
                return false
            }

            if (port != null && port != expectedPort) {
                return false
            }

            return true
        } catch (_: Exception) {
            return false
        }
    }

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
