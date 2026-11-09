package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.serializer
import net.portswigger.mcp.schema.asInputSchema
import net.portswigger.mcp.security.ActivityLog
import kotlin.experimental.ExperimentalTypeInference

class McpToolError(val publicMessage: String) : RuntimeException(publicMessage)

object ToolCatalog {
    private val tools = java.util.concurrent.ConcurrentSkipListSet<String>()
    fun clear() = tools.clear()
    fun register(name: String) { tools.add(name) }
    fun names(): List<String> = tools.toList()
}

@OptIn(InternalSerializationApi::class)
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: suspend I.() -> List<ContentBlock>
) {
    val toolName = I::class.simpleName?.toLowerSnakeCase() ?: error("Couldn't find name for ${I::class}")
    val serializer = I::class.serializer()
    val inputSchema = I::class.asInputSchema()

    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, request ->
        ActivityLog.record(toolName, "called")
        try {
            val arguments = request.params.arguments ?: JsonObject(emptyMap())
            require(Json.encodeToString(arguments).length <= 2_000_000) { "Tool input exceeds the 2 MB limit" }
            val input = Json.decodeFromJsonElement(serializer, arguments)
            if (input is Paginated) {
                require(input.count in 1..100) { "count must be between 1 and 100" }
                require(input.offset >= 0) { "offset must be zero or greater" }
            }
            val result = execute(input)
            ActivityLog.record(toolName, "success")
            CallToolResult(content = result, isError = false)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            ActivityLog.record(toolName, "error", e.javaClass.simpleName)
            CallToolResult(
                content = listOf(TextContent((e as? McpToolError)?.publicMessage ?: "Tool failed (${e.javaClass.simpleName}). Check the Burp MCP activity log for details.")),
                isError = true
            )
        }
    }

    ToolCatalog.register(toolName)
    addTool(name = toolName, description = description, inputSchema = inputSchema, handler = handler)
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpToolString")
inline fun <reified I : Any> Server.mcpTool(
    description: String,
    crossinline execute: suspend I.() -> String
) {
    mcpTool<I>(description, execute = {
        listOf(TextContent(execute(this)))
    })
}

inline fun <reified I : Any> Server.mcpUnitTool(
    description: String,
    crossinline execute: suspend I.() -> Unit
) {
    mcpTool<I>(description, execute = {
        execute(this)

        listOf(TextContent("Executed tool"))
    })
}

inline fun <reified I : Paginated, J : Any> Server.mcpPaginatedTool(
    description: String,
    noinline mapper: (J) -> CharSequence = { it.toString() },
    crossinline execute: suspend I.() -> List<J>
) {
    mcpTool<I>(description, execute = {

        val items = execute(this)

        when {
            offset >= items.size -> {
                "Reached end of items"
            }

            else -> {
                val upperLimit = (offset + count).coerceAtMost(items.size)

                items.subList(offset, upperLimit)
                    .joinToString(separator = "\n\n", transform = mapper)
            }
        }
    })
}

inline fun <reified I : Paginated> Server.mcpPaginatedTool(
    description: String,
    crossinline execute: suspend I.() -> Sequence<String>
) {
    mcpTool<I>(description, execute = {
        val seq = execute(this)
        val paginated = seq.drop(offset).take(count).toList()

        if (paginated.isEmpty()) {
            listOf(TextContent("Reached end of items"))
        } else {
            listOf(TextContent(paginated.joinToString(separator = "\n\n")))
        }
    })
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
@JvmName("mcpNamedToolString")
inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: suspend () -> List<ContentBlock>
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        ActivityLog.record(name, "called")
        try {
            val result = execute()
            ActivityLog.record(name, "success")
            CallToolResult(content = result, isError = false)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            ActivityLog.record(name, "error", e.javaClass.simpleName)
            CallToolResult(content = listOf(TextContent((e as? McpToolError)?.publicMessage ?: "Tool failed (${e.javaClass.simpleName}). Check the Burp MCP activity log for details.")), isError = true)
        }
    }
    ToolCatalog.register(name)
    addTool(name = name, description = description, inputSchema = ToolSchema(), handler = handler)
}

inline fun Server.mcpTool(
    name: String,
    description: String,
    crossinline execute: suspend () -> String
) {
    val handler: suspend (ClientConnection, CallToolRequest) -> CallToolResult = { _, _ ->
        ActivityLog.record(name, "called")
        try {
            val result = execute()
            ActivityLog.record(name, "success")
            CallToolResult(content = listOf(TextContent(result)), isError = false)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            ActivityLog.record(name, "error", e.javaClass.simpleName)
            CallToolResult(content = listOf(TextContent((e as? McpToolError)?.publicMessage ?: "Tool failed (${e.javaClass.simpleName}). Check the Burp MCP activity log for details.")), isError = true)
        }
    }
    ToolCatalog.register(name)
    addTool(name = name, description = description, inputSchema = ToolSchema(), handler = handler)
}

fun String.toLowerSnakeCase(): String {
    return this
        .replace(Regex("([a-z0-9])([A-Z])"), "$1_$2")
        .replace(Regex("([A-Z])([A-Z][a-z])"), "$1_$2")
        .replace(Regex("[\\s-]+"), "_")
        .lowercase()
}

interface Paginated {
    val count: Int
    val offset: Int
}
