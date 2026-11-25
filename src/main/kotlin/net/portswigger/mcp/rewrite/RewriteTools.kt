package net.portswigger.mcp.rewrite

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.ExperimentalSerializationApi
import net.portswigger.mcp.schema.asInputSchema
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.tools.mcpTool
import net.portswigger.mcp.tools.toLowerSnakeCase

@Serializable data class CreateRewriteRule(val hostname: String = "", val method: String = "", val path: String = "", val contentType: String = "", val jsonPointer: String = "", val replacementJson: String, val fieldName: String = "")
@Serializable data class UpdateRewriteRule(val id: String, val hostname: String = "", val method: String = "", val path: String = "", val contentType: String = "", val jsonPointer: String = "", val replacementJson: String, val fieldName: String = "")
@Serializable data class EnableRewriteRule(val id: String)
@Serializable data class DisableRewriteRule(val id: String)
@Serializable data class RemoveRewriteRule(val id: String)
@Serializable data class CreateGlobalParameterRule(val parameterName: String, val replacementValue: String, val locations: List<String>? = null)
@Serializable data class UpdateGlobalParameterRule(val id: String, val parameterName: String, val replacementValue: String, val locations: List<String>)
@Serializable data class EnableGlobalParameterRule(val id: String)
@Serializable data class DisableGlobalParameterRule(val id: String)
@Serializable data class RemoveGlobalParameterRule(val id: String)
@Serializable data class ListGlobalParameterRules(val parameterName: String? = null)
@Serializable data class CreateResponseRewriteRule(val mode: String, val match: String, val replacement: String, val hostname: String = "", val method: String = "", val path: String = "", val status: Int = 0, val contentType: String = "")
@Serializable data class UpdateResponseRewriteRule(val id: String, val mode: String, val match: String, val replacement: String, val hostname: String = "", val method: String = "", val path: String = "", val status: Int = 0, val contentType: String = "")
@Serializable data class EnableResponseRewriteRule(val id: String)
@Serializable data class DisableResponseRewriteRule(val id: String)
@Serializable data class RemoveResponseRewriteRule(val id: String)
@Serializable data class ListResponseRewriteRules(val fieldName: String? = null)

fun Server.registerRewriteTools(manager: RewriteManager) {
    secureRewriteTool<CreateRewriteRule>("Create a disabled JSON request rewrite rule. Supply fieldName for a global case-sensitive field match or jsonPointer for a specific path. Hostname, method, URL path and JSON media type are optional exact filters. replacementJson is a JSON literal; global fields require a scalar. Exact allowlist, Burp scope and local approval apply.") {
        "Created disabled rule ${manager.create(hostname, method, path, contentType, jsonPointer, replacementJson, fieldName)}."
    }
    secureRewriteTool<UpdateRewriteRule>("Replace a rule's configuration and disable it pending fresh approval.") {
        manager.update(id, hostname, method, path, contentType, jsonPointer, replacementJson, fieldName)
        "Rule unchanged, or updated and disabled pending approval."
    }
    mcpTool(name = "list_rewrite_rules", description = "List rule IDs and enabled states; values and match details are only visible in Burp.") {
        val rules = manager.list()
        if (rules.isEmpty()) "No rewrite rules." else rules.joinToString("\n") { "${it.id} ${if (it.enabled) "enabled" else "disabled"}" }
    }
    secureRewriteTool<EnableRewriteRule>("Request local user approval to enable an existing rewrite rule. The allowlist and session switch are controlled in Burp.") {
        val rule = manager.list().firstOrNull { it.id == id } ?: error("Rule not found.")
        val answer = Dialogs.requestOption(null, approvalText(rule), arrayOf("Enable", "Deny"))
        currentCoroutineContext().ensureActive()
        if (answer == 0) { manager.enableApproved(rule); "Rule enabled." } else "Rule not enabled."
    }
    secureRewriteTool<DisableRewriteRule>("Disable a rewrite rule immediately.") { manager.disable(id); "Rule disabled." }
    secureRewriteTool<RemoveRewriteRule>("Remove a rewrite rule.") { manager.remove(id); "Rule removed." }
    secureRewriteTool<CreateGlobalParameterRule>("Create a disabled, case-sensitive parameter rule. Locations default to query, json, form, and multipart. Exact host allowlist and Burp scope apply. JSON replacements are strings. Enable only with local approval.") {
        "Created disabled global rule ${manager.createGlobal(parameterName, replacementValue, locations ?: globalLocations)}."
    }
    secureRewriteTool<UpdateGlobalParameterRule>("Update a global rule and disable it pending fresh local approval.") {
        manager.updateGlobal(id, parameterName, replacementValue, locations); "Global rule unchanged, or updated and disabled pending approval."
    }
    secureRewriteTool<ListGlobalParameterRules>("List global rule IDs and enabled states without exposing names or values; optionally filter by exact parameterName.") {
        val rules = manager.listGlobal().filter { parameterName == null || it.name == parameterName }
        if (rules.isEmpty()) "No global parameter rules." else rules.joinToString("\n") { "${it.id} ${if (it.enabled) "enabled" else "disabled"}" }
    }
    secureRewriteTool<EnableGlobalParameterRule>("Request local approval to enable a global parameter rule.") {
        val rule = manager.listGlobal().firstOrNull { it.id == id } ?: error("Rule not found.")
        val answer = Dialogs.requestOption(null, globalApprovalText(rule), arrayOf("Enable", "Deny"))
        currentCoroutineContext().ensureActive()
        if (answer == 0) { manager.enableGlobalApproved(rule); "Global rule enabled." } else "Global rule not enabled."
    }
    secureRewriteTool<DisableGlobalParameterRule>("Disable a global parameter rule immediately.") { manager.disableGlobal(id); "Global rule disabled." }
    secureRewriteTool<RemoveGlobalParameterRule>("Remove a global parameter rule.") { manager.removeGlobal(id); "Global rule removed." }
    secureRewriteTool<CreateResponseRewriteRule>("Create a disabled response rule. mode is json_field, json_pointer, or text; replacement is a JSON scalar literal for JSON modes and literal text for text mode. Host, method, path, status and content type filters are optional. Local approval, allowlist and Burp scope are required.") {
        "Created disabled response rule ${manager.createResponse(ResponseRewriteRule(mode = mode, match = match, replacement = replacement, hostname = hostname, method = method, path = path, status = status, contentType = contentType))}."
    }
    secureRewriteTool<UpdateResponseRewriteRule>("Update a response rule and disable it pending fresh local approval.") {
        manager.updateResponse(ResponseRewriteRule(id = id, mode = mode, match = match, replacement = replacement, hostname = hostname, method = method, path = path, status = status, contentType = contentType)); "Response rule unchanged, or updated and disabled pending approval."
    }
    secureRewriteTool<ListResponseRewriteRules>("List response rule IDs and enabled states without exposing values or matches; optionally filter JSON field rules by exact fieldName.") {
        val rules = manager.listResponse().filter { fieldName == null || (it.mode == "json_field" && it.match == fieldName) }
        if (rules.isEmpty()) "No response rewrite rules." else rules.joinToString("\n") { "${it.id} ${if (it.enabled) "enabled" else "disabled"}" }
    }
    secureRewriteTool<EnableResponseRewriteRule>("Request local approval to enable a response rule; the response session switch is controlled in Burp.") {
        val rule = manager.listResponse().firstOrNull { it.id == id } ?: error("Rule not found.")
        val answer = Dialogs.requestOption(null, responseApprovalText(rule), arrayOf("Enable", "Deny"))
        currentCoroutineContext().ensureActive()
        if (answer == 0) { manager.enableResponseApproved(rule); "Response rule enabled." } else "Response rule not enabled."
    }
    secureRewriteTool<DisableResponseRewriteRule>("Disable a response rule immediately.") { manager.disableResponse(id); "Response rule disabled." }
    secureRewriteTool<RemoveResponseRewriteRule>("Remove a response rule.") { manager.removeResponse(id); "Response rule removed." }
}

// Never return parser/storage exception messages, which can contain user-provided secrets.
@OptIn(InternalSerializationApi::class, ExperimentalSerializationApi::class)
private inline fun <reified I : Any> Server.secureRewriteTool(description: String, crossinline execute: suspend I.() -> String) {
    val serializer = I::class.serializer()
    val descriptor = serializer.descriptor
    val optional = (0 until descriptor.elementsCount).filter { descriptor.isElementOptional(it) }.map { descriptor.getElementName(it) }.toSet()
    val base = I::class.asInputSchema()
    val schema = ToolSchema(properties = base.properties, required = base.required?.filterNot { it in optional })
    addTool(name = I::class.simpleName!!.toLowerSnakeCase(), description = description, inputSchema = schema) { request ->
        try {
            val input = Json.decodeFromJsonElement(serializer, request.params.arguments ?: JsonObject(emptyMap()))
            CallToolResult(content = listOf(TextContent(execute(input))), isError = false)
        } catch (e: CancellationException) { throw e }
        catch (_: Exception) { CallToolResult(content = listOf(TextContent("Rule operation failed. Check the inputs, allowlist, and rule state in Burp.")), isError = true) }
    }
}

internal fun approvalText(rule: RewriteRule): String = "Approve JSON rewrite?\nHost: ${rule.hostname.ifEmpty { "any allowlisted host" }}\nMethod: ${rule.method.ifEmpty { "any" }}\nPath: ${rule.path.ifEmpty { "any" }}\nContent type: ${rule.contentType.ifEmpty { "supported JSON" }}\n${if (rule.fieldName.isEmpty()) "JSON Pointer: ${rule.pointer}" else "Field name: ${rule.fieldName}"}\nReplacement JSON: ${rule.valueJson}\n\nBurp scope and the manual allowlist still apply."
internal fun globalApprovalText(rule: GlobalParameterRule): String = "Approve global parameter rewrite?\nParameter: ${rule.name}\nReplacement: ${rule.value}\nLocations: ${rule.locations.joinToString()}\n\nAll paths and methods on exact allowlisted hosts in Burp scope. Earlier global rules take precedence."
internal fun responseApprovalText(rule: ResponseRewriteRule): String = "Approve ${rule.mode} response rewriting?\nMatch: ${rule.match}\nReplacement: ${rule.replacement}\nHost: ${rule.hostname.ifEmpty { "any allowlisted host" }}\nMethod: ${rule.method.ifEmpty { "any" }}\nPath: ${rule.path.ifEmpty { "any" }}\nStatus: ${if (rule.status == 0) "any supported" else rule.status}\nContent-Type: ${rule.contentType.ifEmpty { "any supported" }}\n\nExact allowlist and Burp scope apply. Earlier response rules win overlapping matches."
