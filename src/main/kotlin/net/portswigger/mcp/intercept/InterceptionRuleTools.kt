package net.portswigger.mcp.intercept

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.tools.McpToolError
import net.portswigger.mcp.tools.mcpTool
import java.nio.charset.StandardCharsets

fun Server.registerInterceptionRuleTools(live: LiveInterception) {
    fun <T> safeRuleOperation(action: () -> T): T = try {
        action()
    } catch (error: McpToolError) {
        throw error
    } catch (error: Exception) {
        val code = when (error) {
            is RuleAuthorizationRequired -> error.code
            is IllegalArgumentException -> "INVALID_RULE_OR_INPUT"
            is IllegalStateException -> "RULE_STATE_NOT_READY"
            else -> "RULE_OPERATION_REJECTED"
        }
        throw McpToolError("$code: ${safeRuleMessage(error)}")
    }

    mcpTool<BurpCreateInterceptionRule>(
        "Creates a disabled, in-memory rule for a predefined localhost test URL or a currently human-approved exact preparation target. Target activation additionally requires explicit session approval binding the exact prepared rule revisions. Supports separate bounded maximum match and actual modification counts. Requires bearer-authenticated write mode, empty queues, and either a human-activated localhost test identity or an exact-path preparation grant. Rule creation never enables automatic processing."
    ) { Json.encodeToString(safeRuleOperation { live.createInterceptionRule(spec) }) }

    mcpTool<BurpListInterceptionRules>("Lists configured in-memory interception rules in priority order, including state, expiry and counters; never returns message bodies or identity secrets.") {
        Json.encodeToString(live.ruleEngine.list())
    }

    mcpTool<BurpGetInterceptionRule>("Returns one rule configuration and its bounded lifecycle state. The authorization reference is a synthetic run ID or target preparation grant ID; server identity and bearer token are not returned.") {
        Json.encodeToString(safeRuleOperation { live.ruleEngine.get(ruleId) })
    }

    mcpTool<BurpUpdateInterceptionRule>("Replaces a disabled rule configuration before session start. The replacement is disabled and must be enabled again under the current approved session.") {
        Json.encodeToString(safeRuleOperation { live.updateInterceptionRule(ruleId, spec) })
    }

    mcpTool<BurpEnableInterceptionRule>("Enables a rule only inside a healthy human-authorized session bound to its local test identity or exact target grant and rule revision. The effective TTL is capped by rule, session and authorization expiry; no renewal occurs.") {
        Json.encodeToString(safeRuleOperation { live.enableInterceptionRule(ruleId) })
    }

    mcpTool<BurpDisableInterceptionRule>("Immediately pauses one rule. It does not forward, drop or otherwise change any pending message.") {
        Json.encodeToString(safeRuleOperation { live.disableInterceptionRule(ruleId) })
    }

    mcpTool<BurpDeleteInterceptionRule>("Deletes one rule from the in-memory rule store. Any in-flight evaluation is invalidated before it can commit.") {
        Json.encodeToString(safeRuleOperation { mapOf("deleted" to live.deleteInterceptionRule(ruleId)) })
    }

    mcpTool<BurpClearInterceptionRules>("Deletes all configured rules. Any in-flight evaluation is invalidated before it can commit.") {
        Json.encodeToString(safeRuleOperation { mapOf("deletedCount" to live.clearInterceptionRules()) })
    }

    mcpTool<BurpPreviewInterceptionRule>("Dry-runs a rule against a bounded synthetic sample without sending traffic, enabling a rule, or recording sample values. Sensitive, compressed, malformed, or unsupported input is refused or reported as unsupported.") {
        Json.encodeToString(safeRuleOperation {
            val sampleBytes = sample.body.toByteArray(StandardCharsets.UTF_8)
            require(sampleBytes.size <= InterceptionRuleEngine.MAX_MESSAGE_BYTES) { "Sample body exceeds the 64 KiB limit" }
            val message = RuleHttpMessage(
                direction = sample.direction,
                targetUrl = sample.targetUrl,
                url = sample.url,
                method = sample.method,
                headers = sample.headers.map { RuleHeader(it.key, it.value) },
                body = sampleBytes,
                statusCode = sample.statusCode
            )
            live.previewInterceptionRule(spec, message)
        })
    }

    mcpTool<BurpGetInterceptionRuleStats>("Returns one rule's actual request/response matches, modifications, forwards, drops, skips, failures, expiry and last sanitized error code. No message content is stored.") {
        val views = live.ruleEngine.list()
        val selected = ruleId?.let { id -> views.filter { it.id == id }.ifEmpty { error("Unknown interception rule") } } ?: views
        Json.encodeToString(selected.map { it.stats })
    }

    mcpTool<BurpGetInterceptionRuleEvents>("Returns recent bounded, sanitized rule execution events. Events contain IDs, direction, outcome and codes only, never raw HTTP values.") {
        Json.encodeToString(live.ruleEngine.eventHistory(count))
    }

    mcpTool<BurpGetRuleEngineStatus>("Returns bounded engine status, configured/active counts and emergency-stop latch state.") {
        Json.encodeToString(live.ruleEngine.status())
    }

    mcpTool<BurpClearInterceptionRuleStats>("Clears observable audit counters only. Consumed match/modification budgets are preserved; rule configuration, lifecycle state and authorization do not change.") {
        safeRuleOperation { live.clearInterceptionRuleStats(ruleId) }
        "Rule statistics cleared."
    }

    mcpTool<BurpPauseAllInterceptionRules>("Immediately pauses all active rules. The local authorization and session remain bounded and unchanged; rules do not resume automatically.") {
        live.pauseAllInterceptionRules()
        Json.encodeToString(live.ruleEngine.status())
    }

    mcpTool<BurpEmergencyStopRules>("Emergency Stop: immediately latches the rule engine off, disables unattended local authorization, stops the interception session and drops any held traffic. A fresh human-visible Burp activation is required before rules can be re-enabled.") {
        live.emergencyStopUnattendedLocalTestMode()
        Json.encodeToString(live.ruleEngine.status())
    }
}

private fun safeRuleMessage(error: Exception): String = when (error) {
    is RuleAuthorizationRequired -> error.code
    is IllegalArgumentException -> "Check the exact authorized target, required fields, transform type and configured bounds."
    is IllegalStateException -> when {
        error.message?.contains("Unknown interception rule", true) == true -> "The requested rule ID is not configured."
        error.message?.contains("already active", true) == true -> "The rule is already active."
        error.message?.contains("maximum match", true) == true -> "The rule has reached its configured match limit."
        error.message?.contains("maximum modification", true) == true -> "The rule has reached its configured actual modification limit."
        error.message?.contains("emergency-stopped", true) == true -> "A fresh human-visible local activation is required before rules can be enabled."
        else -> "The rule operation is not allowed in the current Burp session or queue state."
    }
    else -> "Check current Burp authorization, scope, queue state and rule ID."
}

@Serializable data class BurpCreateInterceptionRule(val spec: InterceptionRuleSpec)
@Serializable data class BurpListInterceptionRules(val includeDiagnostics: Boolean = true)
@Serializable data class BurpGetInterceptionRule(val ruleId: String)
@Serializable data class BurpUpdateInterceptionRule(val ruleId: String, val spec: InterceptionRuleSpec)
@Serializable data class BurpEnableInterceptionRule(val ruleId: String)
@Serializable data class BurpDisableInterceptionRule(val ruleId: String)
@Serializable data class BurpDeleteInterceptionRule(val ruleId: String)
@Serializable data class BurpClearInterceptionRules(val includeDiagnostics: Boolean = true)
@Serializable data class BurpPreviewSample(
    val direction: RuleDirection,
    val targetUrl: String,
    val url: String,
    val method: String,
    val headers: Map<String,String> = emptyMap(),
    val body: String = "",
    val statusCode: Int? = null
)
@Serializable data class BurpPreviewInterceptionRule(val spec: InterceptionRuleSpec, val sample: BurpPreviewSample)
@Serializable data class BurpGetInterceptionRuleStats(val ruleId: String? = null)
@Serializable data class BurpGetInterceptionRuleEvents(val count: Int = 50)
@Serializable data class BurpGetRuleEngineStatus(val includeDiagnostics: Boolean = true)
@Serializable data class BurpClearInterceptionRuleStats(val ruleId: String? = null)
@Serializable data class BurpPauseAllInterceptionRules(val includeDiagnostics: Boolean = true)
@Serializable data class BurpEmergencyStopRules(val includeDiagnostics: Boolean = true)
