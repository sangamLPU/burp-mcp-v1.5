package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig

object StateChangeSecurity {
    suspend fun confirm(
        api: MontoyaApi,
        config: McpConfig,
        action: String,
        details: String,
        approvalTimeoutMillis: Long = ApprovalTimeout.DEFAULT_TIMEOUT_MILLIS
    ): Boolean {
        if (config.readOnlyMode) {
            ActivityLog.record(action, "denied", "read-only mode")
            return false
        }
        val result = ApprovalTimeout.await("state change: $action", approvalTimeoutMillis) {
            Dialogs.requestOption(
                parent = findBurpFrame(),
                message = "An MCP client requested a Burp state change.\n\nAction: $action\n\nApprove this operation once?",
                options = arrayOf("Approve once", "Deny"),
                requestContent = details.take(16_000),
                api = api
            ) == 0
        } == true
        ActivityLog.record(action, if (result) "approved" else "denied")
        return result
    }
}
