package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import java.net.URI
import java.time.Instant
import java.util.ArrayDeque

interface UserApprovalHandler {
    suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean
}

class SwingUserApprovalHandler : UserApprovalHandler {
    override suspend fun requestApproval(
        hostname: String, port: Int, config: McpConfig, requestContent: String?, api: MontoyaApi?
    ): Boolean {
        val action = requestContent?.lineSequence()?.firstOrNull()
            ?.takeIf { it.startsWith("[Burp MCP action: ") }
            ?.removePrefix("[Burp MCP action: ")?.removeSuffix("]") ?: "HTTP request"
        val message = buildString {
            appendLine("An MCP client is requesting to send an HTTP request to:")
            appendLine("Action: $action")
            appendLine()
            appendLine("Target: $hostname:$port")
            appendLine()
            appendLine("This approval applies to this operation only. The request is subject to Burp scope and the explicit target allowlist.")
        }

        val options = arrayOf("Approve once", "Deny")

        val burpFrame = findBurpFrame()

        val result = Dialogs.requestOption(
            burpFrame, message, options, requestContent, api
        )

        return result == 0
    }
}

object HttpRequestSecurity {

    var approvalHandler: UserApprovalHandler = SwingUserApprovalHandler()

    fun isAllowedByHostAllowlist(hostname: String, port: Int, config: McpConfig): Boolean {
        val target = "$hostname:$port"
        val hostOnly = hostname
        val targets = config.getAutoApproveTargetsList()

        return targets.any { approved ->
            when {
                approved.equals(target, ignoreCase = true) -> true

                approved.equals(hostOnly, ignoreCase = true) -> true

                approved.startsWith("*.") -> {
                    val domain = approved.substring(2)
                    isValidWildcardMatch(hostname, domain)
                }

                else -> false
            }
        }
    }

    private fun isValidWildcardMatch(hostname: String, domain: String): Boolean {
        if (domain.isEmpty() || domain.contains("*")) return false

        if (hostname.length <= domain.length) return false

        val expectedSuffix = ".$domain"
        if (!hostname.endsWith(expectedSuffix, ignoreCase = true)) return false

        val subdomain = hostname.substring(0, hostname.length - expectedSuffix.length)

        if (subdomain.isEmpty()) return false

        return subdomain.split(".").all { label ->
            label.isNotEmpty() && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") && label.matches(
                Regex("^[a-zA-Z0-9-]+$")
            )
        }
    }

    suspend fun checkHttpRequestPermission(
        hostname: String, port: Int, config: McpConfig, requestContent: String? = null, api: MontoyaApi? = null
    ): Boolean {
        if (!config.requireHttpRequestApproval) {
            return true
        }

        if (isAllowedByHostAllowlist(hostname, port, config)) {
            return true
        }

        return ApprovalTimeout.await("HTTP request: $hostname:$port") {
            approvalHandler.requestApproval(hostname, port, config, requestContent, api)
        } == true
    }

    /**
     * Permission check for any MCP-triggered network or Burp state-changing operation.
     * Unlike the legacy helper, this always requires read-only to be disabled, scope membership,
     * an explicit host allowlist entry, a rate-limit slot, and a per-operation user approval.
     */
    suspend fun checkAuthorizedRequest(
        request: HttpRequest,
        config: McpConfig,
        api: MontoyaApi,
        action: String = "HTTP request"
    ): Boolean {
        if (config.readOnlyMode) {
            ActivityLog.record(action, "denied", "read-only mode")
            return false
        }

        val service = request.httpService()
        val host = service.host()
        val port = service.port()
        if (!isAllowedByHostAllowlist(host, port, config)) {
            ActivityLog.record(action, "denied", "target is not allowlisted")
            return false
        }

        val url = runCatching { request.url() }.getOrNull()
        if (url.isNullOrBlank() || !urlMatchesHttpService(url, host, port)) {
            ActivityLog.record(action, "denied", "request URL does not match its Burp HTTP service")
            return false
        }
        if (!runCatching { api.scope().isInScope(url) }.getOrDefault(false)) {
            ActivityLog.record(action, "denied", "target is outside Burp scope")
            return false
        }

        if (!RequestRateLimiter.tryAcquire()) {
            ActivityLog.record(action, "denied", "rate limit exceeded")
            return false
        }

        val approved = ApprovalTimeout.await("$action: $host:$port") {
            approvalHandler.requestApproval(host, port, config, "[Burp MCP action: $action]\n${request}", api)
        } == true
        ActivityLog.record(action, if (approved) "approved" else "denied")
        return approved
    }
}

/** Prevent Host/authority values in a raw request from bypassing the host allowlist for its Burp service. */
internal fun urlMatchesHttpService(url: String, serviceHost: String, servicePort: Int): Boolean = runCatching {
    val uri = URI(url)
    val scheme = uri.scheme?.lowercase() ?: return@runCatching false
    if (scheme !in setOf("http", "https") || uri.userInfo != null) return@runCatching false
    val urlHost = uri.host?.removeSurrounding("[", "]") ?: return@runCatching false
    val urlPort = when {
        uri.port != -1 -> uri.port
        scheme == "https" -> 443
        else -> 80
    }
    urlHost.equals(serviceHost.removeSurrounding("[", "]"), ignoreCase = true) && urlPort == servicePort
}.getOrDefault(false)

/** In-process global limit shared by MCP HTTP requests and approved scan starts. */
object RequestRateLimiter {
    private const val MAX_REQUESTS_PER_MINUTE = 30
    private val timestamps = ArrayDeque<Instant>()

    @Synchronized
    fun tryAcquire(now: Instant = Instant.now()): Boolean {
        val cutoff = now.minusSeconds(60)
        while (timestamps.isNotEmpty() && timestamps.first().isBefore(cutoff)) timestamps.removeFirst()
        if (timestamps.size >= MAX_REQUESTS_PER_MINUTE) return false
        timestamps.addLast(now)
        return true
    }

    @Synchronized
    fun resetForTests() = timestamps.clear()
}
