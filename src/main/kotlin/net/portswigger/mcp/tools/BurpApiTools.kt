package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.sitemap.SiteMap
import burp.api.montoya.core.ByteArray
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.compat.MontoyaRuntimeCompat
import net.portswigger.mcp.McpServerRuntime
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.intercept.LiveInterception
import net.portswigger.mcp.intercept.LocalTestManagementOperation
import net.portswigger.mcp.intercept.LocalTestPolicyDecision
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.ActivityLog
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.RequestRateLimiter
import net.portswigger.mcp.security.SafeContent
import net.portswigger.mcp.security.StateChangeSecurity
import net.portswigger.mcp.security.urlMatchesHttpService
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

private const val MAX_PAGE_SIZE = 25
private const val MAX_SITE_MAP_PAGE_SIZE = 25
private const val DEFAULT_RESPONSE_TIMEOUT_MS = 10_000L
fun io.modelcontextprotocol.kotlin.sdk.server.Server.registerBurpApiTools(
    api: MontoyaApi,
    config: McpConfig,
    live: LiveInterception? = null
) {
    mcpTool<BurpGetStatus>("Returns the Burp MCP server state, endpoint, safety mode, and authentication status. Does not expose the bearer token.") {
        Json.encodeToString(
            StatusResult(
                extension = "Burp MCP Server",
                extensionVersion = net.portswigger.mcp.BuildInfo.version,
                buildId = net.portswigger.mcp.BuildInfo.buildId,
                serverState = McpServerRuntime.state,
                endpoint = McpServerRuntime.endpoint,
                lastError = McpServerRuntime.lastError,
                burpEdition = edition(api).name,
                readOnlyMode = config.readOnlyMode,
                bearerAuthenticationRequired = McpServerRuntime.bearerAuthenticationEnforced || config.requireBearerToken,
                authorizedTargetCount = config.getAutoApproveTargetsList().size
            )
        )
    }

    mcpTool<BurpGetCapabilities>("Lists Montoya API capabilities and edition-dependent features. Community Edition scanner capabilities are reported as unsupported.") {
        val pro = edition(api) == BurpSuiteEdition.PROFESSIONAL
        Json.encodeToString(
            CapabilityResult(
                montoyaApi = "2023.12.1 compile baseline; runtime feature detection",
                extensionVersion = net.portswigger.mcp.BuildInfo.version,
                buildId = net.portswigger.mcp.BuildInfo.buildId,
                burpEdition = edition(api).name,
                proxyHistory = true,
                siteMap = true,
                repeaterSend = true,
                repeaterTabEnumeration = false,
                http1Request = true,
                http2Request = true,
                scannerFindings = pro,
                passiveAudit = pro,
                activeAudit = false,
                collaborator = pro,
                scannerNote = when {
                    !pro -> "Burp Scanner and Collaborator APIs are Professional-only."
                    else -> "Passive audit is available. Active audit is disabled because the Montoya API exposes only legacy active checks here, which can include intrusive tests."
                }
            )
        )
    }

    mcpTool<BurpGetProjectInfo>("Returns the current Burp project name and ID where the loaded Montoya API exposes them; older Burp versions return an explicit unavailable reason.") {
        val project = MontoyaRuntimeCompat.projectInfo(api)
        Json.encodeToString(ProjectInfoResult(project.name, project.id, project.available, project.reason))
    }

    mcpTool<BurpGetScope>("Checks URLs against the current Burp target scope and explicit host allowlist. Montoya does not expose a direct scope-rule listing API, so supply URLs to evaluate.") {
        require(urls.size <= 25) { "At most 25 URLs can be checked per call" }
        val checks = urls.map { url ->
            val parsed = runCatching { java.net.URI(url) }.getOrNull()
            val host = parsed?.host?.removeSurrounding("[", "]")
            val port = if (parsed == null || parsed.port == -1) {
                when (parsed?.scheme?.lowercase()) { "https" -> 443; "http" -> 80; else -> -1 }
            } else parsed.port
            val inScope = runCatching { api.scope().isInScope(url) }.getOrDefault(false)
            val allowlisted = host != null && port in 1..65535 && HttpRequestSecurity.isAllowedByHostAllowlist(host, port, config)
            ScopeCheck(url = SafeContent.redactUrl(url), inBurpScope = inScope, hostAllowlisted = allowlisted, eligible = inScope && allowlisted)
        }
        Json.encodeToString(ScopeResult(scopeRulesEnumerated = false, note = "Use Burp Target > Scope to view or edit scope rules.", checks = checks))
    }

    mcpTool(
        "burp_configure_local_test_scope",
        "Adds only the nine fixed 127.0.0.1:8000 synthetic test endpoints to Burp Target scope and the explicit host allowlist. Requires local confirmation unless the operator has explicitly enabled the bounded Unattended Local Test Mode in Burp."
    ) {
        val details = buildString {
        appendLine("Include these exact local test URLs in Burp Target scope:")
        LocalTestTargets.urls.forEach(::appendLine)
        append("Add only ${LocalTestTargets.ALLOWLIST_ENTRY} to the Burp MCP authorized-host allowlist.")
        }
        val unattendedDecision = live?.unattendedManagementDecision(LocalTestManagementOperation.CONFIGURE_LOCAL_SCOPE)
        val locallyApproved = unattendedDecision?.decision == LocalTestPolicyDecision.AUTO_APPROVE ||
            StateChangeSecurity.confirm(api, config, "Configure localhost test scope", details)
        if (!locallyApproved) {
            ActivityLog.record("configure_local_test_scope", "denied")
            return@mcpTool "Denied: local Burp confirmation was not approved."
        }

        val scope = api.scope()
        val includeFailures = mutableListOf<String>()
        LocalTestTargets.urls.forEachIndexed { index, url ->
            try {
                if (!scope.isInScope(url)) scope.includeInScope(url)
            } catch (error: Exception) {
                includeFailures += "endpoint-${index + 1}:${error.javaClass.simpleName}"
            }
        }
        val inScopeChecks = LocalTestTargets.urls.map { url ->
            runCatching { scope.isInScope(url) }.getOrDefault(false)
        }
        val burpScopeComplete = inScopeChecks.all { it }
        val allowlistChanged = if (burpScopeComplete) {
            config.addAutoApproveTarget(LocalTestTargets.ALLOWLIST_ENTRY)
        } else false
        val hostAllowlisted = HttpRequestSecurity.isAllowedByHostAllowlist(
            LocalTestTargets.HOST, LocalTestTargets.PORT, config
        )
        val configurationComplete = burpScopeComplete && hostAllowlisted
        if (!configurationComplete) {
            ActivityLog.record(
                "configure_local_test_scope", "partial",
                "endpointCount=${LocalTestTargets.urls.size} inBurpScope=${inScopeChecks.count { it }} " +
                    "hostAllowlisted=$hostAllowlisted includeFailures=${includeFailures.size}"
            )
        } else {
            ActivityLog.record("configure_local_test_scope", "configured", "endpointCount=${LocalTestTargets.urls.size}")
        }
        Json.encodeToString(
            LocalTestScopeResult(
                targetAllowlist = LocalTestTargets.ALLOWLIST_ENTRY,
                configurationComplete = configurationComplete,
                allowlistAdded = allowlistChanged,
                failureSummary = when {
                    configurationComplete -> null
                    includeFailures.isNotEmpty() -> "Burp scope inclusion failed for ${includeFailures.joinToString(", ")}; the MCP allowlist was not changed unless already present."
                    !burpScopeComplete -> "Burp did not confirm every predefined localhost URL; the MCP allowlist was not changed unless already present."
                    else -> "The exact localhost MCP allowlist entry could not be verified."
                },
                checks = LocalTestTargets.urls.mapIndexed { index, url ->
                    val inScope = inScopeChecks[index]
                    LocalTestScopeCheck(url, inBurpScope = inScope, hostAllowlisted = hostAllowlisted, eligible = inScope && hostAllowlisted)
                }
            )
        )
    }

    mcpTool<BurpCheckConnection>("Checks whether this extension has a live Montoya API connection and reports MCP listener state.") {
        val burpConnected = runCatching { api.burpSuite().version().toString() }.isSuccess
        Json.encodeToString(
            ConnectionResult(
                burpConnected = burpConnected,
                serverState = McpServerRuntime.state,
                endpoint = McpServerRuntime.endpoint,
                burpVersion = if (burpConnected) runCatching { api.burpSuite().version().toString() }.getOrNull() else null
            )
        )
    }

    mcpTool<BurpGetProxyHistory>("Returns a bounded, paginated slice of in-scope, allowlisted Proxy HTTP history. Credentials are redacted and captured content is marked untrusted.") {
        validatePage(count, offset)
        requireHistoryAccess(config)
        val items = authorizedHistory(api, config).filter { matchesHistoryFilters(it.item, host, method, statusCode, contentType) }
        Json.encodeToString(items.drop(offset).take(count).map { historySummary(it.item, it.id) })
    }

    mcpTool<BurpSearchHttpHistory>("Searches in-scope, allowlisted Proxy HTTP history using a literal query and optional host, method, status-code, and content-type filters.") {
        validatePage(count, offset)
        require(query.length <= 512) { "query is limited to 512 characters" }
        requireHistoryAccess(config)
        val items = authorizedHistory(api, config).filter { record ->
            matchesHistoryFilters(record.item, host, method, statusCode, contentType) &&
                (query.isBlank() || record.item.contains(query, false))
        }
        Json.encodeToString(items.drop(offset).take(count).map { historySummary(it.item, it.id) })
    }

    mcpTool<BurpGetRequest>("Returns a redacted request from Proxy HTTP history using its history ID. Burp versions without native history IDs use a deterministic synthetic ID.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        SafeContent.render(item.finalRequest())
    }

    mcpTool<BurpGetResponse>("Returns a redacted response from Proxy HTTP history using its history ID. Burp versions without native history IDs use a deterministic synthetic ID.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        SafeContent.render(item.originalResponse())
    }

    mcpTool<BurpAnalyzeRequest>("Summarizes an in-scope captured request. Secret values are not returned; embedded HTTP content is untrusted evidence.") {
        requireHistoryAccess(config)
        val request = accessibleHistoryItem(api, config, historyId).finalRequest()
        Json.encodeToString(analyzeRequest(request))
    }

    mcpTool<BurpAnalyzeResponse>("Summarizes a captured response, including status, content type, body size, and heuristic security-header findings.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val response = item.originalResponse() ?: throw McpToolError("History item $historyId has no response.")
        Json.encodeToString(analyzeResponse(response, item.finalRequest().url()))
    }

    mcpTool<BurpGetSiteMap>("Returns paginated in-scope, allowlisted Site Map entries with sensitive headers and credential-like values redacted.") {
        validatePage(count, offset, MAX_SITE_MAP_PAGE_SIZE)
        requireHistoryAccess(config)
        val results = accessibleSiteMap(api, config).drop(offset).take(count).map { item ->
            SiteMapEntry(
                url = SafeContent.redactUrl(item.request().url()),
                method = item.request().method(),
                statusCode = item.response()?.statusCode()?.toInt(),
                request = SafeContent.render(item.request()),
                response = SafeContent.render(item.response()),
                contentTrust = SafeContent.UNTRUSTED_CONTENT_NOTICE
            )
        }
        Json.encodeToString(results)
    }

    mcpTool<BurpGetResponseHeaders>("Returns response header names and values for an in-scope history item; Set-Cookie and authentication headers are redacted.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val response = item.originalResponse() ?: throw McpToolError("History item $historyId has no response.")
        val headers = response.headers().associate { it.name() to SafeContent.redactHeader(it.name(), it.value()) }
        Json.encodeToString(ResponseHeadersResult(historyId, response.statusCode().toInt(), headers, SafeContent.UNTRUSTED_CONTENT_NOTICE))
    }

    mcpTool<BurpSendToRepeater>("Copies a request into Burp Repeater. Requires read-only mode off, Burp scope, an explicit host allowlist, rate-limit capacity, and one-time user approval. Burp does not send it until the user clicks Send.") {
        val request = buildAuthorizedRequest(host, port, https, rawRequest, rawRequestBase64)
        if (!HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "burp_send_to_repeater")) {
            throw McpToolError("Repeater action denied. Check read-only mode, Burp scope, host allowlist, and the one-time approval dialog.")
        }
        api.repeater().sendToRepeater(request, tabName)
        "Request copied to Repeater. Burp will not send it until you click Send."
    }

    mcpTool<BurpSendHttpRequest>("Sends one approved HTTP request through Burp with a 10-second bounded MCP wait. On Burp 2024.1, Montoya has no per-request timeout/cancel API, so Burp may finish a timed-out send in the background; it is never retried. Use either rawRequest or rawRequestBase64. Requires in-scope allowlisted target, read-only mode off, rate-limit capacity, and one-time approval.") {
        val request = buildAuthorizedRequest(host, port, https, rawRequest, rawRequestBase64)
        if (!HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "burp_send_http_request")) {
            throw McpToolError("Request denied. Check read-only mode, Burp target scope, the explicit host allowlist, and the one-time approval dialog.")
        }
        var options = RequestOptions.requestOptions()
        if (http2) options = options.withHttpMode(HttpMode.HTTP_2)
        val response = BurpHttpRequestExecutor.send(api, request, options, DEFAULT_RESPONSE_TIMEOUT_MS)
        SafeContent.render(response?.response())
    }

    mcpTool<BurpCompareResponses>("Compares two in-scope captured responses using status, header, and body hashes; sensitive values are redacted.") {
        requireHistoryAccess(config)
        val first = accessibleHistoryItem(api, config, firstHistoryId)
        val second = accessibleHistoryItem(api, config, secondHistoryId)
        val a = first.originalResponse() ?: throw McpToolError("First history item has no response.")
        val b = second.originalResponse() ?: throw McpToolError("Second history item has no response.")
        Json.encodeToString(compareResponses(firstHistoryId, a, secondHistoryId, b))
    }

    mcpTool<BurpModifyRequest>("Produces a proposed request by updating/removing headers or replacing a textual body. This tool does not send requests or change Burp state; credential-like values in the result are redacted.") {
        require(rawRequest.length <= SafeContent.MAX_REQUEST_BYTES) { "Request exceeds the 1 MiB limit" }
        require(headers.size <= 50 && removeHeaders.size <= 50) { "At most 50 header changes are accepted" }
        require(headers.keys.all { it.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")) }) { "Invalid header name" }
        require(headers.values.all { '\r' !in it && '\n' !in it }) { "Header values cannot contain CR or LF" }
        require(removeHeaders.all { it.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")) }) { "Invalid header name in removeHeaders" }
        val modified = modifyRawRequest(rawRequest, headers, removeHeaders, replacementBody)
        SafeContent.redactRaw(modified)
    }

    mcpTool<BurpGetRepeaterTabs>("The current Montoya Repeater API can create tabs but cannot enumerate existing tabs.") {
        throw McpToolError("Unsupported capability: Montoya exposes sendToRepeater but has no Repeater tab listing method.")
    }

    mcpTool<BurpAnalyzeSecurityHeaders>("Analyzes observed security response headers. Results are heuristic and require manual verification.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val response = item.originalResponse() ?: throw McpToolError("History item has no response.")
        Json.encodeToString(SecurityAnalysis.securityHeaders(headerMap(response), item.finalRequest().httpService().secure()))
    }

    mcpTool<BurpAnalyzeCookies>("Analyzes Set-Cookie attributes. It redacts cookie values and classifies header-only observations as suspicious or requiring manual verification.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val response = item.originalResponse() ?: throw McpToolError("History item has no response.")
        val cookies = response.headers().filter { it.name().equals("Set-Cookie", true) }.map { it.value() }
        Json.encodeToString(SecurityAnalysis.cookies(cookies, item.finalRequest().httpService().secure()))
    }

    mcpTool<BurpAnalyzeCors>("Analyzes observed CORS response headers. A suspicious pattern is not a confirmed vulnerability.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val response = item.originalResponse() ?: throw McpToolError("History item has no response.")
        Json.encodeToString(SecurityAnalysis.cors(headerMap(response), item.finalRequest().headerValue("Origin")))
    }

    mcpTool<BurpAnalyzeAuthentication>("Reports authentication-related HTTP signals without exposing Authorization or Cookie values. Findings require endpoint policy verification.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        Json.encodeToString(
            SecurityAnalysis.authentication(
                headerMap(item.finalRequest()),
                item.originalResponse()?.statusCode()?.toInt(),
                item.originalResponse()?.let(::headerMap).orEmpty()
            )
        )
    }

    mcpTool<BurpFindSensitiveData>("Scans an in-scope captured message for common credential and personal-data patterns. Returns counts and categories only, never matched values.") {
        requireHistoryAccess(config)
        val item = accessibleHistoryItem(api, config, historyId)
        val message = if (part.equals("request", true)) item.finalRequest() else item.originalResponse()
            ?: throw McpToolError("History item has no response.")
        val body = message.body()
        val text = body.subArray(0, body.length().coerceAtMost(65_536)).toString()
        Json.encodeToString(SecurityAnalysis.sensitiveData(text))
    }

    mcpTool<BurpGetScannerIssues>("Returns Burp Scanner findings in Professional Edition. Community Edition returns an explicit unsupported-capability error.") {
        validatePage(count, offset)
        if (edition(api) != BurpSuiteEdition.PROFESSIONAL) {
            throw McpToolError("Unsupported capability: Burp Scanner findings require Burp Suite Professional Edition.")
        }
        requireHistoryAccess(config)
        val issues = api.siteMap().issues().asSequence()
            .filter { isAuthorizedScannerIssue(it, api, config) }
            .drop(offset).take(count)
            .map { it.toSerializableForm { pair -> isAuthorizedRequest(pair.request(), api, config) } }.toList()
        Json.encodeToString(issues)
    }

    mcpTool<BurpStartScan>("Starts a single-request passive audit using Burp Professional's passive checks only. It does not send modified test payloads. Requires an authorized in-scope request, read-only mode off, a rate-limit slot, and explicit per-scan approval.") {
        requireScanner(api)
        val request = buildAuthorizedRequest(host, port, https, rawRequest, null)
        if (!HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "burp_start_passive_scan")) {
            throw McpToolError("Passive audit denied. Check read-only mode, Burp scope, explicit host allowlist, and approval.")
        }
        val audit = withContext(Dispatchers.IO) {
            api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS)
            ).also { it.addRequest(request) }
        }
        val id = UUID.randomUUID().toString()
        ScanRegistry.add(id, audit)
        ActivityLog.record("burp_start_passive_scan", "started", "passive audit")
        Json.encodeToString(ScanStatusResult(id, SafeContent.markUntrusted(audit.statusMessage(), 512), audit.requestCount(), audit.errorCount(), audit.issues().size))
    }

    mcpTool<BurpGetScanStatus>("Returns status for a scan started by this extension instance. Scanner task discovery requires Burp Professional.") {
        requireScanner(api)
        val audit = ScanRegistry.get(scanId) ?: throw McpToolError("No active audit with this extension-generated scan ID. Scan IDs are lost when Burp unloads the extension.")
        Json.encodeToString(ScanStatusResult(scanId, SafeContent.markUntrusted(audit.statusMessage(), 512), audit.requestCount(), audit.errorCount(), audit.issues().size))
    }

    mcpTool<BurpStopScan>("Stops and deletes a passive audit created by this extension instance. Requires read-only mode off and one-time approval.") {
        requireScanner(api)
        val audit = ScanRegistry.get(scanId) ?: throw McpToolError("No active audit with this extension-generated scan ID.")
        if (!StateChangeSecurity.confirm(api, config, "Stop Burp passive audit", "Scan ID: $scanId")) {
            throw McpToolError("Scan stop denied: read-only mode is enabled or the operation was not approved.")
        }
        withContext(Dispatchers.IO) { audit.delete() }
        ScanRegistry.remove(scanId)
        "Passive audit stopped and its task removed."
    }

    mcpTool<BurpGenerateSecurityReport>("Generates a bounded summary from in-scope Site Map responses and Scanner findings where available. Findings are labeled as observed, suspicious, or requiring manual verification.") {
        validatePage(count, offset, MAX_PAGE_SIZE)
        requireHistoryAccess(config)
        val items = accessibleSiteMap(api, config).drop(offset).take(count)
        val findings = items.flatMap { item ->
            val response = item.response() ?: return@flatMap emptyList()
            SecurityAnalysis.securityHeaders(headerMap(response), item.request().httpService().secure()) +
                SecurityAnalysis.cookies(response.headers().filter { it.name().equals("Set-Cookie", true) }.map { it.value() }, item.request().httpService().secure()) +
                SecurityAnalysis.cors(headerMap(response), item.request().headerValue("Origin"))
        }
        val scannerSupported = edition(api) == BurpSuiteEdition.PROFESSIONAL
        val scannerIssueCount = if (scannerSupported) runCatching {
            api.siteMap().issues().count { isAuthorizedScannerIssue(it, api, config) }
        }.getOrDefault(0) else null
        Json.encodeToString(
            SecurityReport(
                generatedAt = Instant.now().toString(),
                analyzedSiteMapEntries = items.size,
                findingCount = findings.size,
                findingsByClassification = findings.groupingBy { it.classification }.eachCount(),
                findings = findings.take(200),
                scannerSupported = scannerSupported,
                scannerIssueCount = scannerIssueCount,
                scannerNote = if (scannerSupported) null else "Burp Scanner requires Professional Edition; Community Edition findings are not available.",
                contentTrust = SafeContent.UNTRUSTED_CONTENT_NOTICE
            )
        )
    }
}

private fun validatePage(count: Int, offset: Int, maxCount: Int = MAX_PAGE_SIZE) {
    require(count in 1..maxCount) { "count must be between 1 and $maxCount" }
    require(offset >= 0) { "offset must be zero or greater" }
}

private fun edition(api: MontoyaApi): BurpSuiteEdition = api.burpSuite().version().edition()

private suspend fun requireHistoryAccess(config: McpConfig) {
    if (!DataAccessSecurity.checkDataAccessPermission(DataAccessType.HTTP_HISTORY, config)) {
        throw McpToolError("Project traffic access denied by Burp MCP settings or user approval.")
    }
}

private fun requireScanner(api: MontoyaApi) {
    if (edition(api) != BurpSuiteEdition.PROFESSIONAL) {
        throw McpToolError("Unsupported capability: Burp Scanner is available only in Burp Suite Professional Edition.")
    }
}

private data class IdentifiedHistoryItem(val item: ProxyHttpRequestResponse, val id: Int)

private fun identifiedHistory(api: MontoyaApi): List<IdentifiedHistoryItem> {
    val history = api.proxy().history()
    val reservedNativeIds = history.mapNotNull(MontoyaRuntimeCompat::nativeHistoryId).toSet()
    val usedIds = mutableSetOf<Int>()
    return history.map { item ->
        val nativeId = MontoyaRuntimeCompat.nativeHistoryId(item)
        var id = nativeId ?: MontoyaRuntimeCompat.historyId(item)
        if (nativeId == null) {
            while (id in usedIds || id in reservedNativeIds) id = if (id == Int.MAX_VALUE) 1 else id + 1
        }
        usedIds += id
        IdentifiedHistoryItem(item, id)
    }
}

private fun authorizedHistory(api: MontoyaApi, config: McpConfig): List<IdentifiedHistoryItem> =
    identifiedHistory(api).filter { isAuthorizedItem(it.item, api, config) }

private fun accessibleHistoryItem(api: MontoyaApi, config: McpConfig, historyId: Int): ProxyHttpRequestResponse =
    identifiedHistory(api).firstOrNull { it.id == historyId && isAuthorizedItem(it.item, api, config) }?.item
        ?: throw McpToolError("History item $historyId is unavailable or outside the current Burp scope/host allowlist.")

internal fun isAuthorizedItem(item: ProxyHttpRequestResponse, api: MontoyaApi, config: McpConfig): Boolean {
    val request = runCatching { item.finalRequest() }.getOrNull() ?: return false
    val service = runCatching { request.httpService() }.getOrNull() ?: return false
    val url = runCatching { request.url() }.getOrNull() ?: return false
    return HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config) &&
        urlMatchesHttpService(url, service.host(), service.port()) &&
        runCatching { api.scope().isInScope(url) }.getOrDefault(false)
}

internal fun isAuthorizedRequest(request: HttpRequest?, api: MontoyaApi, config: McpConfig): Boolean {
    if (request == null) return false
    val service = runCatching { request.httpService() }.getOrNull() ?: return false
    val url = runCatching { request.url() }.getOrNull() ?: return false
    return HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config) &&
        urlMatchesHttpService(url, service.host(), service.port()) &&
        runCatching { api.scope().isInScope(url) }.getOrDefault(false)
}

internal fun isAuthorizedScannerIssue(
    issue: burp.api.montoya.scanner.audit.issues.AuditIssue, api: MontoyaApi, config: McpConfig
): Boolean = runCatching {
    val url = issue.baseUrl() ?: return@runCatching false
    val service = issue.httpService()
    HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config) &&
        urlMatchesHttpService(url, service.host(), service.port()) && api.scope().isInScope(url)
}.getOrDefault(false)

private fun accessibleSiteMap(api: MontoyaApi, config: McpConfig) =
    api.siteMap().requestResponses().filter { item ->
        val request = runCatching { item.request() }.getOrNull() ?: return@filter false
        val service = runCatching { request.httpService() }.getOrNull() ?: return@filter false
        val url = runCatching { request.url() }.getOrNull() ?: return@filter false
        HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config) &&
            urlMatchesHttpService(url, service.host(), service.port()) &&
            runCatching { api.scope().isInScope(url) }.getOrDefault(false)
    }

private fun matchesHistoryFilters(
    item: ProxyHttpRequestResponse,
    host: String?,
    method: String?,
    statusCode: Int?,
    contentType: String?
): Boolean {
    val request = item.finalRequest()
    val response = item.originalResponse()
    return (host.isNullOrBlank() || request.httpService().host().equals(host, true)) &&
        (method.isNullOrBlank() || request.method().equals(method, true)) &&
        (statusCode == null || response?.statusCode()?.toInt() == statusCode) &&
        (contentType.isNullOrBlank() || response?.headerValue("Content-Type")?.contains(contentType, true) == true)
}

private fun historySummary(item: ProxyHttpRequestResponse, historyId: Int): HistoryEntry {
    val request = item.finalRequest()
    val response = item.originalResponse()
    return HistoryEntry(
        historyId = historyId,
        timestamp = runCatching { item.time().toString() }.getOrDefault(""),
        url = SafeContent.redactUrl(request.url()),
        method = request.method(),
        statusCode = response?.statusCode()?.toInt(),
        contentType = response?.headerValue("Content-Type")?.let { SafeContent.redactHeader("Content-Type", it) }?.take(256),
        request = SafeContent.render(request),
        response = SafeContent.render(response),
        contentTrust = SafeContent.UNTRUSTED_CONTENT_NOTICE
    )
}

private fun analyzeRequest(request: HttpRequest): RequestAnalysis {
    val headers = headerMap(request).mapValues { (name, value) -> SafeContent.redactHeader(name, value) }
    val bodyBytes = request.body().length()
    val findings = mutableListOf<SecurityFinding>()
    if (request.hasHeader("Authorization")) findings += SecurityFinding("Authentication header", "observed", "directly_observed", "Authorization is present; value redacted", "Protect credentials and verify token scope and transport security.")
    if (request.hasHeader("Cookie")) findings += SecurityFinding("Cookie header", "observed", "directly_observed", "Cookie is present; value redacted", "Review cookie scope and session handling.")
    if (request.method() in setOf("PUT", "PATCH", "DELETE")) findings += SecurityFinding("State-changing HTTP method", "observed", "directly_observed", "A state-changing HTTP method was observed", "Verify that authorization and CSRF protections match the endpoint's intended behavior.")
    return RequestAnalysis(
        url = SafeContent.redactUrl(request.url()),
        method = request.method(),
        httpVersion = request.httpVersion(),
        contentType = request.headerValue("Content-Type")?.let { SafeContent.redactHeader("Content-Type", it) },
        bodyBytes = bodyBytes,
        headers = headers,
        findings = findings,
        safeRequest = SafeContent.render(request),
        contentTrust = SafeContent.UNTRUSTED_CONTENT_NOTICE
    )
}

private fun analyzeResponse(response: burp.api.montoya.http.message.responses.HttpResponse, requestUrl: String): ResponseAnalysis {
    val headers = headerMap(response).mapValues { (name, value) -> SafeContent.redactHeader(name, value) }
    val https = requestUrl.startsWith("https://", true)
    val findings = SecurityAnalysis.securityHeaders(headerMap(response), https) +
        SecurityAnalysis.cookies(response.headers().filter { it.name().equals("Set-Cookie", true) }.map { it.value() }, https)
    return ResponseAnalysis(
        statusCode = response.statusCode().toInt(),
        contentType = response.headerValue("Content-Type")?.let { SafeContent.redactHeader("Content-Type", it) },
        bodyBytes = response.body().length(),
        headers = headers,
        findings = findings,
        safeResponse = SafeContent.render(response),
        contentTrust = SafeContent.UNTRUSTED_CONTENT_NOTICE
    )
}

private fun headerMap(message: HttpMessage): Map<String, String> = message.headers().associate { it.name() to it.value() }

private fun compareResponses(firstId: Int, first: burp.api.montoya.http.message.responses.HttpResponse, secondId: Int, second: burp.api.montoya.http.message.responses.HttpResponse) =
    ResponseComparison(
        firstHistoryId = firstId,
        secondHistoryId = secondId,
        statusCodesEqual = first.statusCode() == second.statusCode(),
        firstStatusCode = first.statusCode().toInt(),
        secondStatusCode = second.statusCode().toInt(),
        bodyHashesEqual = sha256(first.body().getBytes()) == sha256(second.body().getBytes()),
        firstBodyBytes = first.body().length(),
        secondBodyBytes = second.body().length(),
        differingHeaderNames = (headerMap(first).keys + headerMap(second).keys).distinct().filter { name ->
            headerMap(first).filterKeys { it.equals(name, true) }.values.firstOrNull() !=
                headerMap(second).filterKeys { it.equals(name, true) }.values.firstOrNull()
        }.map { it.lowercase() }.distinct()
    )

private fun sha256(bytes: kotlin.ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

private fun buildAuthorizedRequest(
    host: String,
    port: Int,
    https: Boolean,
    rawRequest: String?,
    rawRequestBase64: String?
): HttpRequest {
    require(host.isNotBlank() && host.length <= 253 && host.matches(Regex("^[A-Za-z0-9.\\-:\\[\\]]+$"))) { "Invalid target hostname" }
    require(port in 1..65535) { "port must be between 1 and 65535" }
    require((rawRequest != null) xor (rawRequestBase64 != null)) { "Provide exactly one of rawRequest or rawRequestBase64" }
    val service = burp.api.montoya.http.HttpService.httpService(host, port, https)
    return if (rawRequestBase64 != null) {
        HttpRequest.httpRequest(service, ByteArray.byteArray(*SafeContent.decodeRawRequestBase64(rawRequestBase64)))
    } else {
        val raw = requireNotNull(rawRequest)
        require(raw.toByteArray().size <= SafeContent.MAX_REQUEST_BYTES) { "HTTP request exceeds the 1 MiB limit" }
        HttpRequest.httpRequest(service, raw)
    }
}

private fun modifyRawRequest(
    raw: String,
    updates: Map<String, String>,
    removals: List<String>,
    replacementBody: String?
): String {
    val separator = Regex("\\r?\\n\\r?\\n").find(raw)
        ?: throw IllegalArgumentException("rawRequest must contain a header/body separator")
    val lines = raw.substring(0, separator.range.first).replace("\r\n", "\n").split('\n').toMutableList()
    require(lines.isNotEmpty() && lines.first().matches(Regex("^[A-Z]+\\s+\\S+\\s+HTTP/[0-9.]+$"))) { "Invalid HTTP request line" }
    val removalSet = removals.map { it.lowercase() }.toSet()
    val filtered = mutableListOf(lines.first())
    val seenUpdates = mutableSetOf<String>()
    for (line in lines.drop(1)) {
        val colon = line.indexOf(':')
        if (colon <= 0) {
            filtered += line
            continue
        }
        val name = line.substring(0, colon).trim()
        val key = name.lowercase()
        if (key in removalSet) continue
        val update = updates.entries.firstOrNull { it.key.equals(name, true) }
        if (update != null) {
            if (seenUpdates.add(key)) filtered += "$name: ${update.value}"
        } else filtered += line
    }
    updates.forEach { (name, value) ->
        if (seenUpdates.add(name.lowercase())) filtered += "$name: $value"
    }
    val oldBody = raw.substring(separator.range.last + 1)
    val body = replacementBody ?: oldBody
    if (replacementBody != null) {
        fun headerName(line: String) = line.substringBefore(':').trim().lowercase()
        require(filtered.drop(1).none { headerName(it) == "transfer-encoding" }) { "Body replacement with transfer encoding is unsupported" }
        require(filtered.drop(1).count { headerName(it) == "content-length" } <= 1) { "Ambiguous Content-Length" }
        val contentTypes = filtered.drop(1).filter { headerName(it) == "content-type" }
        require(contentTypes.size <= 1) { "Ambiguous Content-Type" }
        val charsets = contentTypes.singleOrNull()?.substringAfter(':')?.split(';')?.drop(1).orEmpty()
            .map(String::trim).filter { it.substringBefore('=').trim().equals("charset", true) }
        require(charsets.size <= 1 && charsets.all {
            Regex("(?i)^charset\\s*=\\s*(?:utf-8|\"utf-8\"|'utf-8')\\s*$").matches(it)
        }) { "Text body replacement requires UTF-8 charset" }
        val encodings = filtered.drop(1).filter { headerName(it) == "content-encoding" }
        require(encodings.size <= 1 && encodings.all { it.substringAfter(':').trim().equals("identity", true) }) {
            "Text body replacement of compressed messages is unsupported"
        }
        val encodedBody = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(body))
        filtered.removeAll { headerName(it) == "content-length" }
        filtered += "Content-Length: ${encodedBody.remaining()}"
    }
    val result = filtered.joinToString("\r\n") + "\r\n\r\n" + body
    require(result.toByteArray(Charsets.UTF_8).size <= SafeContent.MAX_REQUEST_BYTES) { "Proposed request exceeds the 1 MiB limit" }
    return result
}

private object ScanRegistry {
    private val audits = ConcurrentHashMap<String, Audit>()
    fun add(id: String, audit: Audit) { audits[id] = audit }
    fun get(id: String): Audit? = audits[id]
    fun remove(id: String) { audits.remove(id) }
}

@Serializable data class BurpGetStatus(val includeDiagnostics: Boolean = true)
@Serializable data class BurpGetCapabilities(val includeUnsupported: Boolean = true)
@Serializable data class BurpGetProjectInfo(val includeProjectId: Boolean = true)
@Serializable data class BurpGetScope(val urls: List<String> = emptyList())
@Serializable data class BurpCheckConnection(val includeBurpVersion: Boolean = true)
@Serializable data class BurpGetProxyHistory(
    val count: Int = 20, val offset: Int = 0, val host: String? = null, val method: String? = null,
    val statusCode: Int? = null, val contentType: String? = null
)
@Serializable data class BurpSearchHttpHistory(
    val query: String, val count: Int = 20, val offset: Int = 0, val host: String? = null,
    val method: String? = null, val statusCode: Int? = null, val contentType: String? = null
)
@Serializable data class BurpGetRequest(val historyId: Int)
@Serializable data class BurpGetResponse(val historyId: Int)
@Serializable data class BurpAnalyzeRequest(val historyId: Int)
@Serializable data class BurpAnalyzeResponse(val historyId: Int)
@Serializable data class BurpGetSiteMap(val count: Int = 20, val offset: Int = 0)
@Serializable data class BurpGetResponseHeaders(val historyId: Int)
@Serializable data class BurpSendToRepeater(
    val host: String, val port: Int, val https: Boolean, val rawRequest: String? = null,
    val rawRequestBase64: String? = null, val tabName: String? = null
)
@Serializable data class BurpSendHttpRequest(
    val host: String, val port: Int, val https: Boolean, val rawRequest: String? = null,
    val rawRequestBase64: String? = null, val http2: Boolean = false
)
@Serializable data class BurpCompareResponses(val firstHistoryId: Int, val secondHistoryId: Int)
@Serializable data class BurpModifyRequest(
    val rawRequest: String, val headers: Map<String, String> = emptyMap(),
    val removeHeaders: List<String> = emptyList(), val replacementBody: String? = null
)
@Serializable data class BurpGetRepeaterTabs(val includeDiagnostics: Boolean = true)
@Serializable data class BurpAnalyzeSecurityHeaders(val historyId: Int)
@Serializable data class BurpAnalyzeCookies(val historyId: Int)
@Serializable data class BurpAnalyzeCors(val historyId: Int)
@Serializable data class BurpAnalyzeAuthentication(val historyId: Int)
@Serializable data class BurpFindSensitiveData(val historyId: Int, val part: String = "response")
@Serializable data class BurpGetScannerIssues(val count: Int = 20, val offset: Int = 0)
@Serializable data class BurpStartScan(val host: String, val port: Int, val https: Boolean, val rawRequest: String)
@Serializable data class BurpGetScanStatus(val scanId: String)
@Serializable data class BurpStopScan(val scanId: String)
@Serializable data class BurpGenerateSecurityReport(val count: Int = 20, val offset: Int = 0)

@Serializable private data class StatusResult(val extension: String, val extensionVersion: String, val buildId: String, val serverState: String, val endpoint: String, val lastError: String?, val burpEdition: String, val readOnlyMode: Boolean, val bearerAuthenticationRequired: Boolean, val authorizedTargetCount: Int)
@Serializable private data class CapabilityResult(val montoyaApi: String, val extensionVersion: String, val buildId: String, val burpEdition: String, val proxyHistory: Boolean, val siteMap: Boolean, val repeaterSend: Boolean, val repeaterTabEnumeration: Boolean, val http1Request: Boolean, val http2Request: Boolean, val scannerFindings: Boolean, val passiveAudit: Boolean, val activeAudit: Boolean, val collaborator: Boolean, val scannerNote: String?)
@Serializable private data class ProjectInfoResult(val projectName: String?, val projectId: String?, val available: Boolean, val reason: String?)
@Serializable private data class ScopeCheck(val url: String, val inBurpScope: Boolean, val hostAllowlisted: Boolean, val eligible: Boolean)
@Serializable private data class ScopeResult(val scopeRulesEnumerated: Boolean, val note: String, val checks: List<ScopeCheck>)
@Serializable private data class LocalTestScopeCheck(val url: String, val inBurpScope: Boolean, val hostAllowlisted: Boolean, val eligible: Boolean)
@Serializable private data class LocalTestScopeResult(
    val targetAllowlist: String,
    val configurationComplete: Boolean,
    val allowlistAdded: Boolean,
    val failureSummary: String?,
    val checks: List<LocalTestScopeCheck>
)
@Serializable private data class ConnectionResult(val burpConnected: Boolean, val serverState: String, val endpoint: String, val burpVersion: String?)
@Serializable private data class HistoryEntry(val historyId: Int, val timestamp: String, val url: String, val method: String, val statusCode: Int?, val contentType: String?, val request: String, val response: String, val contentTrust: String)
@Serializable private data class SiteMapEntry(val url: String, val method: String, val statusCode: Int?, val request: String, val response: String, val contentTrust: String)
@Serializable private data class ResponseHeadersResult(val historyId: Int, val statusCode: Int, val headers: Map<String, String>, val contentTrust: String)
@Serializable private data class RequestAnalysis(val url: String, val method: String, val httpVersion: String, val contentType: String?, val bodyBytes: Int, val headers: Map<String, String>, val findings: List<SecurityFinding>, val safeRequest: String, val contentTrust: String)
@Serializable private data class ResponseAnalysis(val statusCode: Int, val contentType: String?, val bodyBytes: Int, val headers: Map<String, String>, val findings: List<SecurityFinding>, val safeResponse: String, val contentTrust: String)
@Serializable private data class ResponseComparison(val firstHistoryId: Int, val secondHistoryId: Int, val statusCodesEqual: Boolean, val firstStatusCode: Int, val secondStatusCode: Int, val bodyHashesEqual: Boolean, val firstBodyBytes: Int, val secondBodyBytes: Int, val differingHeaderNames: List<String>)
@Serializable private data class ScanStatusResult(val scanId: String, val status: String, val requestCount: Int, val errorCount: Int, val issueCount: Int)
@Serializable private data class SecurityReport(val generatedAt: String, val analyzedSiteMapEntries: Int, val findingCount: Int, val findingsByClassification: Map<String, Int>, val findings: List<SecurityFinding>, val scannerSupported: Boolean, val scannerIssueCount: Int?, val scannerNote: String?, val contentTrust: String)
