package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.security.SafeContent
import net.portswigger.mcp.security.StateChangeSecurity
import net.portswigger.mcp.security.ActivityEvent
import net.portswigger.mcp.security.ActivityLog
import net.portswigger.mcp.security.ApprovalTimeout
import net.portswigger.mcp.tools.mcpTool
import net.portswigger.mcp.tools.McpToolError

internal data class SafeRequestMetadata(val method: String, val hostname: String, val urlPath: String)

internal fun requestMetadata(request: HttpRequest): SafeRequestMetadata {
    val rawMethod = runCatching { request.method() }.getOrDefault("UNKNOWN").take(32)
    val method = rawMethod.takeIf { it.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")) } ?: "UNKNOWN"
    val hostname = runCatching { request.httpService().host() }
        .getOrDefault("unknown")
        .filter { it.code >= 0x21 && it.code != 0x7f }
        .take(253)
        .ifBlank { "unknown" }
    val path = runCatching { request.path() }.getOrDefault("/")
    return SafeRequestMetadata(method, hostname, SafeContent.redactMetadataPath(path))
}

fun Server.registerInterceptionTools(live: LiveInterception, api: MontoyaApi) {
    mcpTool<BurpStartTargetRuleSession>("Requests human approval to bind one existing grant and exact prepared rule revisions to a bounded live session, then activates those rules. Unrelated, sensitive, expired or unapproved messages continue unchanged. No automatic renewal or disclosure.") {
        live.startTargetRuleSession(grantId, ruleIds, durationSeconds)
        "Approved target session started."
    }
    mcpTool<BurpRequestTargetRuleAuthorization>("Requests explicit human approval for preparing disabled rules for 1..16 exact paths on one HTTP(S) host and port for up to 300 seconds. Requires existing Burp scope and exact host:port allowlist; never enables interception or execution.") {
        Json.encodeToString(live.requestTargetRuleAuthorization(urls, durationSeconds))
    }
    mcpTool<BurpListTargetRuleAuthorizations>("Lists current in-memory target preparation grants. Expired or revoked permissions are removed; never renews approval.") {
        Json.encodeToString(live.targetRuleAuthorizationStatus())
    }

    fun read(id: String, kind: String): DecisionQueue.Ticket<HeldMessage> = try { live.snapshot(id,kind) }
        catch(e:IllegalStateException) { throw McpToolError(e.message?.take(256) ?: "Interception message unavailable") }
    fun status(): String {
        live.touch()
        val health = live.health()
        return Json.encodeToString(InterceptStatus(
            enabled = health.enabled,
            editsEnabled = live.allowEdits,
            timeoutSeconds = live.timeoutSeconds,
            pendingRequests = health.pendingRequests,
            pendingResponses = health.pendingResponses,
            queueCapacity = health.queueCapacity,
            heartbeatHealth = health.heartbeatHealth,
            heartbeatIntervalSeconds = health.heartbeatIntervalSeconds,
            sessionLifetimeSeconds = health.sessionLifetimeSeconds,
            sessionRemainingMillis = health.sessionRemainingMillis,
            sessionExpiresAtEpochMillis = health.sessionExpiresAtEpochMillis,
            leaseRemainingMillis = health.leaseRemainingMillis,
            leaseExpiresAtEpochMillis = health.leaseExpiresAtEpochMillis,
            lastHeartbeatAtEpochMillis = health.lastHeartbeatAtEpochMillis,
            sessionEndReason = health.sessionEndReason,
            unattendedMode = live.unattendedSnapshot()
        ))
    }
    fun listing(kind: String): String { live.touch(); return Json.encodeToString(live.queue.list(kind).mapNotNull { runCatching { view(read(it.id,kind),false) }.getOrNull() }) }
    fun get(id: String, kind: String): String { live.touch(); return Json.encodeToString(view(read(id, kind), true)) }
    fun propose(id: String, kind: String, revision: Int, headers: Map<String,String>, remove: List<String>, body: String?, path: String?): String {
        live.touch(); live.propose(id,kind,revision,headers,remove,body,path); return get(id,kind)
    }
    suspend fun forward(id: String, kind: String, revision: Int): String {
        live.touch()
        if (read(id,kind).approvedRevision != revision) live.requestApproval(id,kind,revision)
        currentCoroutineContext().ensureActive()
        live.forward(id,kind,revision)
        return "FORWARDED: callback released this revision to Burp; network delivery is not guaranteed."
    }
    suspend fun drop(id: String, kind: String): String {
        live.touch()
        live.dropWithLocalApproval(id, kind)
        return "DROPPED: locally approved message drop."
    }
    mcpTool<BurpGetInterceptStatus>("Live interception status, including automatic heartbeat health, session/lease expiry and bounded pending-message counts. This tool is not needed to keep a locally approved session alive.") { status() }
    mcpTool<BurpGetInterceptDiagnostics>("Read-only, payload-free live interception diagnostics. Shows bounded captured, skipped, expired, dropped, approval and forwarding events with safe metadata; never returns HTTP headers, bodies, cookies, or tokens.") {
        require(count in 1..100) { "count must be between 1 and 100" }
        val health = live.health()
        Json.encodeToString(InterceptDiagnostics(
            enabled = health.enabled,
            editsEnabled = live.allowEdits,
            readOnlyMode = live.config.readOnlyMode,
            timeoutSeconds = live.timeoutSeconds,
            heartbeatHealth = health.heartbeatHealth,
            sessionRemainingMillis = health.sessionRemainingMillis,
            pendingRequests = health.pendingRequests,
            pendingResponses = health.pendingResponses,
            queueCapacity = health.queueCapacity,
            events = ActivityLog.snapshot().take(count)
        ))
    }
    mcpTool<BurpListPendingRequests>("Lists genuinely held Proxy requests with immediately visible safe metadata: method, host, redacted path, stable request ID and remaining hold time. Query values and message content stay local until a human approves disclosure. The shared request/response queue is bounded to eight; tool activity does not extend the approved session lifetime.") { listing("request") }
    mcpTool<BurpGetInterceptedRequest>("Shows safe request metadata by default. Headers, body, parameter names and diffs are returned only after local human disclosure approval for this exact revision; common credentials remain redacted.") { get(id,"request") }
    mcpTool<BurpProposeInterceptedRequestEdit>("Proposes header, path/query or textual body patches to an actually held request. Requires local live-edit permission and read-only mode off. Each proposal replaces the prior proposal, starts from the original, and invalidates approval. Host and framing headers cannot be changed.") {
        propose(id,"request",revision,headers,removeHeaders,body,path)
    }
    mcpTool<BurpApproveInterceptedRequestEdit>("Requests HUMAN approval in Burp for this exact live request revision. Calling this tool never approves without the user's local confirmation.") {
        live.touch(); live.requestApproval(id,"request",revision); "Human approved revision $revision; it is still pending."
    }
    mcpTool<BurpForwardInterceptedRequest>("Releases the exact pending request revision. Requests human approval if needed. A tool timeout never substitutes an automatic forward.") { forward(id,"request",revision) }
    mcpTool<BurpDropInterceptedRequest>("Requests explicit local human confirmation before dropping this held request. Read-only mode blocks the action.") { drop(id,"request") }
    mcpTool<BurpListPendingResponses>("Lists genuinely held Proxy responses with safe request metadata, stable IDs and remaining hold times. Query values and message content stay local until a human approves disclosure. Requests and responses share eight slots; tool activity does not extend the approved session lifetime.") { listing("response") }
    mcpTool<BurpGetInterceptedResponse>("Shows safe request metadata by default. Response headers, body and diffs are returned only after local human disclosure approval for this exact revision; common credentials remain redacted.") { get(id,"response") }
    mcpTool<BurpProposeInterceptedResponseEdit>("Proposes header or textual-body patches to a held response, invalidating any approval. Requires locally enabled edits and read-only mode off.") {
        propose(id,"response",revision,headers,removeHeaders,body,null)
    }
    mcpTool<BurpApproveInterceptedResponseEdit>("Requests human approval in Burp for a pending response revision without forwarding it.") {
        live.touch(); live.requestApproval(id,"response",revision); "Human approved revision $revision; it is still pending."
    }
    mcpTool<BurpForwardInterceptedResponse>("Releases a held response revision after exact-revision human approval. The upstream request has already been sent; dropping a response cannot undo it.") { forward(id,"response",revision) }
    mcpTool<BurpDropInterceptedResponse>("Requests explicit local human confirmation before dropping this held downstream response. Read-only mode blocks the action; a response drop does not undo upstream side effects.") { drop(id,"response") }
    mcpTool<BurpSetLiveInterceptionState>("Starts a bounded live-interception session only after local human approval. The Burp-local heartbeat runs automatically until the approved lifetime expires. Stopping an active session asks for local confirmation and drops all held traffic.") {
        if (enabled) {
            val lifetime = sessionLifetimeSeconds ?: live.configuredSessionLifetimeSeconds
            live.validateSessionLifetime(lifetime)
            val unattendedDecision = live.unattendedManagementDecision(
                LocalTestManagementOperation.START_SESSION,
                requestedSessionLifetimeSeconds = lifetime
            )
            if (unattendedDecision.decision != LocalTestPolicyDecision.AUTO_APPROVE) {
                check(StateChangeSecurity.confirm(
                    api, live.config, "Approve live interception session",
                    "Capture only requests already authorized by Burp scope and the explicit host allowlist. " +
                        "Burp will keep the client lease alive automatically for $lifetime seconds (hard maximum " +
                        "${LiveInterception.MAX_SESSION_LIFETIME_SECONDS} seconds). Held messages still drop at their own deadlines."
                )) { "User denied live interception session" }
            }
            live.startApprovedSession(lifetime)
        } else {
            val health = live.health()
            if (health.enabled) {
                val unattendedDecision = live.unattendedManagementDecision(LocalTestManagementOperation.STOP_SESSION)
                if (unattendedDecision.decision != LocalTestPolicyDecision.AUTO_APPROVE) {
                    check(ApprovalTimeout.await("stop live interception") {
                        Dialogs.requestOption(
                            net.portswigger.mcp.security.findBurpFrame(),
                            "Stop live interception? Any held request or response will be dropped.\n\n" +
                                "Currently pending: ${health.pendingRequests} requests and ${health.pendingResponses} responses.",
                            arrayOf("Stop and drop held traffic", "Keep session active"),
                            title = "Confirm live interception stop"
                        ) == 0
                    } == true) { "User denied or timed out stopping live interception" }
                }
            }
            live.disable()
        }
        status()
    }
    mcpTool<BurpCancelInterceptions>("Emergency cancellation: asks for local confirmation, then disables live interception and drops all held traffic.") {
        val health = live.health()
        check(ApprovalTimeout.await("emergency interception cancellation") {
            Dialogs.requestOption(
                net.portswigger.mcp.security.findBurpFrame(),
                "An MCP client requested emergency cancellation. This stops capture and drops all held requests and responses.\n\n" +
                    "Currently pending: ${health.pendingRequests} requests and ${health.pendingResponses} responses.",
                arrayOf("Cancel and drop all", "Keep session active"),
                title = "Confirm emergency cancellation"
            ) == 0
        } == true) { "User denied or timed out emergency cancellation" }
        live.cancel()
        "CANCELLED: all held traffic dropped and capture disabled."
    }
    mcpTool<BurpRequestInterceptDisclosure>("Requests HUMAN consent in Burp before sending a held message's redacted headers/body/diff to an external model. Returns immediately with the same request ID and disclosure state; poll the pending queue or request tool again after approval. Metadata alone is available by default. Disclosure does not authorize forwarding.") {
        live.touch()
        read(id,kind)
        live.requestDisclosure(id,kind,revision)
        Json.encodeToString(view(read(id,kind),false))
    }
    mcpTool<BurpSetProxyInterceptState>("Controls Burp's native Intercept toggle after local user approval. The separate AI live-interception mode has its own toggle and queue.") {
        check(StateChangeSecurity.confirm(api,live.config,"Change Proxy interception","Native intercept enabled=$enabled"))
        if(enabled) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        "Native Proxy interception updated."
    }
}

private fun view(t: DecisionQueue.Ticket<HeldMessage>, full: Boolean): InterceptView {
    val disclosed=t.disclosedRevision==t.revision
    val original = if(full && disclosed) SafeContent.render(t.original.message) else null
    val proposed = if(full && disclosed) t.proposed?.let { SafeContent.render(it.message) } else null
    val metadata = requestMetadata(t.original.request)
    val parameters = if(full && disclosed && t.original.message is HttpRequest) t.original.message.parameters().take(100).map { if(it.name().matches(Regex("[A-Za-z0-9_.-]{1,128}"))) SafeContent.redactInlineSecrets(it.name()) else "[nonstandard parameter name]" } else emptyList()
    return InterceptView(
        id=t.id,
        kind=t.kind,
        status=if(t.approvedRevision==t.revision) "APPROVED" else if(t.proposed!=null) "PROPOSED" else "PENDING",
        revision=t.revision,
        approvedRevision=t.approvedRevision,
        remainingMillis=((t.deadline-System.nanoTime())/1_000_000).coerceAtLeast(0),
        method=metadata.method,
        hostname=metadata.hostname,
        urlPath=metadata.urlPath,
        disclosureStatus=t.disclosureStatus,
        original=original,
        proposed=proposed,
        redactedDiff=if(original!=null && proposed!=null) redactedDiff(original,proposed) else null,
        parameterNames=parameters,
        contentDisclosureApproved=disclosed
    )
}
internal fun redactedDiff(original: String, proposed: String): String {
    val a=original.lines(); val b=proposed.lines()
    return (0 until maxOf(a.size,b.size)).mapNotNull { i ->
        if(a.getOrNull(i)==b.getOrNull(i)) null else "- ${a.getOrNull(i).orEmpty()}\n+ ${b.getOrNull(i).orEmpty()}"
    }.joinToString("\n").take(24_000)
}
@Serializable private data class InterceptStatus(
    val enabled: Boolean,
    val editsEnabled: Boolean,
    val timeoutSeconds: Int,
    val pendingRequests: Int,
    val pendingResponses: Int,
    val queueCapacity: Int,
    val heartbeatHealth: String,
    val heartbeatIntervalSeconds: Int,
    val sessionLifetimeSeconds: Int,
    val sessionRemainingMillis: Long,
    val sessionExpiresAtEpochMillis: Long?,
    val leaseRemainingMillis: Long,
    val leaseExpiresAtEpochMillis: Long?,
    val lastHeartbeatAtEpochMillis: Long?,
    val sessionEndReason: String,
    val unattendedMode: UnattendedLocalTestSnapshot
)
@Serializable private data class InterceptDiagnostics(
    val enabled: Boolean,
    val editsEnabled: Boolean,
    val readOnlyMode: Boolean,
    val timeoutSeconds: Int,
    val heartbeatHealth: String,
    val sessionRemainingMillis: Long,
    val pendingRequests: Int,
    val pendingResponses: Int,
    val queueCapacity: Int,
    val events: List<ActivityEvent>
)
@Serializable private data class InterceptView(
    val id: String,
    val kind: String,
    val status: String,
    val revision: Int,
    val approvedRevision: Int?,
    val remainingMillis: Long,
    val method: String,
    val hostname: String,
    val urlPath: String,
    val disclosureStatus: String,
    val original: String?,
    val proposed: String?,
    val redactedDiff: String?,
    val parameterNames: List<String>,
    val contentDisclosureApproved: Boolean,
    val contentTrust: String = SafeContent.UNTRUSTED_CONTENT_NOTICE
)
@Serializable data class BurpGetInterceptStatus(val includeDiagnostics:Boolean=true)
@Serializable data class BurpGetInterceptDiagnostics(val count: Int = 50)
@Serializable data class BurpListPendingRequests(val includeDiagnostics:Boolean=true)
@Serializable data class BurpGetInterceptedRequest(val id:String)
@Serializable data class BurpProposeInterceptedRequestEdit(val id:String,val revision:Int,val headers:Map<String,String> = emptyMap(),val removeHeaders:List<String> = emptyList(),val body:String?=null,val path:String?=null)
@Serializable data class BurpApproveInterceptedRequestEdit(val id:String,val revision:Int)
@Serializable data class BurpForwardInterceptedRequest(val id:String,val revision:Int)
@Serializable data class BurpDropInterceptedRequest(val id:String)
@Serializable data class BurpListPendingResponses(val includeDiagnostics:Boolean=true)
@Serializable data class BurpGetInterceptedResponse(val id:String)
@Serializable data class BurpProposeInterceptedResponseEdit(val id:String,val revision:Int,val headers:Map<String,String> = emptyMap(),val removeHeaders:List<String> = emptyList(),val body:String?=null)
@Serializable data class BurpApproveInterceptedResponseEdit(val id:String,val revision:Int)
@Serializable data class BurpForwardInterceptedResponse(val id:String,val revision:Int)
@Serializable data class BurpDropInterceptedResponse(val id:String)
@Serializable data class BurpSetLiveInterceptionState(val enabled:Boolean, val sessionLifetimeSeconds:Int?=null)
@Serializable data class BurpCancelInterceptions(val includeDiagnostics:Boolean=true)
@Serializable data class BurpRequestInterceptDisclosure(val id:String,val kind:String,val revision:Int)
@Serializable data class BurpSetProxyInterceptState(val enabled:Boolean)

@Serializable data class BurpRequestTargetRuleAuthorization(val urls: List<String>, val durationSeconds: Int = 120)
@Serializable data class BurpListTargetRuleAuthorizations(val includeDiagnostics: Boolean = false)

@Serializable data class BurpStartTargetRuleSession(val grantId: String, val ruleIds: List<String>, val durationSeconds: Int = 60)
