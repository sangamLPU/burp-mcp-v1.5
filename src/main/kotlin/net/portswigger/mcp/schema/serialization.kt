package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.compat.MontoyaRuntimeCompat
import net.portswigger.mcp.security.SafeContent

fun AuditIssue.toSerializableForm(
    includeRequestResponse: (burp.api.montoya.http.message.HttpRequestResponse) -> Boolean = { true }
): IssueDetails {
    return IssueDetails(
        name = name()?.let { SafeContent.markUntrusted(it) },
        detail = detail()?.let { SafeContent.markUntrusted(it) },
        remediation = remediation()?.let { SafeContent.markUntrusted(it) },
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl()?.let { SafeContent.markUntrusted(SafeContent.redactUrl(it)) },
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().filter(includeRequestResponse).map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = SafeContent.markUntrusted(definition().name(), 512),
            background = definition().background()?.let { SafeContent.markUntrusted(it) },
            remediation = definition().remediation()?.let { SafeContent.markUntrusted(it) },
            typeIndex = definition().typeIndex(),
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = renderSafely(request()),
        response = renderSafely(response()),
        notes = annotations().notes()?.let { SafeContent.markUntrusted(it) }
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): HttpRequestResponse {
    return HttpRequestResponse(
        request = renderSafely(finalRequest()),
        response = renderSafely(originalResponse()),
        notes = annotations().notes()?.let { SafeContent.markUntrusted(it) }
    )
}

fun organizerItemToSerializableForm(item: Any): OrganizerItemDetails {
    val status = MontoyaRuntimeCompat.readNoArg(item, "status")
    val statusName = MontoyaRuntimeCompat.readNoArg(status, "displayName")?.toString() ?: "Unknown"
    val request = MontoyaRuntimeCompat.readNoArg(item, "request") as? burp.api.montoya.http.message.requests.HttpRequest
    val response = MontoyaRuntimeCompat.readNoArg(item, "response") as? burp.api.montoya.http.message.responses.HttpResponse
    val annotations = MontoyaRuntimeCompat.readNoArg(item, "annotations")
    return OrganizerItemDetails(
        id = (MontoyaRuntimeCompat.readNoArg(item, "id") as? Number)?.toInt() ?: -1,
        status = SafeContent.markUntrusted(statusName, 512),
        request = renderSafely(request),
        response = renderSafely(response),
        notes = (MontoyaRuntimeCompat.readNoArg(annotations, "notes") as? String)?.let { SafeContent.markUntrusted(it) }
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): WebSocketMessage {
    return WebSocketMessage(
        payload = payload()?.toString()?.let { SafeContent.markUntrusted(it, 4000) } ?: "<no payload>",
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()?.let { SafeContent.markUntrusted(it) }
    )
}

private fun renderSafely(message: burp.api.montoya.http.message.HttpMessage?): String =
    runCatching { SafeContent.render(message) }.getOrElse { "<message omitted: rendering error>" }

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: HttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<HttpRequestResponse>,
    val collaboratorInteractions: List<Interaction>,
    val definition: AuditIssueDefinition
)

@Serializable
data class HttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH,
    MEDIUM,
    LOW,
    INFORMATION,
    FALSE_POSITIVE;
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
data class HttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class OrganizerItemDetails(
    val id: Int,
    val status: String,
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class Interaction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class AuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)


@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null)?.let { SafeContent.markUntrusted(it) },
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = renderSafely(it.requestResponse()?.request()),
                response = renderSafely(it.requestResponse()?.response())
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = SafeContent.markUntrusted(it.conversation())
            )
        }
    )
}

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)
