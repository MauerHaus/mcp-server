package net.portswigger.mcp.schema

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.redaction.RedactionContext
import net.portswigger.mcp.redaction.RedactionUtils

fun AuditIssue.toSerializableForm(redactionContext: RedactionContext? = null, customKeywords: List<String> = emptyList()): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = HttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm(redactionContext, customKeywords) },
        collaboratorInteractions = collaboratorInteractions().map {
            Interaction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = AuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex(),
        ),
        contextId = redactionContext?.contextId
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(redactionContext: RedactionContext? = null, customKeywords: List<String> = emptyList()): HttpRequestResponse {
    val rawRequest = request()?.toString() ?: "<no request>"
    val rawResponse = response()?.toString() ?: "<no response>"

    val processedRequest = if (redactionContext != null && rawRequest != "<no request>") {
        RedactionUtils.redactHttpRequest(rawRequest, redactionContext, customKeywords)
    } else {
        rawRequest
    }

    val processedResponse = if (redactionContext != null && rawResponse != "<no response>") {
        RedactionUtils.redactHttpResponse(rawResponse, redactionContext, customKeywords)
    } else {
        rawResponse
    }

    return HttpRequestResponse(
        request = processedRequest,
        response = processedResponse,
        notes = annotations().notes(),
        contextId = redactionContext?.contextId
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(redactionContext: RedactionContext? = null, customKeywords: List<String> = emptyList()): HttpRequestResponse {
    val rawRequest = request()?.toString() ?: "<no request>"
    val rawResponse = response()?.toString() ?: "<no response>"

    val processedRequest = if (redactionContext != null && rawRequest != "<no request>") {
        RedactionUtils.redactHttpRequest(rawRequest, redactionContext, customKeywords)
    } else {
        rawRequest
    }

    val processedResponse = if (redactionContext != null && rawResponse != "<no response>") {
        RedactionUtils.redactHttpResponse(rawResponse, redactionContext, customKeywords)
    } else {
        rawResponse
    }

    return HttpRequestResponse(
        request = processedRequest,
        response = processedResponse,
        notes = annotations().notes(),
        contextId = redactionContext?.contextId
    )
}

fun ProxyWebSocketMessage.toSerializableForm(redactionContext: RedactionContext? = null, customKeywords: List<String> = emptyList()): WebSocketMessage {
    val rawPayload = payload()?.toString() ?: "<no payload>"

    val processedPayload = if (redactionContext != null && rawPayload != "<no payload>") {
        RedactionUtils.redactWebSocketPayload(rawPayload, redactionContext, customKeywords)
    } else {
        rawPayload
    }

    return WebSocketMessage(
        payload = processedPayload,
        direction =
            if (direction() == Direction.CLIENT_TO_SERVER)
                WebSocketMessageDirection.CLIENT_TO_SERVER
            else
                WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes(),
        contextId = redactionContext?.contextId
    )
}

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

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
    val definition: AuditIssueDefinition,
    val contextId: String? = null
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
    val notes: String?,
    val contextId: String? = null
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

// ✅ YOUR contextId field kept + upstream closing paren fixed
@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?,
    val contextId: String? = null
)

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
