package net.portswigger.mcp.schema

import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable
import net.portswigger.mcp.redaction.RedactionContext
import net.portswigger.mcp.redaction.RedactionUtils

fun AuditIssue.toSerializableForm(redactionContext: RedactionContext? = null): IssueDetails {
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
        requestResponses = requestResponses().map { it.toSerializableForm(redactionContext) },
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

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(redactionContext: RedactionContext? = null): HttpRequestResponse {
    val rawRequest = request()?.toString() ?: "<no request>"
    val rawResponse = response()?.toString() ?: "<no response>"
    
    val processedRequest = if (redactionContext != null && rawRequest != "<no request>") {
        RedactionUtils.redactHttpRequest(rawRequest, redactionContext)
    } else {
        rawRequest
    }
    
    val processedResponse = if (redactionContext != null && rawResponse != "<no response>") {
        RedactionUtils.redactHttpResponse(rawResponse, redactionContext)
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

fun ProxyHttpRequestResponse.toSerializableForm(redactionContext: RedactionContext? = null): HttpRequestResponse {
    val rawRequest = request()?.toString() ?: "<no request>"
    val rawResponse = response()?.toString() ?: "<no response>"
    
    val processedRequest = if (redactionContext != null && rawRequest != "<no request>") {
        RedactionUtils.redactHttpRequest(rawRequest, redactionContext)
    } else {
        rawRequest
    }
    
    val processedResponse = if (redactionContext != null && rawResponse != "<no response>") {
        RedactionUtils.redactHttpResponse(rawResponse, redactionContext)
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

fun ProxyWebSocketMessage.toSerializableForm(redactionContext: RedactionContext? = null): WebSocketMessage {
    val rawPayload = payload()?.toString() ?: "<no payload>"
    
    val processedPayload = if (redactionContext != null && rawPayload != "<no payload>") {
        RedactionUtils.redactWebSocketPayload(rawPayload, redactionContext)
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

@Serializable
data class WebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?,
    val contextId: String? = null
)