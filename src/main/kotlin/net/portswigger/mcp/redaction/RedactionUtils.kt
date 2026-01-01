package net.portswigger.mcp.redaction

import java.util.regex.Pattern

/**
 * Utilities for redacting/tokenizing sensitive data in HTTP and WebSocket content.
 */
object RedactionUtils {

    // Common API key header patterns
    private val API_KEY_HEADERS = setOf(
        "x-api-key",
        "x-apikey",
        "api-key",
        "apikey",
        "x-amz-security-token",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token"
    )

    // Pattern to match JWT tokens (three base64 segments separated by dots)
    private val JWT_PATTERN = Pattern.compile("\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b")

    // Pattern to match long random tokens (e.g., API keys, session tokens)
    // Matches sequences of 20+ alphanumeric/special chars that look like tokens
    private val TOKEN_PATTERN = Pattern.compile("\\b[A-Za-z0-9+/=_-]{20,}\\b")

    /**
     * Redacts sensitive information from an HTTP request string.
     */
    fun redactHttpRequest(request: String, context: RedactionContext): String {
        val lines = request.split("\r\n", "\n")
        if (lines.isEmpty()) return request

        val result = StringBuilder()
        var inBody = false
        var bodyLines = mutableListOf<String>()

        for (i in lines.indices) {
            val line = lines[i]

            if (!inBody) {
                if (i == 0) {
                    // Request line: redact absolute-form URIs
                    result.appendLine(redactRequestLine(line, context))
                } else if (line.isBlank()) {
                    // Empty line marks start of body
                    result.appendLine(line)
                    inBody = true
                } else {
                    // Header line
                    result.appendLine(redactRequestHeader(line, context))
                }
            } else {
                bodyLines.add(line)
            }
        }

        // Redact body if present
        if (bodyLines.isNotEmpty()) {
            val body = bodyLines.joinToString("\n")
            result.append(redactTokensInText(body, context))
        }

        return result.toString()
    }

    /**
     * Redacts sensitive information from an HTTP response string.
     */
    fun redactHttpResponse(response: String, context: RedactionContext): String {
        val lines = response.split("\r\n", "\n")
        if (lines.isEmpty()) return response

        val result = StringBuilder()
        var inBody = false
        var bodyLines = mutableListOf<String>()

        for (i in lines.indices) {
            val line = lines[i]

            if (!inBody) {
                if (i == 0) {
                    // Status line - no redaction needed
                    result.appendLine(line)
                } else if (line.isBlank()) {
                    // Empty line marks start of body
                    result.appendLine(line)
                    inBody = true
                } else {
                    // Header line
                    result.appendLine(redactResponseHeader(line, context))
                }
            } else {
                bodyLines.add(line)
            }
        }

        // Redact body if present
        if (bodyLines.isNotEmpty()) {
            val body = bodyLines.joinToString("\n")
            result.append(redactTokensInText(body, context))
        }

        return result.toString()
    }

    /**
     * Redacts sensitive information from WebSocket payload.
     */
    fun redactWebSocketPayload(payload: String, context: RedactionContext): String {
        return redactTokensInText(payload, context)
    }

    /**
     * Redacts the request line, specifically absolute-form URIs.
     */
    private fun redactRequestLine(line: String, context: RedactionContext): String {
        // Match: METHOD http://hostname:port/path HTTP/VERSION
        val absoluteFormPattern = Pattern.compile("^(\\w+)\\s+(https?://[^/]+)(/.*)\\s+(HTTP/\\S+)$")
        val matcher = absoluteFormPattern.matcher(line)

        if (matcher.matches()) {
            val method = matcher.group(1)
            val hostPort = matcher.group(2)
            val path = matcher.group(3)
            val version = matcher.group(4)
            val redactedHostPort = context.addRedaction(hostPort)
            return "$method $redactedHostPort$path $version"
        }

        return line
    }

    /**
     * Redacts sensitive request headers.
     */
    private fun redactRequestHeader(line: String, context: RedactionContext): String {
        val colonIndex = line.indexOf(':')
        if (colonIndex == -1) return line

        val headerName = line.substring(0, colonIndex).trim().lowercase()
        val headerValue = line.substring(colonIndex + 1).trim()

        val redactedValue = when (headerName) {
            "host" -> context.addRedaction(headerValue)
            "cookie" -> context.addRedaction(headerValue)
            "authorization" -> context.addRedaction(headerValue)
            "proxy-authorization" -> context.addRedaction(headerValue)
            in API_KEY_HEADERS -> context.addRedaction(headerValue)
            else -> redactTokensInText(headerValue, context)
        }

        return "${line.substring(0, colonIndex)}: $redactedValue"
    }

    /**
     * Redacts sensitive response headers.
     */
    private fun redactResponseHeader(line: String, context: RedactionContext): String {
        val colonIndex = line.indexOf(':')
        if (colonIndex == -1) return line

        val headerName = line.substring(0, colonIndex).trim().lowercase()
        val headerValue = line.substring(colonIndex + 1).trim()

        val redactedValue = when (headerName) {
            "set-cookie" -> context.addRedaction(headerValue)
            else -> redactTokensInText(headerValue, context)
        }

        return "${line.substring(0, colonIndex)}: $redactedValue"
    }

    /**
     * Redacts JWT and token-like strings in text.
     */
    private fun redactTokensInText(text: String, context: RedactionContext): String {
        var result = text

        // Redact JWTs
        var jwtMatcher = JWT_PATTERN.matcher(result)
        val jwtMatches = mutableListOf<Pair<String, String>>()
        while (jwtMatcher.find()) {
            val token = jwtMatcher.group()
            jwtMatches.add(token to context.addRedaction(token))
        }
        jwtMatches.forEach { (original, placeholder) ->
            result = result.replace(original, placeholder)
        }

        // Redact other long tokens (but not JWTs we already redacted)
        var tokenMatcher = TOKEN_PATTERN.matcher(result)
        val tokenMatches = mutableListOf<Pair<String, String>>()
        while (tokenMatcher.find()) {
            val token = tokenMatcher.group()
            // Skip if it's already a placeholder
            if (!token.startsWith("REDACTED_")) {
                // Only redact if it looks like a random token (has mix of chars/numbers)
                if (looksLikeToken(token)) {
                    tokenMatches.add(token to context.addRedaction(token))
                }
            }
        }
        tokenMatches.forEach { (original, placeholder) ->
            result = result.replace(original, placeholder)
        }

        return result
    }

    /**
     * Heuristic to determine if a string looks like a random token.
     */
    private fun looksLikeToken(value: String): Boolean {
        // Must be at least 20 chars
        if (value.length < 20) return false

        // Must have a mix of letters and numbers/special chars
        val hasLetter = value.any { it.isLetter() }
        val hasDigitOrSpecial = value.any { it.isDigit() || it in "+=/_-" }

        // Exclude common patterns that aren't tokens
        val isLikelyNotToken = value.all { it.isLetter() } || // All letters (words)
                value.all { it.isDigit() } || // All digits (numbers)
                value.count { it == '=' } > value.length / 3 // Too many '=' chars (base64 padding)

        return hasLetter && hasDigitOrSpecial && !isLikelyNotToken
    }
}
