package net.portswigger.mcp.redaction

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RedactionUtilsTest {

    private lateinit var context: RedactionContext

    @BeforeEach
    fun setup() {
        context = RedactionContext("test_context", System.currentTimeMillis() + 60000)
    }

    @Test
    fun `redactHttpRequest should redact Host header`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            User-Agent: Test
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("example.com"))
        assertTrue(redacted.contains("REDACTED_"))
        assertTrue(redacted.contains("GET /path HTTP/1.1"))
    }

    @Test
    fun `redactHttpRequest should redact Cookie header`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            Cookie: session=abc123def456
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("session=abc123def456"))
        assertTrue(redacted.contains("Cookie: REDACTED_"))
    }

    @Test
    fun `redactHttpRequest should redact Authorization header`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))
        assertTrue(redacted.contains("Authorization: REDACTED_"))
    }

    @Test
    fun `redactHttpRequest should redact API key headers`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            X-API-Key: sk_test_123456789abcdef
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("sk_test_123456789abcdef"))
        assertTrue(redacted.contains("X-API-Key: REDACTED_"))
    }

    @Test
    fun `redactHttpRequest should redact absolute-form URI`() {
        val request = """
            GET http://example.com:8080/path HTTP/1.1
            User-Agent: Test
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("http://example.com:8080"))
        assertTrue(redacted.contains("GET REDACTED_"))
        assertTrue(redacted.contains("/path HTTP/1.1"))
    }

    @Test
    fun `redactHttpRequest should redact JWT tokens in body`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            Content-Type: application/json
            
            {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        assertFalse(redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"))
        assertTrue(redacted.contains("REDACTED_"))
        assertTrue(redacted.contains("\"token\":\"REDACTED_"))
    }

    @Test
    fun `redactHttpResponse should redact Set-Cookie header`() {
        val response = """
            HTTP/1.1 200 OK
            Content-Type: text/html
            Set-Cookie: session=xyz789; Path=/; HttpOnly
            
            <html>body</html>
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpResponse(response, context)

        assertFalse(redacted.contains("session=xyz789"))
        assertTrue(redacted.contains("Set-Cookie: REDACTED_"))
        assertTrue(redacted.contains("HTTP/1.1 200 OK"))
    }

    @Test
    fun `redactHttpResponse should preserve status line`() {
        val response = """
            HTTP/1.1 404 Not Found
            Content-Type: text/plain
            
            Not found
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpResponse(response, context)

        assertTrue(redacted.contains("HTTP/1.1 404 Not Found"))
    }

    @Test
    fun `redactWebSocketPayload should redact JWT tokens`() {
        val payload = """{"auth":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}"""

        val redacted = RedactionUtils.redactWebSocketPayload(payload, context)

        assertFalse(redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `redactWebSocketPayload should redact long token-like strings`() {
        val payload = """{"apiKey":"test_key_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U"}"""

        val redacted = RedactionUtils.redactWebSocketPayload(payload, context)

        assertFalse(redacted.contains("test_key_51A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5P6Q7R8S9T0U"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `redacted request can be rehydrated`() {
        val originalRequest = """
            GET /path HTTP/1.1
            Host: example.com
            Cookie: session=abc123def456
            Authorization: Bearer secret_token_12345
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(originalRequest, context)
        val rehydrated = context.rehydrate(redacted)

        // After rehydration, should contain the original values
        assertTrue(rehydrated.contains("example.com"))
        assertTrue(rehydrated.contains("session=abc123def456"))
        assertTrue(rehydrated.contains("Bearer secret_token_12345"))
        assertFalse(rehydrated.contains("REDACTED_"))
    }

    @Test
    fun `redaction should preserve structure for LLM reasoning`() {
        val request = """
            GET /api/users HTTP/1.1
            Host: api.example.com
            Cookie: session=secret123
            X-API-Key: myapikey12345
            Content-Length: 42
            
            {"user":"john","password":"pass123"}
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        // Structure should be preserved
        assertTrue(redacted.contains("GET /api/users HTTP/1.1"))
        assertTrue(redacted.contains("Host: REDACTED_"))
        assertTrue(redacted.contains("Cookie: REDACTED_"))
        assertTrue(redacted.contains("X-API-Key: REDACTED_"))
        assertTrue(redacted.contains("Content-Length: 42"))
        assertTrue(redacted.contains("{\"user\":\"john\",\"password\":\"pass123\"}"))
    }

    @Test
    fun `redaction should not leak secrets in output`() {
        val request = """
            GET /path HTTP/1.1
            Host: secret-internal-host.local
            Cookie: auth=supersecretcookie123
            
        """.trimIndent()

        val redacted = RedactionUtils.redactHttpRequest(request, context)

        // Verify no secrets are present in redacted output
        assertFalse(redacted.contains("secret-internal-host.local"))
        assertFalse(redacted.contains("supersecretcookie123"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should redact in request body`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            Content-Type: application/json
            
            {"server":"int.aws.internal","data":"test"}
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        assertFalse(redacted.contains("int.aws"))
        assertTrue(redacted.contains("REDACTED_"))
        assertTrue(redacted.contains("\"server\":\"REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should redact in response body`() {
        val response = """
            HTTP/1.1 200 OK
            Content-Type: text/html
            
            <html><body>Connect to int.aws for more info</body></html>
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpResponse(response, context, customKeywords)

        assertFalse(redacted.contains("int.aws"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should redact in headers`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            X-Custom-Header: int.aws.internal
            
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        assertFalse(redacted.contains("int.aws"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should be case insensitive`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            
            {"server":"INT.AWS.internal","data":"Int.Aws"}
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        assertFalse(redacted.contains("INT.AWS"))
        assertFalse(redacted.contains("Int.Aws"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should support multiple keywords`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            
            {"server":"int.aws","backup":"staging.internal"}
        """.trimIndent()

        val customKeywords = listOf("int.aws", "staging.internal")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        assertFalse(redacted.contains("int.aws"))
        assertFalse(redacted.contains("staging.internal"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should work in websocket payload`() {
        val payload = """{"server":"int.aws","action":"connect"}"""

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactWebSocketPayload(payload, context, customKeywords)

        assertFalse(redacted.contains("int.aws"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should preserve rehydration`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            
            {"server":"int.aws","data":"test"}
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)
        val rehydrated = context.rehydrate(redacted)

        // After rehydration, should contain the original values
        assertTrue(rehydrated.contains("int.aws"))
        assertFalse(rehydrated.contains("REDACTED_"))
    }

    @Test
    fun `should work without custom keywords - backward compatibility`() {
        val request = """
            GET /path HTTP/1.1
            Host: example.com
            Cookie: session=abc123
            
        """.trimIndent()

        // Call with empty list (default)
        val redacted = RedactionUtils.redactHttpRequest(request, context, emptyList())

        // Standard redaction should still work
        assertFalse(redacted.contains("example.com"))
        assertFalse(redacted.contains("session=abc123"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should not affect standard redaction`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            Cookie: session=abc123
            Authorization: Bearer token123
            
            {"server":"int.aws","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        // Both standard and custom redaction should work
        assertFalse(redacted.contains("example.com")) // Host header
        assertFalse(redacted.contains("session=abc123")) // Cookie
        assertFalse(redacted.contains("Bearer token123")) // Authorization
        assertFalse(redacted.contains("int.aws")) // Custom keyword
        assertFalse(redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")) // JWT
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should handle special regex characters`() {
        val request = """
            POST /api HTTP/1.1
            Host: example.com
            
            {"server":"test.internal","query":"a+b*c?d"}
        """.trimIndent()

        // Test with special regex characters
        val customKeywords = listOf("test.internal", "a+b*c?d")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        assertFalse(redacted.contains("test.internal"))
        assertFalse(redacted.contains("a+b*c?d"))
        assertTrue(redacted.contains("REDACTED_"))
    }

    @Test
    fun `custom keyword redaction should redact in request line`() {
        val request = """
            GET http://int.aws:8080/path HTTP/1.1
            User-Agent: Test
            
        """.trimIndent()

        val customKeywords = listOf("int.aws")
        val redacted = RedactionUtils.redactHttpRequest(request, context, customKeywords)

        // Should redact in absolute-form URI
        assertFalse(redacted.contains("int.aws"))
        assertTrue(redacted.contains("REDACTED_"))
    }
}
