package net.portswigger.mcp.redaction

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RedactionContextTest {

    private lateinit var context: RedactionContext

    @BeforeEach
    fun setup() {
        context = RedactionContext("test_context", System.currentTimeMillis() + 60000)
    }

    @Test
    fun `addRedaction should return unique placeholders`() {
        val placeholder1 = context.addRedaction("secret1")
        val placeholder2 = context.addRedaction("secret2")

        assertNotNull(placeholder1)
        assertNotNull(placeholder2)
        assertNotEquals(placeholder1, placeholder2)
        assertTrue(placeholder1.startsWith("REDACTED_"))
        assertTrue(placeholder2.startsWith("REDACTED_"))
    }

    @Test
    fun `addRedaction should store mapping`() {
        val originalValue = "my-secret-value"
        val placeholder = context.addRedaction(originalValue)

        val mappings = context.getMappings()
        assertTrue(mappings.containsKey(placeholder))
        assertEquals(originalValue, mappings[placeholder])
    }

    @Test
    fun `rehydrate should replace single placeholder`() {
        val originalValue = "secret123"
        val placeholder = context.addRedaction(originalValue)

        val text = "Authorization: Bearer $placeholder"
        val rehydrated = context.rehydrate(text)

        assertEquals("Authorization: Bearer secret123", rehydrated)
        assertFalse(rehydrated.contains("REDACTED_"))
    }

    @Test
    fun `rehydrate should replace multiple placeholders`() {
        val secret1 = "cookie_value"
        val secret2 = "auth_token"
        val placeholder1 = context.addRedaction(secret1)
        val placeholder2 = context.addRedaction(secret2)

        val text = "Cookie: $placeholder1; Authorization: $placeholder2"
        val rehydrated = context.rehydrate(text)

        assertEquals("Cookie: cookie_value; Authorization: auth_token", rehydrated)
        assertFalse(rehydrated.contains("REDACTED_"))
    }

    @Test
    fun `rehydrate should handle text with no placeholders`() {
        val text = "No placeholders here"
        val rehydrated = context.rehydrate(text)

        assertEquals(text, rehydrated)
    }

    @Test
    fun `rehydrate should handle empty text`() {
        val rehydrated = context.rehydrate("")

        assertEquals("", rehydrated)
    }

    @Test
    fun `getMappings should return all stored mappings`() {
        context.addRedaction("value1")
        context.addRedaction("value2")
        context.addRedaction("value3")

        val mappings = context.getMappings()
        assertEquals(3, mappings.size)
    }
}
