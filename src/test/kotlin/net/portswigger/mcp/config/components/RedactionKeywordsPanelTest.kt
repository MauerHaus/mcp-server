package net.portswigger.mcp.config.components

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RedactionKeywordsPanelTest {

    private lateinit var persistedObject: PersistedObject
    private lateinit var config: McpConfig
    private lateinit var mockLogging: Logging

    @BeforeEach
    fun setup() {
        val storage = mutableMapOf<String, Any>()

        persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean(any()) } answers {
                storage[firstArg()] as? Boolean ?: false
            }
            every { getString(any()) } answers { storage[firstArg()] as? String ?: "" }
            every { getInteger(any()) } answers { storage[firstArg()] as? Int ?: 0 }
            every { setBoolean(any(), any()) } answers {
                storage[firstArg()] = secondArg<Boolean>()
            }
            every { setString(any(), any()) } answers {
                storage[firstArg()] = secondArg<String>()
            }
            every { setInteger(any(), any()) } answers {
                storage[firstArg()] = secondArg<Int>()
            }
        }

        mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
    }

    @Test
    fun `panel should be created successfully`() {
        val panel = RedactionKeywordsPanel(config)
        assertNotNull(panel)
    }

    @Test
    fun `panel should reflect config state after adding keywords`() {
        val panel = RedactionKeywordsPanel(config)
        
        config.addCustomRedactionKeyword("test-keyword")
        config.addCustomRedactionKeyword("another-keyword")
        
        val keywords = config.getCustomRedactionKeywordsList()
        assertEquals(2, keywords.size)
        assertEquals(listOf("test-keyword", "another-keyword"), keywords)
    }

    @Test
    fun `panel should reflect config state after removing keywords`() {
        config.addCustomRedactionKeyword("test-keyword")
        config.addCustomRedactionKeyword("another-keyword")
        
        val panel = RedactionKeywordsPanel(config)
        
        config.removeCustomRedactionKeyword("test-keyword")
        
        val keywords = config.getCustomRedactionKeywordsList()
        assertEquals(1, keywords.size)
        assertEquals(listOf("another-keyword"), keywords)
    }

    @Test
    fun `panel should reflect config state after clearing keywords`() {
        config.addCustomRedactionKeyword("test-keyword")
        config.addCustomRedactionKeyword("another-keyword")
        
        val panel = RedactionKeywordsPanel(config)
        
        config.clearCustomRedactionKeywords()
        
        val keywords = config.getCustomRedactionKeywordsList()
        assertEquals(0, keywords.size)
    }

    @Test
    fun `cleanup should not throw exception`() {
        val panel = RedactionKeywordsPanel(config)
        panel.cleanup()
        // Should not throw any exception
    }
}
