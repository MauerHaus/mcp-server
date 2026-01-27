package net.portswigger.mcp.config.components

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.McpConfig
import javax.swing.*
import java.awt.Dimension

/**
 * Simple UI test application to visually test the RedactionKeywordsPanel
 * Run this to see how the panel looks
 */
fun main() {
    SwingUtilities.invokeLater {
        val storage = mutableMapOf<String, Any>()

        val persistedObject = mockk<PersistedObject>().apply {
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

        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
        }

        val config = McpConfig(persistedObject, mockLogging)
        
        // Pre-populate with some test data
        config.addCustomRedactionKeyword("api-key")
        config.addCustomRedactionKeyword("secret-token")
        config.addCustomRedactionKeyword("internal.aws")

        val frame = JFrame("Redaction Keywords Panel Test")
        frame.defaultCloseOperation = JFrame.EXIT_ON_CLOSE
        
        val panel = RedactionKeywordsPanel(config)
        
        frame.contentPane.add(panel)
        frame.size = Dimension(600, 500)
        frame.setLocationRelativeTo(null)
        frame.isVisible = true
        
        println("RedactionKeywordsPanel UI Test")
        println("Initial keywords: ${config.getCustomRedactionKeywordsList()}")
        println("Try adding, removing, and clearing keywords!")
    }
}
