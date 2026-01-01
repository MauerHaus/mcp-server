package net.portswigger.mcp.redaction

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class RedactionManagerTest {

    private lateinit var redactionManager: RedactionManager

    @BeforeEach
    fun setup() {
        redactionManager = RedactionManager(ttlMinutes = 60, cleanupIntervalMinutes = 10)
    }

    @AfterEach
    fun tearDown() {
        redactionManager.shutdown()
    }

    @Test
    fun `createContext should generate unique context IDs`() {
        val context1 = redactionManager.createContext()
        val context2 = redactionManager.createContext()

        assertNotNull(context1.contextId)
        assertNotNull(context2.contextId)
        assertNotEquals(context1.contextId, context2.contextId)
    }

    @Test
    fun `getContext should return created context`() {
        val context = redactionManager.createContext()
        val retrieved = redactionManager.getContext(context.contextId)

        assertNotNull(retrieved)
        assertEquals(context.contextId, retrieved?.contextId)
    }

    @Test
    fun `getContext should return null for non-existent context`() {
        val retrieved = redactionManager.getContext("non_existent_context")

        assertNull(retrieved)
    }

    @Test
    fun `getContext should return null for expired context`() {
        // Create a manager with very short TTL
        val shortTtlManager = RedactionManager(ttlMinutes = 0, cleanupIntervalMinutes = 10)
        val context = shortTtlManager.createContext()

        // Wait a bit to ensure expiration
        Thread.sleep(100)

        val retrieved = shortTtlManager.getContext(context.contextId)
        assertNull(retrieved)

        shortTtlManager.shutdown()
    }

    @Test
    fun `clear should remove all contexts`() {
        redactionManager.createContext()
        redactionManager.createContext()
        redactionManager.createContext()

        assertEquals(3, redactionManager.getContextCount())

        redactionManager.clear()

        assertEquals(0, redactionManager.getContextCount())
    }

    @Test
    fun `getContextCount should return correct count`() {
        assertEquals(0, redactionManager.getContextCount())

        redactionManager.createContext()
        assertEquals(1, redactionManager.getContextCount())

        redactionManager.createContext()
        assertEquals(2, redactionManager.getContextCount())
    }
}
