package net.portswigger.mcp.redaction

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Manages redaction contexts with TTL-based cleanup.
 * Each context stores mappings from placeholders to original values for a single tool call.
 */
class RedactionManager(
    private val ttlMinutes: Long = 60,
    private val cleanupIntervalMinutes: Long = 10
) {
    private val contexts = ConcurrentHashMap<String, RedactionContext>()
    private val contextIdCounter = AtomicLong(0)
    private val cleanupExecutor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "RedactionManager-Cleanup").apply { isDaemon = true }
    }

    init {
        // Schedule periodic cleanup
        cleanupExecutor.scheduleAtFixedRate(
            { cleanup() },
            cleanupIntervalMinutes,
            cleanupIntervalMinutes,
            TimeUnit.MINUTES
        )
    }

    /**
     * Creates a new redaction context for a tool call.
     */
    fun createContext(): RedactionContext {
        val contextId = "ctx_${contextIdCounter.incrementAndGet()}_${System.currentTimeMillis()}"
        val context = RedactionContext(contextId, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(ttlMinutes))
        contexts[contextId] = context
        return context
    }

    /**
     * Retrieves a redaction context by ID.
     */
    fun getContext(contextId: String): RedactionContext? {
        val context = contexts[contextId]
        // Check if context is expired
        if (context != null && context.expiresAt < System.currentTimeMillis()) {
            contexts.remove(contextId)
            return null
        }
        return context
    }

    /**
     * Removes expired contexts.
     */
    private fun cleanup() {
        val now = System.currentTimeMillis()
        contexts.entries.removeIf { (_, context) ->
            context.expiresAt < now
        }
    }

    /**
     * Shuts down the cleanup executor.
     */
    fun shutdown() {
        cleanupExecutor.shutdown()
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            cleanupExecutor.shutdownNow()
            Thread.currentThread().interrupt()
        }
    }

    /**
     * Clears all contexts (for testing).
     */
    fun clear() {
        contexts.clear()
    }

    /**
     * Gets the number of active contexts (for testing).
     */
    fun getContextCount(): Int = contexts.size
}

/**
 * A redaction context stores mappings from placeholders to original values.
 */
class RedactionContext(
    val contextId: String,
    val expiresAt: Long
) {
    private val placeholderMap = ConcurrentHashMap<String, String>()
    private val placeholderCounter = AtomicLong(0)

    /**
     * Adds a value to redact and returns a placeholder token.
     */
    fun addRedaction(originalValue: String): String {
        val placeholder = "REDACTED_${placeholderCounter.incrementAndGet()}"
        placeholderMap[placeholder] = originalValue
        return placeholder
    }

    /**
     * Rehydrates (replaces) all placeholders in the given text with their original values.
     */
    fun rehydrate(text: String): String {
        var result = text
        placeholderMap.forEach { (placeholder, originalValue) ->
            result = result.replace(placeholder, originalValue)
        }
        return result
    }

    /**
     * Gets all placeholder mappings (for testing).
     */
    fun getMappings(): Map<String, String> = placeholderMap.toMap()
}
