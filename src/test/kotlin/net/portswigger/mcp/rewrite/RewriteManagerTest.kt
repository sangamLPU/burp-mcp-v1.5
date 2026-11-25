package net.portswigger.mcp.rewrite

import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RewriteManagerTest {
    private val saved = mutableMapOf<String, String>()
    private val storage = mockk<PersistedObject> {
        every { getString(any()) } answers { saved[firstArg()] }
        every { setString(any(), any()) } answers { saved[firstArg()] = secondArg(); Unit }
    }
    private val manager = RewriteManager(storage)

    private fun rule(): String = manager.create("example.test", "POST", "/api", "application/json", "/user/items/0/name", "\"new\"")
    private fun ready(): String {
        manager.setTargets("example.test")
        val id = rule()
        manager.enableApproved(manager.list().single())
        manager.activate()
        return id
    }
    private fun rewrite(host: String = "example.test", method: String = "POST", path: String = "/api", type: String = "application/json", scope: Boolean = true, body: String = "{\"user\": {\"items\": [{\"name\": \"old\", \"other\":1}]}}") =
        manager.rewrite(host, method, path, type, scope, body)

    @Test fun `replaces nested array field while preserving unrelated bytes`() {
        ready()
        assertEquals("{\"user\": {\"items\": [{\"name\": \"new\", \"other\":1}]}}", rewrite())
        assertNull(rewrite(body = "{\"user\":{\"items\":[]}}"))
        assertEquals("{\"a/b\":{\"~x\":true}}", replaceJsonField("{\"a/b\":{\"~x\":false}}", listOf("a/b", "~x"), "true"))
    }
    @Test fun `requires exact target method path media type and Burp scope`() {
        ready()
        assertNull(rewrite(host = "sub.example.test")); assertNull(rewrite(method = "GET"))
        assertNull(rewrite(path = "/api/other")); assertNull(rewrite(type = "application/problem+json")); assertNull(rewrite(scope = false))
        assertNotNull(rewrite(host = "EXAMPLE.TEST", method = "post", type = "APPLICATION/JSON"))
    }
    @Test fun `allowlist session approval disabling persistence and stale approval`() {
        val id = rule()
        assertThrows(IllegalArgumentException::class.java) { manager.enableApproved(manager.list().single()) }
        manager.setTargets("example.test")
        val old = manager.list().single()
        manager.update(id, "example.test", "POST", "/api", "application/json", "/user/items/0/name", "1")
        assertThrows(IllegalArgumentException::class.java) { manager.enableApproved(old) }
        manager.enableApproved(manager.list().single()); manager.activate(); assertNotNull(rewrite())
        manager.disable(id); assertNull(rewrite())
        manager.enableApproved(manager.list().single()); manager.disableAll(); assertNull(rewrite())
        manager.activate(); assertNotNull(rewrite())
        val restarted = RewriteManager(storage)
        assertFalse(restarted.isActive()); assertTrue(restarted.list().single().enabled)
        manager.setTargets("another.test"); assertNull(rewrite())
    }
    @Test fun `malformed duplicate and deeply nested input fail closed`() {
        ready()
        assertNull(rewrite(body = "{\"user\":")); assertNull(rewrite(body = "{\"x\":1,\"x\":2}"))
        assertNull(rewrite(body = "[".repeat(140) + "0" + "]".repeat(140)))
        assertThrows(IllegalArgumentException::class.java) { manager.create("example.test", "POST", "/", "application/json", "/a", "not-json") }
        assertThrows(IllegalArgumentException::class.java) { manager.setTargets("*.example.test") }
    }
    @Test fun `updates and removal stop rules and events contain no values`() {
        val id = ready()
        manager.update(id, "example.test", "POST", "/api", "application/json", "/user/items/0/name", "\"secret-value\"")
        assertNull(rewrite())
        manager.enableApproved(manager.list().single()); assertNotNull(rewrite())
        assertFalse(manager.logs().joinToString().contains("secret-value"))
        manager.remove(id); assertNull(rewrite())
    }
    @Test fun `global typed JSON request rule works across methods paths and persists alongside old rules`() {
        manager.setTargets("example.test")
        val legacy = rule()
        val id = manager.create("", "", "", "", "", "true", "isPremium")
        manager.enableApproved(manager.list().first { it.id == id }); manager.activate()
        val body = "{\"isPremium\":false,\"list\":[{\"isPremium\":null,\"keep\":7}]}"
        val expected = "{\"isPremium\":true,\"list\":[{\"isPremium\":true,\"keep\":7}]}"
        assertEquals(expected, rewrite(method = "GET", path = "/one", body = body))
        assertEquals(expected, rewrite(method = "PATCH", path = "/two", type = "application/problem+json", body = body))
        assertNull(rewrite(method = "GET", path = "/one", scope = false, body = body))
        assertNull(rewrite(host = "other.test", method = "GET", path = "/one", body = body))
        assertNull(rewrite(type = "text/plain", body = body))
        assertEquals(2, manager.activityFor(id).count)
        val restarted = RewriteManager(storage)
        assertFalse(restarted.isActive())
        assertEquals(setOf(legacy, id), restarted.list().map { it.id }.toSet())
        assertTrue(restarted.list().single { it.id == id }.enabled)
        assertEquals("", restarted.list().single { it.id == legacy }.fieldName)
    }
    @Test fun `credential fields in JSON are retained even when another field matches`() {
        manager.setTargets("example.test")
        manager.create("", "", "", "", "", "true", "isPremium")
        manager.enableApproved(manager.list().single()); manager.activate()
        assertNull(rewrite(body = "{\"isPremium\":false,\"nested\":{\"access_token\":\"secret\"}}"))
        assertTrue(isSensitiveParameterName("api_key"))
        assertTrue(isSensitiveParameterName("Password"))
        assertFalse(isSensitiveParameterName("user_id"))
        val filtered = rulesFor(listOf(GlobalParameterRule("a", "password", "x", listOf("form")), GlobalParameterRule("b", "user_id", "1", listOf("form"))), "form")
        assertEquals(setOf("user_id"), filtered.keys)
    }
    @Test fun `unchanged updates keep approval but changed updates require approval again`() {
        manager.setTargets("example.test")
        val id = manager.createGlobal("user_id", "12345", listOf("query"))
        manager.enableGlobalApproved(manager.listGlobal().single())
        manager.updateGlobal(id, "user_id", "12345", listOf("query"))
        assertTrue(manager.listGlobal().single().enabled)
        manager.updateGlobal(id, "user_id", "456", listOf("query"))
        assertFalse(manager.listGlobal().single().enabled)
    }
}
