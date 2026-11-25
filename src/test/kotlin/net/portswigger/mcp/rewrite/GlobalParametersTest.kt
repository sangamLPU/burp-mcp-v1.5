package net.portswigger.mcp.rewrite

import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class GlobalParametersTest {
    private val saved = mutableMapOf<String, String>()
    private val storage = mockk<PersistedObject> {
        every { getString(any()) } answers { saved[firstArg()] }
        every { setString(any(), any()) } answers { saved[firstArg()] = secondArg(); Unit }
    }
    private val manager = RewriteManager(storage)
    private fun rule(value: String = "12345") = GlobalParameterRule("id", "user_id", value, globalLocations, true)

    @Test fun `query and form preserve unrelated bytes and replace duplicate decoded names`() {
        val rules = rulesFor(listOf(rule("a +é&=")), "query")
        val result = rewriteEncoded("a=%2f&user_id=old&user%5Fid=2&User_id=no&empty&z=+", rules)
        assertEquals("a=%2f&user_id=a+%2B%C3%A9%26%3D&user%5Fid=a+%2B%C3%A9%26%3D&User_id=no&empty&z=+", result.value)
        assertEquals(setOf("id"), result.matched)
        assertThrows(Exception::class.java) { rewriteEncoded("user_id=x&other=%FF", rules) }
        for (invalid in listOf("%+1", "%-1", "% 1", "%１1")) {
            assertThrows(IllegalArgumentException::class.java) { rewriteEncoded("user_id=x&other=$invalid", rules) }
        }
        assertEquals("user_id=a+%2B%C3%A9%26%3D", rewriteEncoded("user_id=x", rulesFor(listOf(rule("a +é&=")), "form")).value)
    }
    @Test fun `large replacements fail before repeated edits can expand beyond the limit`() {
        val replacement = rule("x".repeat(65_536))
        val query = List(20) { "user_id=a" }.joinToString("&")
        val json = List(20) { "{\"user_id\":0}" }.joinToString(",", "[", "]")
        val multipart = (("--abc\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nx\r\n").repeat(20) + "--abc--\r\n").toByteArray()
        assertThrows(IllegalArgumentException::class.java) { rewriteEncoded(query, rulesFor(listOf(replacement), "form")) }
        assertThrows(IllegalArgumentException::class.java) { rewriteGlobalJson(json, rulesFor(listOf(replacement), "json")) }
        assertThrows(IllegalArgumentException::class.java) { rewriteMultipart(multipart, "abc", rulesFor(listOf(replacement), "multipart")) }
    }
    @Test fun `already matching values do not report changes`() {
        val rules = listOf(rule())
        assertTrue(rewriteEncoded("user_id=12345", rulesFor(rules, "query")).matched.isEmpty())
        assertTrue(rewriteGlobalJson("{\"user_id\":\"12345\"}", rulesFor(rules, "json")).matched.isEmpty())
    }
    @Test fun `JSON nested arrays and types change only named scalars preserving formatting`() {
        val input = "{ \"user_id\": 7, \"objects\": [ {\"user_id\":false, \"keep\":1}, {\"USER_ID\": 2} ], \"x\":\"user_id\" }"
        val output = rewriteGlobalJson(input, rulesFor(listOf(rule()), "json"))
        assertEquals("{ \"user_id\": \"12345\", \"objects\": [ {\"user_id\":\"12345\", \"keep\":1}, {\"USER_ID\": 2} ], \"x\":\"user_id\" }", output.value)
        assertThrows(Exception::class.java) { rewriteGlobalJson("{\"user_id\":1,\"user_id\":2}", rulesFor(listOf(rule()), "json")) }
        assertThrows(Exception::class.java) { rewriteGlobalJson("{\"user_id\":{\"keep\":1}}", rulesFor(listOf(rule()), "json")) }
    }
    @Test fun `multipart text duplicate fields and file bytes are preserved`() {
        val input = ("--abc\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nold\r\n" +
            "--abc\r\nContent-Disposition: form-data; name=\"user_id\"; filename=\"x.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n" +
            "binary\u00ff\r\n--abc\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nold2\r\n--abc--\r\n").toByteArray(Charsets.ISO_8859_1)
        val (out, ids) = rewriteMultipart(input, "abc", rulesFor(listOf(rule("é")), "multipart"))
        val expected = input.toString(Charsets.ISO_8859_1).replace("\r\n\r\nold\r\n", "\r\n\r\nÃ©\r\n").replace("\r\n\r\nold2\r\n", "\r\n\r\nÃ©\r\n")
        assertEquals(expected, out.toString(Charsets.ISO_8859_1)); assertEquals(setOf("id"), ids)
        assertThrows(Exception::class.java) { rewriteMultipart(input.copyOf(input.size - 5), "abc", rulesFor(listOf(rule()), "multipart")) }
    }
    @Test fun `first rule wins independently for each location`() {
        val a = rule("first").copy(locations = listOf("query"))
        val b = rule("second").copy(id = "second", locations = listOf("query", "json"))
        assertEquals("first", rulesFor(listOf(a, b), "query")["user_id"]?.value)
        assertEquals("second", rulesFor(listOf(a, b), "json")["user_id"]?.value)
    }
    @Test fun `approval exact host scope updates persistence and emergency disabling`() {
        val id = manager.createGlobal("user_id", "secret-value", listOf("query", "json"))
        assertFalse(manager.listGlobal().single().enabled)
        assertThrows(IllegalArgumentException::class.java) { manager.enableGlobalApproved(manager.listGlobal().single()) }
        manager.setTargets("example.test")
        val old = manager.listGlobal().single()
        manager.updateGlobal(id, "user_id", "new-secret", listOf("json"))
        assertThrows(IllegalArgumentException::class.java) { manager.enableGlobalApproved(old) }
        manager.enableGlobalApproved(manager.listGlobal().single())
        assertTrue(manager.globalFor("example.test", true).isEmpty())
        manager.activate()
        assertEquals(1, manager.globalFor("EXAMPLE.TEST", true).size)
        assertTrue(manager.globalFor("sub.example.test", true).isEmpty())
        assertTrue(manager.globalFor("example.test", false).isEmpty())
        manager.disableAll(); assertTrue(manager.globalFor("example.test", true).isEmpty())
        manager.activate(); manager.disableGlobal(id); assertTrue(manager.globalFor("example.test", true).isEmpty())
        assertFalse(manager.logs().joinToString().contains("secret"))
        manager.removeGlobal(id); assertTrue(manager.listGlobal().isEmpty())
        assertFalse(RewriteManager(storage).isActive())
    }
}
