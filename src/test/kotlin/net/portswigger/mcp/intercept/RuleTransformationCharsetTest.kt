package net.portswigger.mcp.intercept

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets.UTF_8

class RuleTransformationCharsetTest {
    private fun message(type: String, body: String) = RuleHttpMessage(
        RuleDirection.REQUEST, "http://127.0.0.1:8000/test-post", "http://127.0.0.1:8000/test-post",
        "POST", listOf(RuleHeader("Content-Type", type), RuleHeader("Content-Length", body.toByteArray(UTF_8).size.toString())), body.toByteArray(UTF_8)
    )
    private val jsonEdit = RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.value", valueJson = "\"\u96ea\"")
    private val textEdit = RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "old", replacement = "\u96ea")

    @Test fun `JSON refuses unsupported charset with optional whitespace`() {
        for (charset in listOf("charset=iso-8859-1", "charset = iso-8859-1", "CHARSET\t=\tutf-16")) {
            val original = message("application/json; $charset", "{\"value\":\"old\"}")
            val before = original.body.copyOf()
            val failure = assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) { RuleTransformations.apply(original, jsonEdit) }
            assertEquals("CHARSET_UNSUPPORTED", failure.code)
            assertArrayEquals(before, original.body)
        }
    }

    @Test fun `literal text refuses unsupported charset before inserting UTF8 bytes`() {
        for (type in listOf("text/plain; charset=iso-8859-1", "text/html; charset = windows-1252")) {
            val original = message(type, "old")
            val failure = assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) { RuleTransformations.apply(original, textEdit) }
            assertEquals("CHARSET_UNSUPPORTED", failure.code)
            assertEquals("old", original.body.toString(UTF_8))
        }
    }

    @Test fun `duplicate or malformed charset declarations are ambiguous`() {
        for (suffix in listOf("charset=utf-8; charset=iso-8859-1", "charset=utf-8; charset=utf-8", "charset=", "charset=\"utf-8'")) {
            for ((type, body, edit) in listOf(Triple("application/json", "{\"value\":\"old\"}", jsonEdit), Triple("text/plain", "old", textEdit))) {
                assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) { RuleTransformations.apply(message("$type; $suffix", body), edit) }
            }
        }
    }

    @Test fun `UTF8 declarations retain Unicode values and exact byte framing`() {
        for (suffix in listOf("", "; charset=utf-8", "; CHARSET = \"UTF-8\"", "; charset='utf-8'")) {
            for ((type, body, edit) in listOf(Triple("application/json", "{\"value\":\"old\"}", jsonEdit), Triple("text/plain", "old", textEdit))) {
                val changed = RuleTransformations.apply(message("$type$suffix", body), edit)
                assertTrue(changed.body.toString(UTF_8).contains("\u96ea"))
                assertEquals(changed.body.size.toString(), changed.headers.single { it.name == "Content-Length" }.value)
            }
        }
    }
}
