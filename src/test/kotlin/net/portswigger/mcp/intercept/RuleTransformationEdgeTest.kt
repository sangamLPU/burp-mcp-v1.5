package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.LocalTestTargets
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets.UTF_8

class RuleTransformationEdgeTest {
    private val target = LocalTestTargets.urls.first()
    private fun message(body: String = "", type: String = "application/json", direction: RuleDirection = RuleDirection.REQUEST,
                        url: String = target) = RuleHttpMessage(direction, target, url, "POST",
        listOf(RuleHeader("Content-Type", type), RuleHeader("Content-Length", body.toByteArray(UTF_8).size.toString())), body.toByteArray(UTF_8),
        if (direction == RuleDirection.RESPONSE) 200 else null)
    private fun edit(type: RuleTransformType, name: String? = null, value: String? = null) = RuleTransformation(type, name = name, value = value)
    private val jsonEdit = RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")

    @Test fun `nested array removal preserves parsed unrelated values in requests and responses`() {
        for (direction in listOf(RuleDirection.REQUEST, RuleDirection.RESPONSE)) {
            val original = message("{\"items\":[{\"value\":false},{\"keep\":\"\u96ea\"}],\"other\":null}", direction = direction)
            val changed = RuleTransformations.apply(original, RuleTransformation(RuleTransformType.REMOVE_JSON_FIELD, path = "$.items[0]"))
            assertEquals(Json.parseToJsonElement("{\"items\":[{\"keep\":\"\u96ea\"}],\"other\":null}"), Json.parseToJsonElement(changed.body.toString(UTF_8)))
            assertEquals(changed.body.size.toString(), changed.headers.last().value)
        }
    }

    @Test fun `missing parents array indices and removed fields leave originals intact`() {
        for (path in listOf("$.missing.value", "$.items[9]", "$.missing")) {
            val original = message("{\"items\":[1]}")
            assertThrows(Exception::class.java) { RuleTransformations.apply(original, RuleTransformation(RuleTransformType.REMOVE_JSON_FIELD, path = path)) }
            assertEquals("{\"items\":[1]}", original.body.toString(UTF_8))
        }
    }

    @Test fun `empty malformed and non UTF8 JSON are refused`() {
        for (body in listOf("", "{", "[]", "null")) {
            assertThrows(Exception::class.java) { RuleTransformations.apply(message(body), jsonEdit) }
        }
        val invalid = message().copy(body = byteArrayOf(0xc3.toByte(), 0x28), headers = listOf(RuleHeader("Content-Type", "application/json")))
        assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) { RuleTransformations.apply(invalid, jsonEdit) }
    }

    @Test fun `query removal preserves unrelated encoded duplicate and empty values byte for byte`() {
        val original = message(url = "$target?x=1&keep=%E9%9B%AA&x=&bare&empty=&plus=a+b")
        val changed = RuleTransformations.apply(original, edit(RuleTransformType.REMOVE_QUERY_PARAMETER, "x"))
        assertEquals("$target?keep=%E9%9B%AA&bare&empty=&plus=a+b", changed.url)
        assertArrayEquals(original.body, changed.body)
        assertThrows(Exception::class.java) { RuleTransformations.apply(message(url = "$target?%=x"), edit(RuleTransformType.SET_QUERY_PARAMETER, "x", "y")) }
    }

    @Test fun `form edits preserve unrelated encoding and deterministically replace all duplicates`() {
        val original = message("x=one&keep=a%2Bb&x=&empty=&bare", "application/x-www-form-urlencoded")
        val changed = RuleTransformations.apply(original, edit(RuleTransformType.SET_FORM_FIELD, "x", "\u96ea &+"))
        assertEquals("x=%E9%9B%AA+%26%2B&keep=a%2Bb&x=%E9%9B%AA+%26%2B&empty=&bare", changed.body.toString(UTF_8))
        val removed = RuleTransformations.apply(changed, edit(RuleTransformType.REMOVE_FORM_FIELD, "x"))
        assertEquals("keep=a%2Bb&empty=&bare", removed.body.toString(UTF_8))
    }

    @Test fun `header transformations remove duplicates case insensitively and respect direction`() {
        for (direction in listOf(RuleDirection.REQUEST, RuleDirection.RESPONSE)) {
            val original = message(direction = direction).copy(headers = listOf(RuleHeader("X-Test", "a"), RuleHeader("x-test", "b"), RuleHeader("X-Keep", "yes")))
            val set = if (direction == RuleDirection.REQUEST) RuleTransformType.SET_REQUEST_HEADER else RuleTransformType.SET_RESPONSE_HEADER
            val remove = if (direction == RuleDirection.REQUEST) RuleTransformType.REMOVE_REQUEST_HEADER else RuleTransformType.REMOVE_RESPONSE_HEADER
            val changed = RuleTransformations.apply(original, edit(set, "X-Test", "\u96ea"))
            assertEquals(listOf(RuleHeader("X-Keep", "yes"), RuleHeader("X-Test", "\u96ea")), changed.headers)
            assertEquals(listOf(RuleHeader("X-Keep", "yes")), RuleTransformations.apply(changed, edit(remove, "x-test")).headers)
        }
        val response = message(direction = RuleDirection.RESPONSE)
        assertTrue(RuleTransformations.byteAndMetadataEqual(response, RuleTransformations.apply(response, edit(RuleTransformType.SET_QUERY_PARAMETER, "x", "1"))))
    }

    @Test fun `literal replacement uses exact text with byte framing and refuses absent search`() {
        val original = message("old old + &", "text/plain")
        val changed = RuleTransformations.apply(original, RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "old", replacement = "\u96ea"))
        assertEquals("\u96ea \u96ea + &", changed.body.toString(UTF_8))
        assertEquals(changed.body.size.toString(), changed.headers.last().value)
        assertThrows(Exception::class.java) { RuleTransformations.apply(message("", "text/html"), RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "x", replacement = "y")) }
    }

    @Test fun `partial transformation failure cannot commit a prior compatible edit or count a modification`() {
        val engine = InterceptionRuleEngine()
        val spec = InterceptionRuleSpec(name = "rollback", targetUrl = target, authorizationReference = "11111111-2222-3333-4444-555555555555",
            direction = RuleDirection.REQUEST, transformations = listOf(edit(RuleTransformType.SET_REQUEST_HEADER, "X-First", "changed"),
                RuleTransformation(RuleTransformType.REMOVE_JSON_FIELD, path = "$.missing")))
        val id = engine.create(spec).id
        engine.enable(id, 120_000)
        val original = message("{\"enabled\":false}")
        val evaluated = engine.evaluate(original)!!
        assertEquals(RuleEvaluationStatus.MANUAL_REQUIRED, evaluated.status)
        assertTrue(RuleTransformations.byteAndMetadataEqual(original, evaluated.output))
        engine.finish(evaluated, "SKIPPED", "MANUAL", evaluated.code)
        assertEquals(0L, engine.get(id).stats.modified)
        assertEquals(0L, engine.get(id).stats.forwarded)
    }

    @Test fun `bounded large JSON succeeds while oversized original and output are rejected`() {
        val original = message("{\"keep\":\"${"a".repeat(60_000)}\"}")
        val changed = RuleTransformations.apply(original, jsonEdit)
        assertEquals(60_000, Json.parseToJsonElement(changed.body.toString(UTF_8)).jsonObject["keep"]!!.jsonPrimitive.content.length)
        assertThrows(Exception::class.java) { RuleTransformations.apply(message("{\"keep\":\"${"a".repeat(65_536)}\"}"), jsonEdit) }
        assertThrows(Exception::class.java) { RuleTransformations.apply(message("a".repeat(40_000), "text/plain"),
            RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "a", replacement = "aaa")) }
    }

    @Test fun `invalid content types compression and duplicate lengths are rejected before body edits`() {
        val original = message("{\"enabled\":false}")
        val cases = listOf(original.copy(headers = listOf(RuleHeader("Content-Type", "application/jsonp"))),
            original.copy(headers = original.headers + RuleHeader("Content-Type", "application/json")),
            original.copy(headers = original.headers + RuleHeader("Content-Length", original.body.size.toString())),
            original.copy(headers = original.headers + RuleHeader("Content-Encoding", "gzip")))
        for (input in cases) assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) { RuleTransformations.apply(input, jsonEdit) }
    }
}
