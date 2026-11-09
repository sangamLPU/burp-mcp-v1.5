package net.portswigger.mcp.intercept

import net.portswigger.mcp.config.LocalTestTargets
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class InterceptionRuleEngineTest {
    private fun spec(
        name: String = "test",
        direction: RuleDirection = RuleDirection.REQUEST,
        conditions: RuleMatchConditions = RuleMatchConditions(),
        transformations: List<RuleTransformation> = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
        action: RuleAction = RuleAction.MODIFY_AND_FORWARD,
        priority: Int = 100,
        maximumMatches: Int = 32,
        maximumModifications: Int = 32,
        durationSeconds: Int = 120,
        target: String = LocalTestTargets.urls.first()
) = InterceptionRuleSpec(
    name = name,
    targetUrl = target,
    authorizationReference = UUID.randomUUID().toString(),
    direction = direction,
    conditions = conditions,
    transformations = transformations,
    action = action,
    priority = priority,
    maximumMatches = maximumMatches,
    maximumModifications = maximumModifications,
    durationSeconds = durationSeconds
)

    private fun message(
        direction: RuleDirection = RuleDirection.REQUEST,
        path: String = "/test-html",
        body: String = "{\"enabled\":false,\"name\":\"stay\",\"nested\":{\"ready\":false}}",
        headers: List<RuleHeader> = listOf(RuleHeader("Content-Type", "application/json"), RuleHeader("Content-Length", body.toByteArray().size.toString())),
        status: Int? = null,
        url: String = "http://127.0.0.1:8000$path"
    ) = RuleHttpMessage(direction, "http://127.0.0.1:8000$path", url, "GET", headers, body.toByteArray(StandardCharsets.UTF_8), status)

    private fun enabledEngine(vararg specs: InterceptionRuleSpec): InterceptionRuleEngine {
        val engine = InterceptionRuleEngine()
        specs.forEach { engine.enable(engine.create(it).id, it.durationSeconds * 1000L) }
        return engine
    }

    @Test fun `typed JSON field changes preserve other nested values and valid framing`() {
        val body = "{\"enabled\":false,\"count\":3,\"nested\":{\"ready\":false},\"items\":[{\"ok\":false}]}"
        val original = message(body = body)
        val rule = spec(transformations = listOf(
            RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"),
            RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.items[0].ok", valueJson = "true")
        ))
        val engine = enabledEngine(rule)
        val evaluation = engine.evaluate(original) ?: error("Expected a matching rule")
        assertEquals(RuleEvaluationStatus.READY, evaluation.status)
        val output = evaluation.output.body.toString(StandardCharsets.UTF_8)
        assertTrue(output.contains("\"enabled\":true"))
        assertTrue(output.contains("\"count\":3"))
        assertTrue(output.contains("\"nested\":{\"ready\":false}"))
        assertTrue(output.contains("\"items\":[{\"ok\":true}]"))
        assertEquals(output.toByteArray().size.toString(), evaluation.output.headers.single { it.name == "Content-Length" }.value)
        engine.finish(evaluation, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        assertEquals(1, engine.list().single().stats.modified)
    }

    @Test fun `typed match distinguishes boolean from string and preserves unrelated messages`() {
        val rule = spec(conditions = RuleMatchConditions(jsonPath = "$.enabled", jsonValueJson = "false"))
        val engine = enabledEngine(rule)
        assertNotNull(engine.evaluate(message(body = "{\"enabled\":false}")))
        val stringValue = message(body = "{\"enabled\":\"false\"}")
        assertNull(engine.evaluate(stringValue))
        assertNull(engine.evaluate(message(path = "/test-post")))
    }

    @Test fun `content type matching compares the exact media type`() {
        val jsonRule = spec(conditions = RuleMatchConditions(contentType = "application/json"))
        val engine = enabledEngine(jsonRule)
        assertNotNull(engine.evaluate(message(headers = listOf(RuleHeader("Content-Type", "Application/JSON; charset=utf-8")))))
        assertNull(engine.evaluate(message(headers = listOf(RuleHeader("Content-Type", "application/jsonp")))))
    }

    @Test fun `request and response directions are evaluated independently for both rules`() {
        val rule = spec(direction = RuleDirection.BOTH)
        val engine = enabledEngine(rule)
        val request = engine.evaluate(message(direction = RuleDirection.REQUEST)) ?: error("Expected request match")
        assertEquals(RuleDirection.REQUEST, request.output.direction)
        assertEquals("true", request.output.body.toString(StandardCharsets.UTF_8).substringAfter("enabled\":").substringBefore(','))
        engine.finish(request, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        val response = engine.evaluate(message(direction = RuleDirection.RESPONSE, status = 200)) ?: error("Expected response match")
        assertEquals(RuleDirection.RESPONSE, response.output.direction)
        assertTrue(response.output.body.toString(StandardCharsets.UTF_8).contains("\"enabled\":true"))
        engine.finish(response, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        val stats = engine.list().single().stats
        assertEquals(1, stats.matchedRequests)
        assertEquals(1, stats.matchedResponses)
        assertEquals(2, stats.modified)
    }

    @Test fun `both direction request-only headers do not block matching responses`() {
        val rule = spec(direction = RuleDirection.BOTH, transformations = listOf(
            RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Request-Only", value = "yes"),
            RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")
        ))
        val engine = enabledEngine(rule)
        val request = engine.evaluate(message(direction = RuleDirection.REQUEST)) ?: error("Expected request match")
        assertEquals("yes", request.output.headers.single { it.name == "X-Request-Only" }.value)
        engine.finish(request, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        val response = engine.evaluate(message(direction = RuleDirection.RESPONSE, status = 200)) ?: error("Expected response match")
        assertFalse(response.output.headers.any { it.name == "X-Request-Only" })
        assertTrue(response.output.body.toString(StandardCharsets.UTF_8).contains("\"enabled\":true"))
        assertEquals(RuleEvaluationStatus.READY, response.status)
    }

    @Test fun `no-op transformations count forwarded without claiming a modification`() {
        val rule = spec(transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "false")))
        val engine = enabledEngine(rule)
        val evaluation = engine.evaluate(message()) ?: error("Expected a matching rule")
        assertFalse(evaluation.changed)
        engine.finish(evaluation, "FORWARDED_UNCHANGED", "AUTOMATIC", evaluation.code)
        val stats = engine.list().single().stats
        assertEquals(0, stats.modified)
        assertEquals(1, stats.forwarded)
        assertEquals(0, stats.skipped)
    }

    @Test fun `maximum modifications stops only after the configured number of actual changes`() {
        val engine = enabledEngine(spec(maximumModifications = 1))
        val id = engine.list().single().id
        val first = engine.evaluate(message()) ?: error("Expected first changed message")
        assertEquals(0, engine.get(id).stats.remainingModifications, "in-flight changed message reserves the sole modification")
        engine.finish(first, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        assertEquals(InterceptionRuleState.MAX_MODIFICATIONS, engine.get(id).state)
        assertEquals(1L, engine.get(id).stats.modified)
        assertEquals(0, engine.get(id).stats.remainingModifications)
        assertNull(engine.evaluate(message(body = "{\"enabled\":false}")), "a later matching message must remain on the manual queue")
    }

    @Test fun `no-op forwarding does not consume the modification budget`() {
        val engine = enabledEngine(spec(maximumModifications = 1))
        val noOp = engine.evaluate(message(body = "{\"enabled\":true}")) ?: error("Expected no-op match")
        assertFalse(noOp.changed)
        engine.finish(noOp, "FORWARDED_UNCHANGED", "AUTOMATIC", noOp.code)
        assertEquals(1, engine.list().single().stats.remainingModifications)
        assertEquals(0L, engine.list().single().stats.modified)

        val changed = engine.evaluate(message(body = "{\"enabled\":false}")) ?: error("No-op must leave modification budget available")
        engine.finish(changed, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        assertEquals(1L, engine.list().single().stats.modified)
        assertEquals(InterceptionRuleState.MAX_MODIFICATIONS, engine.list().single().state)
    }

    @Test fun `concurrent evaluations reserve modification budget atomically`() {
        val engine = enabledEngine(spec(maximumModifications = 1))
        val first = engine.evaluate(message(body = "{\"enabled\":false,\"id\":1}")) ?: error("Expected first evaluation")
        assertEquals(0, engine.list().single().stats.remainingModifications)
        assertNull(engine.evaluate(message(body = "{\"enabled\":false,\"id\":2}")), "second changed message must be held manually")
        assertEquals(1L, engine.list().single().stats.skipped)
        engine.finish(first, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        val stats = engine.list().single().stats
        assertEquals(1L, stats.modified)
        assertEquals(0, stats.remainingModifications)
        assertEquals(InterceptionRuleState.MAX_MODIFICATIONS, stats.state)
    }

    @Test fun `clearing audit counters does not reset consumed match or modification budgets`() {
        val engine = enabledEngine(spec(maximumMatches = 3, maximumModifications = 2))
        val id = engine.list().single().id
        val first = engine.evaluate(message(body = "{\"enabled\":false,\"id\":1}")) ?: error("Expected first changed message")
        engine.finish(first, "MODIFIED_AND_FORWARDED", "AUTOMATIC")

        engine.clearStats(id)
        val cleared = engine.get(id).stats
        assertEquals(0L, cleared.matchedRequests)
        assertEquals(0L, cleared.modified)
        assertEquals(2, cleared.remainingMatches)
        assertEquals(1, cleared.remainingModifications)

        val second = engine.evaluate(message(body = "{\"enabled\":false,\"id\":2}")) ?: error("Expected remaining permitted change")
        engine.finish(second, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        assertEquals(InterceptionRuleState.MAX_MODIFICATIONS, engine.get(id).state)
        assertEquals(0, engine.get(id).stats.remainingModifications)
        assertNull(engine.evaluate(message(body = "{\"enabled\":false,\"id\":3}")), "cleared audit fields must not restore consumed rule budgets")
    }

    @Test fun `compatible rules apply together and higher priority wins field conflict`() {
        val jsonRule = spec(name = "json", priority = 200)
        val headerRule = spec(name = "header", transformations = listOf(RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Test-Mode", value = "active")), priority = 100)
        val conflictRule = spec(name = "conflict", transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "false")), priority = 50)
        val engine = enabledEngine(jsonRule, headerRule, conflictRule)
        val eval = engine.evaluate(message()) ?: error("Expected matching rules")
        assertEquals(RuleEvaluationStatus.READY, eval.status)
        assertTrue(eval.output.body.toString(StandardCharsets.UTF_8).contains("\"enabled\":true"))
        assertEquals("active", eval.output.headers.single { it.name == "X-Test-Mode" }.value)
        assertEquals(setOf(engine.list().first { it.spec.name == "json" }.id, engine.list().first { it.spec.name == "header" }.id), eval.contributingRuleIds)
    }

    @Test fun `equal priority conflicts fail closed and mixed drop forward conflict is explicit`() {
        val left = spec(name = "left", priority = 100)
        val right = spec(name = "right", transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "false")), priority = 100)
        val engine = enabledEngine(left, right)
        val conflict = engine.evaluate(message()) ?: error("Expected conflict evaluation")
        assertEquals(RuleEvaluationStatus.CONFLICT, conflict.status)
        assertEquals("TRANSFORMATION_CONFLICT", conflict.code)
        engine.finish(conflict, "SKIPPED", "MANUAL", conflict.code)

        val drop = spec(name = "drop", transformations = emptyList(), action = RuleAction.DROP, priority = 100)
        val modify = spec(name = "modify", priority = 100)
        val mixed = enabledEngine(drop, modify)
        val actionConflict = mixed.evaluate(message()) ?: error("Expected action conflict")
        assertEquals(RuleEvaluationStatus.CONFLICT, actionConflict.status)
        assertEquals("ACTION_CONFLICT", actionConflict.code)
    }

    @Test fun `query form header and exact text transformations have deterministic behavior`() {
        val q = RuleTransformations.apply(message(url = "http://127.0.0.1:8000/test-html?a=1&a=2&keep=x"),
            RuleTransformation(RuleTransformType.SET_QUERY_PARAMETER, name = "a", value = "3"))
        assertEquals("http://127.0.0.1:8000/test-html?a=3&a=3&keep=x", q.url)
        val excessiveQuery = (1..257).joinToString("&") { "x=$it" }
        val tooMany = RuleTransformations.matches(
            RuleMatchConditions(queryParameterName = "x"),
            message(url = "http://127.0.0.1:8000/test-html?$excessiveQuery")
        )
        assertEquals(MatchResult.UNSUPPORTED("TOO_MANY_PARAMETERS"), tooMany)
        val formBody = "x=1&x=2&keep=a+b"
        val form = message(path = "/test-post", body = formBody,
            headers = listOf(RuleHeader("Content-Type", "application/x-www-form-urlencoded"), RuleHeader("Content-Length", formBody.length.toString())))
        val updated = RuleTransformations.apply(form, RuleTransformation(RuleTransformType.SET_FORM_FIELD, name = "x", value = "z z"))
        assertEquals("x=z+z&x=z+z&keep=a+b", updated.body.toString(StandardCharsets.UTF_8))
        assertEquals(updated.body.size.toString(), updated.headers.single { it.name == "Content-Length" }.value)
        val header = RuleTransformations.apply(message(), RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Test", value = "yes"))
        assertEquals("yes", header.headers.single { it.name == "X-Test" }.value)
        val html = message(body = "<p>old old</p>", headers = listOf(RuleHeader("Content-Type", "text/html"), RuleHeader("Content-Length", "14")))
        val replaced = RuleTransformations.apply(html, RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "old", replacement = "new"))
        assertEquals("<p>new new</p>", replaced.body.toString(StandardCharsets.UTF_8))
    }

    @Test fun `unsafe headers compressed bodies malformed JSON and duplicate keys are skipped`() {
        assertThrows(IllegalArgumentException::class.java) {
            RuleTransformations.validate(RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "Authorization", value = "bad"))
        }
        val compressed = message(headers = listOf(RuleHeader("Content-Type", "application/json"), RuleHeader("Content-Encoding", "gzip")))
        assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(compressed, RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        }
        val duplicate = message(body = "{\"enabled\":false,\"enabled\":true}")
        val duplicateFailure = assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(duplicate, RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "false"))
        }
        assertEquals("DUPLICATE_JSON_KEY", duplicateFailure.code)
        assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(message(body = "{invalid}"), RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        }
    }

    @Test fun `deeply nested JSON is bounded before recursive parsing`() {
        val nested = "[".repeat(65) + "false" + "]".repeat(65)
        val failure = assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(message(body = nested), RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        }
        assertEquals("JSON_NESTING_TOO_DEEP", failure.code)
        assertThrows(IllegalArgumentException::class.java) {
            RuleTransformations.validate(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = nested))
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuleTransformations.validate(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "{\"x\":false,\"x\":true}"))
        }
    }

    @Test fun `unsupported active conditions prevent a co-matched rule from auto processing`() {
        val jsonCondition = spec(name = "json-condition", conditions = RuleMatchConditions(jsonPath = "$.enabled", jsonValueJson = "false"))
        val headerRule = spec(name = "header-rule", transformations = listOf(
            RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Result", value = "changed")
        ))
        val engine = enabledEngine(jsonCondition, headerRule)
        val input = message(
            body = "{invalid-json}",
            headers = listOf(
                RuleHeader("Content-Type", "application/json"),
                RuleHeader("Content-Length", "14"),
                RuleHeader("X-Match", "yes")
            )
        )
        assertNull(engine.evaluate(input))
        val views = engine.list()
        assertEquals(1L, views.single { it.spec.name == "json-condition" }.stats.skipped)
        assertEquals(1L, views.single { it.spec.name == "header-rule" }.stats.skipped)
        assertTrue(views.all { it.stats.matchedRequests == 0L && it.stats.forwarded == 0L })
    }

    @Test fun `ambiguous content type condition is unsupported rather than first-match`() {
        val contentTypeRule = spec(conditions = RuleMatchConditions(contentType = "application/json"))
        val engine = enabledEngine(contentTypeRule)
        assertNull(engine.evaluate(message(headers = listOf(
            RuleHeader("Content-Type", "application/json"),
            RuleHeader("Content-Type", "text/plain")
        ))))
        assertEquals("AMBIGUOUS_CONTENT_TYPE", engine.list().single().stats.lastErrorCode)
    }

    @Test fun `framing and payload limits fail closed`() {
        val badLength = message(headers = listOf(RuleHeader("Content-Type", "application/json"), RuleHeader("Content-Length", "999")))
        assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(badLength, RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        }
        val chunked = message(headers = listOf(RuleHeader("Content-Type", "application/json"), RuleHeader("Transfer-Encoding", "chunked")))
        assertThrows(RuleTransformations.UnsupportedRuleMessage::class.java) {
            RuleTransformations.apply(chunked, RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        }
        assertNull(enabledEngine(spec()).evaluate(message(body = "x".repeat(InterceptionRuleEngine.MAX_MESSAGE_BYTES + 1))))
    }

    @Test fun `body edits add or recalculate content length by UTF8 byte count`() {
        val original = message(body = "{\"enabled\":false,\"label\":\"café\"}", headers = listOf(RuleHeader("Content-Type", "application/json")))
        val changed = RuleTransformations.apply(original, RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        val contentLength = changed.headers.single { it.name.equals("Content-Length", true) }.value.toInt()
        assertEquals(changed.body.size, contentLength)

        val text = message(body = "α old", headers = listOf(RuleHeader("Content-Type", "text/plain")))
        val replaced = RuleTransformations.apply(text, RuleTransformation(RuleTransformType.REPLACE_EXACT_TEXT, search = "old", replacement = "new"))
        assertEquals(replaced.body.size.toString(), replaced.headers.single { it.name.equals("Content-Length", true) }.value)
    }

    @Test fun `exact target whitelist and bounded rule properties are enforced`() {
        assertThrows(IllegalArgumentException::class.java) { InterceptionRuleEngine().create(spec(target = "http://example.com/")) }
        assertThrows(IllegalArgumentException::class.java) { InterceptionRuleEngine().create(spec(maximumMatches = 33)) }
        assertThrows(IllegalArgumentException::class.java) { InterceptionRuleEngine().create(spec(maximumModifications = 33)) }
        assertThrows(IllegalArgumentException::class.java) { InterceptionRuleEngine().create(spec(maximumModifications = 0)) }
        assertThrows(IllegalArgumentException::class.java) { InterceptionRuleEngine().create(spec(durationSeconds = 301)) }
        assertThrows(IllegalArgumentException::class.java) {
            InterceptionRuleEngine().create(spec(target = LocalTestTargets.RULE_AUTHORITY_URL))
        }
        val prefixRule = spec(target = LocalTestTargets.RULE_AUTHORITY_URL, conditions = RuleMatchConditions(pathPrefix = "/test-"))
        val prefixEngine = enabledEngine(prefixRule)
        assertNotNull(prefixEngine.evaluate(message(path = "/test-cancel")))
        assertNull(prefixEngine.evaluate(message(path = "/outside")))
        assertThrows(IllegalArgumentException::class.java) {
            InterceptionRuleEngine().create(spec(direction = RuleDirection.BOTH, action = RuleAction.DROP, transformations = emptyList()))
        }
        assertThrows(IllegalArgumentException::class.java) {
            InterceptionRuleEngine().create(spec(direction = RuleDirection.RESPONSE, transformations = listOf(
                RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Test", value = "yes")
            )))
        }
    }

    @Test fun `rule maximum matches and ttl stop subsequent evaluation`() {
        var nanos = 0L
        var millis = 1_000L
        val engine = InterceptionRuleEngine({ nanos }, { millis })
        val rule = spec(maximumMatches = 2, durationSeconds = 30)
        val id = engine.create(rule).id; engine.enable(id, 30_000)
        repeat(2) {
            val evaluation = engine.evaluate(message()) ?: error("Expected match within maximum")
            engine.finish(evaluation, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
        }
        assertNull(engine.evaluate(message()))
        assertEquals(InterceptionRuleState.MAX_MATCHES, engine.get(id).state)
        val secondEngine = InterceptionRuleEngine({ nanos }, { millis })
        val second = secondEngine.create(rule.copy(maximumMatches = 32)).id; secondEngine.enable(second, 30_000)
        nanos += TimeUnit.SECONDS.toNanos(31); millis += 31_000
        assertNull(secondEngine.evaluate(message()))
        assertEquals(InterceptionRuleState.EXPIRED, secondEngine.get(second).state)
    }

    @Test fun `disable and emergency stop invalidate an in-flight rule plan`() {
        val engine = enabledEngine(spec())
        val ruleId = engine.list().single().id
        val plan = engine.evaluate(message()) ?: error("Expected a rule plan")
        engine.disable(ruleId)
        var released = false
        assertNull(engine.commit(plan) { released = true; "released" })
        assertFalse(released)
        assertEquals(InterceptionRuleState.PAUSED, engine.get(ruleId).state)

        engine.emergencyStop()
        assertTrue(engine.status().emergencyStopped)
        assertNull(engine.evaluate(message()))
        engine.freshHumanActivation()
        assertFalse(engine.status().emergencyStopped)
        assertEquals(InterceptionRuleState.PAUSED, engine.get(ruleId).state)
        engine.enable(ruleId, 10_000)
        val afterActivation = engine.evaluate(message())
        assertNotNull(afterActivation)
    }

    @Test fun `rule evaluation can be committed only once`() {
        val engine = enabledEngine(spec())
        val evaluation = engine.evaluate(message()) ?: error("Expected evaluation")
        var releases = 0
        assertEquals("released", engine.commit(evaluation) { releases++; "released" })
        assertNull(engine.commit(evaluation) { releases++; "duplicate" })
        engine.finish(evaluation, "DROPPED", "AUTOMATIC")
        assertEquals(1, releases)
        val stats = engine.list().single().stats
        assertEquals(1, stats.forwarded)
        assertEquals(0, stats.dropped)
        assertEquals(0, stats.failed)
    }

    @Test fun `pending rule evaluations have a strict bounded capacity`() {
        val engine = enabledEngine(spec(maximumMatches = 32))
        val pending = (0 until InterceptionRuleEngine.MAX_PENDING_EVALUATIONS).map { index ->
            engine.evaluate(message(body = "{\"enabled\":false,\"index\":$index}")) ?: error("Expected reservation $index")
        }
        assertNull(engine.evaluate(message(body = "{\"enabled\":false,\"index\":99}")))
        val before = engine.list().single().stats
        assertEquals(InterceptionRuleEngine.MAX_PENDING_EVALUATIONS.toLong(), before.matchedRequests)
        assertEquals(1, before.skipped)
        pending.forEach { engine.finish(it, "FORWARDED_UNCHANGED", "AUTOMATIC") }
        assertEquals(0, engine.list().single().stats.failed)
    }

    @Test fun `mutable caller inputs cannot change a stored rule or evaluated message`() {
        val transforms = mutableListOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))
        val sourceBody = "{\"enabled\":false}".toByteArray(StandardCharsets.UTF_8)
        val source = message(body = sourceBody.toString(StandardCharsets.UTF_8)).copy(body = sourceBody)
        val engine = InterceptionRuleEngine()
        val rule = engine.create(spec(transformations = transforms))
        transforms[0] = RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "false")
        engine.enable(rule.id, 120_000)
        val evaluation = engine.evaluate(source) ?: error("Expected evaluation")
        sourceBody.fill('x'.code.toByte())
        assertTrue(evaluation.input.body.toString(StandardCharsets.UTF_8).contains("false"))
        assertTrue(evaluation.output.body.toString(StandardCharsets.UTF_8).contains("true"))
        engine.finish(evaluation, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
    }

    @Test fun `invalidating one rule releases and records co-matched reservations`() {
        val first = spec(name = "first", priority = 200)
        val second = spec(name = "second", transformations = listOf(
            RuleTransformation(RuleTransformType.SET_REQUEST_HEADER, name = "X-Secondary", value = "yes")
        ), priority = 100)
        val engine = enabledEngine(first, second)
        val plan = engine.evaluate(message()) ?: error("Expected co-matched evaluation")
        val firstId = engine.list().first { it.spec.name == "first" }.id
        engine.disable(firstId)
        var released = false
        assertNull(engine.commit(plan) { released = true })
        assertFalse(released)
        val views = engine.list()
        assertEquals(1L, views.single { it.spec.name == "first" }.stats.skipped)
        assertEquals(1L, views.single { it.spec.name == "second" }.stats.skipped)
        assertTrue(views.all { it.stats.failed == 0L })
    }

    @Test fun `concurrent request counts 1 2 4 and 8 remain isolated`() {
        for (concurrency in listOf(1,2,4,8)) {
            val engine = enabledEngine(spec(maximumMatches = 32))
            val pool = Executors.newFixedThreadPool(concurrency)
            val gate = CountDownLatch(1); val completed = AtomicInteger()
            val futures = (0 until concurrency).map { index -> pool.submit {
                gate.await(2,TimeUnit.SECONDS)
                val value = message(body = "{\"enabled\":false,\"index\":$index}")
                val evaluation = engine.evaluate(value)
                assertNotNull(evaluation)
                assertTrue(evaluation!!.output.body.toString(StandardCharsets.UTF_8).contains("\"index\":$index"))
                engine.finish(evaluation, "MODIFIED_AND_FORWARDED", "AUTOMATIC")
                completed.incrementAndGet()
            } }
            gate.countDown(); futures.forEach { it.get(5,TimeUnit.SECONDS) }; pool.shutdownNow()
            assertEquals(concurrency, completed.get())
            assertEquals(concurrency.toLong(), engine.list().single().stats.matchedRequests)
        }
    }
}
