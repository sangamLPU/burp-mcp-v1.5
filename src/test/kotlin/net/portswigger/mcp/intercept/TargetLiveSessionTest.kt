package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import io.mockk.*
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.RequestRateLimiter
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import java.net.URI
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class TargetLiveSessionTest {
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val now = AtomicLong(0)
    private var scoped = true
    private lateinit var config: McpConfig
    private lateinit var live: LiveInterception
    private val target = "https://fixture.example:443/lab"
    private val headers = listOf("Host" to "fixture.example:443", "Content-Type" to "application/json")

    @BeforeEach fun setup() {
        val storage = mockk<PersistedObject>(relaxed = true)
        val values = mutableMapOf<String, Any>("readOnlyMode" to false, "_autoApproveTargets" to "fixture.example:443", "bearerToken" to "synthetic")
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg<Boolean>() }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        every { storage.setInteger(any(), any()) } answers { values[firstArg()] = secondArg<Int>() }
        config = McpConfig(storage, api.logging())
        every { api.scope().isInScope(any()) } answers { scoped }
        mockkObject(Dialogs)
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
        live = LiveInterception(api, config, now::get)
        live.allowEdits = true
        RequestRateLimiter.resetForTests()
    }

    @AfterEach fun cleanup() { live.close(); unmockkObject(Dialogs) }

    private fun bytes(value: String): BurpBytes = mockk<BurpBytes>().also {
        every { it.getBytes() } returns value.toByteArray()
        every { it.length() } returns value.toByteArray().size
    }
    private fun header(name: String, value: String) = mockk<HttpHeader>().also {
        every { it.name() } returns name; every { it.value() } returns value
    }
    private fun request(url: String = target, body: String = "{\"enabled\":false}", hs: List<Pair<String, String>> = headers,
                        onEdit: () -> Unit = {}, onRead: () -> Unit = {}): InterceptedRequest {
        val r = mockk<InterceptedRequest>(relaxed = true)
        val u = URI(url); val port = if (u.port == -1) 443 else u.port
        every { r.url() } returns url
        every { r.path() } returns u.rawPath + (u.rawQuery?.let { "?$it" } ?: "")
        every { r.method() } returns "POST"
        every { r.httpService().host() } returns u.host
        every { r.httpService().port() } returns port
        every { r.httpService().secure() } returns (u.scheme == "https")
        every { r.headers() } returns hs.map { header(it.first, it.second) }
        every { r.toByteArray() } returns bytes("POST $url\n${hs.joinToString()}\n$body")
        every { r.body().getBytes() } answers { onRead(); body.toByteArray() }
        every { r.withBody(any<String>()) } answers { onEdit(); request(url, firstArg(), hs) }
        every { r.withRemovedHeader(any<String>()) } answers { request(url, body, hs.filterNot { it.first.equals(firstArg<String>(), true) }) }
        every { r.withAddedHeader(any<String>(), any<String>()) } answers { request(url, body, hs + (firstArg<String>() to secondArg<String>())) }
        every { r.withPath(any<String>()) } answers { request("${u.scheme}://${u.host}:$port${firstArg<String>()}", body, hs) }
        return r
    }
    private fun response(req: HttpRequest, body: String = "{\"enabled\":false}", hs: List<Pair<String, String>> = listOf("Content-Type" to "application/json"),
                         status: Short = 200, onEdit: () -> Unit = {}): InterceptedResponse {
        val r = mockk<InterceptedResponse>(relaxed = true)
        every { r.initiatingRequest() } returns req
        every { r.headers() } returns hs.map { header(it.first, it.second) }
        every { r.body().getBytes() } returns body.toByteArray()
        every { r.toByteArray() } returns bytes("$status\n${hs.joinToString()}\n$body")
        every { r.statusCode() } returns status
        every { r.hasHeader(any<String>()) } answers { hs.any { it.first.equals(firstArg<String>(), true) } }
        every { r.withBody(any<String>()) } answers { onEdit(); response(req, firstArg(), hs, status) }
        every { r.withRemovedHeader(any<String>()) } answers { response(req, body, hs.filterNot { it.first.equals(firstArg<String>(), true) }, status) }
        every { r.withAddedHeader(any<String>(), any<String>()) } answers { response(req, body, hs + (firstArg<String>() to secondArg<String>()), status) }
        return r
    }
    private fun start(direction: RuleDirection = RuleDirection.BOTH, seconds: Int = 60): String = runBlocking {
        val grant = live.requestTargetRuleAuthorization(listOf(target), 300)
        val rule = live.createInterceptionRule(InterceptionRuleSpec("Exact lab", target, grant.id, direction,
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true"))))
        live.startTargetRuleSession(grant.id, listOf(rule.id), seconds)
        rule.id
    }
    private fun execute(req: HttpRequest, id: Int = 1) = live.processTargetMessage("request", HeldMessage(req, req), id)

    @Test fun `revised browser form target supports separately approved one budget rule pair`() = runBlocking<Unit> {
        val url = "http://127.0.0.1:8000/test-form-browser-validation"
        config.autoApproveTargets = "127.0.0.1:8000"
        val grant = live.requestTargetRuleAuthorization(listOf(url), 300)
        val requestRule = live.createInterceptionRule(InterceptionRuleSpec("Browser form", url, grant.id,
            RuleDirection.REQUEST, conditions = RuleMatchConditions(method = "POST", contentType = "application/x-www-form-urlencoded",
                formFieldName = "mcp_test", formFieldValue = "original"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_FORM_FIELD, name = "mcp_test", value = "modified")),
            maximumMatches = 1, maximumModifications = 1))
        val responseRule = live.createInterceptionRule(InterceptionRuleSpec("Browser response", url, grant.id,
            RuleDirection.RESPONSE, conditions = RuleMatchConditions(method = "POST", responseStatus = 200, contentType = "application/json"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.browser_verified", valueJson = "true")),
            maximumMatches = 1, maximumModifications = 1))
        assertEquals(InterceptionRuleState.DISABLED, requestRule.state)
        assertEquals(InterceptionRuleState.DISABLED, responseRule.state)
        live.startTargetRuleSession(grant.id, listOf(requestRule.id, responseRule.id), 60)
        val req = request(url, "name=test&mcp_test=original", listOf("Host" to "127.0.0.1:8000", "Content-Type" to "application/x-www-form-urlencoded"))
        val sent = execute(req)
        assertEquals("name=test&mcp_test=modified", String(sent.message.body().getBytes()))
        val originalResponse = response(sent.request, "{\"serverVerified\":true}")
        val body = String(live.processTargetMessage("response", HeldMessage(originalResponse, sent.request), 1).message.body().getBytes())
        assertTrue(body.contains("\"serverVerified\":true"), body)
        assertTrue(body.contains("\"browser_verified\":true"), body)
        for (id in listOf(requestRule.id, responseRule.id)) {
            assertEquals(1, live.ruleEngine.get(id).stats.modified)
            assertEquals(0, live.ruleEngine.get(id).stats.remainingMatches)
        }
        val sibling = request("${url}-unrelated", "name=test&mcp_test=original", listOf("Host" to "127.0.0.1:8000", "Content-Type" to "application/x-www-form-urlencoded"))
        assertSame(sibling, execute(sibling, 2).message)
    }

    private fun startSeparateRules(matches: Int = 1, modifications: Int = matches): Pair<String, String> = runBlocking {
        val grant = live.requestTargetRuleAuthorization(listOf(target), 300)
        val requestRule = live.createInterceptionRule(InterceptionRuleSpec("One request", target, grant.id,
            RuleDirection.REQUEST, conditions = RuleMatchConditions(method = "POST", contentType = "application/json"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            maximumMatches = matches, maximumModifications = modifications))
        val responseRule = live.createInterceptionRule(InterceptionRuleSpec("One response", target, grant.id,
            RuleDirection.RESPONSE, conditions = RuleMatchConditions(method = "POST", responseStatus = 200, contentType = "application/json"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.browser_verified", valueJson = "true")),
            maximumMatches = matches, maximumModifications = modifications))
        live.startTargetRuleSession(grant.id, listOf(requestRule.id, responseRule.id), 60)
        requestRule.id to responseRule.id
    }

    @Test fun `safe query variants stay on the approved path while credential keys remain unchanged`() {
        start()
        val safe = request("$target?x=one&x=&keep=%E9%9B%AA")
        val changed = execute(safe)
        assertTrue(String(changed.message.body().getBytes()).contains("true"))
        assertEquals(safe.url(), changed.request.url())
        for (query in listOf("password=synthetic", "p%61ssword=synthetic", "token=synthetic")) {
            val sensitive = request("$target?$query")
            assertSame(sensitive, execute(sensitive).message)
        }
    }

    @Test fun `userinfo encoded aliases and traversal never inherit exact path authority`() {
        start()
        for (url in listOf("https://user:synthetic@fixture.example:443/lab", "https://fixture.example:443/a/../lab",
                "https://fixture.example:443/./lab", "https://fixture.example:443/%6cab", "https://fixture.example:443//lab")) {
            val original = request(url)
            assertSame(original, execute(original).message, url)
        }
    }

    @Test fun `broad Burp scope never extends an exact session to prefix siblings`() {
        // setup deliberately reports every URL in scope: scope is an eligibility gate,
        // not the exact execution authority supplied by the grant and rule binding.
        val id = start()
        for (url in listOf("$target-unrelated", "${target}yrinth", "$target/child")) {
            val req = request(url)
            assertSame(req, execute(req).message, url)
            val res = response(req)
            assertSame(res, live.processTargetMessage("response", HeldMessage(res, req), 1).message, url)
        }
        assertEquals(0, live.ruleEngine.get(id).stats.modified)
        assertTrue(String(execute(request()).message.body().getBytes()).contains("true"))
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(live.queue.list("response").isEmpty())
    }

    @Test fun `reserved localhost form path cannot use a preparation grant instead of unattended authority`() = runBlocking<Unit> {
        config.autoApproveTargets = "127.0.0.1:8000"
        val formTarget = "http://127.0.0.1:8000/test-form"
        val grant = live.requestTargetRuleAuthorization(listOf(formTarget), 300)
        val spec = InterceptionRuleSpec("Prepared browser form", formTarget, grant.id, RuleDirection.REQUEST,
            conditions = RuleMatchConditions(method = "POST", contentType = "application/x-www-form-urlencoded",
                formFieldName = "mcp_test", formFieldValue = "original"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_FORM_FIELD, name = "mcp_test", value = "modified")),
            maximumMatches = 1, maximumModifications = 1)
        assertThrows(IllegalStateException::class.java) { live.createInterceptionRule(spec) }
        // Even a low-level prepared rule cannot bypass the target-session boundary.
        val rule = live.ruleEngine.create(spec)
        assertThrows(IllegalStateException::class.java) {
            runBlocking { live.startTargetRuleSession(grant.id, listOf(rule.id), 60) }
        }
        assertFalse(live.enabled)
        assertFalse(live.unattendedSnapshot().active)
        assertEquals(InterceptionRuleState.DISABLED, live.ruleEngine.get(rule.id).state)
        coVerify(exactly = 1) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
    }

    @Test fun `approved request and associated response transformations execute without a manual queue`() {
        val id = start()
        val req = request()
        val sent = execute(req)
        assertTrue(String(sent.message.body().getBytes()).contains("true"))
        val res = response(sent.request)
        val received = live.processTargetMessage("response", HeldMessage(res, sent.request), 1)
        assertTrue(String(received.message.body().getBytes()).contains("true"))
        assertEquals(2, live.ruleEngine.get(id).stats.modified)
        assertTrue(live.queue.list("request").isEmpty()); assertTrue(live.queue.list("response").isEmpty())
        coVerify(exactly = 2) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
    }

    @Test fun `separate one match request and response rules preserve origin verification`() {
        val (requestId, responseId) = startSeparateRules()
        val sent = execute(request())
        assertTrue(String(sent.message.body().getBytes()).contains("\"enabled\":true"))
        val original = response(sent.request, "{\"serverVerified\":true}")
        val received = live.processTargetMessage("response", HeldMessage(original, sent.request), 1)
        val body = String(received.message.body().getBytes())
        assertTrue(body.contains("\"serverVerified\":true"), body)
        assertTrue(body.contains("\"browser_verified\":true"), body)
        for (id in listOf(requestId, responseId)) {
            val stats = live.ruleEngine.get(id).stats
            assertEquals(1, stats.modified)
            assertEquals(1, stats.forwarded)
            assertEquals(0, stats.remainingMatches)
            assertEquals(0, stats.remainingModifications)
        }
        assertSame(original, live.processTargetMessage("response", HeldMessage(original, sent.request), 1).message)
    }

    @Test fun `separate rules transform repeated pairs through the last permitted match only`() {
        val ids = startSeparateRules(matches = 2)
        for (pair in 1..2) {
            val sent = execute(request(), pair)
            assertTrue(String(sent.message.body().getBytes()).contains("\"enabled\":true"))
            val res = response(sent.request, "{\"serverVerified\":true}")
            val result = live.processTargetMessage("response", HeldMessage(res, sent.request), pair)
            assertTrue(String(result.message.body().getBytes()).contains("\"browser_verified\":true"))
        }
        val overBudget = request()
        assertSame(overBudget, execute(overBudget, 3).message)
        val res = response(overBudget, "{\"serverVerified\":true}")
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, overBudget), 3).message)
        for (id in listOf(ids.first, ids.second)) {
            assertEquals(2, live.ruleEngine.get(id).stats.modified)
            assertEquals(2, live.ruleEngine.get(id).stats.forwarded)
        }
    }

    @Test fun `modification budget exhaustion preserves the paired response without restoring budgets`() {
        val ids = startSeparateRules(matches = 2, modifications = 1)
        val sent = execute(request())
        assertEquals(InterceptionRuleState.MAX_MODIFICATIONS, live.ruleEngine.get(ids.first).state)
        val res = response(sent.request, "{\"serverVerified\":true}")
        val result = live.processTargetMessage("response", HeldMessage(res, sent.request), 1)
        assertTrue(String(result.message.body().getBytes()).contains("\"browser_verified\":true"))
        val another = request()
        assertSame(another, execute(another, 2).message)
        assertEquals(0, live.ruleEngine.get(ids.first).stats.remainingModifications)
        assertEquals(1, live.ruleEngine.get(ids.first).stats.modified)
    }

    @Test fun `paused or deleted exhausted request rules still invalidate response association`() {
        for (delete in listOf(false, true)) {
            val ids = startSeparateRules()
            val sent = execute(request())
            if (delete) live.deleteInterceptionRule(ids.first) else live.disableInterceptionRule(ids.first)
            val res = response(sent.request, "{\"serverVerified\":true}")
            assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
            assertEquals(0, live.ruleEngine.get(ids.second).stats.modified)
            live.disable()
        }
    }

    @Test fun `request rule pause and resume during response materialization invalidates final release`() {
        val ids = startSeparateRules(matches = 2)
        val sent = execute(request())
        val res = response(sent.request, "{\"serverVerified\":true}", onEdit = {
            live.disableInterceptionRule(ids.first)
            live.enableInterceptionRule(ids.first)
        })
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
        assertEquals(0, live.ruleEngine.get(ids.second).stats.modified)
    }

    @Test fun `canonical default port works but wrong scheme host port path service or Host does not`() {
        start()
        assertTrue(String(execute(request("https://fixture.example/lab")).message.body().getBytes()).contains("true"))
        for (url in listOf("http://fixture.example:443/lab", "https://other.example:443/lab", "https://fixture.example:444/lab",
            "$target/child", "$target/../other", "$target%2fchild", "$target#fragment")) {
            val req = request(url); assertSame(req, execute(req).message, url)
        }
        for (hs in listOf(headers + ("Host" to "fixture.example:443"), headers.filterNot { it.first == "Host" },
            headers.filterNot { it.first == "Host" } + ("Host" to "other.example:443"))) {
            val req = request(hs = hs); assertSame(req, execute(req).message)
        }
        val wrongService = request(); every { wrongService.httpService().secure() } returns false
        assertSame(wrongService, execute(wrongService).message)
    }

    @Test fun `response only permission never transforms requests or mismatched and replayed responses`() {
        start(RuleDirection.RESPONSE)
        val req = request(); assertSame(req, execute(req).message)
        val other = request(body = "{\"enabled\":false,\"other\":1}")
        val mismatch = response(other)
        assertSame(mismatch, live.processTargetMessage("response", HeldMessage(mismatch, other), 1).message)
        execute(req, 2)
        val res = response(req)
        assertTrue(String(live.processTargetMessage("response", HeldMessage(res, req), 2).message.body().getBytes()).contains("true"))
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, req), 2).message)
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, req), 999).message)
    }

    @Test fun `sensitive credentials redirects and oversized messages pass unchanged`() {
        start()
        for (hs in listOf(headers + ("Cookie" to "synthetic=fixture"), headers + ("Authorization" to "synthetic"))) {
            val req = request(hs = hs); assertSame(req, execute(req).message)
        }
        val large = request(body = "x".repeat(65_537)); assertSame(large, execute(large).message)
        for (hs in listOf(listOf("Set-Cookie" to "synthetic=fixture"), listOf("Location" to "https://other.example/"))) {
            val req = request(); val sent = execute(req)
            val res = response(sent.request, hs = hs)
            assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
        }
    }

    @Test fun `grant expiry at the exact in flight materialization boundary commits no mutation`() {
        start(seconds = 300)
        val req = request(onEdit = { now.set(TimeUnit.SECONDS.toNanos(300)) })
        assertSame(req, execute(req).message)
        assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
    }

    @Test fun `session expiry before forwarding commits no mutation`() {
        start()
        val req = request(onEdit = { now.set(TimeUnit.SECONDS.toNanos(60)) })
        assertSame(req, execute(req).message)
    }

    @Test fun `scope and exact allowlist revocation during materialization commit no mutation`() {
        start()
        val req = request(onEdit = { scoped = false })
        assertSame(req, execute(req).message)
        assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
    }

    @Test fun `allowlist revocation during materialization commits no mutation`() {
        start()
        val req = request(onEdit = { config.autoApproveTargets = "*.example" })
        assertSame(req, execute(req).message)
    }

    @Test fun `emergency stop during materialization commits no mutation and latches engine`() {
        start()
        val req = request(onEdit = { live.emergencyStopUnattendedLocalTestMode() })
        assertSame(req, execute(req).message)
        assertFalse(live.enabled); assertTrue(live.ruleEngine.status().emergencyStopped)
    }

    @Test fun `rule pause or deletion invalidates the in flight transaction`() {
        val id = start()
        val req = request(onEdit = { live.disableInterceptionRule(id) })
        assertSame(req, execute(req).message)
        live.enableInterceptionRule(id)
        val deleted = request(onEdit = { live.deleteInterceptionRule(id) })
        assertSame(deleted, execute(deleted).message)
    }

    @Test fun `replacement session cannot inherit grant or request associations`() {
        start()
        val req = request(onEdit = { live.startApprovedSession(60) })
        assertSame(req, execute(req).message)
        val next = request(); assertSame(next, execute(next).message)
    }

    @Test fun `two in flight messages share a grant and excess traffic continues unchanged`() {
        start()
        val entered = CountDownLatch(2); val release = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(3)
        fun blocked(): HttpRequest {
            val once = AtomicBoolean()
            return request(onRead = { if (once.compareAndSet(false, true)) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) } })
        }
        try {
            val one = blocked(); val two = blocked()
            val a = pool.submit<HeldMessage> { execute(one, 10) }; val b = pool.submit<HeldMessage> { execute(two, 11) }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val extra = request(); assertSame(extra, pool.submit<HeldMessage> { execute(extra, 12) }.get(1, TimeUnit.SECONDS).message)
            release.countDown()
            assertTrue(String(a.get(5, TimeUnit.SECONDS).message.body().getBytes()).contains("true"))
            assertTrue(String(b.get(5, TimeUnit.SECONDS).message.body().getBytes()).contains("true"))
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun `denied and stale session approvals cannot enable rules`() = runBlocking<Unit> {
        val grant = live.requestTargetRuleAuthorization(listOf(target), 300)
        val spec = InterceptionRuleSpec("Exact lab", target, grant.id, RuleDirection.REQUEST, action = RuleAction.FORWARD_UNCHANGED)
        val rule = live.createInterceptionRule(spec)
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 1
        assertThrows(IllegalStateException::class.java) { runBlocking { live.startTargetRuleSession(grant.id, listOf(rule.id), 60) } }
        assertFalse(live.enabled)
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } answers { live.emergencyStopUnattendedLocalTestMode(); 0 }
        assertThrows(IllegalStateException::class.java) { runBlocking { live.startTargetRuleSession(grant.id, listOf(rule.id), 60) } }
        assertFalse(live.enabled)
    }

    @Test fun `request only operation and paused response associations cannot be reused`() {
        val id = start(RuleDirection.REQUEST)
        val sent = execute(request())
        val res = response(sent.request)
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
        live.disableInterceptionRule(id)
        live.enableInterceptionRule(id)
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
    }

    @Test fun `response association becomes stale when an approved rule is paused and resumed`() {
        val id = start(RuleDirection.BOTH)
        val sent = execute(request())
        live.disableInterceptionRule(id)
        live.enableInterceptionRule(id)
        val res = response(sent.request)
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
    }

    @Test fun `installed callback transforms approved traffic and leaves unrelated traffic unchanged`() {
        val handler = slot<burp.api.montoya.proxy.http.ProxyRequestHandler>()
        every { api.proxy().registerRequestHandler(capture(handler)) } returns mockk(relaxed = true)
        mockkStatic(burp.api.montoya.proxy.http.ProxyRequestReceivedAction::class)
        try {
            every { burp.api.montoya.proxy.http.ProxyRequestReceivedAction.continueWith(any<HttpRequest>()) } answers {
                val req = firstArg<HttpRequest>()
                mockk<burp.api.montoya.proxy.http.ProxyRequestReceivedAction>().also { a -> every { a.request() } returns req }
            }
            live.install()
            start()
            val approved = request()
            val sent = handler.captured.handleRequestReceived(approved).request()
            assertTrue(String(sent.body().getBytes()).contains("true"))
            val unrelated = request("https://other.example:443/ordinary")
            assertSame(unrelated, handler.captured.handleRequestReceived(unrelated).request())
            assertTrue(live.queue.list("request").isEmpty())
            verify(exactly = 0) { burp.api.montoya.proxy.http.ProxyRequestReceivedAction.drop() }
        } finally { unmockkStatic(burp.api.montoya.proxy.http.ProxyRequestReceivedAction::class) }
    }

    @Test fun `automatic drop operation cannot acquire a target session`() = runBlocking<Unit> {
        val grant = live.requestTargetRuleAuthorization(listOf(target), 300)
        val rule = live.createInterceptionRule(InterceptionRuleSpec("Forbidden target drop", target, grant.id,
            RuleDirection.REQUEST, action = RuleAction.DROP))
        assertThrows(IllegalStateException::class.java) { runBlocking { live.startTargetRuleSession(grant.id, listOf(rule.id), 60) } }
        assertFalse(live.enabled)
        coVerify(exactly = 1) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
    }

    @Test fun `scope and allowlist change events permanently revoke grants even if restored`() {
        val scopeHandler = slot<burp.api.montoya.scope.ScopeChangeHandler>()
        every { api.scope().registerScopeChangeHandler(capture(scopeHandler)) } returns mockk(relaxed = true)
        live.install()
        start()
        scopeHandler.captured.scopeChanged(mockk(relaxed = true))
        val req = request()
        assertSame(req, execute(req).message)
        assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
        live.disable()
        start()
        config.autoApproveTargets = ""
        config.autoApproveTargets = "fixture.example:443"
        assertSame(req, execute(req).message)
        assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
    }

    @Test fun `response materialization rechecks revocation before releasing changed bytes`() {
        start()
        val sent = execute(request())
        val res = response(sent.request, onEdit = { live.targetRuleAuthorizations.revokeAll() })
        assertSame(res, live.processTargetMessage("response", HeldMessage(res, sent.request), 1).message)
    }

    @Test fun `missed internal heartbeat cannot authorize an automatic action`() {
        start()
        now.set(TimeUnit.SECONDS.toNanos(16))
        val req = request()
        assertSame(req, execute(req).message)
    }

    @Test fun `callback arriving while a target session binds cannot enter the manual queue`() = runBlocking<Unit> {
        val handler = slot<burp.api.montoya.proxy.http.ProxyRequestHandler>()
        every { api.proxy().registerRequestHandler(capture(handler)) } returns mockk(relaxed = true)
        mockkStatic(burp.api.montoya.proxy.http.ProxyRequestReceivedAction::class)
        val pool = Executors.newFixedThreadPool(2)
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val once = AtomicBoolean()
        try {
            every { burp.api.montoya.proxy.http.ProxyRequestReceivedAction.continueWith(any<HttpRequest>()) } answers {
                val req = firstArg<HttpRequest>()
                mockk<burp.api.montoya.proxy.http.ProxyRequestReceivedAction>().also { a -> every { a.request() } returns req }
            }
            live.install()
            val grant = live.requestTargetRuleAuthorization(listOf(target), 300)
            val rule = live.createInterceptionRule(InterceptionRuleSpec("Bound lab", target, grant.id, RuleDirection.REQUEST, action = RuleAction.FORWARD_UNCHANGED))
            every { api.scope().isInScope(any()) } answers {
                if (live.enabled && Thread.currentThread().name.startsWith("target-bind") && once.compareAndSet(false, true)) {
                    entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
                }
                true
            }
            val bind = pool.submit { Thread.currentThread().name = "target-bind"; runBlocking { live.startTargetRuleSession(grant.id, listOf(rule.id), 60) } }
            if (!entered.await(3, TimeUnit.SECONDS)) { bind.get(1, TimeUnit.SECONDS); fail<Unit>("Binding did not reach its policy gate") }
            val unrelated = request("https://fixture.example:443/unapproved")
            val callback = pool.submit<HttpRequest> { handler.captured.handleRequestReceived(unrelated).request() }
            release.countDown()
            bind.get(5, TimeUnit.SECONDS)
            assertSame(unrelated, callback.get(5, TimeUnit.SECONDS))
            assertTrue(live.queue.list("request").isEmpty())
        } finally {
            release.countDown(); pool.shutdownNow()
            unmockkStatic(burp.api.montoya.proxy.http.ProxyRequestReceivedAction::class)
        }
    }
}
