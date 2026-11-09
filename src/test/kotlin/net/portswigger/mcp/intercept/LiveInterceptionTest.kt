package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.*
import io.mockk.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.security.RequestRateLimiter
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import net.portswigger.mcp.config.Dialogs

class LiveInterceptionTest {
    private val api=mockk<MontoyaApi>(relaxed=true)
    private val request=mockk<InterceptedRequest>(relaxed=true)
    private val response=mockk<InterceptedResponse>(relaxed=true)
    private val requestHandler=slot<ProxyRequestHandler>();private val responseHandler=slot<ProxyResponseHandler>()
    private val registration=mockk<Registration>(relaxed=true)
    private val pool=Executors.newFixedThreadPool(2)
    private lateinit var live:LiveInterception
    private lateinit var config:McpConfig
    private val requestDropped=mockk<ProxyRequestReceivedAction>();private val responseDropped=mockk<ProxyResponseReceivedAction>()
    @BeforeEach fun setup() {
        val storage=mockk<PersistedObject>(relaxed=true)
        val values=mutableMapOf<String,Any>("readOnlyMode" to false,"_autoApproveTargets" to "localhost:8000","bearerToken" to "test")
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(),any()) } answers { values[firstArg()]=secondArg<Boolean>() }
        every { storage.setString(any(),any()) } answers { values[firstArg()]=secondArg<String>() }
        every { storage.setInteger(any(),any()) } answers { values[firstArg()]=secondArg<Int>() }
        config=McpConfig(storage,api.logging())
        every { request.httpService().host() } returns "localhost"
        every { request.httpService().port() } returns 8000
        every { request.url() } returns "http://localhost:8000/test"
        every { request.method() } returns "GET"
        every { request.path() } returns "/test?token=query-secret&item=private-value"
        every { request.toByteArray().length() } returns 50
        every { response.toByteArray().length() } returns 50
        every { response.initiatingRequest() } returns request
        every { api.scope().isInScope(any()) } returns true
        every { api.proxy().registerRequestHandler(capture(requestHandler)) } returns registration
        every { api.proxy().registerResponseHandler(capture(responseHandler)) } returns registration
        mockkStatic(ProxyRequestReceivedAction::class);mockkStatic(ProxyResponseReceivedAction::class)
        every { ProxyRequestReceivedAction.drop() } returns requestDropped
        every { ProxyResponseReceivedAction.drop() } returns responseDropped
        every { ProxyRequestReceivedAction.continueWith(any<HttpRequest>()) } answers { mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns firstArg() } }
        every { ProxyRequestReceivedAction.doNotIntercept(any<HttpRequest>()) } answers { val sent=firstArg<HttpRequest>();mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns sent } }
        every { ProxyResponseReceivedAction.doNotIntercept(any<HttpResponse>()) } answers { val sent=firstArg<HttpResponse>();mockk<ProxyResponseReceivedAction>().also { action -> every { action.response() } returns sent } }
        live=LiveInterception(api,config);live.install();live.startApprovedSession(60);RequestRateLimiter.resetForTests()
    }
    @AfterEach fun cleanup() { live.close();pool.shutdownNow();unmockkStatic(ProxyRequestReceivedAction::class);unmockkStatic(ProxyResponseReceivedAction::class) }
    private fun pending(kind:String):DecisionQueue.Ticket<HeldMessage> {
        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2)
        while(System.nanoTime()<deadline) { live.queue.list(kind).firstOrNull()?.let { return it };Thread.yield() }
        error("Callback failed to enter pending queue")
    }
    private fun prepareAuthorizedJsonPost(identity: UnattendedLocalTestSnapshot, caseId: String): HttpRequest {
        val target = "http://127.0.0.1:8000/test-post"
        every { request.httpService().host() } returns LocalTestTargets.HOST
        every { request.httpService().port() } returns LocalTestTargets.PORT
        every { request.httpService().secure() } returns false
        every { request.url() } returns target
        every { request.method() } returns "POST"
        every { request.path() } returns "/test-post"
        every { request.toByteArray().length() } returns 256
        val falseBody = "{\"enabled\":false,\"name\":\"original\",\"mcp_test\":\"after\",\"marker\":\"preserve\",\"case\":\"$caseId\",\"nested\":{\"keep\":17}}".toByteArray()
        val trueBody = "{\"enabled\":true,\"name\":\"original\",\"mcp_test\":\"after\",\"marker\":\"preserve\",\"case\":\"$caseId\",\"nested\":{\"keep\":17}}".toByteArray()
        val requestHeaders = listOf(
            "Host" to "127.0.0.1:8000",
            "Content-Type" to "application/json",
            "Content-Length" to falseBody.size.toString(),
            "X-MCP-Test-Run" to identity.testRunId!!,
            "X-MCP-Server-Identity" to identity.serverIdentity!!,
            "X-MCP-Test-ID" to caseId
        ).map { (name, value) -> mockk<HttpHeader>().also { header ->
            every { header.name() } returns name
            every { header.value() } returns value
        } }
        every { request.headers() } returns requestHeaders
        every { request.body().getBytes() } returns falseBody
        every { request.body().length() } returns falseBody.size

        val modifiedRequest = mockk<HttpRequest>(relaxed = true)
        every { request.withBody(any<String>()) } returns modifiedRequest
        every { modifiedRequest.httpService() } returns request.httpService()
        every { modifiedRequest.url() } returns target
        every { modifiedRequest.method() } returns "POST"
        every { modifiedRequest.path() } returns "/test-post"
        val modifiedLengthHeader = mockk<HttpHeader>().also {
            every { it.name() } returns "Content-Length"
            every { it.value() } returns trueBody.size.toString()
        }
        every { modifiedRequest.headers() } returns (requestHeaders.filterNot { it.name().equals("Content-Length", true) } + modifiedLengthHeader)
        every { modifiedRequest.body().getBytes() } returns trueBody
        every { modifiedRequest.body().length() } returns trueBody.size
        every { modifiedRequest.toByteArray().length() } returns 256
        every { modifiedRequest.withRemovedHeader("Content-Length") } returns modifiedRequest
        every { modifiedRequest.withAddedHeader("Content-Length", trueBody.size.toString()) } returns modifiedRequest
        return modifiedRequest
    }
    @Test fun `request callback stays pending and forwards only the approved patch`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val t=pending("request");assertFalse(result.isDone)
        val edited=mockk<HttpRequest>(relaxed=true)
        every { edited.httpService() } returns request.httpService();every { edited.url() } returns request.url()
        every { edited.toByteArray().length() } returns 50
        every { request.withHeader("X-Test","changed") } returns edited
        assertThrows(IllegalStateException::class.java) { live.propose(t.id,"request",0,mapOf("X-Test" to "changed"),emptyList(),null,null) }
        live.allowEdits=true
        live.propose(t.id,"request",0,mapOf("X-Test" to "changed"),emptyList(),null,null)
        assertThrows(IllegalStateException::class.java) { live.forward(t.id,"request",1) }
        live.approveLocally(t.id,"request",1);live.forward(t.id,"request",1)
        assertSame(edited,result.get(2,TimeUnit.SECONDS).request())
        assertThrows(IllegalStateException::class.java) { live.forward(t.id,"request",1) }
    }
    @Test fun `response patch reaches downstream callback and drop is final`() {
        val result=pool.submit<ProxyResponseReceivedAction> { responseHandler.captured.handleResponseReceived(response) }
        val t=pending("response");assertFalse(result.isDone)
        val edited=mockk<HttpResponse>(relaxed=true);every { edited.toByteArray().length() } returns 50
        every { response.hasHeader("X-Test") } returns false
        every { response.withAddedHeader("X-Test","value") } returns edited
        every { edited.withBody("replacement") } returns edited
        live.allowEdits=true;live.propose(t.id,"response",0,mapOf("X-Test" to "value"),emptyList(),"replacement",null)
        live.approveLocally(t.id,"response",1);live.forward(t.id,"response",1)
        assertSame(edited,result.get(2,TimeUnit.SECONDS).response())
        verify(exactly=1) { edited.withBody("replacement") }
        val dropped=pool.submit<ProxyResponseReceivedAction> { responseHandler.captured.handleResponseReceived(response) }
        live.queue.drop(pending("response").id);assertSame(responseDropped,dropped.get(2,TimeUnit.SECONDS))
    }
    @Test fun `scope revocation drops already held request`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val t=pending("request");every { api.scope().isInScope(any()) } returns false
        assertThrows(IllegalStateException::class.java) { live.snapshot(t.id,"request") }
        assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
    }
    @Test fun `missed internal heartbeat and unload release callbacks with drop`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) };pending("request")
        live.heartbeatTick(System.nanoTime()+TimeUnit.SECONDS.toNanos(16))
        assertFalse(live.enabled);assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
        live.startApprovedSession(60)
        val second=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) };pending("request");live.close()
        assertSame(requestDropped,second.get(2,TimeUnit.SECONDS))
        assertEquals("UNLOADED", live.health().sessionEndReason)
        assertEquals("STOPPED", live.health().heartbeatHealth)
        verify(atLeast=1) { registration.deregister() }
    }

    @Test fun `automatic heartbeat keeps approved session healthy without MCP polling`() {
        val initialHealth = live.health()
        val startedAt = initialHealth.lastHeartbeatAtEpochMillis
        val fixedSessionExpiry = initialHealth.sessionExpiresAtEpochMillis
        live.touch()
        assertEquals(fixedSessionExpiry, live.health().sessionExpiresAtEpochMillis, "Client activity must not extend the approved session")
        Thread.sleep(TimeUnit.SECONDS.toMillis(4))
        val health = live.health()
        assertTrue(live.enabled)
        assertEquals("HEALTHY", health.heartbeatHealth)
        assertTrue(health.lastHeartbeatAtEpochMillis!! > startedAt!!)
        assertTrue(health.leaseRemainingMillis > TimeUnit.SECONDS.toMillis(10))
    }

    @Test fun `pending metadata exposes safe request identity without query values`() {
        val metadata = requestMetadata(request)
        assertEquals("GET", metadata.method)
        assertEquals("localhost", metadata.hostname)
        assertEquals("/test?[query redacted]", metadata.urlPath)
        assertFalse(metadata.urlPath.contains("query-secret"))
        assertFalse(metadata.urlPath.contains("private-value"))
    }

    @Test fun `unattended credential gate scans arbitrary header and query values`() {
        val opaqueHeader = mockk<HttpHeader>()
        every { opaqueHeader.name() } returns "X-Test-Metadata"
        every { opaqueHeader.value() } returns ("Bearer " + "synthetic-" + "secret-value")
        every { request.headers() } returns listOf(opaqueHeader)
        every { request.body().getBytes() } returns ByteArray(0)
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel?case=local-1"
        assertTrue(live.hasSensitiveContent(request, request))

        every { request.headers() } returns emptyList()
        every { request.url() } returns ("http://127.0.0.1:8000/test-cancel?note=Bearer%20" + "synthetic-secret-value")
        assertTrue(live.hasSensitiveContent(request, request))

        every { opaqueHeader.value() } returns "eyJabcdefghijk.abcdefghijk.abcdefghijk"
        every { request.headers() } returns listOf(opaqueHeader)
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel?case=local-1"
        assertTrue(live.hasSensitiveContent(request, request))

        every { request.headers() } returns emptyList()
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel?note=eyJabcdefghijk.abcdefghijk.abcdefghijk"
        assertTrue(live.hasSensitiveContent(request, request))

        val encodingHeader = mockk<HttpHeader>()
        every { encodingHeader.name() } returns "Content-Encoding"
        every { encodingHeader.value() } returns "gzip"
        every { request.headers() } returns listOf(encodingHeader)
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel?case=local-1"
        assertTrue(live.hasSensitiveContent(request, request))

        every { request.url() } returns "http://127.0.0.1:8000/test-cancel?case=local-1"
        every { request.headers() } returns emptyList()
        assertFalse(live.hasSensitiveContent(request, request))
    }

    @Test fun `remote drop waits for explicit local confirmation`() = runBlocking {
        mockkObject(Dialogs)
        val localDecision = CompletableDeferred<Int>()
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } coAnswers {
            localDecision.await()
        }
        try {
            val callback = pool.submit<ProxyRequestReceivedAction> {
                requestHandler.captured.handleRequestReceived(request)
            }
            val ticket = pending("request")
            val drop = async { live.dropWithLocalApproval(ticket.id, "request") }
            delay(25)
            assertFalse(callback.isDone, "the callback must remain held until a local decision")
            assertEquals(ticket.id, live.queue.get(ticket.id).id)
            localDecision.complete(0)
            drop.await()
            assertSame(requestDropped, callback.get(2, TimeUnit.SECONDS))
            assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
                it.action == "intercept_drop" && it.detail.contains(ticket.id)
            })
        } finally {
            localDecision.complete(1)
            unmockkObject(Dialogs)
        }
    }

    @Test fun `explicitly activated local mode auto drops only an identity-bound request`() = runBlocking {
        val body = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { body.length() } returns 0
        every { body.getBytes() } returns byteArrayOf()
        every { request.body() } returns body
        every { request.toByteArray().length() } returns 128
        every { request.httpService().host() } returns LocalTestTargets.HOST
        every { request.httpService().port() } returns LocalTestTargets.PORT
        every { request.httpService().secure() } returns false
        every { request.url() } returns "http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}/test-cancel"
        every { request.method() } returns "GET"
        every { request.path() } returns "/test-cancel"
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        live.startApprovedSession(60)
        val requestHeaders = listOf(
            "Host" to "127.0.0.1:8000",
            "X-MCP-Test-Run" to identity.testRunId!!,
            "X-MCP-Server-Identity" to identity.serverIdentity!!,
            "X-MCP-Test-ID" to "phase4a-case-1"
        ).map { (name, value) ->
            mockk<HttpHeader>().also { header ->
                every { header.name() } returns name
                every { header.value() } returns value
            }
        }
        every { request.headers() } returns requestHeaders
        val callback = pool.submit<ProxyRequestReceivedAction> {
            requestHandler.captured.handleRequestReceived(request)
        }
        val ticket = pending("request")

        val edited = mockk<HttpRequest>(relaxed = true)
        every { edited.httpService() } returns request.httpService()
        every { edited.url() } returns "http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}/test-html"
        every { edited.method() } returns "GET"
        every { edited.headers() } returns requestHeaders
        every { edited.body() } returns body
        every { edited.toByteArray().length() } returns 128
        every { request.withPath("/test-html") } returns edited
        live.allowEdits = true
        assertEquals(1, live.propose(ticket.id, "request", 0, emptyMap(), emptyList(), null, "/test-html"))

        live.dropWithLocalApproval(ticket.id, "request")

        assertSame(requestDropped, callback.get(2, TimeUnit.SECONDS))
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "unattended_local_test" && it.outcome == "auto_approved" &&
                it.detail.contains("/test-html") && it.detail.contains(ticket.id)
        })
    }

    @Test fun `unattended mode rejects an out of policy proposed request path`() = runBlocking {
        val body = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { body.length() } returns 0
        every { body.getBytes() } returns byteArrayOf()
        every { request.body() } returns body
        every { request.toByteArray().length() } returns 128
        every { request.httpService().host() } returns LocalTestTargets.HOST
        every { request.httpService().port() } returns LocalTestTargets.PORT
        every { request.httpService().secure() } returns false
        every { request.url() } returns "http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}/test-cancel"
        every { request.method() } returns "GET"
        every { request.path() } returns "/test-cancel"
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        live.startApprovedSession(60)
        val requestHeaders = listOf(
            "Host" to "127.0.0.1:8000",
            "X-MCP-Test-Run" to identity.testRunId!!,
            "X-MCP-Server-Identity" to identity.serverIdentity!!,
            "X-MCP-Test-ID" to "phase4a-edit-case"
        ).map { (name, value) ->
            mockk<HttpHeader>().also { header ->
                every { header.name() } returns name
                every { header.value() } returns value
            }
        }
        every { request.headers() } returns requestHeaders

        val edited = mockk<HttpRequest>(relaxed = true)
        every { edited.httpService() } returns request.httpService()
        every { edited.url() } returns "http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}/outside"
        every { edited.method() } returns "GET"
        every { edited.headers() } returns requestHeaders
        every { edited.body() } returns body
        every { edited.toByteArray().length() } returns 128
        every { request.withPath("/outside") } returns edited
        live.allowEdits = true

        val callback = pool.submit<ProxyRequestReceivedAction> {
            requestHandler.captured.handleRequestReceived(request)
        }
        val ticket = pending("request")
        assertThrows(IllegalStateException::class.java) {
            live.propose(ticket.id, "request", 0, emptyMap(), emptyList(), null, "/outside")
        }
        assertEquals(0, live.queue.get(ticket.id).revision, "an ineligible unattended edit must not mutate the queue")
        assertTrue(live.queue.get(ticket.id).proposed == null)
        assertFalse(callback.isDone)
        live.disable("TEST_CLEANUP")
        assertSame(requestDropped, callback.get(2, TimeUnit.SECONDS))
    }

    @Test fun `authorized rule transforms and forwards through the installed request callback`() {
        val originalBody = "{\"enabled\":false,\"name\":\"keep\"}".toByteArray()
        val body = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { body.getBytes() } returns originalBody
        every { body.length() } returns originalBody.size
        every { request.body() } returns body
        every { request.toByteArray().length() } returns 160
        every { request.httpService().host() } returns LocalTestTargets.HOST
        every { request.httpService().port() } returns LocalTestTargets.PORT
        every { request.httpService().secure() } returns false
        every { request.url() } returns "http://${LocalTestTargets.HOST}:${LocalTestTargets.PORT}/test-html"
        every { request.method() } returns "POST"
        every { request.path() } returns "/test-html"
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.allowEdits = true
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        val requestHeaders = listOf(
            "Host" to "127.0.0.1:8000",
            "Content-Type" to "application/json",
            "X-MCP-Test-Run" to identity.testRunId!!,
            "X-MCP-Server-Identity" to identity.serverIdentity!!,
            "X-MCP-Test-ID" to "rule-request-1"
        ).map { (name, value) -> mockk<HttpHeader>().also { header -> every { header.name() } returns name; every { header.value() } returns value } }
        every { request.headers() } returns requestHeaders
        val modifiedBody = "{\"enabled\":true,\"name\":\"keep\"}".toByteArray()
        val modifiedBodyView = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { modifiedBodyView.getBytes() } returns modifiedBody
        every { modifiedBodyView.length() } returns modifiedBody.size
        val edited = mockk<HttpRequest>(relaxed = true)
        every { edited.httpService() } returns request.httpService()
        every { edited.url() } returns request.url()
        every { edited.method() } returns request.method()
        every { edited.path() } returns request.path()
        every { edited.headers() } returns requestHeaders
        every { edited.body() } returns modifiedBodyView
        every { edited.toByteArray().length() } returns 170
        val editedLengthHeader = mockk<HttpHeader>().also {
            every { it.name() } returns "Content-Length"
            every { it.value() } returns modifiedBody.size.toString()
        }
        every { edited.headers() } returns (requestHeaders + editedLengthHeader)
        every { edited.withRemovedHeader("Content-Length") } returns edited
        every { edited.withAddedHeader("Content-Length", modifiedBody.size.toString()) } returns edited
        every { request.withBody("{\"enabled\":true,\"name\":\"keep\"}") } returns edited

        val spec = InterceptionRuleSpec(
            name = "Enable JSON flag",
            targetUrl = LocalTestTargets.urls.first(),
            authorizationReference = identity.testRunId!!,
            direction = RuleDirection.REQUEST,
            conditions = RuleMatchConditions(jsonPath = "$.enabled", jsonValueJson = "false"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            action = RuleAction.MODIFY_AND_FORWARD,
            maximumMatches = 5,
            durationSeconds = 60
        )
        val rule = live.createInterceptionRule(spec)
        live.startApprovedSession(60)
        live.enableInterceptionRule(rule.id)
        val callback = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val result = callback.get(2, TimeUnit.SECONDS)
        assertSame(edited, result.request())
        assertTrue(live.queue.list("request").isEmpty())
        val stats = live.ruleEngine.get(rule.id).stats
        assertEquals(1, stats.matchedRequests)
        assertEquals(1, stats.modified)
        assertEquals(1, stats.forwarded)
        assertEquals(0, stats.failed)
        assertTrue(live.ruleEngine.eventHistory(10).any { it.ruleId == rule.id && it.messageId != null && it.approvalMode == "AUTOMATIC" })
    }

    @Test fun `deactivating local authorization pauses rules before a new message can be modified`() {
        every { request.httpService().host() } returns LocalTestTargets.HOST
        every { request.httpService().port() } returns LocalTestTargets.PORT
        every { request.httpService().secure() } returns false
        every { request.url() } returns LocalTestTargets.urls.first()
        every { request.method() } returns "GET"
        every { request.path() } returns "/test-html"
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        val spec = InterceptionRuleSpec(
            name = "Forward eligible request", targetUrl = LocalTestTargets.urls.first(), authorizationReference = identity.testRunId!!,
            direction = RuleDirection.REQUEST, action = RuleAction.FORWARD_UNCHANGED, maximumMatches = 5, durationSeconds = 60
        )
        val rule = live.createInterceptionRule(spec)
        live.startApprovedSession(60)
        live.enableInterceptionRule(rule.id)
        live.deactivateUnattendedLocalTestMode("TEST_AUTHORIZATION_STOP")
        assertEquals(InterceptionRuleState.PAUSED, live.ruleEngine.get(rule.id).state)
        val callback = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val pending = pending("request")
        assertFalse(callback.isDone, "A disabled rule must leave the message in the existing manual queue")
        live.disable("TEST_CLEANUP")
        assertSame(requestDropped, callback.get(2, TimeUnit.SECONDS))
        assertEquals(0, live.ruleEngine.get(rule.id).stats.forwarded)
        assertEquals(0, live.ruleEngine.get(rule.id).stats.modified)
        assertTrue(pending.original.message === request)
    }

    @Test fun `request and associated response rules modify and forward one synthetic post`() {
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.allowEdits = true
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        val caseId = "rule-response-1"
        val modifiedRequest = prepareAuthorizedJsonPost(identity, caseId)
        val requestRule = live.createInterceptionRule(InterceptionRuleSpec(
            name = "Modify associated request", targetUrl = "http://127.0.0.1:8000/test-post",
            authorizationReference = identity.testRunId!!, direction = RuleDirection.REQUEST,
            conditions = RuleMatchConditions(method = "POST", path = "/test-post", contentType = "application/json",
                jsonPath = "$.enabled", jsonValueJson = "false"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            durationSeconds = 60
        ))
        val responseBody = "{\"enabled\":false,\"status\":\"ok\"}".toByteArray()
        val responseHeaders = listOf(
            "Content-Type" to "application/json"
        ).map { (name, value) -> mockk<HttpHeader>().also { header -> every { header.name() } returns name; every { header.value() } returns value } }
        every { response.initiatingRequest() } returns modifiedRequest
        every { response.headers() } returns responseHeaders
        every { response.body().getBytes() } returns responseBody
        every { response.body().length() } returns responseBody.size
        every { response.toByteArray().length() } returns 128
        every { response.statusCode() } returns 200.toShort()
        val changedResponseBody = "{\"enabled\":true,\"status\":\"ok\"}".toByteArray()
        val changedResponseBodyView = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { changedResponseBodyView.getBytes() } returns changedResponseBody
        every { changedResponseBodyView.length() } returns changedResponseBody.size
        val changedResponse = mockk<HttpResponse>(relaxed = true)
        val changedLengthHeader = mockk<HttpHeader>().also {
            every { it.name() } returns "Content-Length"
            every { it.value() } returns changedResponseBody.size.toString()
        }
        every { changedResponse.headers() } returns (responseHeaders + changedLengthHeader)
        every { changedResponse.body() } returns changedResponseBodyView
        every { changedResponse.statusCode() } returns 200.toShort()
        every { changedResponse.toByteArray().length() } returns 130
        every { changedResponse.withRemovedHeader("Content-Length") } returns changedResponse
        every { changedResponse.withAddedHeader("Content-Length", changedResponseBody.size.toString()) } returns changedResponse
        every { response.withBody("{\"enabled\":true,\"status\":\"ok\"}") } returns changedResponse
        val responseRule = live.createInterceptionRule(InterceptionRuleSpec(
            name = "Modify associated JSON response", targetUrl = "http://127.0.0.1:8000/test-post",
            authorizationReference = identity.testRunId!!, direction = RuleDirection.RESPONSE,
            conditions = RuleMatchConditions(method = "POST", path = "/test-post", responseStatus = 200,
                contentType = "application/json", jsonPath = "$.enabled", jsonValueJson = "false"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            durationSeconds = 60
        ))

        live.startApprovedSession(60)
        live.enableInterceptionRule(requestRule.id)
        live.enableInterceptionRule(responseRule.id)
        val releasedRequest = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }.get(2, TimeUnit.SECONDS)
        assertSame(modifiedRequest, releasedRequest.request())
        assertTrue(String(modifiedRequest.body().getBytes()).contains("\"enabled\":true"))
        val releasedResponse = pool.submit<ProxyResponseReceivedAction> { responseHandler.captured.handleResponseReceived(response) }.get(2, TimeUnit.SECONDS)
        assertSame(changedResponse, releasedResponse.response())
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(live.queue.list("response").isEmpty())
        assertEquals(1, live.ruleEngine.get(responseRule.id).stats.matchedResponses)
        assertEquals(1, live.ruleEngine.get(responseRule.id).stats.modified)
        assertEquals(1, live.ruleEngine.get(responseRule.id).stats.forwarded)
        assertEquals(1, live.ruleEngine.get(requestRule.id).stats.matchedRequests)
        assertEquals(1, live.ruleEngine.get(requestRule.id).stats.modified)
        assertEquals(1, live.ruleEngine.get(requestRule.id).stats.forwarded)
    }

    @Test fun `modified request with disabled response rule is explicitly left waiting for approval`() {
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        live.disable("TEST_SETUP")
        live.allowEdits = true
        live.activateUnattendedLocalTestMode(60)
        val identity = live.unattendedSnapshot()
        val caseId = "rule-response-disabled-1"
        val modifiedRequest = prepareAuthorizedJsonPost(identity, caseId)
        val requestRule = live.createInterceptionRule(InterceptionRuleSpec(
            name = "Modify request while response rule is disabled", targetUrl = "http://127.0.0.1:8000/test-post",
            authorizationReference = identity.testRunId!!, direction = RuleDirection.REQUEST,
            conditions = RuleMatchConditions(method = "POST", path = "/test-post", contentType = "application/json",
                jsonPath = "$.enabled", jsonValueJson = "false"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            durationSeconds = 60
        ))
        val responseRule = live.createInterceptionRule(InterceptionRuleSpec(
            name = "Disabled response rule regression", targetUrl = "http://127.0.0.1:8000/test-post",
            authorizationReference = identity.testRunId!!, direction = RuleDirection.RESPONSE,
            conditions = RuleMatchConditions(method = "POST", path = "/test-post", responseStatus = 200,
                contentType = "application/json", jsonPath = "$.enabled", jsonValueJson = "false"),
            transformations = listOf(RuleTransformation(RuleTransformType.SET_JSON_FIELD, path = "$.enabled", valueJson = "true")),
            durationSeconds = 60
        ))
        val responseBody = "{\"enabled\":false,\"status\":\"ok\"}".toByteArray()
        val responseHeaders = listOf("Content-Type" to "application/json").map { (name, value) ->
            mockk<HttpHeader>().also { header -> every { header.name() } returns name; every { header.value() } returns value }
        }
        every { response.initiatingRequest() } returns modifiedRequest
        every { response.headers() } returns responseHeaders
        every { response.body().getBytes() } returns responseBody
        every { response.body().length() } returns responseBody.size
        every { response.statusCode() } returns 200.toShort()
        every { response.toByteArray().length() } returns 128

        live.startApprovedSession(60)
        live.enableInterceptionRule(requestRule.id)
        val releasedRequest = pool.submit<ProxyRequestReceivedAction> {
            requestHandler.captured.handleRequestReceived(request)
        }.get(2, TimeUnit.SECONDS)
        assertSame(modifiedRequest, releasedRequest.request())
        assertEquals(1, live.ruleEngine.get(requestRule.id).stats.modified)

        val clientResponse = pool.submit<ProxyResponseReceivedAction> {
            responseHandler.captured.handleResponseReceived(response)
        }
        val pendingResponse = pending("response")
        assertFalse(clientResponse.isDone)
        assertEquals(responseRule.id, live.ruleEngine.get(responseRule.id).id)
        assertEquals(InterceptionRuleState.DISABLED, live.ruleEngine.get(responseRule.id).state)
        assertEquals(0, live.ruleEngine.get(responseRule.id).stats.matchedResponses)
        assertEquals(0, live.ruleEngine.get(responseRule.id).stats.modified)
        assertTrue(pendingResponse.original.message === response)
        assertEquals(1, live.health().pendingResponses)

        live.disable("TEST_CLEANUP")
        assertSame(responseDropped, clientResponse.get(2, TimeUnit.SECONDS))
        assertEquals(0, live.health().pendingResponses)
    }

    @Test fun `disclosure request returns immediately and keeps the same ID until local approval`() = runBlocking {
        mockkObject(Dialogs)
        val promptShown = CompletableDeferred<Unit>()
        val allowDisclosure = CompletableDeferred<Int>()
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } coAnswers {
            promptShown.complete(Unit)
            allowDisclosure.await()
        }
        try {
            val callback = pool.submit<ProxyRequestReceivedAction> {
                requestHandler.captured.handleRequestReceived(request)
            }
            val ticket = pending("request")
            assertEquals("PENDING", live.requestDisclosure(ticket.id, "request", 0))
            withTimeout(2_000) { promptShown.await() }

            val visible = live.queue.get(ticket.id)
            assertEquals(ticket.id, visible.id)
            assertEquals("PENDING", visible.disclosureStatus)
            assertTrue(visible.disclosedRevision == null)
            assertFalse(callback.isDone)
            assertThrows(IllegalStateException::class.java) { live.queue.forward(ticket.id, 0) }

            assertEquals("PENDING", live.requestDisclosure(ticket.id, "request", 0))
            coVerify(exactly = 1) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
            allowDisclosure.complete(0)
            withTimeout(2_000) {
                while (live.queue.get(ticket.id).disclosureStatus != "APPROVED") delay(10)
            }
            val approvedDisclosure = live.queue.get(ticket.id)
            assertEquals(ticket.id, approvedDisclosure.id)
            assertEquals(0, approvedDisclosure.disclosedRevision)
            assertTrue(approvedDisclosure.approvedRevision == null)
            assertFalse(callback.isDone)
        } finally {
            allowDisclosure.complete(1)
            unmockkObject(Dialogs)
        }
    }

    @Test fun `configured per-message timeout persists and stays bounded`() {
        live.setTimeout(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS)
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, live.timeoutSeconds)
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, config.interceptionTimeoutSeconds)
        assertThrows(IllegalArgumentException::class.java) { live.setTimeout(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS + 1) }
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, live.timeoutSeconds)
    }

    @Test fun `session lifetime is capped and expiry drops pending traffic`() {
        assertThrows(IllegalArgumentException::class.java) {
            live.startApprovedSession(LiveInterception.MAX_SESSION_LIFETIME_SECONDS + 1)
        }
        val result = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        pending("request")
        live.heartbeatTick(System.nanoTime() + TimeUnit.SECONDS.toNanos(61))
        assertFalse(live.enabled)
        assertEquals("SESSION_EXPIRED", live.health().sessionEndReason)
        assertSame(requestDropped, result.get(2, TimeUnit.SECONDS))
    }

    @Test fun `explicit disable stops heartbeat and drops held traffic`() {
        val result = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        pending("request")
        live.disable()
        assertSame(requestDropped, result.get(2, TimeUnit.SECONDS))
        val health = live.health()
        assertFalse(health.enabled)
        assertEquals("STOPPED", health.heartbeatHealth)
        assertEquals("DISABLED", health.sessionEndReason)
        assertTrue(health.lastHeartbeatAtEpochMillis == null)
        live.heartbeatTick(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))
        assertTrue(live.health().lastHeartbeatAtEpochMillis == null)
    }

    @Test fun `off scope requests are never held`() {
        net.portswigger.mcp.security.ActivityLog.clear()
        every { api.scope().isInScope(any()) } returns false
        assertSame(request,requestHandler.captured.handleRequestReceived(request).request())
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "skipped" && it.detail.contains("outside Burp scope")
        })
    }

    @Test fun `eligible GET messages on the UI thread and oversized messages are dropped with diagnostics`() {
        net.portswigger.mcp.security.ActivityLog.clear()
        var uiAction: ProxyRequestReceivedAction? = null
        javax.swing.SwingUtilities.invokeAndWait {
            uiAction = requestHandler.captured.handleRequestReceived(request)
        }
        assertSame(requestDropped, uiAction)
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "dropped" && it.detail.contains("UI thread")
        })

        every { request.toByteArray().length() } returns net.portswigger.mcp.security.SafeContent.MAX_REQUEST_BYTES + 1
        val oversized = requestHandler.captured.handleRequestReceived(request)
        assertSame(requestDropped, oversized)
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "dropped" && it.detail.contains("interception limit")
        })
    }
    @Test fun `disabling authentication prevents disclosure and cancels held traffic`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val ticket=pending("request");config.requireBearerToken=false
        assertThrows(IllegalStateException::class.java) { live.snapshot(ticket.id,"request") }
        assertFalse(live.enabled);assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
    }
    @Test fun `emergency cancellation dismisses a pending human approval without forwarding`() = runBlocking {
        mockkObject(Dialogs)
        val entered=CompletableDeferred<Unit>()
        coEvery { Dialogs.requestOption(any(),any(),any(),any(),any(),any()) } coAnswers { entered.complete(Unit);awaitCancellation() }
        try {
            val callback=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
            val ticket=pending("request")
            val review=async { live.requestApproval(ticket.id,"request",0) }
            withTimeout(2000) { entered.await() }
            live.cancel()
            val reviewFailure = withTimeout(2000) { runCatching { review.await() }.exceptionOrNull() }
            assertTrue(reviewFailure is CancellationException)
            assertSame(requestDropped,callback.get(2,TimeUnit.SECONDS))
        } finally { unmockkObject(Dialogs) }
    }

    @Test fun `target preparation uses human approval exact allowlist and emergency revocation`() = runBlocking<Unit> {
        live.disable("PREPARE_TARGET")
        val url = "http://localhost:8000/lab"
        mockkObject(Dialogs)
        try {
            coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 1
            assertThrows(IllegalStateException::class.java) { runBlocking { live.requestTargetRuleAuthorization(listOf(url), 30) } }
            assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
            coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
            val grant = live.requestTargetRuleAuthorization(listOf(url), 30)
            val spec = InterceptionRuleSpec("Prepared local lab", url, grant.id, RuleDirection.REQUEST, action = RuleAction.FORWARD_UNCHANGED)
            val rule = live.createInterceptionRule(spec)
            assertEquals(InterceptionRuleState.DISABLED, rule.state)
            assertFalse(live.enabled)
            assertThrows(IllegalStateException::class.java) { live.enableInterceptionRule(rule.id) }
            live.emergencyStopUnattendedLocalTestMode()
            assertTrue(live.targetRuleAuthorizationStatus().isEmpty())
            assertEquals(InterceptionRuleState.EMERGENCY_STOPPED, live.ruleEngine.get(rule.id).state)
            assertTrue(live.ruleEngine.status().emergencyStopped)
            assertThrows(IllegalArgumentException::class.java) { live.createInterceptionRule(spec) }
            coVerify(exactly = 2) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
        } finally { unmockkObject(Dialogs) }
    }

    @Test fun `target preparation refuses wildcard allowlist missing scope and read only before approval`() = runBlocking<Unit> {
        live.disable("PREPARE_TARGET")
        val url = "https://fixture.example:443/lab"
        config.autoApproveTargets = "*.example"
        assertThrows(IllegalStateException::class.java) { runBlocking { live.requestTargetRuleAuthorization(listOf(url), 30) } }
        config.autoApproveTargets = "fixture.example:443"
        every { api.scope().isInScope(url) } returns false
        assertThrows(IllegalStateException::class.java) { runBlocking { live.requestTargetRuleAuthorization(listOf(url), 30) } }
        every { api.scope().isInScope(url) } returns true
        config.readOnlyMode = true
        assertThrows(IllegalStateException::class.java) { runBlocking { live.requestTargetRuleAuthorization(listOf(url), 30) } }
    }
}
