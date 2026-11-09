package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.ktor.client.HttpClient
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonArray
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.intercept.LiveInterception
import net.portswigger.mcp.intercept.LocalTestManagementOperation
import net.portswigger.mcp.intercept.LocalTestPolicyDecision
import net.portswigger.mcp.security.ActivityLog
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import java.net.ServerSocket

@Tag("loopback")
class McpServerIntegrationTest {
    private val client = TestStreamableHttpMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val live by lazy { LiveInterception(api, config) }
    private val serverManager by lazy { KtorServerManager(api, live) }
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    @Volatile private var serverStarted = false
    @Volatile private var serverFailure: Throwable? = null

    private fun assertReportedBuildIdentity(result: CallToolResult?, toolName: String) {
        assertNotNull(result, "$toolName should return a result")
        val text = (result!!.content.singleOrNull() as? TextContent)?.text
        assertNotNull(text, "$toolName should return one JSON text content item")
        val identity = Json.parseToJsonElement(text!!).jsonObject
        assertEquals(BuildInfo.version, identity["extensionVersion"]?.jsonPrimitive?.content)
        assertEquals(BuildInfo.buildId, identity["buildId"]?.jsonPrimitive?.content)
    }

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getInteger(any()) } returns null
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    @BeforeEach
    fun setup() {
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.PROFESSIONAL
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
            if (state is ServerState.Failed) serverFailure = state.exception
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && serverFailure == null && attempts < 100) {
                delay(100)
                attempts++
            }
            
            if (!serverStarted) {
                throw IllegalStateException("Server failed to start after timeout", serverFailure)
            }
            client.connectToServer("http://127.0.0.1:${testPort}/mcp", config.bearerToken)
        }
    }

    @Test fun `send and repeater adapters honor denial and preserve exact request options`() = runBlocking {
        val request = syntheticHeldRequest()
        val repeater = api.repeater()
        val options = mockk<burp.api.montoya.http.RequestOptions>(relaxed = true)
        val http2Options = mockk<burp.api.montoya.http.RequestOptions>()
        every { options.withHttpMode(burp.api.montoya.http.HttpMode.HTTP_2) } returns http2Options
        val response = mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true)
        every { response.statusCode() } returns 200.toShort()
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.reasonPhrase() } returns "OK"
        every { response.headers() } returns fixtureHeaders(listOf("Content-Type" to "text/plain"))
        every { response.headerValue("Content-Type") } returns "text/plain"
        every { response.body() } returns fixtureBytes("synthetic-reply")
        val pair = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
        every { pair.response() } returns response
        val args = mapOf("host" to "127.0.0.1", "port" to 8000, "https" to false,
            "rawRequest" to "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
        io.mockk.mockkStatic(burp.api.montoya.http.HttpService::class, burp.api.montoya.http.message.requests.HttpRequest::class,
            burp.api.montoya.http.RequestOptions::class)
        mockkObject(net.portswigger.mcp.security.HttpRequestSecurity, net.portswigger.mcp.tools.BurpHttpRequestExecutor)
        try {
            every { burp.api.montoya.http.HttpService.httpService(any<String>(), any<Int>(), any<Boolean>()) } returns request.httpService()
            every { burp.api.montoya.http.message.requests.HttpRequest.httpRequest(any<burp.api.montoya.http.HttpService>(), any<String>()) } returns request
            every { burp.api.montoya.http.RequestOptions.requestOptions() } returns options
            coEvery { net.portswigger.mcp.security.HttpRequestSecurity.checkAuthorizedRequest(any(), any(), any(), any()) } returns false
            assertTrue(client.callTool("burp_send_http_request", args)!!.isError == true)
            assertTrue(client.callTool("burp_send_to_repeater", args)!!.isError == true)
            val legacyArgs = mapOf("content" to args.getValue("rawRequest"), "targetHostname" to "127.0.0.1", "targetPort" to 8000, "usesHttps" to false, "tabName" to "synthetic-legacy")
            assertTrue(client.callTool("create_repeater_tab", legacyArgs)!!.content.toString().contains("denied"))
            io.mockk.verify(exactly = 0) { repeater.sendToRepeater(any(), any<String>()) }
            coEvery { net.portswigger.mcp.security.HttpRequestSecurity.checkAuthorizedRequest(any(), any(), any(), any()) } returns true
            coEvery { net.portswigger.mcp.tools.BurpHttpRequestExecutor.send(api, request, http2Options, 10_000L) } returns pair
            val sent = client.callTool("burp_send_http_request", args + ("http2" to true))!!
            assertFalse(sent.isError == true, sent.content.toString())
            assertTrue(sent.content.toString().contains("synthetic-reply"))
            io.mockk.coVerify(exactly = 1) { net.portswigger.mcp.tools.BurpHttpRequestExecutor.send(api, request, http2Options, 10_000L) }
            assertFalse(client.callTool("burp_send_to_repeater", args + ("tabName" to "synthetic-current"))!!.isError == true)
            assertFalse(client.callTool("create_repeater_tab", legacyArgs + ("tabName" to "synthetic-legacy"))!!.isError == true)
            io.mockk.verify(exactly = 1) { repeater.sendToRepeater(request, "synthetic-current"); repeater.sendToRepeater(request, "synthetic-legacy") }
            coEvery { net.portswigger.mcp.tools.BurpHttpRequestExecutor.send(any(), any(), any(), any()) } throws IllegalStateException("password=synthetic-send-canary")
            val failed = client.callTool("burp_send_http_request", args)!!
            assertTrue(failed.isError == true)
            assertFalse(failed.content.toString().contains("synthetic-send-canary"))
            assertTrue(client.callTool("burp_send_http_request", args + ("rawRequestBase64" to "AA=="))!!.isError == true)
            assertTrue(client.callTool("burp_send_to_repeater", args + ("port" to 0))!!.isError == true)
        } finally {
            unmockkObject(net.portswigger.mcp.security.HttpRequestSecurity, net.portswigger.mcp.tools.BurpHttpRequestExecutor)
            io.mockk.unmockkStatic(burp.api.montoya.http.HttpService::class, burp.api.montoya.http.message.requests.HttpRequest::class,
                burp.api.montoya.http.RequestOptions::class)
        }
    }

    @Test fun `native proxy toggle adapter enforces approval and reports API failure`() = runBlocking {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        val proxy = api.proxy()
        mockkObject(net.portswigger.mcp.config.Dialogs)
        try {
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 1
            assertTrue(client.callTool("burp_set_proxy_intercept_state", mapOf("enabled" to true))!!.isError == true)
            io.mockk.verify(exactly = 0) { proxy.enableIntercept(); proxy.disableIntercept() }
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
            assertFalse(client.callTool("burp_set_proxy_intercept_state", mapOf("enabled" to true))!!.isError == true)
            assertFalse(client.callTool("burp_set_proxy_intercept_state", mapOf("enabled" to false))!!.isError == true)
            io.mockk.verify(exactly = 1) { proxy.enableIntercept(); proxy.disableIntercept() }
            every { api.proxy().enableIntercept() } throws IllegalStateException("password=synthetic-toggle-canary")
            val failed = client.callTool("burp_set_proxy_intercept_state", mapOf("enabled" to true))!!
            assertTrue(failed.isError == true)
            assertFalse(failed.content.toString().contains("synthetic-toggle-canary"))
        } finally { unmockkObject(net.portswigger.mcp.config.Dialogs) }
    }

    @Test fun `organizer adapters gate access filter scope and report unavailable runtime`() = runBlocking {
        val request = syntheticHeldRequest()
        val item = Any()
        mockkObject(net.portswigger.mcp.compat.MontoyaRuntimeCompat, net.portswigger.mcp.security.DataAccessSecurity)
        try {
            coEvery { net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(any(), any()) } returns false
            assertTrue(client.callTool("get_organizer_items", mapOf("count" to 1, "offset" to 0))!!.content.toString().contains("denied"))
            assertTrue(client.callTool("get_organizer_items_regex", mapOf("regex" to "synthetic", "count" to 1, "offset" to 0))!!.content.toString().contains("denied"))
            io.mockk.verify(exactly = 0) { net.portswigger.mcp.compat.MontoyaRuntimeCompat.organizerItems(any()) }
            coEvery { net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(any(), any()) } returns true
            every { net.portswigger.mcp.compat.MontoyaRuntimeCompat.organizerItems(api) } returns listOf(item)
            every { net.portswigger.mcp.compat.MontoyaRuntimeCompat.readNoArg(item, any()) } answers {
                when (secondArg<String>()) { "request" -> request; "id" -> 7; else -> null }
            }
            every { net.portswigger.mcp.compat.MontoyaRuntimeCompat.organizerItemMatches(item, any()) } returns true
            val allowed = client.callTool("get_organizer_items", mapOf("count" to 1, "offset" to 0))!!
            assertFalse(allowed.isError == true)
            assertEquals("7", Json.parseToJsonElement((allowed.content.single() as TextContent).text).jsonObject["id"]!!.jsonPrimitive.content)
            val matched = client.callTool("get_organizer_items_regex", mapOf("regex" to "synthetic", "count" to 1, "offset" to 0))!!
            assertFalse(matched.isError == true)
            assertTrue(matched.content.toString().contains("synthetic"))
            every { api.scope().isInScope(any()) } returns false
            assertTrue(client.callTool("get_organizer_items", mapOf("count" to 1, "offset" to 0))!!.content.toString().contains("Reached end"))
            assertTrue(client.callTool("get_organizer_items_regex", mapOf("regex" to "synthetic", "count" to 1, "offset" to 0))!!.content.toString().contains("Reached end"))
            assertTrue(client.callTool("get_organizer_items_regex", mapOf("regex" to "[", "count" to 1, "offset" to 0))!!.isError == true)
            every { net.portswigger.mcp.compat.MontoyaRuntimeCompat.organizerItems(api) } returns null
            assertTrue(client.callTool("get_organizer_items", mapOf("count" to 1, "offset" to 0))!!.isError == true)
            assertTrue(client.callTool("get_organizer_items_regex", mapOf("regex" to "synthetic", "count" to 1, "offset" to 0))!!.isError == true)
        } finally { unmockkObject(net.portswigger.mcp.compat.MontoyaRuntimeCompat, net.portswigger.mcp.security.DataAccessSecurity) }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    private fun syntheticHeldRequest(): burp.api.montoya.http.message.requests.HttpRequest {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        every { persistedObject.getString("_autoApproveTargets") } returns "127.0.0.1:8000"
        every { api.scope().isInScope(any()) } returns true
        live.allowEdits = true
        live.startApprovedSession(60)
        return mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed = true).also { request ->
            every { request.httpService().host() } returns "127.0.0.1"
            every { request.httpService().port() } returns 8000
            every { request.httpService().secure() } returns false
            every { request.url() } returns "http://127.0.0.1:8000/test-post"
            every { request.path() } returns "/test-post"
            every { request.method() } returns "POST"
            every { request.headers() } returns fixtureHeaders(listOf("Host" to "127.0.0.1:8000"))
            every { request.headerValue(any()) } returns null
            every { request.body() } returns fixtureBytes("synthetic-body")
            every { request.toByteArray() } returns fixtureBytes("synthetic-request")
            every { request.toString() } returns "SYNTHETIC_PRIVATE_REQUEST"
        }
    }

    @Test fun `scanner definition identifier cannot bypass metadata redaction`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        every { persistedObject.getString("_autoApproveTargets") } returns "127.0.0.1:8000"
        every { api.scope().isInScope(any()) } returns true
        val issue = syntheticIssue("http://127.0.0.1:8000/test-post")
        every { issue.definition().name() } returns "password=synthetic-definition-canary"
        every { api.siteMap().issues() } returns listOf(issue)
        val current = client.callTool("burp_get_scanner_issues", emptyMap())!!
        val legacy = client.callTool("get_scanner_issues", mapOf("count" to 1, "offset" to 0))!!
        for (result in listOf(current, legacy)) {
            assertFalse(result.isError == true)
            assertFalse(result.content.toString().contains("synthetic-definition-canary"))
        }
    }

    @Test fun `request proposal refuses ambiguous charset and compressed replacement`() = runBlocking {
        for (header in listOf("Content-Type: text/plain; charset=iso-8859-1", "Content-Type: text/plain; charset=bogus",
            "Content-Type: text/plain; charset=utf-8; charset=utf-8", "Content-Encoding: gzip")) {
            val result = client.callTool("burp_modify_request", mapOf("rawRequest" to
                "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n$header\r\nContent-Length: 3\r\n\r\nold",
                "replacementBody" to "\u96ea"))!!
            assertTrue(result.isError == true, header)
        }
    }

    @Test fun `request proposal refuses malformed Unicode without replacement bytes`() = runBlocking {
        // Literal JSON escape bypasses the test client's own strict UTF-8 encoder.
        val (_, text) = protocolPost(body = """{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"burp_modify_request","arguments":{"rawRequest":"POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\nold","replacementBody":"\ud800"}}}""")
        val result = Json.parseToJsonElement(text).jsonObject
        assertTrue(result.containsKey("error") || result["result"]?.jsonObject?.get("isError")?.jsonPrimitive?.content == "true")
    }

    @Test fun `request proposal validates final UTF8 framing and output byte limit`() = runBlocking {
        val raw = "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nX-Keep: unchanged\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\nContent-Length: 3\r\n\r\nold"
        for (body in listOf("", "\u96ea\r\nnext")) {
            val result = client.callTool("burp_modify_request", mapOf("rawRequest" to raw, "replacementBody" to body))!!
            assertFalse(result.isError == true)
            val text = (result.content.single() as TextContent).text
            assertTrue(text.contains("X-Keep: unchanged\r\n"))
            assertTrue(text.contains("Content-Length: ${body.toByteArray(Charsets.UTF_8).size}\r\n"))
            assertEquals(body, text.substringAfter("\r\n\r\n"))
        }
        assertTrue(client.callTool("burp_modify_request", mapOf("rawRequest" to raw, "replacementBody" to "\u96ea".repeat(350_000)))!!.isError == true)
        assertTrue(client.callTool("burp_modify_request", mapOf("rawRequest" to raw.replace("Content-Length: 3", "Content-Length: 3\r\nContent-Length: 3"), "replacementBody" to "new"))!!.isError == true)
    }

    @Test fun `held response metadata stays private and proposal revisions invalidate approval`() = runBlocking {
        val request = syntheticHeldRequest()
        val response = mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true)
        every { response.toString() } returns "SYNTHETIC_PRIVATE_RESPONSE"
        every { response.headerValue(any()) } returns null
        every { response.toByteArray() } returns fixtureBytes("synthetic-response")
        every { response.withAddedHeader("X-Test", "yes") } returns response
        val ticket = live.queue.offer("response", net.portswigger.mcp.intercept.HeldMessage(response, request), 30_000)!!
        val hidden = client.callTool("burp_get_intercepted_response", mapOf("id" to ticket.id))!!
        assertFalse(hidden.isError == true)
        assertFalse(hidden.content.toString().contains("SYNTHETIC_PRIVATE_RESPONSE"))
        live.approveLocally(ticket.id, "response", 0)
        val proposed = client.callTool("burp_propose_intercepted_response_edit", mapOf("id" to ticket.id,
            "revision" to 0, "headers" to mapOf("X-Test" to "yes")))!!
        assertFalse(proposed.isError == true, proposed.content.toString())
        assertEquals(1, ticket.revision)
        assertNull(ticket.approvedRevision)
        assertFalse(proposed.content.toString().contains("SYNTHETIC_PRIVATE_RESPONSE"))
        val stale = client.callTool("burp_propose_intercepted_response_edit", mapOf("id" to ticket.id,
            "revision" to 0, "headers" to mapOf("X-Test" to "yes")))!!
        assertTrue(stale.isError == true)
        assertEquals(1, ticket.revision)
        val wrongDirection = client.callTool("burp_get_intercepted_response", mapOf("id" to
            live.queue.offer("request", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!.id))!!
        assertTrue(wrongDirection.isError == true)
    }

    @Test fun `held request proposal rejects protected headers and preserves state on API failure`() = runBlocking {
        val request = syntheticHeldRequest()
        every { request.withHeader("X-Test", "yes") } returns request
        val ticket = live.queue.offer("request", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!
        val proposed = client.callTool("burp_propose_intercepted_request_edit", mapOf("id" to ticket.id,
            "revision" to 0, "headers" to mapOf("X-Test" to "yes")))!!
        assertFalse(proposed.isError == true)
        assertEquals(1, ticket.revision)
        val protected = client.callTool("burp_propose_intercepted_request_edit", mapOf("id" to ticket.id,
            "revision" to 1, "headers" to mapOf("Host" to "outside.invalid")))!!
        assertTrue(protected.isError == true)
        every { request.withHeader("X-Test", "yes") } throws IllegalStateException("password=synthetic-api-canary")
        val failed = client.callTool("burp_propose_intercepted_request_edit", mapOf("id" to ticket.id,
            "revision" to 1, "headers" to mapOf("X-Test" to "yes")))!!
        assertTrue(failed.isError == true)
        assertFalse(failed.content.toString().contains("synthetic-api-canary"))
        assertEquals(1, ticket.revision)
        assertFalse(ticket.result.isDone)
    }

    @Test fun `forward tools honor exact revisions and release only the approved queue item`() = runBlocking {
        val request = syntheticHeldRequest()
        val a = live.queue.offer("request", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!
        val b = live.queue.offer("response", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!
        live.approveLocally(a.id, "request", 0)
        live.approveLocally(b.id, "response", 0)
        assertTrue(client.callTool("burp_forward_intercepted_request", mapOf("id" to a.id, "revision" to 1))!!.isError == true)
        assertFalse(a.result.isDone)
        val first = client.callTool("burp_forward_intercepted_request", mapOf("id" to a.id, "revision" to 0))!!
        assertFalse(first.isError == true, first.content.toString())
        assertSame(request, a.result.get()!!.request)
        assertFalse(b.result.isDone)
        val second = client.callTool("burp_forward_intercepted_response", mapOf("id" to b.id, "revision" to 0))!!
        assertFalse(second.isError == true, second.content.toString())
        assertSame(request, b.result.get()!!.request)
        assertTrue(client.callTool("burp_forward_intercepted_response", mapOf("id" to b.id, "revision" to 0))!!.isError == true)
    }

    @Test fun `drop tools require local decision and read only rejection leaves tickets pending`() = runBlocking {
        val request = syntheticHeldRequest()
        val a = live.queue.offer("request", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!
        val b = live.queue.offer("response", net.portswigger.mcp.intercept.HeldMessage(request, request), 30_000)!!
        every { persistedObject.getBoolean("readOnlyMode") } returns true
        assertTrue(client.callTool("burp_drop_intercepted_request", mapOf("id" to a.id))!!.isError == true)
        assertTrue(client.callTool("burp_drop_intercepted_response", mapOf("id" to b.id))!!.isError == true)
        assertFalse(a.result.isDone || b.result.isDone)
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        mockkObject(net.portswigger.mcp.config.Dialogs)
        try {
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 1
            assertTrue(client.callTool("burp_drop_intercepted_request", mapOf("id" to a.id))!!.isError == true)
            assertFalse(a.result.isDone)
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
            assertFalse(client.callTool("burp_drop_intercepted_request", mapOf("id" to a.id))!!.isError == true)
            assertNull(a.result.get())
            assertFalse(b.result.isDone)
            assertFalse(client.callTool("burp_drop_intercepted_response", mapOf("id" to b.id))!!.isError == true)
            assertNull(b.result.get())
        } finally { unmockkObject(net.portswigger.mcp.config.Dialogs) }
    }

    @Test fun `passive scan lifecycle uses owned IDs and explicit approvals`() = runBlocking {
        val request = syntheticHeldRequest()
        val audit = mockk<burp.api.montoya.scanner.audit.Audit>(relaxed = true)
        every { audit.statusMessage() } returns "password=synthetic-scan-canary"
        every { audit.requestCount() } returns 1
        every { audit.errorCount() } returns 0
        every { audit.issues() } returns emptyList()
        every { api.scanner().startAudit(any()) } returns audit
        val args = mapOf("host" to "127.0.0.1", "port" to 8000, "https" to false,
            "rawRequest" to "GET /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
        io.mockk.mockkStatic(burp.api.montoya.http.HttpService::class, burp.api.montoya.http.message.requests.HttpRequest::class,
            burp.api.montoya.scanner.AuditConfiguration::class)
        mockkObject(net.portswigger.mcp.security.HttpRequestSecurity, net.portswigger.mcp.security.StateChangeSecurity)
        try {
            every { burp.api.montoya.http.HttpService.httpService(any<String>(), any<Int>(), any<Boolean>()) } returns request.httpService()
            every { burp.api.montoya.http.message.requests.HttpRequest.httpRequest(any<burp.api.montoya.http.HttpService>(), any<String>()) } returns request
            every { burp.api.montoya.scanner.AuditConfiguration.auditConfiguration(burp.api.montoya.scanner.BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS) } returns mockk(relaxed = true)
            coEvery { net.portswigger.mcp.security.HttpRequestSecurity.checkAuthorizedRequest(any(), any(), any(), any()) } returns false
            assertTrue(client.callTool("burp_start_scan", args)!!.isError == true)
            io.mockk.verify(exactly = 0) { api.scanner().startAudit(any()) }
            coEvery { net.portswigger.mcp.security.HttpRequestSecurity.checkAuthorizedRequest(any(), any(), any(), any()) } returns true
            val started = client.callTool("burp_start_scan", args)!!
            assertFalse(started.isError == true, started.content.toString())
            val scanId = Json.parseToJsonElement((started.content.single() as TextContent).text).jsonObject["scanId"]!!.jsonPrimitive.content
            val status = client.callTool("burp_get_scan_status", mapOf("scanId" to scanId))!!
            assertFalse(status.isError == true)
            // Scan status is untrusted metadata, including the initial start result.
            assertFalse(started.content.toString().contains("synthetic-scan-canary"))
            assertFalse(status.content.toString().contains("synthetic-scan-canary"))
            coEvery { net.portswigger.mcp.security.StateChangeSecurity.confirm(any(), any(), any(), any()) } returns false
            assertTrue(client.callTool("burp_stop_scan", mapOf("scanId" to scanId))!!.isError == true)
            io.mockk.verify(exactly = 0) { audit.delete() }
            coEvery { net.portswigger.mcp.security.StateChangeSecurity.confirm(any(), any(), any(), any()) } returns true
            assertFalse(client.callTool("burp_stop_scan", mapOf("scanId" to scanId))!!.isError == true)
            io.mockk.verify(exactly = 1) { audit.addRequest(request); audit.delete() }
            assertTrue(client.callTool("burp_get_scan_status", mapOf("scanId" to scanId))!!.isError == true)
            assertTrue(client.callTool("burp_stop_scan", mapOf("scanId" to scanId))!!.isError == true)
        } finally {
            unmockkObject(net.portswigger.mcp.security.HttpRequestSecurity, net.portswigger.mcp.security.StateChangeSecurity)
            io.mockk.unmockkStatic(burp.api.montoya.http.HttpService::class, burp.api.montoya.http.message.requests.HttpRequest::class,
                burp.api.montoya.scanner.AuditConfiguration::class)
        }
    }

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.shutdown()
        live.close()
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            println("CATALOG_JSON: ${Json.encodeToString(tools)}")
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            assertEquals(89, tools.size, "The Professional MCP catalog must retain the existing tools and expose the bounded interception-rule API")
            assertEquals(tools.size, tools.map { it.name }.toSet().size, "MCP tool names must be unique")
            val expectedToolNames = setOf(
                "base64_decode", "base64_encode",
                "burp_analyze_authentication", "burp_analyze_cookies", "burp_analyze_cors",
                "burp_analyze_request", "burp_analyze_response", "burp_analyze_security_headers",
                "burp_approve_intercepted_request_edit", "burp_approve_intercepted_response_edit",
                "burp_cancel_interceptions", "burp_check_connection", "burp_compare_responses",
                "burp_configure_local_test_scope", "burp_drop_intercepted_request", "burp_drop_intercepted_response",
                "burp_find_sensitive_data", "burp_forward_intercepted_request", "burp_forward_intercepted_response",
                "burp_generate_security_report", "burp_get_capabilities", "burp_get_intercept_diagnostics",
                "burp_get_intercept_status", "burp_get_intercepted_request", "burp_get_intercepted_response",
                "burp_get_project_info", "burp_get_proxy_history", "burp_get_repeater_tabs", "burp_get_request",
                "burp_get_response", "burp_get_response_headers", "burp_get_scan_status", "burp_get_scanner_issues",
                "burp_get_scope", "burp_get_site_map", "burp_get_status", "burp_list_pending_requests",
                "burp_create_interception_rule", "burp_list_interception_rules", "burp_get_interception_rule",
                "burp_update_interception_rule", "burp_enable_interception_rule", "burp_disable_interception_rule",
                "burp_delete_interception_rule", "burp_clear_interception_rules", "burp_preview_interception_rule",
                "burp_get_interception_rule_stats", "burp_get_interception_rule_events", "burp_request_target_rule_authorization", "burp_list_target_rule_authorizations", "burp_start_target_rule_session",
                "burp_get_rule_engine_status",
                "burp_clear_interception_rule_stats", "burp_pause_all_interception_rules", "burp_emergency_stop_rules",
                "burp_list_pending_responses", "burp_modify_request", "burp_propose_intercepted_request_edit",
                "burp_propose_intercepted_response_edit", "burp_request_intercept_disclosure",
                "burp_search_http_history", "burp_send_http_request", "burp_send_to_repeater",
                "burp_set_live_interception_state", "burp_set_proxy_intercept_state", "burp_start_scan",
                "burp_stop_scan", "create_repeater_tab", "create_repeater_tab_http2",
                "generate_collaborator_payload", "generate_random_string", "get_active_editor_contents",
                "get_collaborator_interactions", "get_organizer_items", "get_organizer_items_regex",
                "get_proxy_http_history", "get_proxy_http_history_regex", "get_scanner_issues",
                "output_project_options", "output_user_options", "send_http1_request", "send_http2_request",
                "set_active_editor_contents", "set_project_options", "set_proxy_intercept_state",
                "set_task_execution_engine_state", "set_user_options", "url_decode", "url_encode"
            )
            assertEquals(expectedToolNames, tools.map { it.name }.toSet(), "The Professional tool contract must not lose or rename an existing tool")
            assertTrue(tools.any { it.name == "burp_configure_local_test_scope" })
            assertTrue(tools.any { it.name == "burp_get_intercepted_request" })
            assertTrue(tools.any { it.name == "burp_forward_intercepted_response" })
            assertTrue(tools.any { it.name == "burp_get_intercept_diagnostics" })
            tools.forEach { tool ->
                assertEquals("object", tool.inputSchema.type, "${tool.name} must expose an object input schema")
                assertFalse(tool.description.isNullOrBlank(), "${tool.name} must document its behavior")
                val properties = tool.inputSchema.properties
                val required = tool.inputSchema.required.orEmpty()
                assertTrue(required.all { properties?.containsKey(it) == true }, "${tool.name} required fields must exist in properties")
                properties?.forEach { (propertyName, schema) ->
                    assertTrue(schema is JsonObject, "${tool.name}.$propertyName must have a JSON object schema")
                    assertTrue((schema as JsonObject).containsKey("type"), "${tool.name}.$propertyName must declare a schema type")
                }
            }
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            assertTrue(toolNames.contains("burp_get_status"), "Server should expose the Burp API tools")
            assertTrue(toolNames.contains("burp_get_capabilities"), "Server should expose the Burp capability tool")
            val status = client.callTool("burp_get_status", emptyMap())
            assertReportedBuildIdentity(status, "burp_get_status")

            val capabilities = client.callTool("burp_get_capabilities", emptyMap())
            assertReportedBuildIdentity(capabilities, "burp_get_capabilities")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }

    @Test
    fun `MCP endpoint rejects requests without bearer authentication`() = runBlocking {
        val httpClient = HttpClient { install(SSE) }
        try {
            val response = httpClient.get("http://127.0.0.1:$testPort/mcp")
            assertEquals(HttpStatusCode.Unauthorized, response.status)
        } finally {
            httpClient.close()
        }
    }

    private val initializeBody = """{"jsonrpc":"2.0","id":71,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"connection-regression","version":"1"}}}"""

    private suspend fun protocolPost(
        authorization: String? = "Bearer ${config.bearerToken}",
        origin: String? = null,
        userAgent: String = "codex-connection-regression",
        host: String? = null,
        body: String = initializeBody
    ): Pair<HttpStatusCode, String> {
        val http = HttpClient()
        return try {
            val response = http.post("http://127.0.0.1:$testPort/mcp") {
                header("Accept", "application/json, text/event-stream")
                header("Content-Type", "application/json")
                header("User-Agent", userAgent)
                authorization?.let { header("Authorization", it) }
                origin?.let { header("Origin", it) }
                host?.let { header("Host", it) }
                setBody(body)
            }
            response.status to response.bodyAsText()
        } finally {
            http.close()
        }
    }

    @Test
    fun `connection security accepts authenticated native initialize and discovery`() = runBlocking {
        val (status, body) = protocolPost()
        assertEquals(HttpStatusCode.OK, status)
        val initialized = Json.parseToJsonElement(body).jsonObject
        assertFalse(initialized.containsKey("error"))
        assertEquals("2025-03-26", initialized["result"]!!.jsonObject["protocolVersion"]!!.jsonPrimitive.content)
        val (listStatus, listBody) = protocolPost(body = """{"jsonrpc":"2.0","id":72,"method":"tools/list","params":{}}""")
        assertEquals(HttpStatusCode.OK, listStatus)
        val listed = Json.parseToJsonElement(listBody).jsonObject
        assertFalse(listed.containsKey("error"))
        val tools = listed["result"]!!.jsonObject["tools"] as kotlinx.serialization.json.JsonArray
        assertEquals(89, tools.size)
        assertEquals(89, tools.map { it.jsonObject["name"]!!.jsonPrimitive.content }.toSet().size)
    }

    @Test
    fun `connection security accepts approved browser origins`() = runBlocking {
        for (origin in listOf("http://127.0.0.1:$testPort", "http://localhost:$testPort")) {
            val (status, body) = protocolPost(origin = origin, userAgent = "Mozilla/5.0")
            assertEquals(HttpStatusCode.OK, status, origin)
            val initialized = Json.parseToJsonElement(body).jsonObject
            assertTrue(initialized.containsKey("result"))
            assertFalse(initialized.containsKey("error"))
        }
    }

    @Test
    fun `connection security never bypasses bearer authentication without Origin`() = runBlocking {
        for (origin in listOf(null, "http://127.0.0.1:$testPort")) {
            for (authorization in listOf(null, "Bearer incorrect-token", "Basic invalid", "Bearer", "Bearer ")) {
                assertEquals(HttpStatusCode.Unauthorized, protocolPost(authorization = authorization, origin = origin).first)
                assertEquals(HttpStatusCode.Unauthorized, protocolPost(authorization = authorization, origin = origin,
                    body = """{"jsonrpc":"2.0","id":72,"method":"tools/list","params":{}}""").first)
            }
        }
    }

    @Test
    fun `connection security retains origin host and browser restrictions`() = runBlocking {
        assertEquals(HttpStatusCode.Forbidden, protocolPost(origin = "http://untrusted.invalid").first)
        assertEquals(HttpStatusCode.Forbidden, protocolPost(origin = "null").first)
        assertEquals(HttpStatusCode.Forbidden, protocolPost(host = "untrusted.invalid:$testPort").first)
        assertEquals(HttpStatusCode.Forbidden, protocolPost(host = "127.0.0.1:${testPort + 1}").first)
        assertEquals(HttpStatusCode.Forbidden, protocolPost(userAgent = "Mozilla/5.0").first)
    }

    @Test
    fun `connection security does not treat malformed initialize as success`() = runBlocking {
        val (status, body) = protocolPost(body = """{"jsonrpc":"2.0","id":71,"method":"initialize","params":{}}""")
        val response = Json.parseToJsonElement(body).jsonObject
        assertFalse(response.containsKey("result"), "HTTP $status must not turn a protocol error into success")
        assertTrue(response.containsKey("error"))
        assertEquals("-32602", response["error"]!!.jsonObject["code"]!!.jsonPrimitive.content)
    }

    @Test
    fun `connection security rejects Host query and fragment syntax`() = runBlocking {
        for (host in listOf("127.0.0.1:$testPort?ignored", "127.0.0.1:$testPort#ignored")) {
            assertEquals(HttpStatusCode.Forbidden, protocolPost(host = host).first, host)
        }
    }

    @Test
    fun `malformed JSON and missing required tool arguments cannot return success`() = runBlocking {
        for (body in listOf("{", """{"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"base64_encode","arguments":{}}}""")) {
            val (status, text) = protocolPost(body = body)
            val response = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull()
            assertTrue(status.value >= 400 || response?.containsKey("error") == true ||
                response?.get("result")?.jsonObject?.get("isError")?.jsonPrimitive?.content == "true")
        }
    }

    @Test
    fun `all typed tools reject invalid arguments before handler execution`() = runBlocking {
        val noArgumentHandlers = setOf("burp_configure_local_test_scope", "get_active_editor_contents", "output_project_options", "output_user_options")
        val tools = client.listTools().filter { it.name !in noArgumentHandlers }
        assertEquals(85, tools.size)
        for (tool in tools) {
            val invalid = if (tool.inputSchema.required.orEmpty().isNotEmpty()) emptyMap() else mapOf("__unsupported_argument" to true)
            val result = client.callTool(tool.name, invalid)!!
            assertTrue(result.isError == true, "${tool.name} must reject invalid arguments")
            println("ARGUMENT_REJECTION: ${tool.name}")
        }
        assertEquals(0, live.queue.list("request").size + live.queue.list("response").size)
        assertEquals(0, live.ruleEngine.list().size)
        assertFalse(live.health().enabled)
    }

    @Test
    fun `protocol negotiation does not reflect an unsupported client version`() = runBlocking {
        val (status, text) = protocolPost(body = initializeBody.replace("2025-03-26", "2099-01-01"))
        assertEquals(HttpStatusCode.OK, status)
        val negotiated = Json.parseToJsonElement(text).jsonObject["result"]!!.jsonObject["protocolVersion"]!!.jsonPrimitive.content
        assertTrue(negotiated.isNotBlank())
        assertNotEquals("2099-01-01", negotiated)
    }

    private fun syntheticIssue(url: String): burp.api.montoya.scanner.audit.issues.AuditIssue {
        val issue = mockk<burp.api.montoya.scanner.audit.issues.AuditIssue>(relaxed = true)
        val uri = java.net.URI(url)
        every { issue.baseUrl() } returns url
        every { issue.name() } returns "synthetic-scope-finding"
        every { issue.detail() } returns "synthetic-only-private-detail"
        every { issue.httpService().host() } returns uri.host
        every { issue.httpService().port() } returns uri.port
        every { issue.httpService().secure() } returns false
        every { issue.severity() } returns burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH
        every { issue.confidence() } returns burp.api.montoya.scanner.audit.issues.AuditIssueConfidence.CERTAIN
        every { issue.requestResponses() } returns emptyList()
        every { issue.collaboratorInteractions() } returns emptyList()
        return issue
    }

    private fun fixtureBytes(text: String): burp.api.montoya.core.ByteArray {
        val bytes = text.toByteArray(Charsets.UTF_8)
        val value = mockk<burp.api.montoya.core.ByteArray>(relaxed = true)
        every { value.length() } returns bytes.size
        every { value.getBytes() } returns bytes
        every { value.toString() } returns text
        every { value.subArray(any(), any()) } answers {
            fixtureBytes(String(bytes.copyOfRange(firstArg(), secondArg()), Charsets.UTF_8))
        }
        return value
    }

    private fun fixtureHeaders(values: List<Pair<String, String>>) = values.map { (name, value) ->
        mockk<burp.api.montoya.http.message.HttpHeader>().also {
            every { it.name() } returns name
            every { it.value() } returns value
        }
    }

    private fun historyFixture(contentType: String = "application/json", query: String = "access_token=fake-query"): Pair<Int, Int> {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        every { persistedObject.getString("_autoApproveTargets") } returns "127.0.0.1:8000"
        every { api.scope().isInScope(any()) } answers { firstArg<String>().startsWith("http://127.0.0.1:8000/test-post") }
        fun request(url: String, outside: Boolean): burp.api.montoya.http.message.requests.HttpRequest {
            val value = mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed = true)
            val uri = java.net.URI(url)
            val fields = listOf("Host" to "${uri.host}:8000", "Content-Type" to contentType,
                "Authorization" to "Bearer fake-auth", "Cookie" to "sid=fake-cookie", "Origin" to "http://synthetic.invalid")
            every { value.url() } returns url
            every { value.path() } returns uri.rawPath + (uri.rawQuery?.let { "?$it" } ?: "")
            every { value.method() } returns "POST"
            every { value.httpVersion() } returns "HTTP/1.1"
            every { value.httpService().host() } returns uri.host
            every { value.httpService().port() } returns 8000
            every { value.httpService().secure() } returns false
            every { value.headers() } returns fixtureHeaders(fields)
            every { value.headerValue(any()) } answers { fields.firstOrNull { it.first.equals(firstArg(), true) }?.second }
            every { value.hasHeader(any<String>()) } answers { fields.any { it.first.equals(firstArg(), true) } }
            val body = if (outside) "OUTSIDE_FIXTURE_CANARY" else "{\"password\":\"fake-body\",\"keep\":\"synthetic\"}"
            every { value.body() } returns fixtureBytes(body)
            every { value.toByteArray() } returns fixtureBytes("POST $url\r\n\r\n$body")
            every { value.toString() } returns "POST $url\r\n\r\n$body"
            return value
        }
        fun response(outside: Boolean): burp.api.montoya.http.message.responses.HttpResponse {
            val value = mockk<burp.api.montoya.http.message.responses.HttpResponse>(relaxed = true)
            val fields = listOf("Content-Type" to contentType, "Set-Cookie" to "sid=fake-set-cookie; Path=/",
                "Access-Control-Allow-Origin" to "*", "Access-Control-Allow-Credentials" to "true")
            val body = if (outside) "OUTSIDE_FIXTURE_CANARY" else "{\"password\":\"fake-reply\",\"email\":\"nobody@example.invalid\"}"
            every { value.statusCode() } returns 200.toShort()
            every { value.httpVersion() } returns "HTTP/1.1"
            every { value.reasonPhrase() } returns "OK"
            every { value.headers() } returns fixtureHeaders(fields)
            every { value.headerValue(any()) } answers { fields.firstOrNull { it.first.equals(firstArg(), true) }?.second }
            every { value.body() } returns fixtureBytes(body)
            every { value.toByteArray() } returns fixtureBytes("HTTP/1.1 200 OK\r\n\r\n$body")
            every { value.toString() } returns "HTTP/1.1 200 OK\r\n\r\n$body"
            return value
        }
        fun item(outside: Boolean): burp.api.montoya.proxy.ProxyHttpRequestResponse {
            val value = mockk<burp.api.montoya.proxy.ProxyHttpRequestResponse>(relaxed = true)
            val req = request(if (outside) "http://outside.invalid:8000/private" else "http://127.0.0.1:8000/test-post?$query", outside)
            val res = response(outside)
            every { value.finalRequest() } returns req
            every { value.originalResponse() } returns res
            every { value.time() } returns java.time.ZonedDateTime.parse("2020-01-01T00:00:00Z")
            every { value.contains(any<String>(), any<Boolean>()) } returns true
            every { value.contains(any<java.util.regex.Pattern>()) } returns true
            return value
        }
        val allowed = item(false)
        val outside = item(true)
        every { api.proxy().history() } returns listOf(outside, allowed)
        every { api.proxy().history(any()) } returns listOf(outside, allowed)
        fun pair(item: burp.api.montoya.proxy.ProxyHttpRequestResponse) = mockk<burp.api.montoya.http.message.HttpRequestResponse>(relaxed = true).also {
            every { it.request() } returns item.finalRequest()
            every { it.response() } returns item.originalResponse()
        }
        every { api.siteMap().requestResponses() } returns listOf(pair(outside), pair(allowed))
        every { api.siteMap().issues() } returns emptyList()
        return net.portswigger.mcp.compat.MontoyaRuntimeCompat.historyId(allowed) to
            net.portswigger.mcp.compat.MontoyaRuntimeCompat.historyId(outside)
    }

    @Test fun `history and analysis tool outputs filter scope and redact synthetic credentials`() = runBlocking {
        val (allowedId, outsideId) = historyFixture()
        val cases = listOf(
            "burp_get_proxy_history" to mapOf("count" to 10, "offset" to 0),
            "burp_search_http_history" to mapOf("query" to "synthetic"),
            "burp_get_request" to mapOf("historyId" to allowedId),
            "burp_get_response" to mapOf("historyId" to allowedId),
            "burp_analyze_request" to mapOf("historyId" to allowedId),
            "burp_analyze_response" to mapOf("historyId" to allowedId),
            "burp_get_response_headers" to mapOf("historyId" to allowedId),
            "burp_get_site_map" to emptyMap(),
            "get_proxy_http_history_regex" to mapOf("regex" to "synthetic", "count" to 10, "offset" to 0)
        )
        for ((name, arguments) in cases) {
            val result = client.callTool(name, arguments)!!
            assertFalse(result.isError == true, name)
            val text = (result.content.single() as TextContent).text
            assertTrue(text.contains("UNTRUSTED"), name)
            for (secret in listOf("fake-auth", "fake-cookie", "fake-body", "fake-query", "fake-reply", "fake-set-cookie", "OUTSIDE_FIXTURE_CANARY", "outside.invalid")) {
                assertFalse(text.contains(secret), "$name leaked synthetic canary $secret")
            }
            println("FUNCTIONAL_TOOL_CASE: $name")
        }
        val listing = client.callTool("burp_get_proxy_history", mapOf("count" to 1, "offset" to 0))!!
        val entries = Json.parseToJsonElement((listing.content.single() as TextContent).text).jsonArray
        assertEquals(1, entries.size)
        for (name in listOf("burp_get_request", "burp_get_response", "burp_analyze_request", "burp_get_response_headers")) {
            val rejected = client.callTool(name, mapOf("historyId" to outsideId))!!
            assertTrue(rejected.isError == true, name)
            assertFalse(rejected.content.toString().contains("OUTSIDE_FIXTURE_CANARY"))
        }
    }

    @Test fun `security analysis and response comparison return bounded meaningful observations`() = runBlocking {
        val (id, outsideId) = historyFixture()
        for (name in listOf("burp_analyze_authentication", "burp_analyze_cors", "burp_analyze_cookies", "burp_analyze_security_headers")) {
            val result = client.callTool(name, mapOf("historyId" to id))!!
            assertFalse(result.isError == true, name)
            val findings = Json.parseToJsonElement((result.content.single() as TextContent).text).jsonArray
            assertTrue(findings.isNotEmpty(), name)
            assertFalse(findings.toString().contains("fake-auth"))
            assertFalse(findings.toString().contains("fake-set-cookie"))
            println("FUNCTIONAL_TOOL_CASE: $name")
        }
        val sensitive = client.callTool("burp_find_sensitive_data", mapOf("historyId" to id, "part" to "response"))!!
        assertFalse(sensitive.isError == true)
        val summary = Json.parseToJsonElement((sensitive.content.single() as TextContent).text).jsonObject
        assertEquals("false", summary["valuesIncluded"]?.jsonPrimitive?.content ?: "false")
        assertEquals("1", summary["matchCountsByType"]!!.jsonObject["email_address"]!!.jsonPrimitive.content)
        assertFalse(summary.toString().contains("nobody@example.invalid"))
        val comparison = client.callTool("burp_compare_responses", mapOf("firstHistoryId" to id, "secondHistoryId" to id))!!
        assertFalse(comparison.isError == true)
        val compared = Json.parseToJsonElement((comparison.content.single() as TextContent).text).jsonObject
        assertEquals("true", compared["bodyHashesEqual"]!!.jsonPrimitive.content)
        assertEquals("true", compared["statusCodesEqual"]!!.jsonPrimitive.content)
        assertTrue(client.callTool("burp_compare_responses", mapOf("firstHistoryId" to id, "secondHistoryId" to outsideId))!!.isError == true)
        println("FUNCTIONAL_TOOL_CASE: burp_find_sensitive_data")
        println("FUNCTIONAL_TOOL_CASE: burp_compare_responses")
    }

    @Test fun `data access denial prevents history and site map reads`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns true
        mockkObject(net.portswigger.mcp.security.DataAccessSecurity)
        try {
            coEvery { net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(any(), config) } returns false
            for (name in listOf("burp_get_proxy_history", "burp_get_site_map", "burp_analyze_request")) {
                val result = client.callTool(name, if (name == "burp_analyze_request") mapOf("historyId" to 1) else emptyMap())!!
                assertTrue(result.isError == true)
            }
            io.mockk.verify(exactly = 0) { api.proxy().history() }
            io.mockk.verify(exactly = 0) { api.siteMap().requestResponses() }
        } finally { unmockkObject(net.portswigger.mcp.security.DataAccessSecurity) }
    }

    @Test fun `scanner listing permission denial protects both APIs before issue access`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns true
        every { persistedObject.getString("_autoApproveTargets") } returns "127.0.0.1:8000"
        every { api.scope().isInScope(any()) } returns true
        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://127.0.0.1:8000/test-post"))
        mockkObject(net.portswigger.mcp.security.DataAccessSecurity)
        try {
            coEvery { net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(any(), config) } returns false
            for (name in listOf("burp_get_scanner_issues", "get_scanner_issues")) {
                val result = client.callTool(name, mapOf("count" to 1, "offset" to 0))!!
                assertTrue(result.isError == true, "$name must reject denied native data permission")
                assertFalse(result.content.toString().contains("synthetic-only-private-detail"))
            }
            io.mockk.verify(exactly = 0) { api.siteMap().issues() }
        } finally { unmockkObject(net.portswigger.mcp.security.DataAccessSecurity) }
    }

    @Test fun `scanner listing permission approval preserves both APIs filtering and redaction`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns true
        every { persistedObject.getString("_autoApproveTargets") } returns "127.0.0.1:8000"
        every { api.scope().isInScope(any()) } returns true
        val allowed = syntheticIssue("http://127.0.0.1:8000/test-post")
        every { allowed.definition().name() } returns "password=synthetic-permission-canary"
        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://outside.invalid:8000/private"), allowed)
        mockkObject(net.portswigger.mcp.security.DataAccessSecurity)
        try {
            coEvery { net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(any(), config) } returns true
            for (name in listOf("burp_get_scanner_issues", "get_scanner_issues")) {
                val result = client.callTool(name, mapOf("count" to 1, "offset" to 0))!!
                assertFalse(result.isError == true)
                assertTrue(result.content.toString().contains("127.0.0.1:8000/test-post"))
                assertFalse(result.content.toString().contains("outside.invalid"))
                assertFalse(result.content.toString().contains("synthetic-permission-canary"))
            }
            io.mockk.coVerify(exactly = 2) {
                net.portswigger.mcp.security.DataAccessSecurity.checkDataAccessPermission(
                    net.portswigger.mcp.security.DataAccessType.HTTP_HISTORY, config)
            }
        } finally { unmockkObject(net.portswigger.mcp.security.DataAccessSecurity) }
    }

    @Test fun `secondary content type metadata does not disclose credential values`() = runBlocking {
        val (id, _) = historyFixture(contentType = "application/json; password=fake-meta-secret")
        for (name in listOf("burp_get_proxy_history", "burp_analyze_request", "burp_analyze_response")) {
            val result = client.callTool(name, if (name == "burp_get_proxy_history") emptyMap() else mapOf("historyId" to id))!!
            assertFalse(result.isError == true)
            assertFalse(result.content.toString().contains("fake-meta-secret"), name)
        }
    }

    @Test fun `binary omission metadata does not repeat secret content type parameters`() = runBlocking {
        val (id, _) = historyFixture(contentType = "application/octet-stream; password=fake-meta-secret")
        val result = client.callTool("burp_get_response", mapOf("historyId" to id))!!
        assertFalse(result.isError == true)
        assertFalse(result.content.toString().contains("fake-meta-secret"))
        assertTrue(result.content.toString().contains("binary body omitted"))
    }

    @Test fun `encoded credential query names are redacted in metadata URLs`() = runBlocking {
        val (id, _) = historyFixture(query = "p%61ssword=fake-query")
        for (name in listOf("burp_get_proxy_history", "burp_get_site_map", "burp_analyze_request")) {
            val result = client.callTool(name, if (name == "burp_analyze_request") mapOf("historyId" to id) else emptyMap())!!
            assertFalse(result.isError == true)
            assertFalse(result.content.toString().contains("fake-query"), name)
        }
        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://127.0.0.1:8000/test-post?p%61ssword=fake-query"))
        val finding = client.callTool("burp_get_scanner_issues", emptyMap())!!
        assertFalse(finding.isError == true)
        assertFalse(finding.content.toString().contains("fake-query"))
    }

    @Test fun `proposed request header edits preserve original CRLF body bytes`() = runBlocking {
        val body = "first\r\nsecond"
        val raw = "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nContent-Length: ${body.toByteArray().size}\r\n\r\n$body"
        val result = client.callTool("burp_modify_request", mapOf("rawRequest" to raw, "headers" to mapOf("X-Test" to "yes")))!!
        assertFalse(result.isError == true)
        val text = (result.content.single() as TextContent).text
        assertEquals(body, text.substringAfter("\r\n\r\n"))
    }

    @Test fun `proposed body replacement uses UTF8 byte accurate framing`() = runBlocking {
        for (replacement in listOf("", "\u96ea\r\nnext")) {
            val result = client.callTool("burp_modify_request", mapOf("rawRequest" to "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nContent-Length: 3\r\n\r\nold", "replacementBody" to replacement))!!
            assertFalse(result.isError == true)
            val text = (result.content.single() as TextContent).text
            assertEquals(replacement, text.substringAfter("\r\n\r\n"))
            assertTrue(text.contains("Content-Length: ${replacement.toByteArray(Charsets.UTF_8).size}\r\n"))
        }
    }

    @Test fun `proposed body replacement refuses unsupported transfer framing`() = runBlocking {
        val result = client.callTool("burp_modify_request", mapOf("rawRequest" to "POST /test-post HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nold\r\n0\r\n\r\n", "replacementBody" to "new"))!!
        assertTrue(result.isError == true)
    }

    @Test
    fun `scanner findings outside scope or host allowlist are never serialized`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        val issue = syntheticIssue("http://outside.invalid:8000/private")
        every { api.siteMap().issues() } returns listOf(issue)
        every { api.scope().isInScope(any()) } returns true
        var result = client.callTool("burp_get_scanner_issues", emptyMap())!!
        assertFalse(result.isError == true)
        assertEquals("[]", (result.content.single() as TextContent).text)

        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://127.0.0.1:8000/private"))
        every { api.scope().isInScope(any()) } returns false
        result = client.callTool("burp_get_scanner_issues", emptyMap())!!
        assertFalse(result.isError == true)
        assertEquals("[]", (result.content.single() as TextContent).text)
    }

    @Test
    fun `scanner pagination filters unauthorized findings before applying offsets`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        every { api.scope().isInScope(any()) } returns true
        val allowed = syntheticIssue("http://127.0.0.1:8000/test-post")
        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://outside.invalid:8000/private"), allowed)
        val result = client.callTool("burp_get_scanner_issues", mapOf("count" to 1, "offset" to 0))!!
        assertFalse(result.isError == true)
        val text = (result.content.single() as TextContent).text
        assertTrue(text.contains("127.0.0.1:8000/test-post"))
        assertFalse(text.contains("outside.invalid"))
    }

    @Test
    fun `both scanner listing tools withhold out of scope attached HTTP exchanges`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        every { api.scope().isInScope(any()) } returns true
        val issue = syntheticIssue("http://127.0.0.1:8000/test-post")
        val pair = mockk<burp.api.montoya.http.message.HttpRequestResponse>(relaxed = true)
        every { pair.request().httpService().host() } returns "outside.invalid"
        every { pair.request().httpService().port() } returns 8000
        every { pair.request().url() } returns "http://outside.invalid:8000/private"
        every { issue.requestResponses() } returns listOf(pair)
        every { api.siteMap().issues() } returns listOf(issue)
        for (tool in listOf("burp_get_scanner_issues", "get_scanner_issues")) {
            val result = client.callTool(tool, mapOf("count" to 1, "offset" to 0))!!
            assertFalse(result.isError == true)
            assertTrue((result.content.single() as TextContent).text.contains("\"requestResponses\":[]"), tool)
        }
        every { pair.request().httpService().host() } returns "127.0.0.1"
        every { pair.request().url() } returns "http://127.0.0.1:8000/test-post"
        for (tool in listOf("burp_get_scanner_issues", "get_scanner_issues")) {
            val result = client.callTool(tool, mapOf("count" to 1, "offset" to 0))!!
            assertFalse(result.isError == true)
            assertTrue((result.content.single() as TextContent).text.contains("\"requestResponses\":[{"), tool)
        }
    }

    @Test
    fun `security report counts only authorized scanner findings`() = runBlocking {
        every { persistedObject.getBoolean("requireDataAccessApproval") } returns false
        every { api.scope().isInScope(any()) } returns true
        every { api.siteMap().requestResponses() } returns emptyList()
        every { api.siteMap().issues() } returns listOf(syntheticIssue("http://outside.invalid:8000/private"),
            syntheticIssue("http://127.0.0.1:8000/test-post"))
        val result = client.callTool("burp_generate_security_report", emptyMap())!!
        assertFalse(result.isError == true)
        val report = Json.parseToJsonElement((result.content.single() as TextContent).text).jsonObject
        assertEquals("1", report["scannerIssueCount"]!!.jsonPrimitive.content)
    }

    @Test
    fun `nested interception rule schema and authenticated create workflow work`() = runBlocking {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        every { persistedObject.getString("_autoApproveTargets") } returns LocalTestTargets.ALLOWLIST_ENTRY
        config.readOnlyMode = false
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        every { api.scope().isInScope(any()) } returns true
        val createTool = client.listTools().single { it.name == "burp_create_interception_rule" }
        val specSchema = createTool.inputSchema.properties?.get("spec") as JsonObject
        assertTrue(specSchema["properties"]!!.jsonObject.containsKey("conditions"))
        assertTrue(specSchema["properties"]!!.jsonObject.containsKey("maximumModifications"))
        val transformationSchema = specSchema["properties"]!!.jsonObject["transformations"]!!.jsonObject
        assertEquals("array", transformationSchema["type"]!!.jsonPrimitive.content)
        val itemSchema = transformationSchema["items"]!!.jsonObject
        assertTrue(itemSchema["properties"]!!.jsonObject.containsKey("type"))

        live.activateUnattendedLocalTestMode(60)
        val runId = live.unattendedSnapshot().testRunId!!
        assertEquals(listOf(LocalTestTargets.ALLOWLIST_ENTRY), config.getAutoApproveTargetsList())
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE,
            live.unattendedManagementDecision(LocalTestManagementOperation.CONFIGURE_RULE).decision)
        val created = client.callTool("burp_create_interception_rule", mapOf(
            "spec" to mapOf(
                "name" to "Enable synthetic JSON field",
                "targetUrl" to LocalTestTargets.urls.first(),
                "authorizationReference" to runId,
                "direction" to "REQUEST",
                "conditions" to mapOf("jsonPath" to "$.enabled", "jsonValueJson" to "false"),
                "transformations" to listOf(mapOf("type" to "SET_JSON_FIELD", "path" to "$.enabled", "valueJson" to "true")),
                "action" to "MODIFY_AND_FORWARD",
                "priority" to 100,
                "maximumMatches" to 5,
                "maximumModifications" to 4,
                "durationSeconds" to 60
            )
        ))!!
        assertFalse(created.isError == true, created.content.toString())
        assertTrue(created.content.toString().contains("DISABLED"))
        assertTrue(created.content.toString().contains("maximumModifications"))

        val listed = client.callTool("burp_list_interception_rules", mapOf("includeDiagnostics" to false))!!
        assertFalse(listed.isError == true)
        assertTrue(listed.content.toString().contains("Enable synthetic JSON field"))
        val engineStatus = client.callTool("burp_get_rule_engine_status", mapOf("includeDiagnostics" to false))!!
        assertFalse(engineStatus.isError == true, engineStatus.content.toString())
        assertTrue(engineStatus.content.toString().contains("maximumModificationsPerRule"))
        val ruleId = Json.parseToJsonElement((created.content.single() as TextContent).text)
            .jsonObject["id"]!!.jsonPrimitive.content
        val replacement = JsonObject(Json.parseToJsonElement((created.content.single() as TextContent).text)
            .jsonObject["spec"]!!.jsonObject + ("name" to kotlinx.serialization.json.JsonPrimitive("Updated synthetic rule")))
        val updated = client.callTool("burp_update_interception_rule", mapOf("ruleId" to ruleId, "spec" to replacement))!!
        assertFalse(updated.isError == true)
        assertTrue(updated.content.toString().contains("Updated synthetic rule"))
        assertEquals("DISABLED", Json.parseToJsonElement((updated.content.single() as TextContent).text).jsonObject["state"]!!.jsonPrimitive.content)
        val preview = client.callTool("burp_preview_interception_rule", mapOf("spec" to replacement, "sample" to mapOf(
            "direction" to "REQUEST", "targetUrl" to LocalTestTargets.urls.first(), "url" to LocalTestTargets.urls.first(),
            "method" to "POST", "headers" to mapOf("Content-Type" to "application/json"), "body" to "{\"enabled\":false}")))!!
        assertFalse(preview.isError == true)
        assertEquals("true", Json.parseToJsonElement((preview.content.single() as TextContent).text).jsonObject["wouldModify"]!!.jsonPrimitive.content)
        assertEquals(0L, live.ruleEngine.get(ruleId).stats.modified)
        val clearedStats = client.callTool("burp_clear_interception_rule_stats", mapOf("ruleId" to ruleId))!!
        assertFalse(clearedStats.isError == true)
        assertEquals(5, live.ruleEngine.get(ruleId).stats.remainingMatches)
        assertEquals(4, live.ruleEngine.get(ruleId).stats.remainingModifications)
        live.allowEdits = true
        live.startApprovedSession(60)
        val enabled = client.callTool("burp_enable_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(enabled.isError == true, enabled.content.toString())
        assertTrue(enabled.content.toString().contains("ACTIVE"))
        val stats = client.callTool("burp_get_interception_rule_stats", mapOf("ruleId" to ruleId))!!
        assertFalse(stats.isError == true, stats.content.toString())
        assertTrue(stats.content.toString().contains("remainingModifications"))
        val paused = client.callTool("burp_disable_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(paused.isError == true, paused.content.toString())
        assertTrue(paused.content.toString().contains("PAUSED"))
        val deleted = client.callTool("burp_delete_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(deleted.isError == true, deleted.content.toString())
        live.disable("TEST_CLEANUP")
        val another = client.callTool("burp_create_interception_rule", mapOf("spec" to replacement))!!
        assertFalse(another.isError == true)
        val clearedRules = client.callTool("burp_clear_interception_rules", emptyMap())!!
        assertFalse(clearedRules.isError == true)
        assertEquals("1", Json.parseToJsonElement((clearedRules.content.single() as TextContent).text).jsonObject["deletedCount"]!!.jsonPrimitive.content)
        assertTrue(live.ruleEngine.list().isEmpty())
        live.deactivateUnattendedLocalTestMode("TEST_CLEANUP")
        Unit
    }

    @Test fun `user configuration export redacts known secrets and changes require approval`() = runBlocking {
        val suite = api.burpSuite()
        every { suite.exportProjectOptionsAsJson() } returns "{\"target\":{\"scope\":{\"include\":[]}},\"password\":\"fake-project-secret\"}"
        val projectExport = client.callTool("output_project_options", emptyMap())!!
        assertFalse(projectExport.isError == true)
        assertFalse(projectExport.content.toString().contains("fake-project-secret"))
        assertTrue((projectExport.content.single() as TextContent).text.contains("scope"))
        every { suite.exportUserOptionsAsJson() } returns "{\"user_options\":{\"password\":\"fake-export-secret\",\"certificate_password\":\"fake-cert-secret\",\"hashed_key\":\"fake-hash-secret\",\"keep\":7}}"
        val exported = client.callTool("output_user_options", emptyMap())!!
        assertFalse(exported.isError == true)
        val visible = (exported.content.single() as TextContent).text
        assertFalse(visible.contains("fake-export-secret"))
        assertFalse(visible.contains("fake-cert-secret"))
        assertFalse(visible.contains("fake-hash-secret"))
        assertEquals("7", Json.parseToJsonElement(visible).jsonObject["user_options"]!!.jsonObject["keep"]!!.jsonPrimitive.content)
        val payload = "{\"user_options\":{\"synthetic_setting\":true}}"
        val denied = client.callTool("set_user_options", mapOf("json" to payload))!!
        assertTrue(denied.content.toString().contains("Denied"))
        io.mockk.verify(exactly = 0) { suite.importUserOptionsFromJson(any()) }
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        every { persistedObject.getBoolean("configEditingTooling") } returns true
        mockkObject(net.portswigger.mcp.config.Dialogs)
        try {
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 1
            assertTrue(client.callTool("set_user_options", mapOf("json" to payload))!!.content.toString().contains("Denied"))
            io.mockk.verify(exactly = 0) { suite.importUserOptionsFromJson(any()) }
            coEvery { net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
            assertTrue(client.callTool("set_user_options", mapOf("json" to payload))!!.content.toString().contains("has been applied"))
            io.mockk.verify(exactly = 1) { suite.importUserOptionsFromJson(payload) }
        } finally { unmockkObject(net.portswigger.mcp.config.Dialogs) }
    }

    @Test fun `read only status queue and scope adapters return bounded snapshots`() = runBlocking {
        every { api.burpSuite().version().toString() } returns "Burp Suite Professional 2024.1.1.1-synthetic"
        val connected = client.callTool("burp_check_connection", emptyMap())!!
        assertFalse(connected.isError == true)
        assertEquals("true", Json.parseToJsonElement((connected.content.single() as TextContent).text).jsonObject["burpConnected"]!!.jsonPrimitive.content)
        val project = client.callTool("burp_get_project_info", emptyMap())!!
        assertFalse(project.isError == true)
        assertEquals("false", Json.parseToJsonElement((project.content.single() as TextContent).text).jsonObject["available"]!!.jsonPrimitive.content)
        val status = client.callTool("burp_get_intercept_status", emptyMap())!!
        assertFalse(status.isError == true)
        val snapshot = Json.parseToJsonElement((status.content.single() as TextContent).text).jsonObject
        assertEquals("false", snapshot["enabled"]!!.jsonPrimitive.content)
        assertEquals("0", snapshot["pendingRequests"]!!.jsonPrimitive.content)
        assertEquals("0", snapshot["pendingResponses"]!!.jsonPrimitive.content)
        assertEquals("[]", (client.callTool("burp_list_pending_requests", emptyMap())!!.content.single() as TextContent).text)
        assertEquals("[]", (client.callTool("burp_list_pending_responses", emptyMap())!!.content.single() as TextContent).text)
        assertEquals("[]", (client.callTool("burp_get_interception_rule_events", mapOf("count" to 10))!!.content.single() as TextContent).text)
        every { persistedObject.getString("_autoApproveTargets") } returns LocalTestTargets.ALLOWLIST_ENTRY
        every { api.scope().isInScope(any()) } answers { url ->
            val value = url.invocation.args[0] as String
            LocalTestTargets.urls.any(value::startsWith)
        }
        val eligible = LocalTestTargets.urls + "http://127.0.0.1:8000/test-post-phase2"
        val excluded = listOf("http://127.0.0.1:8000/", "http://127.0.0.1:8000/unrelated", "http://localhost:8000/test-post", "http://127.0.0.1:8001/test-post", "https://127.0.0.1:8000/test-post", "http://outside.invalid:8000/test-post")
        val scope = client.callTool("burp_get_scope", mapOf("urls" to eligible + excluded))!!
        assertFalse(scope.isError == true)
        val checks = Json.parseToJsonElement((scope.content.single() as TextContent).text).jsonObject["checks"]!!.jsonArray
        assertEquals(eligible.toSet(), checks.filter { it.jsonObject["eligible"]!!.jsonPrimitive.content == "true" }.map { it.jsonObject["url"]!!.jsonPrimitive.content }.toSet())
    }

    @Test
    fun `eight concurrent read only status calls remain responsive`() = runBlocking {
        val results = coroutineScope {
            (1..8).map {
                async { client.callTool("burp_get_status", mapOf("includeDiagnostics" to false)) }
            }.awaitAll()
        }
        assertEquals(8, results.size)
        results.forEach { assertReportedBuildIdentity(it, "burp_get_status") }
    }

    @Test
    fun `stateless transport rejects SSE and completes repeated MCP clients`() = runBlocking {
        val probe = HttpClient()
        try {
            val get = withTimeout(2_000) {
                probe.get("http://127.0.0.1:$testPort/mcp") {
                    headers.append(io.ktor.http.HttpHeaders.Authorization, "Bearer ${config.bearerToken}")
                    headers.append(io.ktor.http.HttpHeaders.Accept, "text/event-stream")
                }
            }
            assertEquals(HttpStatusCode.MethodNotAllowed, get.status)
            assertEquals("POST", get.headers[io.ktor.http.HttpHeaders.Allow])
        } finally {
            probe.close()
        }

        repeat(10) { index ->
            val sessionClient = TestStreamableHttpMcpClient()
            try {
                withTimeout(5_000) {
                    sessionClient.connectToServer("http://127.0.0.1:${testPort}/mcp", config.bearerToken)
                    val status = sessionClient.callTool("burp_get_status", mapOf("includeDiagnostics" to false))
                    assertReportedBuildIdentity(status, "burp_get_status after session $index")
                }
            } finally {
                withTimeout(5_000) { sessionClient.close() }
            }
        }
    }

    @Test
    fun `stateless listener restarts on the same port after client churn`() = runBlocking {
        repeat(3) {
            val stopped = CompletableDeferred<Unit>()
            serverManager.stop { state ->
                if (state is ServerState.Stopped) stopped.complete(Unit)
                if (state is ServerState.Failed) stopped.completeExceptionally(state.exception)
            }
            withTimeout(10_000) { stopped.await() }
            val started = CompletableDeferred<Unit>()
            serverManager.start(config) { state ->
                if (state is ServerState.Running) started.complete(Unit)
                if (state is ServerState.Failed) started.completeExceptionally(state.exception)
            }
            withTimeout(10_000) { started.await() }
            val freshClient = TestStreamableHttpMcpClient()
            try {
                withTimeout(5_000) {
                    freshClient.connectToServer("http://127.0.0.1:$testPort/mcp", config.bearerToken)
                    freshClient.ping()
                    assertReportedBuildIdentity(freshClient.callTool("burp_get_status", emptyMap()), "restarted server")
                }
            } finally {
                withTimeout(5_000) { freshClient.close() }
            }
        }
    }

    @Test
    fun `one pending approval serializes a second and does not stall MCP health calls`() = runBlocking {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        config.readOnlyMode = false
        config.addAutoApproveTarget("127.0.0.1:8000")
        live.startApprovedSession(60)
        every { api.scope().isInScope(any()) } returns true

        val request = mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed = true)
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns 8000
        every { request.httpService().secure() } returns false
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel"
        every { request.method() } returns "GET"
        assertFalse(config.readOnlyMode)
        assertTrue(live.health().enabled)
        assertTrue(live.authorized(request))
        val ticket = live.queue.offer(
            "request",
            net.portswigger.mcp.intercept.HeldMessage(request, request),
            10_000
        )!!
        val secondTicket = live.queue.offer(
            "request",
            net.portswigger.mcp.intercept.HeldMessage(request, request),
            10_000
        )!!

        mockkObject(net.portswigger.mcp.config.Dialogs)
        val releaseApproval = CompletableDeferred<Unit>()
        try {
            val promptStarted = CompletableDeferred<Unit>()
            coEvery {
                net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any())
            } coAnswers {
                promptStarted.complete(Unit)
                releaseApproval.await()
                0
            }

            val approval = async {
                client.callTool(
                    "burp_approve_intercepted_request_edit",
                    mapOf("id" to ticket.id, "revision" to 0)
                )
            }
            val promptObserved = withTimeoutOrNull(2_000) {
                promptStarted.await()
                true
            } == true
            if (!promptObserved) {
                val result = withTimeoutOrNull(1_000) { approval.await() }
                val detail = result?.content?.joinToString(" ") { it.toString() }?.take(256)
                val events = net.portswigger.mcp.security.ActivityLog.snapshot().take(8)
                    .joinToString(" | ") { "${it.action}:${it.outcome}:${it.detail}" }
                throw AssertionError("Approval did not reach its local review prompt; completed=${approval.isCompleted} error=${result?.isError} detail=$detail events=$events")
            }

            val simultaneousApproval = withTimeout(1_500) {
                client.callTool(
                    "burp_approve_intercepted_request_edit",
                    mapOf("id" to secondTicket.id, "revision" to 0)
                )
            }
            assertTrue(simultaneousApproval!!.isError == true, "A second concurrent local review must fail closed without opening another prompt")

            val healthClients = (1..8).map { TestStreamableHttpMcpClient() }
            val statuses = try {
                coroutineScope {
                    healthClients.mapIndexed { index, healthClient ->
                        async {
                            withTimeout(3_000) {
                                healthClient.connectToServer(
                                    "http://127.0.0.1:${testPort}/mcp",
                                    config.bearerToken
                                )
                                val status = healthClient.callTool(
                                    "burp_get_status",
                                    mapOf("includeDiagnostics" to false)
                                )
                                assertReportedBuildIdentity(status, "concurrent client $index")
                                status
                            }
                        }
                    }.awaitAll()
                }
            } finally {
                healthClients.forEach { healthClient ->
                    if (healthClient.isConnected()) withTimeout(3_000) { healthClient.close() }
                }
            }
            assertEquals(8, statuses.size)
            statuses.forEach { assertReportedBuildIdentity(it, "burp_get_status") }
            assertFalse(approval.isCompleted, "Health calls must complete while the approval prompt is still pending")
            releaseApproval.complete(Unit)
            assertFalse(approval.await()!!.isError == true)
            assertEquals(0, live.queue.get(ticket.id).approvedRevision)
        } finally {
            releaseApproval.complete(Unit)
            unmockkObject(net.portswigger.mcp.config.Dialogs)
        }
    }

    @Test
    fun `MCP input validation rejects unsafe request modifications`() = runBlocking {
        val result = client.callTool(
            "burp_modify_request",
            mapOf(
                "rawRequest" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "headers" to mapOf("X-Test" to "safe\r\nX-Injected: value")
            )
        )
        assertNotNull(result)
        assertTrue(result!!.isError == true)
    }

    @Test
    fun `server stops gracefully`() = runBlocking {
        val stopped = kotlinx.coroutines.CompletableDeferred<ServerState>()
        serverManager.stop { state ->
            if (state is ServerState.Stopped) stopped.complete(state)
        }
        assertTrue(kotlinx.coroutines.withTimeout(5000) { stopped.await() } is ServerState.Stopped)
    }

    @Test
    fun `live tools reject unknown IDs and withhold captured contents before disclosure`() = runBlocking {
        val missing=client.callTool("burp_get_intercepted_request",mapOf("id" to "unknown"))!!
        assertTrue(missing.isError == true)
        assertTrue(missing.content.toString().contains("unknown"))
        val request=mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed=true)
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns 80
        every { request.url() } returns "http://127.0.0.1/"
        every { api.scope().isInScope(any()) } returns true
        every { request.toString() } returns "LOCAL SECRET BODY"
        val ticket=live.queue.offer("request",net.portswigger.mcp.intercept.HeldMessage(request,request),10_000)!!
        val result=client.callTool("burp_get_intercepted_request",mapOf("id" to ticket.id))!!
        assertFalse(result.isError == true)
        assertTrue(result.content.toString().contains("contentDisclosureApproved"))
        assertFalse(result.content.toString().contains("LOCAL SECRET BODY"))
        io.mockk.verify(exactly=0) { request.headers() }
    }

    @Test
    fun `interception diagnostics are read only and payload free`() = runBlocking {
        net.portswigger.mcp.security.ActivityLog.clear()
        net.portswigger.mcp.security.ActivityLog.record("intercept_request", "skipped", "GET 127.0.0.1/test; outside Burp scope")
        val result = client.callTool("burp_get_intercept_diagnostics", mapOf("count" to 10))!!
        assertFalse(result.isError == true)
        val text = result.content.toString()
        assertTrue(text.contains("outside Burp scope"))
        assertTrue(text.contains("heartbeatHealth"))
        assertFalse(text.contains("Cookie:"))
        assertFalse(text.contains("Authorization:"))
    }
}
