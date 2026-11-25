package net.portswigger.mcp.rewrite

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.*
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ResponseRewriteTest {
    private fun rule(mode: String = "json_field", match: String = "isPremium", replacement: String = "true", id: String = "first") =
        ResponseRewriteRule(id = id, mode = mode, match = match, replacement = replacement)

    @Test fun `nested fields and arrays preserve all unrelated bytes and exact case`() {
        val input = "{\"isPremium\":false, \"IsPremium\":false,\"items\":[{\"isPremium\":null,\"credits\":10},[{\"isPremium\":0}]]}"
        val expected = "{\"isPremium\":true, \"IsPremium\":false,\"items\":[{\"isPremium\":true,\"credits\":10},[{\"isPremium\":true}]]}"
        assertEquals(expected, rewriteResponseJson(input, listOf(rule())).body)
    }

    @Test fun `typed replacements and exact pointer with escaping`() {
        val input = "{\"a/b\":{\"n~m\":false},\"x\":false}"
        for (literal in listOf("true", "null", "42.5", "\"hello\"")) {
            val r = rule("json_pointer", "/a~1b/n~0m", literal)
            validateResponseRule(r)
            assertEquals("{\"a/b\":{\"n~m\":$literal},\"x\":false}", rewriteResponseJson(input, listOf(r)).body)
        }
        assertThrows(Exception::class.java) { validateResponseRule(rule(replacement = "{}")) }
        assertThrows(Exception::class.java) { rewriteResponseJson("{\"x\":1,\"x\":2}", listOf(rule())) }
    }

    @Test fun `first rule wins overlapping nodes without cascading`() {
        val body = "{\"user\":{\"isPremium\":false},\"isPremium\":false}"
        val child = rule(replacement = "true")
        val parent = rule("json_pointer", "/user", "null", "second")
        assertEquals("{\"user\":{\"isPremium\":true},\"isPremium\":true}", rewriteResponseJson(body, listOf(child, parent)).body)
        assertEquals("{\"user\":null,\"isPremium\":true}", rewriteResponseJson(body, listOf(parent, child)).body)
        val a = rule("text", "Guest", "Tester")
        val b = rule("text", "Tester", "Other", "second")
        assertEquals("Welcome, Tester", rewriteResponseText("Welcome, Guest", listOf(a, b)).body)
    }

    @Test fun `switches start off and allowlist changes and emergency disable both directions`() {
        val manager = RewriteManager(mockk<PersistedObject>(relaxed = true)) { true }
        manager.setTargets("example.test")
        val id = manager.createResponse(rule())
        assertFalse(manager.listResponse().single().enabled)
        assertFalse(manager.isResponseActive())
        manager.enableResponseApproved(manager.listResponse().single())
        manager.activate(); manager.activateResponse()
        assertEquals(id, manager.responsesFor("example.test", true).single().id)
        assertTrue(manager.responsesFor("example.test", false).isEmpty())
        assertTrue(manager.responsesFor("other.test", true).isEmpty())
        manager.disableAll()
        assertFalse(manager.isActive()); assertFalse(manager.isResponseActive())
        assertTrue(manager.listResponse().single().enabled)
        manager.activate(); manager.activateResponse(); manager.setTargets("example.test")
        assertFalse(manager.isActive()); assertFalse(manager.isResponseActive())
    }

    private val manager = RewriteManager(mockk<PersistedObject>(relaxed = true)) { true }
    private val response = mockk<InterceptedResponse>()
    private val request = mockk<HttpRequest>()
    private val action = mockk<ProxyResponseToBeSentAction>()
    private val modified = mockk<HttpResponse>()
    private val input = "{\"isPremium\":false,\"credits\":10}"
    private val output = "{\"isPremium\":true,\"credits\":10}"

    @BeforeEach fun setup() {
        mockkStatic(ProxyResponseToBeSentAction::class, BurpBytes::class)
        every { ProxyResponseToBeSentAction.continueWith(any()) } returns action
        every { response.initiatingRequest() } returns request
        every { request.httpService() } returns mockk<HttpService> { every { host() } returns "example.test" }
        every { request.isInScope } returns true
        every { request.method() } returns "GET"
        every { request.pathWithoutQuery() } returns "/api"
        every { request.hasHeader(any<String>()) } returns false
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.statusCode() } returns 200
        every { response.hasHeader(any<String>()) } returns false
        every { response.headers() } returns listOf(
            mockk<HttpHeader> { every { name() } returns "Content-Type" },
            mockk<HttpHeader> { every { name() } returns "Content-Length" })
        every { response.headerValue("Content-Type") } returns "application/json; charset=utf-8"
        every { response.headerValue("Content-Length") } returns input.toByteArray().size.toString()
        every { response.body() } returns mockk<BurpBytes> { every { bytes } returns input.toByteArray() }
        val replacement = mockk<BurpBytes>()
        every { BurpBytes.byteArray(*output.toByteArray()) } returns replacement
        every { response.withBody(replacement) } returns modified
        every { modified.withUpdatedHeader("Content-Length", any()) } returns modified
        every { modified.withAddedHeader("Cache-Control", "no-store") } returns modified
        manager.setTargets("example.test")
        manager.createResponse(rule().copy(method = "GET", path = "/api", status = 200))
        manager.enableResponseApproved(manager.listResponse().single()); manager.activateResponse()
    }
    @AfterEach fun cleanup() { unmockkStatic(ProxyResponseToBeSentAction::class, BurpBytes::class) }

    @Test fun `proxy rewrites response and fixes length and cache policy`() {
        ResponseProxyHandler(manager).handleResponseToBeSent(response)
        verify { modified.withUpdatedHeader("Content-Length", output.toByteArray().size.toString()) }
        verify { modified.withAddedHeader("Cache-Control", "no-store") }
        verify { ProxyResponseToBeSentAction.continueWith(modified) }
    }
    @Test fun `proxy applies approved literal text and preserves surrounding content`() {
        val existing = manager.listResponse().single()
        manager.updateResponse(existing.copy(mode = "text", match = "old.", replacement = "new"))
        manager.enableResponseApproved(manager.listResponse().single())
        val input = "Keep old! Replace old. Keep 42."
        val output = "Keep old! Replace new Keep 42."
        val replacement = mockk<BurpBytes>()
        every { response.headerValue("Content-Type") } returns "text/plain; charset=utf-8"
        every { response.headerValue("Content-Length") } returns input.toByteArray().size.toString()
        every { response.body() } returns mockk<BurpBytes> { every { bytes } returns input.toByteArray() }
        every { BurpBytes.byteArray(*output.toByteArray()) } returns replacement
        every { response.withBody(replacement) } returns modified
        ResponseProxyHandler(manager).handleResponseToBeSent(response)
        verify { modified.withUpdatedHeader("Content-Length", output.toByteArray().size.toString()) }
        verify { ProxyResponseToBeSentAction.continueWith(modified) }
    }
    @Test fun `scope encoding path status and emergency deny rewriting`() {
        val handler = ResponseProxyHandler(manager)
        every { request.isInScope } returns false; handler.handleResponseToBeSent(response)
        every { request.isInScope } returns true
        every { response.hasHeader("Content-Encoding") } returns true; handler.handleResponseToBeSent(response)
        every { response.hasHeader("Content-Encoding") } returns false
        every { request.pathWithoutQuery() } returns "/other"; handler.handleResponseToBeSent(response)
        every { request.pathWithoutQuery() } returns "/api"
        every { response.statusCode() } returns 201; handler.handleResponseToBeSent(response)
        manager.disableAll(); handler.handleResponseToBeSent(response)
        verify(exactly = 5) { ProxyResponseToBeSentAction.continueWith(response) }
        verify(exactly = 0) { response.withBody(any<BurpBytes>()) }
    }
    @Test fun `protocol downloads validators and ambiguous lengths bypass body rewriting`() {
        val handler = ResponseProxyHandler(manager)
        every { response.httpVersion() } returns "HTTP/3"
        handler.handleResponseToBeSent(response)
        every { response.httpVersion() } returns "HTTP/1.1"
        for (header in listOf("Content-Disposition", "ETag", "Transfer-Encoding", "Content-Range")) {
            every { response.hasHeader(header) } returns true
            handler.handleResponseToBeSent(response)
            every { response.hasHeader(header) } returns false
        }
        every { response.headerValue("Content-Length") } returns "1"
        handler.handleResponseToBeSent(response)
        verify(exactly = 6) { ProxyResponseToBeSentAction.continueWith(response) }
        verify(exactly = 0) { response.withBody(any<BurpBytes>()) }
    }

    private fun header(name: String, value: String = "") = mockk<HttpHeader> {
        every { name() } returns name
        every { value() } returns value
    }

    private fun setupHttp2Output(length: Int?) {
        every { response.httpVersion() } returns "HTTP/2"
        every { modified.httpVersion() } returns "HTTP/2"
        every { modified.statusCode() } returns 200
        every { modified.hasHeader(any<String>()) } returns false
        val headers = listOf(header("content-type"))
        every { modified.headers() } returns if (length == null) headers else headers + header("content-length", length.toString())
    }

    @Test fun `HTTP2 updates an existing content length after JSON rewrite`() {
        setupHttp2Output(output.toByteArray().size)
        ResponseProxyHandler(manager).handleResponseToBeSent(response)
        verify { modified.withUpdatedHeader("Content-Length", output.toByteArray().size.toString()) }
        verify { ProxyResponseToBeSentAction.continueWith(modified) }
    }

    @Test fun `HTTP2 rewrites without content length while HTTP1 still requires it`() {
        setupHttp2Output(null)
        every { response.headers() } returns listOf(header("content-type"))
        every { modified.withRemovedHeader("Content-Length") } returns modified
        val handler = ResponseProxyHandler(manager)
        handler.handleResponseToBeSent(response)
        every { response.httpVersion() } returns "HTTP/1.1"
        handler.handleResponseToBeSent(response)
        verify(exactly = 1) { modified.withRemovedHeader("Content-Length") }
        verify(exactly = 0) { response.headerValue("Content-Length") }
        verify(exactly = 1) { ProxyResponseToBeSentAction.continueWith(modified) }
        verify(exactly = 1) { ProxyResponseToBeSentAction.continueWith(response) }
    }

    @Test fun `HTTP2 skips forbidden headers duplicate lengths and declared length mismatch`() {
        setupHttp2Output(output.toByteArray().size)
        val handler = ResponseProxyHandler(manager)
        for (name in listOf("Connection", "Keep-Alive", "Proxy-Connection", "TE", "Transfer-Encoding", "Upgrade", "Trailer", "Content-Digest")) {
            every { response.hasHeader(name) } returns true
            handler.handleResponseToBeSent(response)
            every { response.hasHeader(name) } returns false
        }
        every { response.headerValue("Content-Length") } returns "999"
        handler.handleResponseToBeSent(response)
        every { response.headers() } returns listOf(header("content-type"), header("content-length"), header("Content-Length"))
        handler.handleResponseToBeSent(response)
        verify(exactly = 10) { ProxyResponseToBeSentAction.continueWith(response) }
        verify(exactly = 0) { response.withBody(any<BurpBytes>()) }
    }

    @Test fun `HTTP2 rejects a builder result with modified protocol status framing or length`() {
        setupHttp2Output(output.toByteArray().size)
        val handler = ResponseProxyHandler(manager)
        every { modified.httpVersion() } returns "HTTP/1.1"
        handler.handleResponseToBeSent(response)
        every { modified.httpVersion() } returns "HTTP/2"
        every { modified.statusCode() } returns 201
        handler.handleResponseToBeSent(response)
        every { modified.statusCode() } returns 200
        every { modified.hasHeader("Transfer-Encoding") } returns true
        handler.handleResponseToBeSent(response)
        every { modified.hasHeader("Transfer-Encoding") } returns false
        every { modified.headers() } returns listOf(header("content-length", "999"))
        handler.handleResponseToBeSent(response)
        verify(exactly = 4) { ProxyResponseToBeSentAction.continueWith(response) }
        assertEquals(0, manager.activityFor(manager.listResponse().single().id).count)
    }

    @Test fun `deep response rule values fail validation without parser recursion`() {
        val deep = "[".repeat(4096) + "0" + "]".repeat(4096)
        assertThrows(IllegalArgumentException::class.java) {
            validateResponseRule(rule(replacement = deep))
        }
    }
    @Test fun `global response rule matches multiple endpoints and respects independent switches`() {
        manager.updateResponse(manager.listResponse().single().copy(method = "", path = "", status = 0))
        manager.enableResponseApproved(manager.listResponse().single())
        var path = "/one"; var method = "GET"
        every { request.pathWithoutQuery() } answers { path }
        every { request.method() } answers { method }
        val handler = ResponseProxyHandler(manager)
        handler.handleResponseToBeSent(response)
        path = "/two"; method = "POST"; handler.handleResponseToBeSent(response)
        verify(exactly = 2) { ProxyResponseToBeSentAction.continueWith(modified) }
        assertEquals(2, manager.activityFor(manager.listResponse().single().id).count)
        assertFalse(manager.isActive()); assertTrue(manager.isResponseActive())
        manager.disableAll(); assertFalse(manager.isResponseActive())
    }
    @Test fun `response containing credentials passes through without rewriting`() {
        val body = "{\"isPremium\":false,\"access_token\":\"secret\"}"
        every { response.body() } returns mockk<BurpBytes> { every { bytes } returns body.toByteArray() }
        every { response.headerValue("Content-Length") } returns body.toByteArray().size.toString()
        ResponseProxyHandler(manager).handleResponseToBeSent(response)
        verify { ProxyResponseToBeSentAction.continueWith(response) }
        verify(exactly = 0) { response.withBody(any<BurpBytes>()) }
        assertFalse(manager.logs().joinToString().contains("secret"))
    }
    @Test fun `proxy forwards response unchanged if Burp unpacking is enabled after activation`() {
        var safe = true
        val guarded = RewriteManager(mockk<PersistedObject>(relaxed = true)) { safe }
        guarded.setTargets("example.test")
        guarded.createResponse(rule())
        guarded.enableResponseApproved(guarded.listResponse().single())
        guarded.activateResponse()
        safe = false
        ResponseProxyHandler(guarded).handleResponseToBeSent(response)
        verify { ProxyResponseToBeSentAction.continueWith(response) }
        verify(exactly = 0) { response.withBody(any<BurpBytes>()) }
        assertFalse(guarded.isResponseActive())
    }
    @Test fun `configuration lookup can access manager from another thread without deadlock`() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            lateinit var guarded: RewriteManager
            guarded = RewriteManager(mockk<PersistedObject>(relaxed = true)) {
                executor.submit<Boolean> { guarded.isActive() }.get(2, TimeUnit.SECONDS)
                true
            }
            guarded.setTargets("example.test")
            guarded.createResponse(rule())
            guarded.enableResponseApproved(guarded.listResponse().single())
            guarded.activateResponse()
            ResponseProxyHandler(guarded).handleResponseToBeSent(response)
            verify { ProxyResponseToBeSentAction.continueWith(modified) }
            assertTrue(guarded.isResponseActive())
        } finally { executor.shutdownNow() }
    }
}
