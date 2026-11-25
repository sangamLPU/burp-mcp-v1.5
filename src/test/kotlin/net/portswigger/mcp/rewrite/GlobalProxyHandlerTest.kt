package net.portswigger.mcp.rewrite

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertEquals

class GlobalProxyHandlerTest {
    private val manager = RewriteManager(mockk<PersistedObject>(relaxed = true))
    private val request = mockk<InterceptedRequest>()
    private val pathResult = mockk<HttpRequest>()
    private val action = mockk<ProxyRequestToBeSentAction>()

    @BeforeEach fun setup() {
        mockkStatic(ProxyRequestToBeSentAction::class)
        every { ProxyRequestToBeSentAction.continueWith(any()) } returns action
        every { request.httpService() } returns mockk<HttpService> { every { host() } returns "example.test" }
        every { request.isInScope } returns true
        every { request.headers() } returns emptyList()
        every { request.hasHeader(any<String>()) } returns false
        every { request.path() } returns "/api/orders?x=%2F&user_id=old&user_id=two"
        every { request.withPath(any()) } returns pathResult
        manager.setTargets("example.test")
        manager.createGlobal("user_id", "12345", listOf("query"))
        manager.enableGlobalApproved(manager.listGlobal().single()); manager.activate()
    }
    @AfterEach fun cleanup() { unmockkStatic(ProxyRequestToBeSentAction::class) }

    @Test fun `query changes without reading or changing body or sensitive headers`() {
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { request.withPath("/api/orders?x=%2F&user_id=12345&user_id=12345") }
        verify { ProxyRequestToBeSentAction.continueWith(pathResult) }
        verify(exactly = 0) { request.body() }
        verify(exactly = 0) { request.withBody(any<BurpBytes>()) }
    }
    @Test fun `same query rule works across distinct paths and methods`() {
        var path = "/first?user_id=old&keep=one"
        every { request.path() } answers { path }
        every { request.method() } returnsMany listOf("GET", "POST")
        val handler = RewriteProxyHandler(manager)
        handler.handleRequestToBeSent(request)
        path = "/second?user_id=old&keep=two"
        handler.handleRequestToBeSent(request)
        verify { request.withPath("/first?user_id=12345&keep=one") }
        verify { request.withPath("/second?user_id=12345&keep=two") }
    }
    @Test fun `out of scope and emergency disable forward original`() {
        every { request.isInScope } returns false
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        manager.disableAll()
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify(exactly = 2) { ProxyRequestToBeSentAction.continueWith(request) }
        verify(exactly = 0) { request.withPath(any()) }
    }
    @Test fun `malformed query forwards unchanged`() {
        every { request.path() } returns "/api?user_id=old&x=%ZZ"
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        verify(exactly = 0) { request.withPath(any()) }
    }
    @Test fun `failed proxy mutation does not count a match`() {
        every { request.withPath(any()) } throws IllegalStateException("mutation failed")
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        assertEquals(0L, manager.activityFor(manager.listGlobal().single().id).count)
    }

    @Test fun `failed global JSON rewrite does not count a discarded pointer rewrite`() {
        val id = manager.listGlobal().single().id
        manager.updateGlobal(id, "user_id", "12345", listOf("json"))
        manager.enableGlobalApproved(manager.listGlobal().single())
        val pointerId = manager.create("example.test", "POST", "/api", "application/json", "/name", "\"new\"")
        manager.enableApproved(manager.list().single { it.id == pointerId })
        val input = "{\"name\":\"old\",\"user_id\":{\"keep\":1}}"
        val type = mockk<HttpHeader> { every { name() } returns "Content-Type" }
        every { request.headers() } returns listOf(type)
        every { request.headerValue("Content-Type") } returns "application/json"
        every { request.body() } returns mockk<BurpBytes> { every { bytes } returns input.toByteArray() }
        every { request.path() } returns "/api"
        every { request.pathWithoutQuery() } returns "/api"
        every { request.method() } returns "POST"
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        assertEquals(0L, manager.activityFor(pointerId).count)
    }

    @Test fun `proxy rewrites form and multipart text but forwards file uploads unchanged`() {
        mockkStatic(BurpBytes::class)
        try {
            val id = manager.listGlobal().single().id
            manager.updateGlobal(id, "user_id", "12345", listOf("form", "multipart"))
            manager.enableGlobalApproved(manager.listGlobal().single())
            val length = mockk<HttpHeader> { every { name() } returns "Content-Length" }
            val type = mockk<HttpHeader> { every { name() } returns "Content-Type" }
            every { request.headers() } returns listOf(type, length)
            every { request.hasHeader("Content-Length") } returns true
            every { request.path() } returns "/form"
            val handler = RewriteProxyHandler(manager)
            fun send(contentType: String, input: String, expected: String?) {
                every { request.headerValue("Content-Type") } returns contentType
                every { request.headerValue("Content-Length") } returns input.toByteArray().size.toString()
                every { request.body() } returns mockk<BurpBytes> { every { bytes } returns input.toByteArray() }
                if (expected == null) {
                    handler.handleRequestToBeSent(request)
                    verify { ProxyRequestToBeSentAction.continueWith(request) }
                    return
                }
                val rewritten = mockk<BurpBytes>()
                val modified = mockk<HttpRequest>()
                every { BurpBytes.byteArray(*expected.toByteArray()) } returns rewritten
                every { request.withBody(rewritten) } returns modified
                every { modified.withUpdatedHeader("Content-Length", expected.toByteArray().size.toString()) } returns modified
                handler.handleRequestToBeSent(request)
                verify { ProxyRequestToBeSentAction.continueWith(modified) }
            }
            send("application/x-www-form-urlencoded", "user_id=old&keep=a%20b", "user_id=12345&keep=a%20b")
            val multipart = "--abc\r\nContent-Disposition: form-data; name=\"user_id\"\r\n\r\nold\r\n"
            send("multipart/form-data; boundary=abc", multipart + "--abc--\r\n", multipart.replace("old", "12345") + "--abc--\r\n")
            val file = "--abc\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"x.txt\"\r\n\r\nfile\r\n"
            send("multipart/form-data; boundary=abc", multipart + file + "--abc--\r\n", null)
            assertEquals(2L, manager.activityFor(id).count)
        } finally { unmockkStatic(BurpBytes::class) }
    }
    @Test fun `JSON body rewrites nested fields with UTF8 content length and preserves other data`() {
        mockkStatic(BurpBytes::class)
        try {
            val input = "{\"user_id\":\"old\",\"x\":{\"user_id\":1,\"keep\":true}}"
            val output = "{\"user_id\":\"é\",\"x\":{\"user_id\":\"é\",\"keep\":true}}"
            val content = mockk<HttpHeader> { every { name() } returns "Content-Type" }
            val length = mockk<HttpHeader> { every { name() } returns "Content-Length" }
            val body = mockk<BurpBytes> { every { bytes } returns input.toByteArray(Charsets.UTF_8) }
            val replacement = mockk<BurpBytes>()
            val modified = mockk<HttpRequest>()
            val final = mockk<HttpRequest>()
            every { BurpBytes.byteArray(*output.toByteArray(Charsets.UTF_8)) } returns replacement
            every { request.headers() } returns listOf(content, length)
            every { request.hasHeader(any<String>()) } answers { firstArg<String>().equals("Content-Length", true) }
            every { request.headerValue("Content-Type") } returns "application/json; charset=utf-8"
            every { request.headerValue("Content-Length") } returns input.toByteArray().size.toString()
            every { request.body() } returns body
            every { request.path() } returns "/api"
            every { request.pathWithoutQuery() } returns "/api"
            every { request.method() } returns "POST"
            every { request.withBody(replacement) } returns modified
            every { modified.withUpdatedHeader("Content-Length", any()) } returns final
            val id = manager.listGlobal().single().id
            manager.updateGlobal(id, "user_id", "é", listOf("json"))
            manager.enableGlobalApproved(manager.listGlobal().single())
            RewriteProxyHandler(manager).handleRequestToBeSent(request)
            verify { modified.withUpdatedHeader("Content-Length", output.toByteArray(Charsets.UTF_8).size.toString()) }
            verify { ProxyRequestToBeSentAction.continueWith(final) }
            every { request.headerValue("Content-Length") } returns "1"
            RewriteProxyHandler(manager).handleRequestToBeSent(request)
            verify { ProxyRequestToBeSentAction.continueWith(request) }
        } finally { unmockkStatic(BurpBytes::class) }
    }
}
