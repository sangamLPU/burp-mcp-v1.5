package net.portswigger.mcp.rewrite

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.*
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class RewriteProxyHandlerTest {
    private val storage = mockk<PersistedObject>(relaxed = true)
    private val manager = RewriteManager(storage)
    private val request = mockk<InterceptedRequest>()
    private val modified = mockk<HttpRequest>()
    private val final = mockk<HttpRequest>()
    private val action = mockk<ProxyRequestToBeSentAction>()
    private val body = mockk<BurpBytes>()
    private val replacement = mockk<BurpBytes>()
    private val type = mockk<HttpHeader>()
    private val length = mockk<HttpHeader>()

    @BeforeEach fun setup() {
        mockkStatic(BurpBytes::class); mockkStatic(ProxyRequestToBeSentAction::class)
        every { ProxyRequestToBeSentAction.continueWith(any()) } returns action
        every { BurpBytes.byteArray(*"{\"name\":\"é\"}".toByteArray(Charsets.UTF_8)) } returns replacement
        every { type.name() } returns "Content-Type"
        every { length.name() } returns "Content-Length"
        every { request.headers() } returns listOf(type, length)
        every { request.hasHeader(any<String>()) } answers { firstArg<String>().equals("Content-Length", true) }
        every { request.headerValue("Content-Type") } returns "application/json; charset=utf-8"
        every { request.headerValue("Content-Length") } returns "14"
        every { request.body() } returns body
        every { body.bytes } returns "{\"name\":\"old\"}".toByteArray()
        every { request.httpService() } returns mockk<HttpService> { every { host() } returns "example.test" }
        every { request.method() } returns "POST"
        every { request.pathWithoutQuery() } returns "/api"
        every { request.isInScope } returns true
        every { request.withBody(replacement) } returns modified
        every { modified.withUpdatedHeader("Content-Length", any()) } returns final
        manager.setTargets("example.test")
        manager.create("example.test", "POST", "/api", "application/json", "/name", "\"é\"")
        manager.enableApproved(manager.list().single()); manager.activate()
    }
    @AfterEach fun cleanup() { unmockkStatic(BurpBytes::class); unmockkStatic(ProxyRequestToBeSentAction::class) }

    @Test fun `sends updated UTF-8 byte length`() {
        assertSame(action, RewriteProxyHandler(manager).handleRequestToBeSent(request))
        verify { modified.withUpdatedHeader("Content-Length", "13") }
        verify { ProxyRequestToBeSentAction.continueWith(final) }
    }
    @Test fun `disabled rewriting passes the request without examining it`() {
        manager.disableAll()
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        verify(exactly = 0) { request.headers() }
        verify(exactly = 0) { request.body() }
        verify(exactly = 0) { request.withBody(any<BurpBytes>()) }
    }
    @Test fun `inconsistent request length is forwarded unchanged`() {
        every { request.headerValue("Content-Length") } returns "1"
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        verify(exactly = 0) { request.withBody(any<BurpBytes>()) }
    }
    @Test fun `scope failures encoded bodies and exceptions leave original request`() {
        every { request.isInScope } returns false
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify { ProxyRequestToBeSentAction.continueWith(request) }
        verify(exactly = 0) { request.withBody(any<BurpBytes>()) }
        every { request.hasHeader("Content-Encoding") } returns true
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify(exactly = 2) { ProxyRequestToBeSentAction.continueWith(request) }
        every { request.headers() } throws IllegalStateException("sensitive")
        RewriteProxyHandler(manager).handleRequestToBeSent(request)
        verify(exactly = 3) { ProxyRequestToBeSentAction.continueWith(request) }
    }
}
