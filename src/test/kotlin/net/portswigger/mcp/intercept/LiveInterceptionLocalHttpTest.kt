package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest as MontoyaRequest
import burp.api.montoya.http.message.responses.HttpResponse as MontoyaResponse
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.http.*
import com.sun.net.httpserver.HttpServer
import io.mockk.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.security.RequestRateLimiter
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking

/** Exercises the installed Proxy handler callbacks with real loopback client/server HTTP traffic. */
@Tag("loopback")
class LiveInterceptionLocalHttpTest {
    @Test
    fun `approved header edits cross request and response callback boundaries on loopback`() = runBlocking {
        val serverReceivedRequest = AtomicReference<String?>()
        val serverReceivedPreservedHeader = AtomicReference<String?>()
        val bridgeProgress = AtomicReference("not started")
        val origin = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        origin.createContext("/") { exchange ->
            serverReceivedRequest.set(exchange.requestHeaders.getFirst("X-Burp-MCP-Test"))
            serverReceivedPreservedHeader.set(exchange.requestHeaders.getFirst("X-Preserve"))
            val body = "local-origin-body".toByteArray()
            exchange.responseHeaders.add("Content-Type", "text/plain")
            exchange.responseHeaders.add("X-Origin", "preserved")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        origin.start()

        val front = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val frontWorkers = Executors.newCachedThreadPool()
        front.executor = frontWorkers

        val api = mockk<MontoyaApi>(relaxed = true)
        val proxy = mockk<Proxy>(relaxed = true)
        val registration = mockk<Registration>(relaxed = true)
        val requestHandler = slot<ProxyRequestHandler>()
        val responseHandler = slot<ProxyResponseHandler>()
        every { api.proxy() } returns proxy
        every { api.scope().isInScope(any()) } returns true
        every { proxy.registerRequestHandler(capture(requestHandler)) } returns registration
        every { proxy.registerResponseHandler(capture(responseHandler)) } returns registration

        val values = mutableMapOf<String, Any>("readOnlyMode" to false, "bearerToken" to "local-test", "_autoApproveTargets" to "")
        val storage = mockk<PersistedObject>(relaxed = true)
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg<Boolean>() }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        every { storage.setInteger(any(), any()) } answers { values[firstArg()] = secondArg<Int>() }
        val config = McpConfig(storage, api.logging())
        assertTrue(config.addAutoApproveTarget("127.0.0.1:${origin.address.port}"))
        val live = LiveInterception(api, config)

        mockkStatic(ProxyRequestReceivedAction::class)
        mockkStatic(ProxyResponseReceivedAction::class)
        mockkObject(Dialogs)
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } returns 0
        every { ProxyRequestReceivedAction.doNotIntercept(any<MontoyaRequest>()) } answers {
            mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns firstArg() }
        }
        every { ProxyRequestReceivedAction.continueWith(any<MontoyaRequest>()) } answers {
            mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns firstArg() }
        }
        every { ProxyRequestReceivedAction.drop() } returns mockk(relaxed = true)
        every { ProxyResponseReceivedAction.doNotIntercept(any<MontoyaResponse>()) } answers {
            mockk<ProxyResponseReceivedAction>().also { action -> every { action.response() } returns firstArg() }
        }
        every { ProxyResponseReceivedAction.continueWith(any<MontoyaResponse>()) } answers {
            mockk<ProxyResponseReceivedAction>().also { action -> every { action.response() } returns firstArg() }
        }
        every { ProxyResponseReceivedAction.drop() } returns mockk(relaxed = true)

        fun awaitTicket(kind: String): DecisionQueue.Ticket<HeldMessage> {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (System.nanoTime() < deadline) {
                live.queue.list(kind).firstOrNull()?.let { return it }
                Thread.yield()
            }
            error("No local $kind was held by the registered Proxy callback; bridge=${bridgeProgress.get()}; events=${net.portswigger.mcp.security.ActivityLog.snapshot()}")
        }

        front.createContext("/") { exchange ->
            try {
                bridgeProgress.set("received browser request")
                val service = fakeService("127.0.0.1", origin.address.port)
                val path = exchange.requestURI.rawPath.ifBlank { "/" }
                val preserve = exchange.requestHeaders.getFirst("X-Preserve") ?: "keep"
                val interceptedRequest = fakeRequest(
                    service, exchange.requestMethod, path,
                    mapOf("Host" to "127.0.0.1:${origin.address.port}", "X-Preserve" to preserve), intercepted = true
                ) as InterceptedRequest
                bridgeProgress.set("calling registered request handler")
                val releasedRequest = requestHandler.captured.handleRequestReceived(interceptedRequest).request()
                bridgeProgress.set("request handler released")

                val originResponse = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI(releasedRequest.url()))
                        .header("X-Preserve", releasedRequest.headerValue("X-Preserve"))
                        .header("X-Burp-MCP-Test", releasedRequest.headerValue("X-Burp-MCP-Test").orEmpty())
                        .GET().build(),
                    HttpResponse.BodyHandlers.ofString()
                )
                val originBody = originResponse.body()
                val originHeaders = originResponse.headers().map().flatMap { (name, headers) ->
                    headers.map { "$name: $it" }
                }.joinToString("\r\n")
                val interceptedResponse = fakeResponse(
                    originResponse.statusCode(), originResponse.headers().map().mapValues { it.value.joinToString(", ") },
                    originBody, intercepted = true, initiatingRequest = releasedRequest
                ) as InterceptedResponse
                bridgeProgress.set("calling registered response handler")
                val releasedResponse = responseHandler.captured.handleResponseReceived(interceptedResponse).response()
                bridgeProgress.set("response handler released")

                releasedResponse.headers().forEach { header ->
                    if (header.name().lowercase() !in setOf("content-length", "transfer-encoding", "connection")) {
                        exchange.responseHeaders.add(header.name(), header.value())
                    }
                }
                val downstreamBody = releasedResponse.body().getBytes()
                exchange.sendResponseHeaders(releasedResponse.statusCode().toInt(), downstreamBody.size.toLong())
                exchange.responseBody.use { it.write(downstreamBody) }
            } catch (error: Throwable) {
                bridgeProgress.set("bridge error ${error.javaClass.simpleName}: ${error.message}")
                runCatching {
                    val bytes = (error.javaClass.simpleName + ": " + error.message.orEmpty()).toByteArray()
                    exchange.sendResponseHeaders(500, bytes.size.toLong())
                    exchange.responseBody.use { it.write(bytes) }
                }
            }
        }

        try {
            live.install()
            live.allowEdits = true
            live.startApprovedSession(60)
            live.setTimeout(60)
            RequestRateLimiter.resetForTests()
            front.start()

            val browser = Executors.newSingleThreadExecutor()
            try {
                val browserResponse = browser.submit<HttpResponse<String>> {
                    HttpClient.newHttpClient().send(
                        HttpRequest.newBuilder(URI("http://127.0.0.1:${front.address.port}/"))
                            .header("X-Preserve", "keep").GET().build(),
                        HttpResponse.BodyHandlers.ofString()
                    )
                }

                val requestTicket = awaitTicket("request")
                val requestRevision = live.propose(
                    requestTicket.id, "request", requestTicket.revision,
                    mapOf("X-Burp-MCP-Test" to "request-modified"), emptyList(), null, null
                )
                live.requestApproval(requestTicket.id, "request", requestRevision)
                assertEquals(requestRevision, live.queue.get(requestTicket.id).approvedRevision)
                live.forward(requestTicket.id, "request", requestRevision)

                val responseTicket = awaitTicket("response")
                val responseRevision = live.propose(
                    responseTicket.id, "response", responseTicket.revision,
                    mapOf("X-Burp-MCP-Test" to "response-modified"), emptyList(), null, null
                )
                live.requestApproval(responseTicket.id, "response", responseRevision)
                assertEquals(responseRevision, live.queue.get(responseTicket.id).approvedRevision)
                live.forward(responseTicket.id, "response", responseRevision)

                val received = browserResponse.get(5, TimeUnit.SECONDS)
                assertEquals("request-modified", serverReceivedRequest.get(), "The local origin must receive the edited request header")
                assertEquals("keep", serverReceivedPreservedHeader.get(), "The original request header must be preserved")
                assertEquals("response-modified", received.headers().firstValue("X-Burp-MCP-Test").orElse(null))
                assertEquals("preserved", received.headers().firstValue("X-Origin").orElse(null))
                assertEquals("local-origin-body", received.body(), "Response body must stay byte-for-byte equivalent")
                assertEquals(200, received.statusCode())
            } finally {
                browser.shutdownNow()
            }
        } finally {
            live.close()
            front.stop(0)
            frontWorkers.shutdownNow()
            origin.stop(0)
            unmockkStatic(ProxyRequestReceivedAction::class)
            unmockkStatic(ProxyResponseReceivedAction::class)
            unmockkObject(Dialogs)
        }
    }

    private fun fakeService(hostName: String, portNumber: Int): HttpService = mockk {
        every { host() } returns hostName
        every { port() } returns portNumber
        every { secure() } returns false
    }

    private fun fakeRequest(
        service: HttpService,
        methodName: String,
        path: String,
        sourceHeaders: Map<String, String>,
        intercepted: Boolean
    ): MontoyaRequest {
        val headers = LinkedHashMap(sourceHeaders)
        val request: MontoyaRequest = if (intercepted) mockk<InterceptedRequest>(relaxed = true) else mockk(relaxed = true)
        every { request.httpService() } returns service
        every { request.url() } returns "http://${service.host()}:${service.port()}$path"
        every { request.method() } returns methodName
        every { request.path() } returns path
        every { request.httpVersion() } returns "HTTP/1.1"
        every { request.hasHeader(any<String>()) } answers { headers.keys.any { it.equals(firstArg<String>(), true) } }
        every { request.headerValue(any<String>()) } answers { headers.entries.firstOrNull { it.key.equals(firstArg<String>(), true) }?.value }
        every { request.headers() } returns fakeHeaders(headers)
        every { request.toByteArray() } returns fakeByteArray(fakeRequestText(methodName, path, headers).toByteArray())
        every { request.body() } returns fakeByteArray(ByteArray(0))
        every { request.bodyToString() } returns ""
        every { request.withHeader(any<String>(), any<String>()) } answers {
            val next = LinkedHashMap(headers)
            next.keys.firstOrNull { it.equals(firstArg<String>(), true) }?.let(next::remove)
            next[firstArg<String>()] = secondArg<String>()
            fakeRequest(service, methodName, path, next, intercepted = false)
        }
        every { request.withRemovedHeader(any<String>()) } answers {
            val next = LinkedHashMap(headers)
            next.keys.filter { it.equals(firstArg<String>(), true) }.forEach(next::remove)
            fakeRequest(service, methodName, path, next, intercepted = false)
        }
        if (intercepted) every { (request as InterceptedRequest).isInScope() } returns true
        return request
    }

    private fun fakeResponse(
        status: Int,
        sourceHeaders: Map<String, String>,
        body: String,
        intercepted: Boolean = false,
        initiatingRequest: MontoyaRequest? = null
    ): MontoyaResponse {
        val headers = LinkedHashMap(sourceHeaders)
        val response: MontoyaResponse = if (intercepted) mockk<InterceptedResponse>(relaxed = true) else mockk(relaxed = true)
        every { response.statusCode() } returns status.toShort()
        every { response.reasonPhrase() } returns if (status == 200) "OK" else "HTTP"
        every { response.httpVersion() } returns "HTTP/1.1"
        every { response.hasHeader(any<String>()) } answers { headers.keys.any { it.equals(firstArg<String>(), true) } }
        every { response.headerValue(any<String>()) } answers { headers.entries.firstOrNull { it.key.equals(firstArg<String>(), true) }?.value }
        every { response.headers() } returns fakeHeaders(headers)
        every { response.body() } returns fakeByteArray(body.toByteArray())
        every { response.bodyToString() } returns body
        every { response.toByteArray() } returns fakeByteArray(fakeResponseText(status, headers, body).toByteArray())
        every { response.withAddedHeader(any<String>(), any<String>()) } answers {
            val next = LinkedHashMap(headers)
            next.keys.firstOrNull { it.equals(firstArg<String>(), true) }?.let(next::remove)
            next[firstArg<String>()] = secondArg<String>()
            fakeResponse(status, next, body)
        }
        every { response.withUpdatedHeader(any<String>(), any<String>()) } answers {
            val next = LinkedHashMap(headers)
            next.keys.firstOrNull { it.equals(firstArg<String>(), true) }?.let(next::remove)
            next[firstArg<String>()] = secondArg<String>()
            fakeResponse(status, next, body)
        }
        every { response.withRemovedHeader(any<String>()) } answers {
            val next = LinkedHashMap(headers)
            next.keys.filter { it.equals(firstArg<String>(), true) }.forEach(next::remove)
            fakeResponse(status, next, body)
        }
        if (intercepted) every { (response as InterceptedResponse).initiatingRequest() } returns initiatingRequest!!
        return response
    }

    private fun fakeHeaders(values: Map<String, String>): List<HttpHeader> = values.map { (headerName, headerValue) ->
        mockk {
            every { name() } returns headerName
            every { value() } returns headerValue
        }
    }

    private fun fakeByteArray(bytes: ByteArray): MontoyaByteArray = mockk(relaxed = true) {
        every { length() } returns bytes.size
        every { getBytes() } returns bytes.copyOf()
    }

    private fun fakeRequestText(method: String, path: String, headers: Map<String, String>): String =
        "$method $path HTTP/1.1\r\n" + headers.entries.joinToString("\r\n") { "${it.key}: ${it.value}" } + "\r\n\r\n"

    private fun fakeResponseText(status: Int, headers: Map<String, String>, body: String): String =
        "HTTP/1.1 $status OK\r\n" + headers.entries.joinToString("\r\n") { "${it.key}: ${it.value}" } + "\r\n\r\n$body"
}
