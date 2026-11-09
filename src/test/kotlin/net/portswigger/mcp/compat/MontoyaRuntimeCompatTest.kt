package net.portswigger.mcp.compat

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import net.portswigger.mcp.tools.BurpHttpRequestExecutor
import net.portswigger.mcp.tools.McpToolError
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking

class MontoyaRuntimeCompatTest {
    @Test
    fun `old Montoya surface is detected and newer features report explicit fallbacks`() {
        assertFalse(MontoyaApi::class.java.methods.any { it.name == "project" })
        assertFalse(RequestOptions::class.java.methods.any { it.name == "withResponseTimeout" })
        assertFalse(ProxyHttpRequestResponse::class.java.methods.any { it.name == "id" })

        val api = mockk<MontoyaApi>(relaxed = true)
        val project = MontoyaRuntimeCompat.projectInfo(api)
        assertFalse(project.available)
        assertTrue(project.reason!!.contains("Burp 2024.1"))
        assertNull(MontoyaRuntimeCompat.organizerItems(api))
        assertFalse(MontoyaRuntimeCompat.withResponseTimeout(mockk<RequestOptions>(), 1_000).configuredInBurp)
    }

    @Test
    fun `proxy history ID fallback is deterministic and does not expose message content`() {
        val item = mockk<ProxyHttpRequestResponse>(relaxed = true)
        val request = mockk<HttpRequest>(relaxed = true)
        every { item.finalRequest() } returns request
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns 8080
        every { request.url() } returns "http://127.0.0.1:8080/local"
        every { request.toByteArray().getBytes() } returns "GET /local HTTP/1.1\r\n\r\n".toByteArray()

        val first = MontoyaRuntimeCompat.historyId(item)
        assertTrue(first > 0)
        assertEquals(first, MontoyaRuntimeCompat.historyId(item))
    }

    @Test
    fun `native history ID is used when the loaded implementation provides it`() {
        val proxy = Proxy.newProxyInstance(
            ProxyHttpRequestResponse::class.java.classLoader,
            arrayOf(ProxyHttpRequestResponse::class.java, NativeId::class.java)
        ) { _, method, _ -> if (method.name == "id") 7341 else null } as ProxyHttpRequestResponse

        assertEquals(7341, MontoyaRuntimeCompat.historyId(proxy))
    }

    @Test
    fun `newer response timeout option is invoked by runtime reflection`() {
        lateinit var runtimeOptions: RequestOptions
        runtimeOptions = Proxy.newProxyInstance(
            RequestOptions::class.java.classLoader,
            arrayOf(RequestOptions::class.java, TimeoutMethod::class.java)
        ) { _, method, _ -> if (method.name == "withResponseTimeout") runtimeOptions else null } as RequestOptions

        val result = MontoyaRuntimeCompat.withResponseTimeout(runtimeOptions, 9_000)
        assertTrue(result.configuredInBurp)
        assertSame(runtimeOptions, result.options)
    }

    @Test
    fun `old runtime has a bounded MCP wait and does not automatically retry`() = runBlocking {
        val api = mockk<MontoyaApi>(relaxed = true)
        val http = mockk<Http>()
        val request = mockk<HttpRequest>()
        val options = mockk<RequestOptions>()
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { api.http() } returns http
        every { http.sendRequest(request, options) } answers {
            started.countDown()
            release.await()
            mockk<HttpRequestResponse>(relaxed = true)
        }

        val error = try {
            runCatching { BurpHttpRequestExecutor.send(api, request, options, 50) }.exceptionOrNull()
        } finally {
            release.countDown()
        }
        assertTrue(started.await(1, TimeUnit.SECONDS))
        assertTrue(error is McpToolError)
        assertTrue(error!!.message!!.contains("not retried"))
        assertTrue(error.message!!.contains("may finish the request in the background"))
    }

    private interface NativeId { fun id(): Int }
    private interface TimeoutMethod : RequestOptions { fun withResponseTimeout(timeoutMillis: Long): RequestOptions }
}
