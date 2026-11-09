package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scope.Scope
import burp.api.montoya.http.message.requests.HttpRequest as MontoyaHttpRequest
import burp.api.montoya.persistence.PersistedObject
import io.mockk.every
import io.mockk.mockk
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.isAuthorizedRequest
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Assertions.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Real loopback HTTP traffic, with the local target first verified against scope and host allowlist. */
@Tag("loopback")
class DecisionQueueLocalHttpTest {
    @Test fun `queue decisions gate a real local HTTP exchange and drop prevents sending`() {
        val hits=AtomicInteger();val server=HttpServer.create(InetSocketAddress("127.0.0.1",0),0)
        server.createContext("/") { exchange ->
            hits.incrementAndGet()
            val bytes=("received:"+exchange.requestHeaders.getFirst("X-Test")).toByteArray()
            exchange.sendResponseHeaders(200,bytes.size.toLong());exchange.responseBody.use { it.write(bytes) };exchange.close()
        }
        server.start()
        val api = mockk<MontoyaApi>(relaxed = true)
        val values = mutableMapOf<String, Any>()
        val storage = mockk<PersistedObject>()
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg<Boolean>() }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        every { storage.setInteger(any(), any()) } answers { values[firstArg()] = secondArg<Int>() }
        val config = McpConfig(storage, api.logging())
        assertTrue(config.addAutoApproveTarget("127.0.0.1:${server.address.port}"))
        val request = mockk<MontoyaHttpRequest>(relaxed = true)
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns server.address.port
        every { request.url() } returns "http://127.0.0.1:${server.address.port}/"
        val scope = mockk<Scope>()
        every { api.scope() } returns scope
        every { scope.isInScope(any()) } returns true
        assertTrue(isAuthorizedRequest(request, api, config), "Loopback test server must pass Burp scope and explicit host allowlist")

        val queue=DecisionQueue<String>();val pool=Executors.newSingleThreadExecutor()
        try {
            val t=queue.offer("request","original",5000)!!
            val responseReady=CountDownLatch(1)
            val result=pool.submit<String?> {
                val header=queue.await(t) ?: return@submit null
                val response=HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI("http://127.0.0.1:${server.address.port}/")).header("X-Test",header).build(),HttpResponse.BodyHandlers.ofString())
                val heldResponse=queue.offer("response",response.body(),5000)!!
                responseReady.countDown();queue.await(heldResponse)
            }
            assertEquals(0,hits.get());assertFalse(result.isDone)
            queue.propose(t.id,0,"changed");queue.approve(t.id,1);queue.forward(t.id,1)
            assertTrue(responseReady.await(3,TimeUnit.SECONDS))
            val response=queue.list("response").single()
            assertEquals("received:changed",response.original);assertFalse(result.isDone)
            queue.propose(response.id,0,"modified downstream body");queue.approve(response.id,1);queue.forward(response.id,1)
            assertEquals("modified downstream body",result.get(1,TimeUnit.SECONDS))
            val dropped=queue.offer("request","never sent",1000)!!;queue.drop(dropped.id)
            assertNull(queue.await(dropped));assertEquals(1,hits.get())
        } finally { queue.cancelAll();pool.shutdownNow();server.stop(0) }
    }
}
