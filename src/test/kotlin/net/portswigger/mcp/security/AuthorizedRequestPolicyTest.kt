package net.portswigger.mcp.security

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.scope.Scope
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class AuthorizedRequestPolicyTest {
    private val api = mockk<MontoyaApi>()
    private val scope = mockk<Scope>()
    private val request = mockk<HttpRequest>()
    private val service = mockk<HttpService>()
    private val originalApprovalHandler = HttpRequestSecurity.approvalHandler
    private lateinit var config: McpConfig
    private var approvedCalls = 0

    @BeforeEach
    fun setup() {
        val values = mutableMapOf<String, Any>(
            "enabled" to true,
            "readOnlyMode" to false,
            "requireBearerToken" to true,
            "requireHttpRequestApproval" to true,
            "requireDataAccessApproval" to true,
            "host" to "127.0.0.1",
            "port" to 9876,
            "_autoApproveTargets" to ""
        )
        val storage = mockk<PersistedObject>()
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(), any()) } answers { values[firstArg()] = secondArg<Boolean>() }
        every { storage.setString(any(), any()) } answers { values[firstArg()] = secondArg<String>() }
        every { storage.setInteger(any(), any()) } answers { values[firstArg()] = secondArg<Int>() }
        val logging = mockk<Logging>(relaxed = true)
        config = McpConfig(storage, logging)
        config.addAutoApproveTarget("api.example.com:443")

        every { api.scope() } returns scope
        every { scope.isInScope(any()) } returns true
        every { request.httpService() } returns service
        every { service.host() } returns "api.example.com"
        every { service.port() } returns 443
        every { request.url() } returns "https://api.example.com/"
        every { request.toString() } returns "GET / HTTP/1.1"
        HttpRequestSecurity.approvalHandler = object : UserApprovalHandler {
            override suspend fun requestApproval(
                hostname: String, port: Int, config: McpConfig, requestContent: String?, api: MontoyaApi?
            ): Boolean {
                approvedCalls++
                return true
            }
        }
        RequestRateLimiter.resetForTests()
    }

    @AfterEach
    fun cleanup() {
        HttpRequestSecurity.approvalHandler = originalApprovalHandler
        RequestRateLimiter.resetForTests()
    }

    @Test
    fun `authorized request needs scope allowlist and one-time approval`() = runBlocking {
        assertTrue(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(1, approvedCalls)
    }

    @Test
    fun `read-only mode blocks before approval`() = runBlocking {
        config.readOnlyMode = true
        assertFalse(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(0, approvedCalls)
    }

    @Test
    fun `out-of-scope request is denied before approval`() = runBlocking {
        every { scope.isInScope(any()) } returns false
        assertFalse(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(0, approvedCalls)
    }

    @Test
    fun `request URL host and port must match the authorized Burp service`() = runBlocking {
        every { request.url() } returns "https://other.example.com/"
        assertFalse(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(0, approvedCalls)
    }

    @Test
    fun `request outside host allowlist is denied before scope check`() = runBlocking {
        config.clearAutoApproveTargets()
        assertFalse(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(0, approvedCalls)
    }

    @Test
    fun `rate limiter allows thirty requests per minute`() = runBlocking {
        repeat(30) {
            assertTrue(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        }
        assertFalse(HttpRequestSecurity.checkAuthorizedRequest(request, config, api, "test-send"))
        assertEquals(30, approvedCalls)
    }
}
