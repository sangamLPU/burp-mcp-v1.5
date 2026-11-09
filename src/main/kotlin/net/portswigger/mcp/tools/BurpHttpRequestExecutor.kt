package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.portswigger.mcp.compat.MontoyaRuntimeCompat
import java.util.concurrent.ExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/** Bounds MCP waiting even on Montoya versions without per-request response timeouts. */
internal object BurpHttpRequestExecutor {
    private const val WORKER_LIMIT = 4
    private val threadIds = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        0,
        WORKER_LIMIT,
        30,
        TimeUnit.SECONDS,
        SynchronousQueue(),
        ThreadFactory { task -> Thread(task, "burp-mcp-http-${threadIds.incrementAndGet()}").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy()
    )

    suspend fun send(
        api: MontoyaApi,
        request: HttpRequest,
        options: RequestOptions,
        timeoutMillis: Long
    ): HttpRequestResponse? = withContext(Dispatchers.IO) {
        val runtimeOptions = MontoyaRuntimeCompat.withResponseTimeout(options, timeoutMillis)
        val future = try {
            executor.submit<HttpRequestResponse?> { api.http().sendRequest(request, runtimeOptions.options) }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            throw McpToolError("Burp HTTP request capacity is full; no request was retried.")
        }
        try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            val limitation = if (runtimeOptions.configuredInBurp) "" else
                " Burp 2024.1 has no Montoya per-request timeout or cancellation API, so the MCP wait stopped but Burp may finish the request in the background."
            throw McpToolError("Burp HTTP request exceeded the ${timeoutMillis}ms MCP wait limit; it was not retried.$limitation")
        } catch (error: ExecutionException) {
            val cause = error.cause ?: error
            if (cause is RuntimeException) throw cause
            throw McpToolError("Burp HTTP request failed (${cause.javaClass.simpleName}).")
        } finally {
            if (!future.isDone) future.cancel(true)
        }
    }
}
