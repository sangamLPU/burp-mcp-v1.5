package net.portswigger.mcp.security

import kotlinx.coroutines.withTimeoutOrNull

/** Bounds time spent waiting for a person to answer a Burp-local approval prompt. */
object ApprovalTimeout {
    const val DEFAULT_TIMEOUT_MILLIS = 120_000L

    suspend fun <T : Any> await(action: String, timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS, prompt: suspend () -> T): T? {
        require(timeoutMillis in 1..DEFAULT_TIMEOUT_MILLIS) {
            "Approval timeout must be between 1 and $DEFAULT_TIMEOUT_MILLIS milliseconds"
        }
        val result = withTimeoutOrNull(timeoutMillis) { prompt() }
        if (result == null) {
            ActivityLog.record("approval", "timed_out", action)
        }
        return result
    }
}
