package net.portswigger.mcp.config

/** Fixed synthetic loopback targets shared by scope setup and unattended policy checks. */
object LocalTestTargets {
    const val HOST = "127.0.0.1"
    const val PORT = 8000
    const val ALLOWLIST_ENTRY = "$HOST:$PORT"
    const val RULE_AUTHORITY_URL = "http://$HOST:$PORT"

    val paths = listOf(
        "/test-html",
        "/test-post",
        "/test-form",
        "/test-upload",
        "/test-cancel",
        "/test-timeout",
        "/test-session-expiry",
        "/test-concurrent-a",
        "/test-concurrent-b"
    )

    val urls = paths.map { "http://$HOST:$PORT$it" }
}
