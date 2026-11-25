package net.portswigger.mcp.rewrite

import kotlinx.serialization.json.*

/** Conservative common credential-name guard. Arbitrary application-specific secrets cannot be identified reliably. */
internal fun isSensitiveParameterName(name: String): Boolean {
    val n = name.lowercase().filter { it.isLetterOrDigit() }
    return n in setOf("password", "passwd", "passphrase", "pwd", "secret", "clientsecret", "apikey", "privatekey", "authorization", "cookie", "setcookie", "credential", "credentials", "sessionid") ||
        n == "token" || n.endsWith("token")
}

internal fun containsSensitiveJson(body: String): Boolean {
    // Validate depth and duplicate keys before walking; do not expose content in failure messages.
    replaceJsonField(body, listOf("\u0000never-match"), "null")
    fun contains(node: JsonElement): Boolean = when (node) {
        is JsonObject -> node.any { (name, value) -> isSensitiveParameterName(name) || contains(value) }
        is JsonArray -> node.any(::contains)
        else -> false
    }
    return contains(Json.parseToJsonElement(body))
}
