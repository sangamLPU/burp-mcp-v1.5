package net.portswigger.mcp.schema

import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.HttpRequestResponse
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Render known UTF-8 text bodies as Unicode; preserve Burp's original representation otherwise. */
internal fun HttpMessage.renderForMcp(): String {
    val original = toString()
    return try {
        if (hasHeader("Content-Encoding") || hasHeader("Transfer-Encoding")) return original
        if (headers().count { it.name().equals("Content-Type", ignoreCase = true) } != 1) return original
        val parts = headerValue("Content-Type").split(';').map { it.trim() }
        val media = parts.first().lowercase()
        val json = media == "application/json" || (media.startsWith("application/") && media.endsWith("+json"))
        val text = media.startsWith("text/")
        if (!json && !text) return original
        val charset = parts.drop(1).filter { it.substringBefore('=').trim().equals("charset", ignoreCase = true) }
        if (charset.size > 1 || (charset.isEmpty() && !json)) return original
        if (charset.isNotEmpty() && !charset.single().matches(Regex("(?i)charset\\s*=\\s*\"?utf-8\"?"))) return original
        val bytes = toByteArray().bytes
        val offset = bodyOffset()
        if (offset !in 0..bytes.size) return original
        val body = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, offset, bytes.size - offset)).toString()
        String(bytes, 0, offset, StandardCharsets.ISO_8859_1) + body
    } catch (_: Exception) {
        original
    }
}

/** Keep Montoya's existing request/response wrapper while fixing known UTF-8 message bodies. */
internal fun HttpRequestResponse.renderForMcp(): String {
    val original = toString()
    return try {
        val request = request() ?: return original
        val response = response() ?: return original
        val requestText = request.toString()
        val responseText = response.toString()
        val prefix = "HttpRequestResponse{httpRequest=" + requestText + ", httpResponse="
        val responseEnd = prefix.length + responseText.length
        if (!original.startsWith(prefix) || !original.regionMatches(prefix.length, responseText, 0, responseText.length) ||
            !original.startsWith(", messageAnnotations=", responseEnd)) return original
        "HttpRequestResponse{httpRequest=" + request.renderForMcp() + ", httpResponse=" +
            response.renderForMcp() + original.substring(responseEnd)
    } catch (_: Exception) {
        original
    }
}
