package net.portswigger.mcp.rewrite

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

@Serializable
data class GlobalParameterRule(val id: String, val name: String, val value: String, val locations: List<String>, val enabled: Boolean = false)

internal val globalLocations = listOf("query", "json", "form", "multipart")
internal const val MAX_REWRITE_BYTES = 1_048_576
internal fun validateGlobal(rule: GlobalParameterRule) {
    require(rule.name.isNotEmpty() && rule.name.length <= 256 && rule.name.none { it.isISOControl() })
    require(rule.value.length <= 65536 && rule.locations.isNotEmpty() && rule.locations.all { it in globalLocations })
    // Reject malformed UTF-16 instead of silently changing replacement bytes.
    StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(rule.value))
}

internal fun strictUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(ByteBuffer.wrap(bytes)).toString()

private fun decodeParameter(s: String): String {
    val out = ByteArrayOutputStream(); var i = 0
    while (i < s.length) {
        val c = s[i++]
        when (c) {
            '%' -> {
                require(i + 2 <= s.length)
                val high = hexDigit(s[i++])
                val low = hexDigit(s[i++])
                require(high >= 0 && low >= 0)
                out.write(high * 16 + low)
            }
            '+' -> out.write(32)
            else -> { require(c.code in 0x21..0x7e); out.write(c.code) }
        }
    }
    return strictUtf8(out.toByteArray())
}

private fun hexDigit(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> -1
}

/** First enabled rule in creation order wins for each name and location. */
internal fun rulesFor(rules: List<GlobalParameterRule>, location: String): Map<String, GlobalParameterRule> {
    val result = linkedMapOf<String, GlobalParameterRule>()
    rules.filter { location in it.locations && !isSensitiveParameterName(it.name) }.forEach { result.putIfAbsent(it.name, it) }
    return result
}

internal data class ParameterResult(val value: String, val matched: Set<String>)

internal fun rewriteEncoded(input: String, rules: Map<String, GlobalParameterRule>): ParameterResult {
    val matched = linkedSetOf<String>()
    require(input.length <= MAX_REWRITE_BYTES)
    val output = StringBuilder(input.length)
    val encoded = mutableMapOf<String, String>()
    input.splitToSequence('&').forEachIndexed { index, part ->
        val at = part.indexOf('='); val key = if (at < 0) part else part.substring(0, at)
        val decoded = decodeParameter(key)
        // Validate even unrelated values so an ambiguous input cannot be partially rewritten.
        if (at >= 0) decodeParameter(part.substring(at + 1))
        val rule = rules[decoded]
        val replacement = rule?.let { encoded.getOrPut(it.id) { URLEncoder.encode(it.value, StandardCharsets.UTF_8) } }
        val separator = if (index == 0) 0 else 1
        val size = if (replacement == null) part.length else key.length + 1 + replacement.length
        require(output.length + separator + size <= MAX_REWRITE_BYTES)
        if (separator != 0) output.append('&')
        if (rule == null || replacement == null) output.append(part) else {
            if (at < 0 || !part.regionMatches(at + 1, replacement, 0, replacement.length) ||
                part.length - at - 1 != replacement.length) matched.add(rule.id)
            output.append(key).append('=').append(replacement)
        }
    }
    return ParameterResult(output.toString(), matched)
}

private class BoundedEdits(private val input: String) {
    private val output = StringBuilder(input.length)
    private var cursor = 0
    private var projectedSize = input.length

    fun replace(start: Int, end: Int, replacement: String) {
        projectedSize += replacement.length - (end - start)
        require(projectedSize <= MAX_REWRITE_BYTES)
        output.append(input, cursor, start).append(replacement)
        cursor = end
    }

    fun finish(): String = if (cursor == 0) input else output.append(input, cursor, input.length).toString()
}

/** Rewrite scalar values without serializing unrelated JSON. Duplicate keys fail closed. */
internal fun rewriteGlobalJson(body: String, rules: Map<String, GlobalParameterRule>): ParameterResult {
    replaceJsonField(body, listOf("\u0000never-match"), "null") // full, depth-limited validation
    var pos = 0
    val edits = BoundedEdits(body)
    val encoded = mutableMapOf<String, String>()
    val matched = linkedSetOf<String>()
    fun ws() { while (pos < body.length && body[pos] in " \t\r\n") pos++ }
    fun stringEnd(): Int {
        require(body[pos++] == '"')
        while (pos < body.length) when (body[pos++]) {
            '\\' -> { require(pos < body.length); if (body[pos++] == 'u') pos += 4 }
            '"' -> return pos
        }
        error("invalid JSON")
    }
    fun value(rule: GlobalParameterRule?, depth: Int) {
        require(depth <= 128); ws(); val start = pos
        when (body[pos]) {
            '{' -> {
                require(rule == null) // never overwrite a whole container and unrelated fields
                pos++; ws()
                if (body[pos] != '}') while (true) {
                    ws(); val keyStart = pos; stringEnd(); val key = Json.decodeFromString<String>(body.substring(keyStart, pos))
                    ws(); require(body[pos++] == ':'); value(rules[key], depth + 1); ws()
                    if (body[pos] == '}') break else require(body[pos++] == ',')
                }
                pos++
            }
            '[' -> {
                require(rule == null)
                pos++; ws()
                if (body[pos] != ']') while (true) {
                    value(null, depth + 1); ws(); if (body[pos] == ']') break else require(body[pos++] == ',')
                }
                pos++
            }
            '"' -> stringEnd()
            else -> while (pos < body.length && body[pos] !in ",}] \t\r\n") pos++
        }
        if (rule != null) {
            val replacement = encoded.getOrPut(rule.id) { Json.encodeToString(rule.value) }
            if (pos - start != replacement.length || !body.regionMatches(start, replacement, 0, replacement.length)) {
                edits.replace(start, pos, replacement)
                matched.add(rule.id)
            }
        }
    }
    value(null, 0)
    return ParameterResult(edits.finish(), matched)
}

/** Byte-preserving multipart parser for conventional CRLF-framed text fields. */
internal fun rewriteMultipart(bytes: ByteArray, boundary: String, rules: Map<String, GlobalParameterRule>, skipFileUploads: Boolean = false): Pair<ByteArray, Set<String>> {
    require(boundary.length in 1..70 && boundary.matches(Regex("[A-Za-z0-9'()+_,./:=?-]+")))
    val input = bytes.toString(StandardCharsets.ISO_8859_1)
    val delimiter = "--$boundary"; require(input.startsWith("$delimiter\r\n"))
    var pos = delimiter.length + 2
    val edits = BoundedEdits(input)
    val encoded = mutableMapOf<String, String>()
    val matched = linkedSetOf<String>()
    while (true) {
        val headerEnd = input.indexOf("\r\n\r\n", pos); require(headerEnd >= 0 && headerEnd - pos <= 16384)
        val headers = input.substring(pos, headerEnd).split("\r\n")
        require(headers.all { it.contains(':') && !it.startsWith(' ') && !it.startsWith('\t') })
        val dispositions = headers.filter { it.substringBefore(':').equals("Content-Disposition", true) }
        require(dispositions.size == 1)
        val disposition = dispositions.single().substringAfter(':').trim()
        require(disposition.startsWith("form-data;", true))
        val names = Regex("(?:^|;)\\s*name=\"([^\"\\r\\n]*)\"", RegexOption.IGNORE_CASE).findAll(disposition).toList()
        val isFile = Regex("(?:^|;)\\s*filename\\*?\\s*=", RegexOption.IGNORE_CASE).containsMatchIn(disposition)
        require(!isFile || !skipFileUploads) { "File uploads are not rewritten." }
        require(names.size == 1)
        val dataStart = headerEnd + 4; val next = input.indexOf("\r\n$delimiter", dataStart); require(next >= 0)
        val rule = if (isFile) null else rules[names.single().groupValues[1]]
        if (rule != null) {
            require(headers.none { it.startsWith("Content-Transfer-Encoding:", true) || it.startsWith("Content-Encoding:", true) })
            val type = headers.filter { it.startsWith("Content-Type:", true) }
            require(type.size <= 1 && (type.isEmpty() || type.single().substringAfter(':').trim().matches(Regex("(?i)text/plain(?:\\s*;\\s*charset\\s*=\\s*\"?utf-8\"?)?"))))
            strictUtf8(bytes.copyOfRange(dataStart, next))
            require(!rule.value.contains("\r\n$delimiter"))
            val replacement = encoded.getOrPut(rule.id) { rule.value.toByteArray(StandardCharsets.UTF_8).toString(StandardCharsets.ISO_8859_1) }
            if (next - dataStart != replacement.length || !input.regionMatches(dataStart, replacement, 0, replacement.length)) {
                edits.replace(dataStart, next, replacement)
                matched.add(rule.id)
            }
        }
        pos = next + 2 + delimiter.length
        if (input.startsWith("--", pos)) { pos += 2; require(input.substring(pos) == "\r\n" || pos == input.length); break }
        require(input.startsWith("\r\n", pos)); pos += 2
    }
    return edits.finish().toByteArray(StandardCharsets.ISO_8859_1) to matched
}
