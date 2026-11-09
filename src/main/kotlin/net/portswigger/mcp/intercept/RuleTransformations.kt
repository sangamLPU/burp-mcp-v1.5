package net.portswigger.mcp.intercept

import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal sealed interface MatchResult {
    data object MATCH : MatchResult
    data object NO_MATCH : MatchResult
    data class UNSUPPORTED(val code: String) : MatchResult
}

/** Bounded deterministic parsers and transformations. Nothing here can make an authorization decision. */
internal object RuleTransformations {
    class UnsupportedRuleMessage(val code: String) : IllegalArgumentException(code)
    private val json = Json { isLenient = false; ignoreUnknownKeys = false; allowSpecialFloatingPointValues = false }
    private val protectedHeaders = setOf(
        "host", "content-length", "transfer-encoding", "connection", "upgrade", "authorization",
        "proxy-authorization", "cookie", "cookie2", "set-cookie", "x-mcp-test-run",
        "x-mcp-server-identity", "x-mcp-test-id"
    )

    fun validate(t: RuleTransformation) {
        when (t.type) {
            RuleTransformType.SET_JSON_FIELD -> {
                val path = t.path
                val valueJson = t.valueJson
                require(path != null && valueJson != null) { "SET_JSON_FIELD requires path and valueJson" }
                parseJsonPath(path); validateJsonLiteral(valueJson, MAX_JSON_LITERAL_CHARS)
            }
            RuleTransformType.REMOVE_JSON_FIELD -> {
                val path = t.path
                require(path != null) { "REMOVE_JSON_FIELD requires path" }
                parseJsonPath(path)
            }
            RuleTransformType.SET_QUERY_PARAMETER, RuleTransformType.SET_FORM_FIELD -> {
                val value = t.value
                require(validName(t.name) && value != null && value.length <= 2048) { "Set parameter requires a valid name and value" }
            }
            RuleTransformType.REMOVE_QUERY_PARAMETER, RuleTransformType.REMOVE_FORM_FIELD -> require(validName(t.name)) { "Remove parameter requires a valid name" }
            RuleTransformType.SET_REQUEST_HEADER, RuleTransformType.SET_RESPONSE_HEADER -> {
                val name = t.name ?: ""
                require(validHeaderName(name) && name.lowercase() !in protectedHeaders && validHeaderValue(t.value)) { "Invalid or protected header transformation" }
            }
            RuleTransformType.REMOVE_REQUEST_HEADER, RuleTransformType.REMOVE_RESPONSE_HEADER -> {
                val name = t.name ?: ""
                require(validHeaderName(name) && name.lowercase() !in protectedHeaders) { "Invalid or protected header transformation" }
            }
            RuleTransformType.REPLACE_EXACT_TEXT -> {
                val search = t.search
                val replacement = t.replacement
                require(!search.isNullOrEmpty() && search.length <= 4096 && replacement != null && replacement.length <= 8192) { "Exact text replacement requires bounded search and replacement values" }
                require(search.none { it.isISOControl() && it !in "\r\n\t" } && replacement.none { it.isISOControl() && it !in "\r\n\t" }) { "Text replacement contains control characters" }
            }
        }
    }

    fun mutationKey(t: RuleTransformation): String = when (t.type) {
        RuleTransformType.SET_JSON_FIELD, RuleTransformType.REMOVE_JSON_FIELD -> "json:${t.path}"
        RuleTransformType.SET_QUERY_PARAMETER, RuleTransformType.REMOVE_QUERY_PARAMETER -> "query:${t.name}"
        RuleTransformType.SET_FORM_FIELD, RuleTransformType.REMOVE_FORM_FIELD -> "form:${t.name}"
        RuleTransformType.SET_REQUEST_HEADER, RuleTransformType.REMOVE_REQUEST_HEADER -> "request-header:${t.name?.lowercase()}"
        RuleTransformType.SET_RESPONSE_HEADER, RuleTransformType.REMOVE_RESPONSE_HEADER -> "response-header:${t.name?.lowercase()}"
        RuleTransformType.REPLACE_EXACT_TEXT -> "text:${t.search}"
    }

    fun validateJsonLiteral(text: String, maxCharacters: Int) {
        require(text.length in 1..maxCharacters) { "JSON_VALUE_SIZE" }
        try {
            DuplicateKeyGuard(text).verify()
        } catch (_: JsonNestingTooDeepException) {
            throw IllegalArgumentException("JSON_NESTING_TOO_DEEP")
        } catch (_: DuplicateJsonKeyException) {
            throw IllegalArgumentException("DUPLICATE_JSON_KEY")
        } catch (_: Exception) {
            throw IllegalArgumentException("INVALID_JSON")
        }
        try { json.parseToJsonElement(text) }
        catch (_: Exception) { throw IllegalArgumentException("INVALID_JSON") }
    }

    fun overlaps(a: RuleTransformation, b: RuleTransformation): Boolean {
        val aJson = a.type in setOf(RuleTransformType.SET_JSON_FIELD, RuleTransformType.REMOVE_JSON_FIELD)
        val bJson = b.type in setOf(RuleTransformType.SET_JSON_FIELD, RuleTransformType.REMOVE_JSON_FIELD)
        val aText = a.type == RuleTransformType.REPLACE_EXACT_TEXT
        val bText = b.type == RuleTransformType.REPLACE_EXACT_TEXT
        val bodyTypes = setOf(
            RuleTransformType.SET_JSON_FIELD, RuleTransformType.REMOVE_JSON_FIELD,
            RuleTransformType.SET_FORM_FIELD, RuleTransformType.REMOVE_FORM_FIELD,
            RuleTransformType.REPLACE_EXACT_TEXT
        )
        if ((aText && b.type in bodyTypes) || (bText && a.type in bodyTypes)) return true
        if (aJson && bJson) {
            val left = parseJsonPath(a.path!!)
            val right = parseJsonPath(b.path!!)
            return left == right || left.size < right.size && right.take(left.size) == left || right.size < left.size && left.take(right.size) == right
        }
        return mutationKey(a) == mutationKey(b)
    }

    fun matches(c: RuleMatchConditions, message: RuleHttpMessage): MatchResult {
        val uri = runCatching { URI(message.url) }.getOrElse { return MatchResult.UNSUPPORTED("INVALID_URL") }
        val path = uri.rawPath.ifBlank { "/" }
        if (c.method != null && !message.method.equals(c.method, ignoreCase = true)) return MatchResult.NO_MATCH
        if (c.path != null && path != c.path) return MatchResult.NO_MATCH
        if (c.pathPrefix != null && !path.startsWith(c.pathPrefix)) return MatchResult.NO_MATCH
        if (c.responseStatus != null && message.statusCode != c.responseStatus) return MatchResult.NO_MATCH
        if (c.headerName != null) {
            val values = message.headers.filter { it.name.equals(c.headerName, true) }.map { it.value }
            if (values.isEmpty() || (c.headerValue != null && c.headerValue !in values)) return MatchResult.NO_MATCH
        }
        if (c.contentType != null) {
            val expectedType = c.contentType.substringBefore(';').trim()
            val contentTypes = message.headers.filter { it.name.equals("Content-Type", true) }
            if (contentTypes.size > 1) return MatchResult.UNSUPPORTED("AMBIGUOUS_CONTENT_TYPE")
            if (contentTypes.singleOrNull()?.value?.substringBefore(';')?.trim()?.equals(expectedType, true) != true) return MatchResult.NO_MATCH
        }
        if (c.queryParameterName != null) {
            val values = try { parsePairs(uri.rawQuery.orEmpty()).filter { it.first == c.queryParameterName }.map { it.second } }
                catch (e: UnsupportedRuleMessage) { return MatchResult.UNSUPPORTED(e.code) }
                catch (_: Exception) { return MatchResult.UNSUPPORTED("INVALID_QUERY") }
            if (values.isEmpty() || (c.queryParameterValue != null && c.queryParameterValue !in values)) return MatchResult.NO_MATCH
        }
        if (c.jsonPath != null) {
            val root = try { parseJsonBody(message) } catch (e: UnsupportedRuleMessage) { return MatchResult.UNSUPPORTED(e.code) }
                catch (_: Exception) { return MatchResult.UNSUPPORTED("INVALID_JSON") }
            val actual = runCatching { getJson(root, parseJsonPath(c.jsonPath)) }.getOrNull() ?: return MatchResult.NO_MATCH
            val expected = runCatching { json.parseToJsonElement(c.jsonValueJson!!) }.getOrElse { return MatchResult.UNSUPPORTED("INVALID_RULE_JSON") }
            if (actual != expected) return MatchResult.NO_MATCH
        }
        if (c.formFieldName != null) {
            val values = try { parseForm(message).filter { it.first == c.formFieldName }.map { it.second } }
                catch (e: UnsupportedRuleMessage) { return MatchResult.UNSUPPORTED(e.code) }
                catch (_: Exception) { return MatchResult.UNSUPPORTED("INVALID_FORM") }
            if (values.isEmpty() || (c.formFieldValue != null && c.formFieldValue !in values)) return MatchResult.NO_MATCH
        }
        return MatchResult.MATCH
    }

    fun applyAll(spec: InterceptionRuleSpec, input: RuleHttpMessage): RuleHttpMessage = spec.transformations.fold(input, ::apply)

    fun apply(message: RuleHttpMessage, t: RuleTransformation): RuleHttpMessage {
        validate(t)
        var result = message
        when (t.type) {
            RuleTransformType.SET_JSON_FIELD, RuleTransformType.REMOVE_JSON_FIELD -> {
                val root = parseJsonBody(message)
                val targetPath = parseJsonPath(t.path!!)
                val value = if (t.type == RuleTransformType.SET_JSON_FIELD) json.parseToJsonElement(t.valueJson!!) else null
                result = withTextBody(message, json.encodeToString(JsonElement.serializer(), mutateJson(root, targetPath, value, t.type == RuleTransformType.REMOVE_JSON_FIELD)))
            }
            RuleTransformType.SET_QUERY_PARAMETER, RuleTransformType.REMOVE_QUERY_PARAMETER -> {
                if (message.direction != RuleDirection.REQUEST) return message
                val uri = URI(message.url)
                val query = mutatePairs(uri.rawQuery.orEmpty(), t.name!!, t.value, t.type == RuleTransformType.REMOVE_QUERY_PARAMETER)
                result = message.copy(url = composeUrl(uri, query))
            }
            RuleTransformType.SET_FORM_FIELD, RuleTransformType.REMOVE_FORM_FIELD -> {
                if (message.direction != RuleDirection.REQUEST) return message
                ensureTextBody(message, "application/x-www-form-urlencoded")
                val text = decodeUtf8(message.body)
                result = withTextBody(message, mutatePairs(text, t.name!!, t.value, t.type == RuleTransformType.REMOVE_FORM_FIELD))
            }
            RuleTransformType.SET_REQUEST_HEADER, RuleTransformType.SET_RESPONSE_HEADER -> {
                val expected = if (t.type == RuleTransformType.SET_REQUEST_HEADER) RuleDirection.REQUEST else RuleDirection.RESPONSE
                if (message.direction != expected) return message
                result = message.copy(headers = message.headers.filterNot { it.name.equals(t.name, true) } + RuleHeader(t.name!!, t.value!!))
            }
            RuleTransformType.REMOVE_REQUEST_HEADER, RuleTransformType.REMOVE_RESPONSE_HEADER -> {
                val expected = if (t.type == RuleTransformType.REMOVE_REQUEST_HEADER) RuleDirection.REQUEST else RuleDirection.RESPONSE
                if (message.direction != expected) return message
                result = message.copy(headers = message.headers.filterNot { it.name.equals(t.name, true) })
            }
            RuleTransformType.REPLACE_EXACT_TEXT -> {
                ensurePlainTextBody(message)
                val text = decodeUtf8(message.body)
                if (!text.contains(t.search!!)) throw UnsupportedRuleMessage("TEXT_NOT_FOUND")
                result = withTextBody(message, text.replace(t.search, t.replacement!!))
            }
        }
        validateFraming(result)
        require(result.body.size <= InterceptionRuleEngine.MAX_MESSAGE_BYTES) { "BODY_TOO_LARGE" }
        return result
    }

    fun byteAndMetadataEqual(a: RuleHttpMessage, b: RuleHttpMessage): Boolean =
        a.url == b.url && a.headers == b.headers && a.body.contentEquals(b.body) && a.statusCode == b.statusCode

    fun parseJsonPath(path: String): List<Any> {
        require(path.length in 2..256 && path.startsWith('$')) { "JSON path must start with $" }
        val result = mutableListOf<Any>(); var i = 1
        while (i < path.length) when (path[i]) {
            '.' -> {
                i++; val start = i
                while (i < path.length && (path[i].isLetterOrDigit() || path[i] == '_' || path[i] == '-')) i++
                require(i > start) { "Invalid JSON path member" }; result += path.substring(start, i)
            }
            '[' -> {
                val end = path.indexOf(']', i + 1); require(end > i + 1) { "Invalid JSON path array index" }
                val index = path.substring(i + 1, end); require(index.length <= 6 && index.all(Char::isDigit)) { "Only bounded non-negative array indices are supported" }
                result += index.toInt(); i = end + 1
            }
            else -> error("Only dot members and numeric array indices are supported")
        }
        require(result.isNotEmpty()) { "JSON root replacement is not supported" }
        return result
    }

    private fun parseJsonBody(message: RuleHttpMessage): JsonElement {
        ensureTextBody(message, "application/json")
        val text = decodeUtf8(message.body); require(text.length <= InterceptionRuleEngine.MAX_MESSAGE_BYTES)
        try {
            DuplicateKeyGuard(text).verify()
        } catch (_: JsonNestingTooDeepException) {
            throw UnsupportedRuleMessage("JSON_NESTING_TOO_DEEP")
        } catch (_: DuplicateJsonKeyException) {
            throw UnsupportedRuleMessage("DUPLICATE_JSON_KEY")
        } catch (_: Exception) {
            throw UnsupportedRuleMessage("INVALID_JSON")
        }
        return try {
            json.parseToJsonElement(text)
        } catch (_: Exception) {
            throw UnsupportedRuleMessage("INVALID_JSON")
        }
    }
    private fun getJson(root: JsonElement, path: List<Any>): JsonElement? = path.fold(root as JsonElement?) { current, segment ->
        when { current == null -> null; segment is String -> (current as? JsonObject)?.get(segment); else -> (current as? JsonArray)?.getOrNull(segment as Int) }
    }
    private fun mutateJson(root: JsonElement, path: List<Any>, value: JsonElement?, remove: Boolean): JsonElement {
        fun mutate(node: JsonElement, depth: Int): JsonElement {
            val segment = path[depth]; val terminal = depth == path.lastIndex
            if (segment is String) {
                val obj = node as? JsonObject ?: throw UnsupportedRuleMessage("JSON_PATH_TYPE_MISMATCH")
                val members = obj.toMutableMap()
                if (terminal) {
                    if (remove) require(members.remove(segment) != null) { "JSON_FIELD_MISSING" } else members[segment] = value!!
                } else members[segment] = mutate(members[segment] ?: throw UnsupportedRuleMessage("JSON_PATH_MISSING_PARENT"), depth + 1)
                return JsonObject(members)
            }
            val array = node as? JsonArray ?: throw UnsupportedRuleMessage("JSON_PATH_TYPE_MISMATCH")
            val index = segment as Int; require(index in array.indices) { "JSON_ARRAY_INDEX_MISSING" }
            val members = array.toMutableList()
            if (terminal) { if (remove) members.removeAt(index) else members[index] = value!! } else members[index] = mutate(members[index], depth + 1)
            return JsonArray(members)
        }
        return mutate(root, 0)
    }

    private fun ensureTextBody(message: RuleHttpMessage, expected: String) {
        require(message.body.size <= InterceptionRuleEngine.MAX_MESSAGE_BYTES) { "BODY_TOO_LARGE" }
        if (message.headers.any { it.name.equals("Content-Encoding", true) && it.value.isNotBlank() && !it.value.equals("identity", true) }) throw UnsupportedRuleMessage("CONTENT_ENCODING_UNSUPPORTED")
        val types = message.headers.filter { it.name.equals("Content-Type", true) }
        if (types.size > 1) throw UnsupportedRuleMessage("AMBIGUOUS_CONTENT_TYPE")
        val type = types.singleOrNull()?.value.orEmpty()
        if (type.isNotEmpty() && !type.substringBefore(';').trim().equals(expected, true)) throw UnsupportedRuleMessage("CONTENT_TYPE_MISMATCH")
        ensureUtf8Charset(type)
        if (message.headers.any { it.name.equals("Transfer-Encoding", true) }) throw UnsupportedRuleMessage("TRANSFER_ENCODING_UNSUPPORTED")
        validateFraming(message); decodeUtf8(message.body)
    }
    private fun ensurePlainTextBody(message: RuleHttpMessage) {
        if (message.body.size > InterceptionRuleEngine.MAX_MESSAGE_BYTES) throw UnsupportedRuleMessage("BODY_TOO_LARGE")
        if (message.headers.any { it.name.equals("Content-Encoding", true) && it.value.isNotBlank() && !it.value.equals("identity", true) }) throw UnsupportedRuleMessage("CONTENT_ENCODING_UNSUPPORTED")
        if (message.headers.any { it.name.equals("Transfer-Encoding", true) }) throw UnsupportedRuleMessage("TRANSFER_ENCODING_UNSUPPORTED")
        val types = message.headers.filter { it.name.equals("Content-Type", true) }
        if (types.size > 1) throw UnsupportedRuleMessage("AMBIGUOUS_CONTENT_TYPE")
        val contentType = types.singleOrNull()?.value.orEmpty()
        ensureUtf8Charset(contentType)
        val type = contentType.substringBefore(';').trim().lowercase()
        if (type !in setOf("text/plain", "text/html")) throw UnsupportedRuleMessage("TEXT_CONTENT_TYPE_UNSUPPORTED")
        validateFraming(message)
        val text = decodeUtf8(message.body)
        if (text.any { it.isISOControl() && it !in "\r\n\t" }) throw UnsupportedRuleMessage("TEXT_CONTROL_UNSUPPORTED")
    }
    private fun ensureUtf8Charset(contentType: String) {
        val charsets = contentType.split(';').drop(1).map(String::trim)
            .filter { it.substringBefore('=').trim().equals("charset", true) }
        if (charsets.size > 1 || charsets.any {
                !Regex("(?i)^charset\\s*=\\s*(?:utf-8|\"utf-8\"|'utf-8')\\s*$").matches(it)
            }) throw UnsupportedRuleMessage("CHARSET_UNSUPPORTED")
    }
    private fun withTextBody(message: RuleHttpMessage, text: String): RuleHttpMessage {
        val bytes = text.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= InterceptionRuleEngine.MAX_MESSAGE_BYTES) { "BODY_TOO_LARGE" }
        val lengths = message.headers.filter { it.name.equals("Content-Length", true) }
        val headers = if (lengths.isEmpty()) message.headers + RuleHeader("Content-Length", bytes.size.toString())
            else message.headers.map { if (it.name.equals("Content-Length", true)) it.copy(value = bytes.size.toString()) else it }
        return message.copy(headers = headers, body = bytes)
    }
    private fun validateFraming(message: RuleHttpMessage) {
        val lengths = message.headers.filter { it.name.equals("Content-Length", true) }
        if (lengths.size > 1) throw UnsupportedRuleMessage("AMBIGUOUS_CONTENT_LENGTH")
        val length = lengths.singleOrNull()?.value?.toLongOrNull()
        if (lengths.isNotEmpty() && (length == null || length != message.body.size.toLong())) throw UnsupportedRuleMessage("INVALID_CONTENT_LENGTH")
    }
    private fun decodeUtf8(bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Exception) { throw UnsupportedRuleMessage("BODY_NOT_UTF8_TEXT") }
    private fun parseForm(message: RuleHttpMessage): List<Pair<String,String>> {
        ensureTextBody(message, "application/x-www-form-urlencoded"); return parsePairs(decodeUtf8(message.body))
    }
    private fun parsePairs(raw: String): List<Pair<String,String>> {
        if (raw.isEmpty()) return emptyList()
        require(raw.length <= 8_192) { "ENCODED_DATA_TOO_LARGE" }
        val parts = raw.split('&')
        if (parts.size > 256) throw UnsupportedRuleMessage("TOO_MANY_PARAMETERS")
        return parts.map { part ->
            val equals = part.indexOf('='); val key = if (equals < 0) part else part.substring(0, equals); val value = if (equals < 0) "" else part.substring(equals + 1)
            URLDecoder.decode(key, StandardCharsets.UTF_8) to URLDecoder.decode(value, StandardCharsets.UTF_8)
        }
    }
    private fun mutatePairs(raw: String, name: String, value: String?, remove: Boolean): String {
        require(raw.length <= 8_192) { "ENCODED_DATA_TOO_LARGE" }
        val output = mutableListOf<String>(); var found = false
        (if (raw.isEmpty()) emptyList() else raw.split('&')).forEach { part ->
            val equals = part.indexOf('='); val rawName = if (equals < 0) part else part.substring(0, equals); val rawValue = if (equals < 0) "" else part.substring(equals + 1)
            val decoded = runCatching { URLDecoder.decode(rawName, StandardCharsets.UTF_8) }.getOrElse { throw UnsupportedRuleMessage("INVALID_ENCODED_NAME") }
            if (decoded == name) { found = true; if (!remove) output += "$rawName=${encode(value!!)}" }
            else output += if (equals < 0) part else "$rawName=$rawValue"
        }
        if (!remove && !found) output += "${encode(name)}=${encode(value!!)}"
        return output.joinToString("&")
    }
    private fun composeUrl(uri: URI, query: String): String {
        val base = "${uri.scheme}://${uri.rawAuthority}${uri.rawPath.ifBlank { "/" }}"
        return if (query.isEmpty()) base else "$base?$query"
    }
    private fun encode(s: String) = URLEncoder.encode(s, StandardCharsets.UTF_8)
    private fun validName(s: String?) = s != null && s.length in 1..128 && s.none(Char::isISOControl)
    private fun validHeaderName(s: String?) = s != null && s.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$"))
    private fun validHeaderValue(s: String?) = s != null && s.length <= 8192 && s.none { it.isISOControl() && it != '\t' }

    private class DuplicateJsonKeyException : IllegalArgumentException()
    private class JsonNestingTooDeepException : IllegalArgumentException()
    private const val MAX_JSON_LITERAL_CHARS = 4_096

    /** Detects duplicate object names before a map-based JSON parser could collapse them. */
    private class DuplicateKeyGuard(private val text: String) {
        companion object { private const val MAX_JSON_NESTING = 64 }
        private var index = 0
        fun verify() { spaces(); readValue(0); spaces(); require(index == text.length) { "Invalid trailing JSON" } }
        private fun readValue(depth: Int) {
            spaces(); require(index < text.length) { "Unexpected end of JSON" }
            when (text[index]) {
                '{' -> { if (depth >= MAX_JSON_NESTING) throw JsonNestingTooDeepException(); readObject(depth + 1) }
                '[' -> { if (depth >= MAX_JSON_NESTING) throw JsonNestingTooDeepException(); readArray(depth + 1) }
                '"' -> readString()
                else -> { val start=index; while (index < text.length && text[index] !in ",]} \t\r\n") index++; require(index > start) { "Invalid JSON value" } }
            }
        }
        private fun readObject(depth: Int) {
            index++; spaces(); val keys=hashSetOf<String>(); if (consume('}')) return
            while (true) {
                spaces(); require(index < text.length && text[index] == '"') { "Expected object key" }
                val token=readString(); val key=(json.parseToJsonElement(token) as JsonPrimitive).content
                if (!keys.add(key)) throw DuplicateJsonKeyException()
                spaces(); require(consume(':')) { "Expected colon" }; readValue(depth); spaces()
                if (consume('}')) return; require(consume(',')) { "Expected object comma" }
            }
        }
        private fun readArray(depth: Int) {
            index++; spaces(); if (consume(']')) return
            while (true) { readValue(depth); spaces(); if (consume(']')) return; require(consume(',')) { "Expected array comma" } }
        }
        private fun readString(): String {
            val start=index; require(consume('"'))
            while (index < text.length) when (text[index++]) {
                '\\' -> { require(index < text.length); index++ }
                '"' -> return text.substring(start,index)
                else -> Unit
            }
            error("Unterminated JSON string")
        }
        private fun spaces() { while (index < text.length && text[index] in " \t\r\n") index++ }
        private fun consume(c: Char): Boolean { if (index < text.length && text[index] == c) { index++; return true }; return false }
    }
}
