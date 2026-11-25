package net.portswigger.mcp.rewrite

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.proxy.http.*
import burp.api.montoya.http.message.requests.HttpRequest
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

class RewriteProxyHandler(private val manager: RewriteManager) : ProxyRequestHandler {
    override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction =
        ProxyRequestReceivedAction.continueWith(request)

    override fun handleRequestToBeSent(request: InterceptedRequest): ProxyRequestToBeSentAction = synchronized(manager) {
        if (!manager.isActive()) return ProxyRequestToBeSentAction.continueWith(request)
        val global = try { manager.globalFor(request.httpService().host(), request.isInScope) }
            catch (_: Exception) { manager.recordFailure(); return ProxyRequestToBeSentAction.continueWith(request) }
        if (global.isNotEmpty()) {
            val result = try { rewriteGlobal(request, global) } catch (_: Exception) {
                manager.recordSkip("unsupported or malformed request"); request
            } catch (_: StackOverflowError) { manager.recordSkip("excessive nesting"); request }
            return ProxyRequestToBeSentAction.continueWith(result)
        }
        val result = try {
            // Do not reinterpret encoded, chunked, ambiguous, or non-UTF-8 payloads.
            val headers = request.headers()
            if (headers.count { it.name().equals("Content-Type", true) } != 1 ||
                headers.count { it.name().equals("Content-Length", true) } > 1 ||
                request.hasHeader("Transfer-Encoding") || request.hasHeader("Content-Encoding")) return ProxyRequestToBeSentAction.continueWith(request)
            val parts = request.headerValue("Content-Type").split(';').map { it.trim() }
            if (parts.drop(1).any { !it.matches(Regex("(?i)charset\\s*=\\s*\"?utf-8\"?")) }) return ProxyRequestToBeSentAction.continueWith(request)
            val bytes = request.body().bytes
            validateBodyLength(request, bytes.size)
            val body = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            val matches = mutableListOf<String>()
            val rewritten = manager.rewrite(request.httpService().host(), request.method(), request.pathWithoutQuery(), parts[0], request.isInScope, body, matches::add)
                ?: return ProxyRequestToBeSentAction.continueWith(request)
            val replacement = rewritten.toByteArray(StandardCharsets.UTF_8)
            require(replacement.size <= MAX_REWRITE_BYTES)
            var modified = request.withBody(BurpBytes.byteArray(*replacement))
            if (request.hasHeader("Content-Length")) modified = modified.withUpdatedHeader("Content-Length", replacement.size.toString())
            matches.forEach { manager.recordJsonMatched(it) }
            manager.recordApplied()
            modified
        } catch (_: Exception) { manager.recordFailure(); request }
        return ProxyRequestToBeSentAction.continueWith(result)
    }

    private fun rewriteGlobal(request: InterceptedRequest, rules: List<GlobalParameterRule>): HttpRequest {
        val headers = request.headers()
        require(headers.count { it.name().equals("Content-Length", true) } <= 1)
        require(!request.hasHeader("Transfer-Encoding") && !request.hasHeader("Content-Encoding"))
        val path = request.path()
        val queryIndex = path.indexOf('?')
        var newPath = path
        val matches = mutableListOf<Pair<String, String>>()
        val jsonMatches = mutableListOf<String>()
        if (queryIndex >= 0 && rulesFor(rules, "query").isNotEmpty()) {
            val result = rewriteEncoded(path.substring(queryIndex + 1), rulesFor(rules, "query"))
            newPath = path.substring(0, queryIndex + 1) + result.value
            result.matched.forEach { matches.add(it to "query") }
        }
        val types = headers.filter { it.name().equals("Content-Type", true) }
        require(types.size <= 1)
        val contentType = if (types.isEmpty()) "" else request.headerValue("Content-Type")
        val media = contentType.substringBefore(';').trim().lowercase()
        val location = when {
            media == "application/json" || (media.startsWith("application/") && media.endsWith("+json")) -> "json"
            media == "application/x-www-form-urlencoded" -> "form"
            media == "multipart/form-data" -> "multipart"
            else -> ""
        }
        var newBody: ByteArray? = null
        if (location.isNotEmpty()) {
            val bytes = request.body().bytes
            validateBodyLength(request, bytes.size)
            if (location == "multipart") {
                val params = contentType.split(';').drop(1).map { it.trim() }
                require(params.size == 1 && params[0].startsWith("boundary=", true))
                val boundary = params[0].substringAfter('=').removeSurrounding("\"")
                val result = rewriteMultipart(bytes, boundary, rulesFor(rules, location), skipFileUploads = true)
                if (!result.first.contentEquals(bytes)) newBody = result.first
                result.second.forEach { matches.add(it to location) }
            } else {
                val params = contentType.split(';').drop(1).map { it.trim() }
                require(params.size <= 1 && params.all { it.matches(Regex("(?i)charset\\s*=\\s*\"?utf-8\"?")) })
                val body = strictUtf8(bytes)
                val protected = location == "json" && containsSensitiveJson(body)
                if (protected) manager.recordSkip("protected credential fields")
                val legacy = if (location == "json" && !protected) manager.rewrite(request.httpService().host(), request.method(), request.pathWithoutQuery(), media, request.isInScope, body, jsonMatches::add) ?: body else body
                val result = if (protected) ParameterResult(body, emptySet()) else if (location == "json") rewriteGlobalJson(legacy, rulesFor(rules, location)) else rewriteEncoded(legacy, rulesFor(rules, location))
                if (result.value != body) newBody = result.value.toByteArray(StandardCharsets.UTF_8)
                result.matched.forEach { matches.add(it to location) }
            }
        } else if (media.isNotEmpty() && rules.any { it.locations.any { loc -> loc != "query" } }) {
            manager.recordSkip("unsupported body content type; body retained")
        }
        if (newPath == path && newBody == null) return request
        require(newPath.length <= MAX_REWRITE_BYTES && (newBody?.size ?: 0) <= MAX_REWRITE_BYTES)
        var result: HttpRequest = request
        if (newPath != path) result = result.withPath(newPath)
        if (newBody != null) {
            result = result.withBody(BurpBytes.byteArray(*newBody))
            if (request.hasHeader("Content-Length")) result = result.withUpdatedHeader("Content-Length", newBody.size.toString())
        }
        matches.forEach { (id, loc) -> manager.recordGlobalMatched(id, loc) }
        jsonMatches.forEach { manager.recordJsonMatched(it) }
        manager.recordApplied()
        return result
    }

    private fun validateBodyLength(request: HttpRequest, size: Int) {
        require(size <= MAX_REWRITE_BYTES)
        if (request.hasHeader("Content-Length")) {
            val length = request.headerValue("Content-Length")
            require(length.matches(Regex("[0-9]+")) && length.toLongOrNull() == size.toLong())
        }
    }
}
