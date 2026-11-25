package net.portswigger.mcp.rewrite

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.proxy.http.*
import java.nio.charset.StandardCharsets

private val http2ProhibitedResponseHeaders = setOf("Connection", "Keep-Alive", "Proxy-Connection", "TE", "Upgrade")

/** Runs after Proxy processing and before delivery to the client. */
class ResponseProxyHandler(private val manager: RewriteManager) : ProxyResponseHandler {
    override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction =
        ProxyResponseReceivedAction.continueWith(response)

    override fun handleResponseToBeSent(response: InterceptedResponse): ProxyResponseToBeSentAction {
        if (!manager.isResponseActive()) return ProxyResponseToBeSentAction.continueWith(response)
        val request = try { response.initiatingRequest() } catch (_: Exception) { return ProxyResponseToBeSentAction.continueWith(response) }
        val host = try { request.httpService().host() } catch (_: Exception) { return ProxyResponseToBeSentAction.continueWith(response) }
        val inScope = try { request.isInScope } catch (_: Exception) { return ProxyResponseToBeSentAction.continueWith(response) }
        val epoch = manager.responseCheckEpoch(host, inScope) ?: return ProxyResponseToBeSentAction.continueWith(response)
        // Burp's settings export may invoke the Swing event thread. Never hold
        // the manager monitor while calling it: the UI also reads that monitor.
        val configurationSafe = manager.isResponseConfigurationSafe()
        return synchronized(manager) {
        try {
            val rules = manager.responsesFor(host, inScope)
            if (rules.isEmpty()) return ProxyResponseToBeSentAction.continueWith(response)
            if (!manager.enforceResponseConfiguration(configurationSafe, epoch)) return ProxyResponseToBeSentAction.continueWith(response)
            fun skip(reason: String): ProxyResponseToBeSentAction {
                manager.recordResponse("skipped $reason; original retained")
                return ProxyResponseToBeSentAction.continueWith(response)
            }
            val status = response.statusCode().toInt()
            val version = response.httpVersion()
            val http2 = version == "HTTP/2"
            val method = request.method()
            if ((!http2 && version != "HTTP/1.0" && version != "HTTP/1.1") || method.equals("HEAD", true) ||
                (http2 && method.equals("CONNECT", true)) ||
                status !in 200..299 || status in listOf(204, 205, 206)) return skip("unsupported protocol or status")
            if (listOf("Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since").any { request.hasHeader(it) })
                return skip("conditional or range request")
            val headers = response.headers()
            fun count(name: String) = headers.count { it.name().equals(name, true) }
            // HTTP/2 uses DATA frames, so the processed message may omit Content-Length.
            val lengthCount = count("Content-Length")
            if (count("Content-Type") != 1 || lengthCount > 1 || (!http2 && lengthCount == 0) ||
                (http2 && http2ProhibitedResponseHeaders.any { response.hasHeader(it) }) ||
                listOf("Content-Encoding", "Transfer-Encoding", "Content-Range", "Content-Disposition", "Trailer", "ETag", "Last-Modified", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest").any { response.hasHeader(it) })
                return skip("unsupported encoding, framing, download, or validator")
            if (headers.filter { it.name().equals("Cache-Control", true) }.any { it.value().split(',').any { directive -> directive.trim().equals("no-transform", true) } })
                return skip("no-transform cache directive")
            val parts = response.headerValue("Content-Type").split(';').map { it.trim() }
            if (parts.size > 2 || parts.drop(1).any { !it.matches(Regex("(?i)charset\\s*=\\s*\"?utf-8\"?")) }) return skip("unsupported charset")
            val media = parts[0].lowercase()
            val isJson = media == "application/json" || (media.startsWith("application/") && media.endsWith("+json"))
            val isText = media == "text/plain" || media == "text/html"
            if (!isJson && !isText) return skip("unsupported content type")
            val candidates = rules.filter { (it.method.isEmpty() || it.method == method.uppercase()) &&
                (it.path.isEmpty() || it.path == request.pathWithoutQuery()) && (it.status == 0 || it.status == status) &&
                (it.contentType.isEmpty() || it.contentType == media) && if (isJson) it.mode != "text" else it.mode == "text" }
            if (candidates.isEmpty()) return ProxyResponseToBeSentAction.continueWith(response)
            if (candidates.size > 64) return skip("too many rules")
            val bytes = response.body().bytes
            if (bytes.size > 1_048_576) return skip("invalid or oversized body")
            if (lengthCount == 1) {
                val length = response.headerValue("Content-Length")
                if (!length.matches(Regex("[0-9]+")) || length.toLongOrNull() != bytes.size.toLong()) return skip("invalid or oversized body")
            }
            if (http2 && bytes.isEmpty()) return ProxyResponseToBeSentAction.continueWith(response)
            val body = strictUtf8(bytes)
            if (isJson && containsSensitiveJson(body)) return skip("protected credential fields")
            val rewritten = if (isJson) rewriteResponseJson(body, candidates) else rewriteResponseText(body, candidates)
            if (rewritten.body == body) return ProxyResponseToBeSentAction.continueWith(response)
            val replacement = rewritten.body.toByteArray(StandardCharsets.UTF_8)
            if (replacement.size > 1_048_576) return skip("oversized replacement")
            var modified = response.withBody(BurpBytes.byteArray(*replacement))
            modified = if (http2 && lengthCount == 0) {
                modified.withRemovedHeader("Content-Length")
            } else {
                modified.withUpdatedHeader("Content-Length", replacement.size.toString())
            }
            // Validators were rejected above. Do not let caches store the transformed representation.
            modified = modified.withAddedHeader("Cache-Control", "no-store")
            if (http2) {
                val lengths = modified.headers().filter { it.name().equals("Content-Length", true) }
                val lengthPreserved = if (lengthCount == 0) lengths.isEmpty()
                    else lengths.singleOrNull()?.value() == replacement.size.toString()
                if (!lengthPreserved || modified.httpVersion() != version || modified.statusCode().toInt() != status ||
                    modified.hasHeader("Transfer-Encoding") || http2ProhibitedResponseHeaders.any { modified.hasHeader(it) }) {
                    return skip("HTTP/2 response integrity check failed")
                }
            }
            rewritten.matched.forEach { manager.recordResponseMatched(it) }
            manager.recordResponse("rewritten response prepared for forwarding")
            ProxyResponseToBeSentAction.continueWith(modified)
        } catch (_: Exception) {
            manager.recordResponse("skipped malformed or unsupported response; original retained")
            ProxyResponseToBeSentAction.continueWith(response)
        } catch (_: StackOverflowError) {
            manager.recordResponse("skipped excessive nesting; original retained")
            ProxyResponseToBeSentAction.continueWith(response)
        }
        }
    }
}
