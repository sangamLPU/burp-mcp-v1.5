package net.portswigger.mcp.compat

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.regex.Pattern

/** Runtime feature detection for APIs added after the Burp 2024.1 Montoya surface. */
object MontoyaRuntimeCompat {
    data class ProjectInfo(val name: String?, val id: String?, val reason: String?) {
        val available: Boolean get() = reason == null
    }

    data class ResponseTimeoutOptions(val options: RequestOptions, val configuredInBurp: Boolean)

    fun projectInfo(api: MontoyaApi): ProjectInfo {
        val project = invokeNoArg(api, "project")
            ?: return ProjectInfo(null, null, "The running Montoya API does not expose project() (unavailable in Burp 2024.1).")
        val name = invokeNoArg(project, "name") as? String
        val id = invokeNoArg(project, "id")?.toString()
        return if (name != null || id != null) ProjectInfo(name, id, null)
        else ProjectInfo(null, null, "The runtime project() object does not expose readable name/id methods.")
    }

    fun withResponseTimeout(options: RequestOptions, timeoutMillis: Long): ResponseTimeoutOptions {
        require(timeoutMillis > 0)
        val method = options.javaClass.methods.firstOrNull { candidate ->
            candidate.name == "withResponseTimeout" && candidate.parameterTypes.contentEquals(arrayOf(Long::class.javaPrimitiveType))
        } ?: return ResponseTimeoutOptions(options, false)
        return runCatching {
            val updated = method.invoke(options, timeoutMillis) as? RequestOptions
                ?: return@runCatching ResponseTimeoutOptions(options, false)
            ResponseTimeoutOptions(updated, true)
        }.getOrElse { ResponseTimeoutOptions(options, false) }
    }

    /** Returns null when Organizer retrieval is absent, otherwise the runtime's item objects. */
    fun organizerItems(api: MontoyaApi): List<Any>? {
        val organizer = runCatching { api.organizer() }.getOrNull() ?: return null
        val method = organizer.javaClass.methods.firstOrNull {
            it.name == "items" && it.parameterCount == 0
        } ?: return null
        val value = runCatching { method.invoke(organizer) }.getOrNull() ?: return null
        return (value as? Iterable<*>)?.filterNotNull()?.map { it as Any }
    }

    fun readNoArg(target: Any?, methodName: String): Any? = target?.let { invokeNoArg(it, methodName) }

    fun organizerItemMatches(item: Any, pattern: Pattern): Boolean {
        val contains = item.javaClass.methods.firstOrNull {
            it.name == "contains" && it.parameterTypes.contentEquals(arrayOf(Pattern::class.java))
        }
        if (contains != null) {
            return runCatching { contains.invoke(item, pattern) as? Boolean ?: false }.getOrDefault(false)
        }
        val request = invokeNoArg(item, "request")?.toString().orEmpty()
        val response = invokeNoArg(item, "response")?.toString().orEmpty()
        val notes = invokeNoArg(invokeNoArg(item, "annotations") ?: return pattern.matcher("$request\n$response").find(), "notes")?.toString().orEmpty()
        return pattern.matcher("$request\n$response\n$notes").find()
    }

    /** Prefer the native ID when present; hash message bytes on older runtimes. */
    fun historyId(item: ProxyHttpRequestResponse): Int {
        val native = nativeHistoryId(item)
        if (native != null) return native.toInt()
        val digest = MessageDigest.getInstance("SHA-256")
        fun add(value: String?) = digest.update((value.orEmpty() + "\u0000").toByteArray(StandardCharsets.UTF_8))
        val request = runCatching { item.finalRequest() }.getOrNull()
        val response = runCatching { item.originalResponse() }.getOrNull()
        add(runCatching { request?.httpService()?.host() }.getOrNull())
        add(runCatching { request?.httpService()?.port()?.toString() }.getOrNull())
        add(runCatching { request?.url() }.getOrNull())
        add(runCatching { item.time().toInstant().toString() }.getOrNull())
        runCatching { request?.toByteArray()?.getBytes() }.getOrNull()?.let(digest::update)
        runCatching { response?.toByteArray()?.getBytes() }.getOrNull()?.let(digest::update)
        val bytes = digest.digest()
        val candidate = ((bytes[0].toInt() and 0x7f) shl 24) or
            ((bytes[1].toInt() and 0xff) shl 16) or
            ((bytes[2].toInt() and 0xff) shl 8) or
            (bytes[3].toInt() and 0xff)
        return if (candidate == 0) 1 else candidate
    }

    fun nativeHistoryId(item: ProxyHttpRequestResponse): Int? =
        (invokeNoArg(item, "id") as? Number)?.toInt()

    private fun invokeNoArg(target: Any, methodName: String): Any? {
        val method = target.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 } ?: return null
        return runCatching { method.invoke(target) }.getOrNull()
    }
}
