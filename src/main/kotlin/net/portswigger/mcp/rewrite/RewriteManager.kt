package net.portswigger.mcp.rewrite

import burp.api.montoya.persistence.PersistedObject
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.util.UUID
import java.time.Instant

@Serializable
data class RewriteRule(
    val id: String, val hostname: String, val method: String, val path: String,
    val contentType: String, val pointer: String, val valueJson: String, val enabled: Boolean = false,
    val fieldName: String = ""
)

internal data class CompiledRule(val rule: RewriteRule, val segments: List<String>, val replacement: String)
data class RuleActivity(val count: Long = 0, val lastMatched: Instant? = null)

/** Persistence contains rule values: treat the Burp project/extension storage as sensitive. */
class RewriteManager(private val storage: PersistedObject, private val responseConfigurationSafe: () -> Boolean = { false }) {
    private val json = Json
    private var allowlist: Set<String> = runCatching {
        (storage.getString("rewrite.allowlist") ?: "").lines().filter { validHost(it) }.toSet()
    }.getOrDefault(emptySet())
    private var rules: List<CompiledRule> = runCatching {
        json.decodeFromString<List<RewriteRule>>(storage.getString("rewrite.rules") ?: "[]").map { compile(it) }
    }.getOrDefault(emptyList())
    private var master = false // Never restored from persistence.
    private var responseMaster = false // Never restored from persistence.
    private var responseEpoch = 0L
    private var responseRules: List<ResponseRewriteRule> = runCatching {
        json.decodeFromString<List<ResponseRewriteRule>>(storage.getString("rewrite.responseRules") ?: "[]").onEach(::validateResponseRule)
    }.getOrDefault(emptyList())
    private var globalRules: List<GlobalParameterRule> = runCatching {
        json.decodeFromString<List<GlobalParameterRule>>(storage.getString("rewrite.globalRules") ?: "[]").onEach { validateGlobal(it) }
    }.getOrDefault(emptyList())
    private val events = ArrayDeque<String>()
    private val activity = mutableMapOf<String, RuleActivity>()
    @Synchronized fun activityFor(id: String): RuleActivity = activity[id] ?: RuleActivity()
    private fun matched(id: String) {
        val previous = activity[id] ?: RuleActivity()
        activity[id] = RuleActivity(previous.count + 1, Instant.now())
    }

    @Synchronized fun targets(): List<String> = allowlist.sorted()
    @Synchronized fun isActive(): Boolean = master
    @Synchronized fun isResponseActive(): Boolean = responseMaster
    @Synchronized fun listResponse(): List<ResponseRewriteRule> = responseRules.toList()
    private fun saveResponse(next: List<ResponseRewriteRule>) {
        storage.setString("rewrite.responseRules", json.encodeToString(next)); responseRules = next
    }
    @Synchronized fun createResponse(rule: ResponseRewriteRule): String {
        val next = rule.copy(id = UUID.randomUUID().toString(), enabled = false)
        validateResponseRule(next); saveResponse(responseRules + next); return next.id
    }
    @Synchronized fun updateResponse(rule: ResponseRewriteRule) {
        val current = responseRules.firstOrNull { it.id == rule.id } ?: error("Rule not found.")
        val next = rule.copy(enabled = false); validateResponseRule(next)
        if (current.copy(enabled = false) == next) return
        saveResponse(responseRules.map { if (it.id == next.id) next else it })
    }
    @Synchronized fun enableResponseApproved(rule: ResponseRewriteRule) {
        require(responseRules.firstOrNull { it.id == rule.id } == rule) { "Rule changed while approval was pending; retry." }
        require(allowlist.isNotEmpty() && (rule.hostname.isEmpty() || rule.hostname in allowlist)) { "Configure the host allowlist first." }
        saveResponse(responseRules.map { if (it.id == rule.id) it.copy(enabled = true) else it })
    }
    @Synchronized fun disableResponse(id: String) {
        require(responseRules.any { it.id == id }) { "Rule not found." }
        saveResponse(responseRules.map { if (it.id == id) it.copy(enabled = false) else it })
    }
    @Synchronized fun removeResponse(id: String) {
        require(responseRules.any { it.id == id }) { "Rule not found." }
        saveResponse(responseRules.filterNot { it.id == id })
    }
    fun activateResponse() {
        val epoch = synchronized(this) {
            require(allowlist.isNotEmpty()) { "Configure an allowlist first." }
            responseEpoch
        }
        require(isResponseConfigurationSafe()) {
            "Disable Burp Proxy's Unpack compressed responses setting before enabling response rewriting."
        }
        synchronized(this) {
            require(responseEpoch == epoch && allowlist.isNotEmpty()) { "Rewrite configuration changed while approval was pending; retry." }
            responseEpoch++; responseMaster = true; log("Response rewriting enabled for this session")
        }
    }
    @Synchronized fun disableResponseRewriting() { responseEpoch++; responseMaster = false; log("Response rewriting disabled") }
    internal fun isResponseConfigurationSafe(): Boolean = runCatching(responseConfigurationSafe).getOrDefault(false)
    @Synchronized internal fun responseCheckEpoch(host: String, inScope: Boolean): Long? =
        if (responsesFor(host, inScope).isEmpty()) null else responseEpoch
    @Synchronized internal fun enforceResponseConfiguration(safe: Boolean, epoch: Long): Boolean {
        if (!responseMaster || responseEpoch != epoch) return false
        if (!safe) {
            responseEpoch++
            responseMaster = false
            log("Response rewriting disabled: Burp response unpacking is enabled or its setting is unavailable")
            return false
        }
        return true
    }
    @Synchronized internal fun responsesFor(host: String, inScope: Boolean): List<ResponseRewriteRule> =
        if (responseMaster && inScope && host.lowercase() in allowlist) responseRules.filter { it.enabled && (it.hostname.isEmpty() || it.hostname == host.lowercase()) } else emptyList()
    @Synchronized internal fun recordResponse(message: String) = log("Response rewrite: $message")
    @Synchronized internal fun recordResponseMatched(id: String) { matched(id); log("Response rewrite: rule $id matched") }
    @Synchronized fun list(): List<RewriteRule> = rules.map { it.rule }
    @Synchronized fun listGlobal(): List<GlobalParameterRule> = globalRules.toList()
    @Synchronized fun logs(): List<String> = events.toList().reversed()
    private fun log(message: String) { if (events.size >= 100) events.removeFirst(); events.addLast(message) }
    @Synchronized internal fun recordApplied() = log("Rewritten request prepared for forwarding")
    @Synchronized internal fun recordFailure() = log("Proxy rewrite failed; original request retained")
    @Synchronized internal fun recordSkip(reason: String) = log("Rewrite skipped: $reason; original request retained")

    private fun saveGlobal(next: List<GlobalParameterRule>) {
        storage.setString("rewrite.globalRules", json.encodeToString(next))
        globalRules = next
    }
    @Synchronized fun createGlobal(name: String, value: String, locations: List<String>): String {
        val rule = GlobalParameterRule(UUID.randomUUID().toString(), name, value, locations.distinct())
        validateGlobal(rule); saveGlobal(globalRules + rule); return rule.id
    }
    @Synchronized fun updateGlobal(id: String, name: String, value: String, locations: List<String>) {
        val current = globalRules.firstOrNull { it.id == id } ?: error("Rule not found.")
        val rule = GlobalParameterRule(id, name, value, locations.distinct())
        validateGlobal(rule)
        if (current.copy(enabled = false) == rule) return
        saveGlobal(globalRules.map { if (it.id == id) rule else it })
    }
    @Synchronized fun enableGlobalApproved(approved: GlobalParameterRule) {
        val current = globalRules.firstOrNull { it.id == approved.id } ?: error("Rule not found.")
        require(current == approved) { "Rule changed while approval was pending; retry." }
        require(allowlist.isNotEmpty()) { "Configure an allowlist first." }
        saveGlobal(globalRules.map { if (it.id == approved.id) it.copy(enabled = true) else it })
    }
    @Synchronized fun disableGlobal(id: String) {
        require(globalRules.any { it.id == id }) { "Rule not found." }
        saveGlobal(globalRules.map { if (it.id == id) it.copy(enabled = false) else it })
    }
    @Synchronized fun removeGlobal(id: String) {
        require(globalRules.any { it.id == id }) { "Rule not found." }
        saveGlobal(globalRules.filterNot { it.id == id })
    }
    @Synchronized internal fun globalFor(host: String, inScope: Boolean): List<GlobalParameterRule> =
        if (master && inScope && host.lowercase() in allowlist) globalRules.filter { it.enabled } else emptyList()
    @Synchronized internal fun recordGlobalMatched(id: String, location: String) { matched(id); log("Global rule $id matched in $location") }
    @Synchronized internal fun recordJsonMatched(id: String) { matched(id); log("Rule $id matched") }

    @Synchronized fun setTargets(text: String) {
        val targets = text.lines().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        require(targets.all(::validHost)) { "Allowlist must contain exact hostnames, one per line." }
        storage.setString("rewrite.allowlist", targets.sorted().joinToString("\n"))
        allowlist = targets
        master = false
        responseEpoch++
        responseMaster = false
        log("Allowlist changed; rewriting disabled")
    }

    @Synchronized fun activate() {
        require(allowlist.isNotEmpty()) { "Configure an allowlist first." }
        master = true
        log("Rewriting enabled for this session")
    }
    @Synchronized fun disableAll() { master = false; responseEpoch++; responseMaster = false; log("Rewriting disabled") }

    @Synchronized fun create(hostname: String, method: String, path: String, contentType: String, pointer: String, valueJson: String, fieldName: String = ""): String {
        val rule = RewriteRule(UUID.randomUUID().toString(), hostname.lowercase(), method.uppercase(), path, contentType.lowercase(), pointer, valueJson, fieldName = fieldName)
        val compiled = compile(rule)
        save(rules + compiled)
        return rule.id
    }
    @Synchronized fun update(id: String, hostname: String, method: String, path: String, contentType: String, pointer: String, valueJson: String, fieldName: String = "") {
        val current = rules.firstOrNull { it.rule.id == id } ?: error("Rule not found.")
        val rule = RewriteRule(id, hostname.lowercase(), method.uppercase(), path, contentType.lowercase(), pointer, valueJson, fieldName = fieldName)
        val compiled = compile(rule)
        if (current.rule.copy(enabled = false) == rule) return
        save(rules.map { if (it.rule.id == id) compiled else it })
    }
    @Synchronized fun remove(id: String) {
        require(rules.any { it.rule.id == id }) { "Rule not found." }
        save(rules.filterNot { it.rule.id == id })
    }
    @Synchronized fun disable(id: String) {
        require(rules.any { it.rule.id == id }) { "Rule not found." }
        save(rules.map { if (it.rule.id == id) it.copy(rule = it.rule.copy(enabled = false)) else it })
    }
    // Approval must have been obtained for exactly this version of the rule.
    @Synchronized fun enableApproved(approved: RewriteRule) {
        val current = rules.firstOrNull { it.rule.id == approved.id } ?: error("Rule not found.")
        require(current.rule == approved) { "Rule changed while approval was pending; retry." }
        require(allowlist.isNotEmpty() && (current.rule.hostname.isEmpty() || current.rule.hostname in allowlist)) { "Rule hostname is not allowlisted." }
        save(rules.map { if (it.rule.id == approved.id) it.copy(rule = it.rule.copy(enabled = true)) else it })
    }
    private fun save(next: List<CompiledRule>) {
        storage.setString("rewrite.rules", json.encodeToString(next.map { it.rule }))
        rules = next
    }

    /** The callback and state changes are serialized, including emergency disable. */
    @Synchronized internal fun rewrite(host: String, method: String, path: String, contentType: String, inScope: Boolean, body: String, onMatch: (String) -> Unit = ::recordJsonMatched): String? {
        if (!master || !inScope || host.lowercase() !in allowlist || body.length > 1_048_576 ||
            !contentType.lowercase().matches(Regex("application/(?:json|[a-z0-9.+-]+\\+json)"))) return null
        val candidates = rules.filter { it.rule.enabled && (it.rule.hostname.isEmpty() || it.rule.hostname == host.lowercase()) &&
            (it.rule.method.isEmpty() || it.rule.method == method.uppercase()) && (it.rule.path.isEmpty() || it.rule.path == path) &&
            (it.rule.contentType.isEmpty() || it.rule.contentType == contentType.lowercase()) }
        if (candidates.isEmpty()) return null
        return try {
            if (containsSensitiveJson(body)) { log("Rewrite skipped: protected credential fields"); return null }
            var result = body
            var changed = false
            val matches = mutableListOf<String>()
            for (candidate in candidates) {
                val rewritten = if (candidate.rule.fieldName.isEmpty()) replaceJsonField(result, candidate.segments, candidate.replacement)
                    else rewriteResponseJson(result, listOf(ResponseRewriteRule(id = candidate.rule.id, mode = "json_field", match = candidate.rule.fieldName, replacement = candidate.replacement))).body
                if (rewritten != null && rewritten != result) {
                    require(rewritten.toByteArray(Charsets.UTF_8).size <= MAX_REWRITE_BYTES)
                    result = rewritten
                    changed = true
                    matches.add(candidate.rule.id)
                }
            }
            if (changed) { matches.forEach(onMatch); result } else null
        } catch (_: Exception) { log("Rewrite skipped: invalid or unsupported JSON"); null }
    }
}

private fun validHost(host: String): Boolean = host.length in 1..253 && host == host.lowercase() &&
    host.split('.').all { it.length in 1..63 && it.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) }

private fun compile(rule: RewriteRule): CompiledRule {
    require(rule.hostname.isEmpty() || validHost(rule.hostname)) { "Invalid hostname." }
    require(rule.method.isEmpty() || rule.method.matches(Regex("[A-Z]+"))) { "Invalid HTTP method." }
    require(rule.path.isEmpty() || (rule.path.startsWith('/') && '?' !in rule.path && '#' !in rule.path && rule.path.none { it.isISOControl() })) { "Path must be an exact URL path without a query." }
    require(rule.contentType.isEmpty() || rule.contentType.matches(Regex("application/(?:json|[a-z0-9.+-]+\\+json)"))) { "Content type must be a JSON media type." }
    require((rule.fieldName.isEmpty() != rule.pointer.isEmpty()) && rule.fieldName.length <= 256 && rule.fieldName.none { it.isISOControl() }) { "Choose one field name or JSON Pointer." }
    require(rule.pointer.isEmpty() || (rule.pointer.startsWith('/') && rule.pointer.length <= 1024)) { "Use a non-root JSON Pointer beginning with /." }
    val segments = if (rule.pointer.isEmpty()) emptyList() else rule.pointer.substring(1).split('/').map { token ->
        require(!Regex("~(?![01])").containsMatchIn(token)) { "Invalid JSON Pointer escape." }
        token.replace("~1", "/").replace("~0", "~")
    }
    require(segments.size <= 64 && rule.valueJson.length <= 65536) { "Rule is too large." }
    val value = try {
        replaceJsonField(rule.valueJson, emptyList(), "null")
        Json.parseToJsonElement(rule.valueJson)
    } catch (_: Exception) { throw IllegalArgumentException("Replacement must be valid JSON.") } catch (_: StackOverflowError) { throw IllegalArgumentException("Replacement is nested too deeply.") }
    require(rule.fieldName.isEmpty() || value is JsonPrimitive) { "Global field replacement must be a JSON scalar." }
    return CompiledRule(rule, segments, value.toString())
}

/** Locate a value without serializing unrelated fields. Reject duplicate object keys. */
internal fun replaceJsonField(body: String, path: List<String>, replacement: String): String? {
    var pos = 0
    var found: IntRange? = null
    fun ws() { while (pos < body.length && body[pos] in " \t\r\n") pos++ }
    fun stringToken(): String {
        require(body[pos] == '"')
        val start = pos++
        while (pos < body.length) {
            when (val ch = body[pos++]) {
                '\\' -> {
                    require(pos < body.length)
                    val escape = body[pos++]
                    require(escape in "\"\\/bfnrtu")
                    if (escape == 'u') {
                        require(pos + 4 <= body.length && body.substring(pos, pos + 4).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                        pos += 4
                    }
                }
                '"' -> return Json.decodeFromString(body.substring(start, pos))
                else -> require(ch >= ' ')
            }
        }
        error("Invalid string")
    }
    fun value(depth: Int, matches: Boolean) {
        require(depth <= 128)
        ws(); val start = pos
        when (body[pos]) {
            '{' -> {
                pos++; ws(); val keys = HashSet<String>()
                if (body[pos] != '}') while (true) {
                    ws(); val key = stringToken(); require(keys.add(key)); ws(); require(body[pos++] == ':')
                    value(depth + 1, matches && depth < path.size && path[depth] == key)
                    ws(); if (body[pos] == '}') break else require(body[pos++] == ',')
                }
                pos++
            }
            '[' -> {
                pos++; ws(); var index = 0
                if (body[pos] != ']') while (true) {
                    value(depth + 1, matches && depth < path.size && path[depth] == index.toString()); index++
                    ws(); if (body[pos] == ']') break else require(body[pos++] == ',')
                }
                pos++
            }
            '"' -> stringToken()
            else -> {
                while (pos < body.length && body[pos] !in ",}] \t\r\n") pos++
                val token = body.substring(start, pos)
                require(token == "true" || token == "false" || token == "null" || token.matches(Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")))
            }
        }
        if (matches && depth == path.size) found = start until pos
    }
    value(0, true); ws(); require(pos == body.length)
    Json.parseToJsonElement(body) // Validate after the depth-limited scan.
    val span = found ?: return null
    return body.replaceRange(span.first, span.last + 1, replacement)
}
