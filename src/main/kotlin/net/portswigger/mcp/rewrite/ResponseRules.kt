package net.portswigger.mcp.rewrite

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Values are stored in Burp extension storage and shown only in local approval dialogs. */
@Serializable
data class ResponseRewriteRule(
    val id: String = "", val mode: String, val match: String, val replacement: String,
    val hostname: String = "", val method: String = "", val path: String = "",
    val status: Int = 0, val contentType: String = "", val enabled: Boolean = false
)

internal fun validateResponseRule(rule: ResponseRewriteRule) {
    require(rule.mode in listOf("json_field", "json_pointer", "text"))
    require(rule.match.isNotEmpty() && rule.match.length <= 1024 && rule.match.none { it.isISOControl() })
    require(rule.replacement.length <= 65536)
    StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(rule.replacement))
    require(rule.hostname.isEmpty() || (rule.hostname == rule.hostname.lowercase() && rule.hostname.length <= 253 &&
        rule.hostname.split('.').all { it.length in 1..63 && it.matches(Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")) }))
    require(rule.method.isEmpty() || rule.method.matches(Regex("[A-Z]+")))
    require(rule.path.isEmpty() || (rule.path.startsWith('/') && '?' !in rule.path && '#' !in rule.path && rule.path.none { it.isISOControl() }))
    require(rule.status == 0 || rule.status in 100..599)
    require(rule.contentType.isEmpty() || rule.contentType.matches(Regex("[a-z0-9.+-]+/[a-z0-9.+-]+")))
    if (rule.mode == "json_pointer") pointerSegments(rule.match)
    if (rule.mode != "text") {
        replaceJsonField(rule.replacement, emptyList(), "null") // Check syntax and nesting before parsing.
        val value = Json.parseToJsonElement(rule.replacement)
        require(value is JsonPrimitive) { "Replacement must be a JSON scalar." }
    }
}

internal fun pointerSegments(pointer: String): List<String> {
    require(pointer.startsWith('/') && pointer.length <= 1024)
    return pointer.substring(1).split('/').map {
        require(!Regex("~(?![01])").containsMatchIn(it))
        it.replace("~1", "/").replace("~0", "~")
    }.also { require(it.size <= 64) }
}

internal data class ResponseResult(val body: String, val matched: Set<String>)
private data class Edit(val start: Int, val end: Int, val rule: ResponseRewriteRule, val order: Int)

/** Edits are selected against the original representation; first rule wins overlapping spans. */
internal fun rewriteResponseJson(body: String, rules: List<ResponseRewriteRule>): ResponseResult {
    replaceJsonField(body, listOf("\u0000never-match"), "null") // validates full syntax, duplicate keys, and depth
    val pointers = rules.map { if (it.mode == "json_pointer") pointerSegments(it.match) else null }
    val edits = mutableListOf<Edit>()
    var pos = 0
    fun ws() { while (pos < body.length && body[pos] in " \t\r\n") pos++ }
    fun stringEnd(): Int {
        require(body[pos++] == '"')
        while (pos < body.length) when (body[pos++]) {
            '\\' -> { require(pos < body.length); if (body[pos++] == 'u') pos += 4 }
            '"' -> return pos
        }
        error("invalid JSON")
    }
    fun value(path: List<String>, key: String?, depth: Int) {
        require(depth <= 128); ws(); val start = pos
        when (body[pos]) {
            '{' -> {
                pos++; ws()
                if (body[pos] != '}') while (true) {
                    ws(); val begin = pos; stringEnd(); val name = Json.decodeFromString<String>(body.substring(begin, pos))
                    ws(); require(body[pos++] == ':'); value(path + name, name, depth + 1); ws()
                    if (body[pos] == '}') break else require(body[pos++] == ',')
                }; pos++
            }
            '[' -> {
                pos++; ws(); var index = 0
                if (body[pos] != ']') while (true) {
                    value(path + (index++).toString(), null, depth + 1); ws()
                    if (body[pos] == ']') break else require(body[pos++] == ',')
                }; pos++
            }
            '"' -> stringEnd()
            else -> while (pos < body.length && body[pos] !in ",}] \t\r\n") pos++
        }
        for ((i, rule) in rules.withIndex()) {
            if ((rule.mode == "json_field" && key == rule.match) || (rule.mode == "json_pointer" && pointers[i] == path)) {
                require(edits.size < 1000) { "Too many matching fields" }
                edits.add(Edit(start, pos, rule, i))
            }
        }
    }
    value(emptyList(), null, 0)
    val selected = mutableListOf<Edit>()
    for (edit in edits.sortedWith(compareBy<Edit> { it.order }.thenBy { it.start })) {
        if (selected.none { edit.start < it.end && it.start < edit.end }) selected.add(edit)
    }
    val projected = body.length.toLong() + selected.sumOf { Json.parseToJsonElement(it.rule.replacement).toString().length.toLong() - (it.end - it.start) }
    require(projected <= 1_048_576)
    var result = body
    for (edit in selected.sortedByDescending { it.start }) result = result.replaceRange(edit.start, edit.end, Json.parseToJsonElement(edit.rule.replacement).toString())
    return ResponseResult(result, selected.map { it.rule.id }.toSet())
}

/** Literal replacements are chosen in original-text order; earlier rules win at each position. */
internal fun rewriteResponseText(body: String, rules: List<ResponseRewriteRule>): ResponseResult {
    val out = StringBuilder(); val matched = linkedSetOf<String>(); var pos = 0; var count = 0
    while (pos < body.length) {
        val rule = rules.firstOrNull { body.startsWith(it.match, pos) }
        if (rule == null) out.append(body[pos++]) else {
            require(++count <= 10000); out.append(rule.replacement); pos += rule.match.length; matched.add(rule.id)
            require(out.length <= 1_048_576)
        }
    }
    return ResponseResult(out.toString(), matched)
}
