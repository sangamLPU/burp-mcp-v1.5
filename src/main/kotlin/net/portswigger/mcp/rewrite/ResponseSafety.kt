package net.portswigger.mcp.rewrite

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/** Fail closed if Burp may erase the origin's Content-Encoding before callbacks. */
internal fun proxyPreservesResponseEncoding(options: String): Boolean = runCatching {
    val root = Json.parseToJsonElement(options) as JsonObject
    val proxy = root["proxy"] as JsonObject
    val miscellaneous = proxy["miscellaneous"] as JsonObject
    val unpack = miscellaneous["unpack_gzip_deflate_in_responses"] as JsonPrimitive
    return@runCatching !unpack.isString && unpack.booleanOrNull == false
}.getOrDefault(false)
