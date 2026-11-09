package net.portswigger.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties
import kotlin.reflect.full.primaryConstructor

fun getJsonSchemaForProperty(kType: kotlin.reflect.KType): JsonElement = getJsonSchemaForProperty(kType, 0)

private fun getJsonSchemaForProperty(kType: kotlin.reflect.KType, depth: Int): JsonElement {
    require(depth <= 8) { "Input schemas may be nested at most eight levels" }
    val classifier = kType.classifier
    return when {
        classifier is KClass<*> && classifier.java.isEnum -> JsonObject(mapOf(
            "type" to JsonPrimitive("string"),
            "enum" to kotlinx.serialization.json.JsonArray(classifier.java.enumConstants.map { JsonPrimitive((it as Enum<*>).name) })
        ))
        classifier == String::class ->
            JsonObject(mapOf("type" to JsonPrimitive("string")))

        classifier == Int::class || classifier == Long::class ->
            JsonObject(mapOf("type" to JsonPrimitive("integer")))

        classifier == Float::class || classifier == Double::class ->
            JsonObject(mapOf("type" to JsonPrimitive("number")))

        classifier == Boolean::class ->
            JsonObject(mapOf("type" to JsonPrimitive("boolean")))

        classifier == List::class || classifier == Array::class -> {
            val argType = kType.arguments.firstOrNull()?.type
            val itemsSchema = if (argType != null) getJsonSchemaForProperty(argType, depth + 1)
                else JsonObject(mapOf("type" to JsonPrimitive("object")))
            JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to itemsSchema))
        }

        classifier == Map::class -> {
            val valueType = kType.arguments.getOrNull(1)?.type
            val valueSchema = if (valueType != null) getJsonSchemaForProperty(valueType, depth + 1)
                else JsonObject(mapOf("type" to JsonPrimitive("object")))
            JsonObject(mapOf("type" to JsonPrimitive("object"), "additionalProperties" to valueSchema))
        }

        classifier is KClass<*> && classifier != Any::class -> nestedObjectSchema(classifier, depth + 1)

        else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
    }
}

private fun nestedObjectSchema(kClass: KClass<*>, depth: Int): JsonObject {
    require(depth <= 8) { "Input schemas may be nested at most eight levels" }
    val properties = linkedMapOf<String, JsonElement>()
    val required = mutableListOf<String>()
    val optional = kClass.primaryConstructor?.parameters?.filter { it.isOptional }?.mapNotNull { it.name }?.toSet().orEmpty()
    kClass.memberProperties.sortedBy { it.name }.forEach { property ->
        properties[property.name] = getJsonSchemaForProperty(property.returnType, depth + 1)
        if (!property.returnType.isMarkedNullable && property.name !in optional) required += property.name
    }
    return JsonObject(buildMap {
        put("type", JsonPrimitive("object"))
        put("properties", JsonObject(properties))
        put("additionalProperties", JsonPrimitive(false))
        if (required.isNotEmpty()) put("required", kotlinx.serialization.json.JsonArray(required.map(::JsonPrimitive)))
    })
}

fun KClass<*>.asInputSchema(): ToolSchema {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()
    val optional = primaryConstructor?.parameters?.filter { it.isOptional }?.mapNotNull { it.name }?.toSet().orEmpty()

    for (prop in memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType, 0)

        if (!prop.returnType.isMarkedNullable && prop.name !in optional) {
            required.add(prop.name)
        }
    }

    return ToolSchema(
        properties = JsonObject(properties),
        required = required
    )
}
