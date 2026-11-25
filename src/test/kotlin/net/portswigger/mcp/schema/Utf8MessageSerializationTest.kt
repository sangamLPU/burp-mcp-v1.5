package net.portswigger.mcp.schema

import burp.api.montoya.core.ByteArray as BurpBytes
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.mockk.every
import io.mockk.mockk
import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals

class Utf8MessageSerializationTest {
    private fun message(contentType: String, body: ByteArray, encoded: Boolean = false): Pair<HttpMessage, String> {
        val headers = "HTTP/1.1 200 OK\r\nContent-Type: $contentType\r\n\r\n".toByteArray(StandardCharsets.ISO_8859_1)
        val raw = headers + body
        val original = String(raw, StandardCharsets.ISO_8859_1)
        val header = mockk<HttpHeader> { every { name() } returns "Content-Type" }
        val bytes = mockk<BurpBytes>()
        every { bytes.bytes } returns raw
        val message = mockk<HttpMessage>()
        every { message.toString() } returns original
        every { message.hasHeader("Content-Encoding") } returns encoded
        every { message.hasHeader("Transfer-Encoding") } returns false
        every { message.headers() } returns listOf(header)
        every { message.headerValue("Content-Type") } returns contentType
        every { message.toByteArray() } returns bytes
        every { message.bodyOffset() } returns headers.size
        return message to original
    }

    @Test
    fun `UTF-8 JSON text is rendered without mojibake`() {
        val body = "{\"keep\":\"café ✓\"}".toByteArray(StandardCharsets.UTF_8)
        val (message, _) = message("application/json; charset=utf-8", body)
        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"keep\":\"café ✓\"}", message.renderForMcp())
    }

    @Test
    fun `binary encoded malformed and unsupported charset messages keep original rendering`() {
        for ((type, body, encoded) in listOf(
            Triple("application/octet-stream", byteArrayOf(0, -1, -2), false),
            Triple("application/json", byteArrayOf(-1, -2), false),
            Triple("application/json; charset=iso-8859-1", byteArrayOf(-23), false),
            Triple("application/json; charset=utf-8", byteArrayOf(-1, -2), true),
        )) {
            val (message, original) = message(type, body, encoded)
            assertEquals(original, message.renderForMcp())
        }
    }

    @Test
    fun `request response wrapper preserves format and decodes only safe text`() {
        val requestText = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
        val request = mockk<HttpRequest>()
        every { request.toString() } returns requestText
        every { request.hasHeader("Content-Encoding") } returns true

        val raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"keep\":\"café\"}".toByteArray(StandardCharsets.UTF_8)
        val originalResponse = String(raw, StandardCharsets.ISO_8859_1)
        val response = mockk<HttpResponse>()
        val responseBytes = mockk<BurpBytes>()
        val header = mockk<HttpHeader> { every { name() } returns "Content-Type" }
        every { response.toString() } returns originalResponse
        every { response.hasHeader(any<String>()) } returns false
        every { response.headers() } returns listOf(header)
        every { response.headerValue("Content-Type") } returns "application/json"
        every { responseBytes.bytes } returns raw
        every { response.toByteArray() } returns responseBytes
        every { response.bodyOffset() } returns raw.indexOfFirst { it == '{'.code.toByte() }

        val wrapper = mockk<HttpRequestResponse>()
        every { wrapper.request() } returns request
        every { wrapper.response() } returns response
        val original = "HttpRequestResponse{httpRequest=$requestText, httpResponse=$originalResponse, messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        every { wrapper.toString() } returns original
        assertEquals(original.replace("cafÃ©", "café"), wrapper.renderForMcp())

        every { response.hasHeader("Content-Encoding") } returns true
        assertEquals(original, wrapper.renderForMcp())
        every { wrapper.toString() } returns "unrecognized wrapper $originalResponse"
        assertEquals("unrecognized wrapper $originalResponse", wrapper.renderForMcp())
    }
}
