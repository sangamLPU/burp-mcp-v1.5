package net.portswigger.mcp.tools

import kotlinx.serialization.Serializable
import java.util.Locale

@Serializable
data class SecurityFinding(
    val category: String,
    val classification: String,
    val confidence: String,
    val evidence: String,
    val recommendation: String
)

@Serializable
data class SensitiveDataSummary(
    val scannedCharacters: Int,
    val matchCountsByType: Map<String, Int>,
    val valuesIncluded: Boolean = false
)

object SecurityAnalysis {
    fun securityHeaders(headers: Map<String, String>, https: Boolean): List<SecurityFinding> {
        val h = headers.mapKeys { it.key.lowercase(Locale.ROOT) }
        val findings = mutableListOf<SecurityFinding>()
        if (https && h["strict-transport-security"].isNullOrBlank()) {
            findings += finding("Strict-Transport-Security", "suspicious", "Header not observed on HTTPS response", "Set an appropriate max-age after confirming all subdomains support HTTPS.")
        }
        if (h["content-security-policy"].isNullOrBlank()) {
            findings += finding("Content-Security-Policy", "suspicious", "Header not observed", "Review whether a restrictive Content-Security-Policy is appropriate for this response.")
        }
        if (h["x-content-type-options"]?.equals("nosniff", true) != true) {
            findings += finding("X-Content-Type-Options", "suspicious", "nosniff directive not observed", "Set X-Content-Type-Options: nosniff where compatible.")
        }
        if (h["x-frame-options"].isNullOrBlank() && !h["content-security-policy"].orEmpty().contains("frame-ancestors", true)) {
            findings += finding("Clickjacking protection", "suspicious", "X-Frame-Options and CSP frame-ancestors not observed", "Review framing requirements and configure an explicit framing policy.")
        }
        if (h["referrer-policy"].isNullOrBlank()) {
            findings += finding("Referrer-Policy", "suspicious", "Header not observed", "Select a referrer policy that limits cross-origin URL disclosure.")
        }
        val hsts = h["strict-transport-security"]
        if (https && hsts != null && Regex("(?i)max-age\\s*=\\s*0").containsMatchIn(hsts)) {
            findings += finding("Strict-Transport-Security", "suspicious", "max-age=0 was observed", "Verify whether HSTS is intentionally disabled.")
        }
        return findings
    }

    fun cookies(setCookieHeaders: List<String>, https: Boolean): List<SecurityFinding> {
        val findings = mutableListOf<SecurityFinding>()
        setCookieHeaders.forEachIndexed { index, cookie ->
            val attrs = cookie.split(';').drop(1).map { it.trim() }
            val secure = attrs.any { it.equals("secure", true) }
            val httpOnly = attrs.any { it.equals("httponly", true) }
            val sameSite = attrs.firstOrNull { it.startsWith("samesite=", true) }?.substringAfter('=')
            val cookieLabel = "Cookie #${index + 1}"
            if (https && !secure) findings += finding("Cookie Secure flag", "suspicious", "$cookieLabel is set without Secure", "Set Secure for cookies that should only be sent over HTTPS.")
            if (!httpOnly) findings += finding("Cookie HttpOnly flag", "suspicious", "$cookieLabel is set without HttpOnly", "Use HttpOnly for session cookies that do not need JavaScript access.")
            if (sameSite == null) findings += finding("Cookie SameSite attribute", "manual_verification_required", "$cookieLabel has no SameSite attribute", "Choose Strict, Lax, or None based on the application's cross-site flow requirements.")
            if (sameSite.equals("none", true) && !secure) findings += finding("Cookie SameSite=None", "suspicious", "$cookieLabel uses SameSite=None without Secure", "Add Secure when SameSite=None is required.")
        }
        return findings
    }

    fun cors(headers: Map<String, String>, requestOrigin: String?): List<SecurityFinding> {
        val h = headers.mapKeys { it.key.lowercase(Locale.ROOT) }
        val allowOrigin = h["access-control-allow-origin"]?.trim()
        val allowCredentials = h["access-control-allow-credentials"]?.equals("true", true) == true
        if (allowOrigin.isNullOrBlank()) return emptyList()
        val findings = mutableListOf<SecurityFinding>()
        if (allowOrigin == "*" && allowCredentials) {
            findings += finding("CORS", "suspicious", "Wildcard origin and credentials=true were both observed; browsers reject this combination", "Use an explicit trusted-origin allowlist and verify the browser's effective CORS behavior.")
        } else if (requestOrigin != null && allowOrigin.equals(requestOrigin, true) && allowCredentials) {
            findings += finding("CORS origin reflection", "manual_verification_required", "The response allows the supplied Origin and credentials", "Test with controlled untrusted origins and confirm authentication and cache behavior before classifying this as a vulnerability.")
        } else if (allowOrigin == "*") {
            findings += finding("CORS wildcard", "manual_verification_required", "Access-Control-Allow-Origin: * was observed", "Confirm the response contains no data that should be restricted to trusted origins.")
        }
        return findings
    }

    fun authentication(requestHeaders: Map<String, String>, statusCode: Int?, responseHeaders: Map<String, String>): List<SecurityFinding> {
        val req = requestHeaders.mapKeys { it.key.lowercase(Locale.ROOT) }
        val res = responseHeaders.mapKeys { it.key.lowercase(Locale.ROOT) }
        return when {
            statusCode == 401 && !res["www-authenticate"].isNullOrBlank() -> listOf(
                finding("Authentication challenge", "observed", "HTTP 401 and WWW-Authenticate were observed", "Verify that protected resources consistently require the expected authentication scheme.")
            )
            "authorization" in req -> listOf(
                finding("Authentication header", "observed", "An Authorization header was present; its value is redacted", "Review the authentication flow and token handling without exposing credentials.")
            )
            statusCode != null && statusCode in 200..299 -> listOf(
                finding("Authentication coverage", "manual_verification_required", "A successful response was captured without an Authorization header", "This alone does not establish missing authentication; verify the endpoint's intended access policy and test unauthenticated access safely.")
            )
            else -> emptyList()
        }
    }

    fun sensitiveData(text: String): SensitiveDataSummary {
        val patterns = linkedMapOf(
            "private_key" to Regex("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            "jwt" to Regex("(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),
            "aws_access_key_id" to Regex("\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b"),
            "github_token" to Regex("\\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b"),
            "email_address" to Regex("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b", RegexOption.IGNORE_CASE),
            "possible_payment_card" to Regex("\\b(?:\\d[ -]*?){13,19}\\b")
        )
        val counts = patterns.mapNotNull { (type, pattern) ->
            val count = pattern.findAll(text).count()
            if (count == 0) null else type to count
        }.toMap()
        return SensitiveDataSummary(scannedCharacters = text.length, matchCountsByType = counts)
    }

    private fun finding(category: String, classification: String, evidence: String, recommendation: String) =
        SecurityFinding(
            category = category,
            classification = classification,
            confidence = if (classification == "observed") "directly_observed" else "manual_verification_required",
            evidence = evidence,
            recommendation = recommendation
        )
}
