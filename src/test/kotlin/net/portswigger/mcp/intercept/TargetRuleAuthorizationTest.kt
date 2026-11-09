package net.portswigger.mcp.intercept

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CancellationException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class TargetRuleAuthorizationTest {
    private val url = "https://fixture.example:443/lab"
    private fun spec(id: String, target: String = url) = InterceptionRuleSpec(
        "Approved fixture", target, id, RuleDirection.REQUEST, action = RuleAction.FORWARD_UNCHANGED
    )

    @Test fun `requires explicit approval and exact scheme host port and path`() = runBlocking<Unit> {
        val store = TargetRuleAuthorization({ true })
        var prompted = false
        val grant = store.request(listOf(url), 30) { detail ->
            prompted = true; assertTrue(detail.contains(url)); assertTrue(detail.contains("30s")); true
        }
        assertTrue(prompted)
        assertTrue(store.permits(spec(grant.id)))
        listOf("http://fixture.example:443/lab", "https://other.example:443/lab",
            "https://fixture.example:444/lab", "$url/child", "$url?x=1", "$url/../other").forEach {
            assertFalse(store.permits(spec(grant.id, it)), it)
        }
        assertFalse(store.permits(spec("unapproved")))
    }

    @Test fun `rejects ambiguous unrestricted or credential bearing URLs before prompting`() = runBlocking<Unit> {
        listOf("https://fixture.example/lab", "https://*.example:443/lab", "https://fixture.example:443/",
            "$url%2fchild", "$url/../other", "$url//other", "$url?token=synthetic", "$url#fragment",
            "https://user:synthetic@fixture.example:443/lab", "ftp://fixture.example:443/lab",
            "https://fixture.example:0/lab", "https://FIXTURE.example:443/lab", "$url/./x", "$url/*").forEach {
            var prompted = false
            assertThrows(IllegalArgumentException::class.java) { runBlocking { store().request(listOf(it), 10) { prompted = true; true } } }
            assertFalse(prompted, it)
        }
    }

    private fun store() = TargetRuleAuthorization({ true })

    @Test fun `denial cancellation and missing scope grant nothing`() = runBlocking<Unit> {
        val store = store()
        assertThrows(IllegalStateException::class.java) { runBlocking { store.request(listOf(url), 10) { false } } }
        assertThrows(CancellationException::class.java) { runBlocking { store.request(listOf(url), 10) { throw CancellationException() } } }
        assertTrue(store.list().isEmpty())
        assertThrows(IllegalStateException::class.java) { runBlocking { TargetRuleAuthorization({ false }).request(listOf(url), 10) { fail("Must not prompt") } } }
    }

    @Test fun `expiry cannot be renewed by listing or use and expires disabled rules`() = runBlocking<Unit> {
        var now = 0L
        val store = TargetRuleAuthorization({ true }, { now })
        val engine = InterceptionRuleEngine(approvedPreparationTarget = store::permits)
        assertThrows(IllegalArgumentException::class.java) { engine.create(spec("00000000-0000-0000-0000-000000000000")) }
        val grant = store.request(listOf(url), 1) { true }
        val rule = engine.create(spec(grant.id))
        assertEquals(InterceptionRuleState.DISABLED, rule.state)
        assertThrows(IllegalStateException::class.java) { engine.enable(rule.id, 1000) }
        assertEquals(1000L, store.list().single().remainingMillis)
        now = 1_000_000_000L
        assertFalse(store.permits(spec(grant.id)))
        assertTrue(store.list().isEmpty())
        assertEquals(InterceptionRuleState.AUTHORIZATION_ENDED, engine.get(rule.id).state)
        assertThrows(IllegalArgumentException::class.java) { engine.create(spec(grant.id)) }
    }

    @Test fun `policy changes and emergency stop during approval invalidate permissions`() = runBlocking<Unit> {
        var eligible = true
        val store = TargetRuleAuthorization({ eligible })
        assertThrows(IllegalStateException::class.java) { runBlocking { store.request(listOf(url), 10) { eligible = false; true } } }
        eligible = true
        assertThrows(IllegalStateException::class.java) { runBlocking { store.request(listOf(url), 10) { store.revokeAll(); true } } }
        val grant = store.request(listOf(url), 10) { true }
        eligible = false
        assertFalse(store.permits(spec(grant.id)))
        eligible = true
        assertFalse(store.permits(spec(grant.id)))
        val next = store.request(listOf(url), 10) { true }
        store.revokeAll()
        assertFalse(store.permits(spec(next.id)))
    }

    @Test fun `one origin per approval bounded paths duration and grant count`() = runBlocking<Unit> {
        val store = store()
        for (targets in listOf(emptyList(), listOf(url, url), listOf(url, "https://other.example:443/lab"), (1..17).map { "$url/$it" })) {
            assertThrows(IllegalArgumentException::class.java) { runBlocking { store.request(targets, 10) { true } } }
        }
        for (seconds in listOf(0, 301)) assertThrows(IllegalArgumentException::class.java) { runBlocking { store.request(listOf(url), seconds) { true } } }
        repeat(16) { store.request(listOf(url), 10) { true } }
        assertThrows(IllegalStateException::class.java) { runBlocking { store.request(listOf(url), 10) { true } } }
    }
}
