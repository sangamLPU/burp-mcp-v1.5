package net.portswigger.mcp.intercept

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import net.portswigger.mcp.security.ActivityLog

class DecisionQueueTest {
    @Test fun `interrupted callback is cancelled and never forwards original`() {
        val q=DecisionQueue<String>();val t=q.offer("request","secret",5000)!!
        val worker=Thread { assertNull(q.await(t)) }
        worker.start();worker.interrupt();worker.join(1000)
        assertFalse(worker.isAlive);assertTrue(q.list("request").isEmpty())
    }
    @Test fun `decision genuinely holds until approved revision is forwarded`() {
        val queue=DecisionQueue<String>();val t=queue.offer("request","original",1000)!!
        val pool=Executors.newSingleThreadExecutor()
        try {
            val waiting=pool.submit<String?> { queue.await(t) }
            assertFalse(waiting.isDone)
            val revision=queue.propose(t.id,0,"modified")
            assertThrows(IllegalStateException::class.java) { queue.forward(t.id,revision) }
            queue.approve(t.id,revision);queue.forward(t.id,revision)
            assertEquals("modified",waiting.get(1,TimeUnit.SECONDS))
            assertThrows(IllegalStateException::class.java) { queue.forward(t.id,revision) }
        } finally { pool.shutdownNow() }
    }
    @Test fun `new proposal invalidates approval and stale revisions`() {
        val q=DecisionQueue<String>();val t=q.offer("response","a",1000)!!
        q.disclose(t.id,0);assertEquals(0,q.get(t.id).disclosedRevision)
        q.approve(t.id,0);q.propose(t.id,0,"b")
        assertNull(q.get(t.id).disclosedRevision)
        assertThrows(IllegalStateException::class.java) { q.forward(t.id,0) }
        assertThrows(IllegalStateException::class.java) { q.forward(t.id,1) }
        assertThrows(IllegalStateException::class.java) { q.approve(t.id,0) }
        q.drop(t.id);assertNull(q.await(t))
        assertThrows(IllegalStateException::class.java) { q.drop(t.id) }
    }

    @Test fun `disclosure review keeps its ID and does not approve forwarding`() {
        val q=DecisionQueue<String>();val t=q.offer("request","local request",5000)!!
        val first=q.beginDisclosureRequest(t.id,0)
        assertEquals("PENDING",first.status);assertTrue(first.shouldPrompt)
        val duplicate=q.beginDisclosureRequest(t.id,0)
        assertEquals("PENDING",duplicate.status);assertFalse(duplicate.shouldPrompt)
        assertEquals(t.id,q.get(t.id).id)
        assertEquals("PENDING",q.get(t.id).disclosureStatus)
        assertTrue(q.completeDisclosureRequest(t.id,0,"APPROVED"))
        val disclosed=q.get(t.id)
        assertEquals(t.id,disclosed.id)
        assertEquals(0,disclosed.disclosedRevision)
        assertNull(disclosed.approvedRevision)
        assertThrows(IllegalStateException::class.java) { q.forward(t.id,0) }
        assertNull(q.await(t))
    }
    @Test fun `timeout drops without substituting the original`() {
        val q=DecisionQueue<String>();val t=q.offer("request","secret",10)!!
        assertNull(q.await(t));assertTrue(q.list("request").isEmpty())
        val error=assertThrows(IllegalStateException::class.java) { q.get(t.id) }
        assertTrue(error.message!!.contains("EXPIRED"))
    }

    @Test fun `terminal actions log explicit expiration forwarding dropping and cancellation reasons`() {
        ActivityLog.clear()
        val q=DecisionQueue<String>()
        val forwarded=q.offer("request","original",5000)!!
        q.approve(forwarded.id,0);q.forward(forwarded.id,0)
        val dropped=q.offer("request","original",5000)!!
        q.drop(dropped.id)
        val expired=q.offer("response","original",1)!!
        Thread.sleep(3);q.expire()
        val cancelled=q.offer("request","original",5000)!!
        q.cancelAll("SESSION_EXPIRED")

        val events=ActivityLog.snapshot()
        assertTrue(events.any { it.action=="intercept_forward" && it.detail.contains(forwarded.id) })
        assertTrue(events.any { it.action=="intercept_drop" && it.detail.contains(dropped.id) })
        assertTrue(events.any { it.action=="intercept_expiration" && it.detail.contains(expired.id) })
        assertTrue(events.any { it.action=="intercept_cancellation" && it.outcome=="session_expired" && it.detail.contains(cancelled.id) })
    }
    @Test fun `capacity and retained terminal records are bounded`() {
        val q=DecisionQueue<String>(2);val a=q.offer("request","a",1000)!!;val b=q.offer("response","b",1000)!!
        assertNull(q.offer("request","overflow",1000));q.cancelAll("UNLOADED")
        assertNull(q.await(a));assertNull(q.await(b));assertTrue(q.list("request").isEmpty())
        assertNotNull(q.offer("request","new",1000))
        assertThrows(IllegalStateException::class.java) { q.get("unknown") }
    }
    @Test fun `concurrent forward and drop complete once`() {
        val q=DecisionQueue<String>();val t=q.offer("request","a",1000)!!;q.approve(t.id,0)
        val pool=Executors.newFixedThreadPool(2)
        try {
            val actions=listOf(pool.submit<Boolean> { runCatching { q.forward(t.id,0) }.isSuccess },pool.submit<Boolean> { runCatching { q.drop(t.id) }.isSuccess })
            assertEquals(1,actions.count { it.get(1,TimeUnit.SECONDS) });assertTrue(t.result.isDone)
        } finally { pool.shutdownNow() }
    }
    @Test fun `simultaneous request response cancellation releases every waiter`() {
        val q=DecisionQueue<String>();val all=(1..8).map { q.offer(if(it%2==0) "request" else "response","$it",1000)!! }
        val pool=Executors.newFixedThreadPool(8)
        try {
            val waiting=all.map { t -> pool.submit<String?> { q.await(t) } }
            q.cancelAll("CLIENT_LEASE_EXPIRED")
            waiting.forEach { assertNull(it.get(1,TimeUnit.SECONDS)) }
            all.forEach { assertThrows(IllegalStateException::class.java) { q.get(it.id) } }
        } finally { pool.shutdownNow() }
    }

    @Test fun `concurrent 1 2 4 and 8 message queues keep identities revisions and decisions independent`() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            for (count in listOf(1, 2, 4, 8)) {
                val queue = DecisionQueue<String>(8)
                val start = CountDownLatch(1)
                val submitted = (0 until count).map { index ->
                    pool.submit<DecisionQueue.Ticket<String>?> {
                        check(start.await(2, TimeUnit.SECONDS))
                        queue.offer("request", "original-$count-$index", 5_000)
                    }
                }
                start.countDown()
                val tickets = submitted.mapIndexed { index, future ->
                    future.get(2, TimeUnit.SECONDS)
                        ?: fail("Queue rejected message $index at concurrency $count")
                }

                assertEquals(count, tickets.map { it.id }.toSet().size)
                assertEquals(count, queue.list("request").size)
                if (count == 8) assertNull(queue.offer("request", "overflow", 5_000))

                tickets.forEachIndexed { index, originalTicket ->
                    assertEquals(originalTicket.id, queue.get(originalTicket.id).id)
                    val revised = "revised-$count-$index"
                    val revision = queue.propose(originalTicket.id, 0, revised)
                    assertEquals(1, revision)
                    queue.approve(originalTicket.id, revision)
                }
                tickets.forEachIndexed { index, ticket ->
                    queue.forward(ticket.id, 1)
                    assertEquals("revised-$count-$index", ticket.result.get(1, TimeUnit.SECONDS))
                }
                assertTrue(queue.list("request").isEmpty())
            }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun `mode expiry revokes only unattended approvals and leaves human approvals intact`() {
        val q = DecisionQueue<String>()
        val unattended = q.offer("request", "synthetic", 5_000)!!
        val human = q.offer("request", "manual", 5_000)!!
        q.approve(unattended.id, 0, UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE)
        q.approve(human.id, 0, "HUMAN")

        assertEquals(1, q.revokeApprovals(UnattendedLocalTestMode.AUTO_APPROVAL_SOURCE))
        assertNull(q.get(unattended.id).approvedRevision)
        assertNull(q.get(unattended.id).approvedBy)
        assertEquals(0, q.get(human.id).approvedRevision)
        assertEquals("HUMAN", q.get(human.id).approvedBy)
    }
}
