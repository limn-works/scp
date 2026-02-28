/** Multi-agent coordination: multiple agents collaborating in a shared context. */

package com.limn.scp.examples;

import com.limn.scp.Context;
import com.limn.scp.Identity;
import com.limn.scp.Types.Message;
import com.limn.scp.Ucan;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.CountDownLatch;

public class MultiAgent {

    static void runAgent(String name, Identity identity, String contextId) throws Exception {
        var ctx = Context.join(identity, contextId).join();
        System.out.println("[" + name + "] Joined context " + contextId);

        ctx.send(("[" + name + "] reporting in").getBytes()).join();

        var latch = new CountDownLatch(2);
        ctx.receive().subscribe(new Flow.Subscriber<>() {
            private Flow.Subscription subscription;

            @Override
            public void onSubscribe(Flow.Subscription s) {
                this.subscription = s;
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(Message msg) {
                var sender = msg.senderDid().length() > 16
                    ? msg.senderDid().substring(0, 16) : msg.senderDid();
                System.out.println("[" + name + "] Received from " + sender + "...: "
                    + new String(msg.content()));
                latch.countDown();
                if (latch.getCount() == 0) subscription.cancel();
            }

            @Override
            public void onError(Throwable t) { t.printStackTrace(); }

            @Override
            public void onComplete() {}
        });
        latch.await();

        ctx.close();
        System.out.println("[" + name + "] Left context");
    }

    public static void main(String[] args) throws Exception {
        // Create identities for coordinator and two agents
        var coordinator = Identity.create("platform").join();
        var agentA = Identity.create("platform").join();
        var agentB = Identity.create("platform").join();

        // Coordinator creates the context
        var ctx = Context.create(coordinator, Map.of(
            "ceiling", List.of("msg:send", "msg:receive", "tool:invoke"),
            "roles", Map.of("agent", List.of("msg:send", "msg:receive", "tool:invoke")),
            "governance", "single_admin"
        )).join();
        System.out.println("Context created: " + ctx.contextId());

        // Mint UCANs for each agent
        Ucan.mint(coordinator, agentA.did(),
            List.of("msg:send", "msg:receive"), ctx.contextId()).join();
        Ucan.mint(coordinator, agentB.did(),
            List.of("msg:send", "msg:receive"), ctx.contextId()).join();

        // Run agents concurrently
        var futureA = CompletableFuture.runAsync(() -> {
            try { runAgent("Agent-A", agentA, ctx.contextId()); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        var futureB = CompletableFuture.runAsync(() -> {
            try { runAgent("Agent-B", agentB, ctx.contextId()); }
            catch (Exception e) { throw new RuntimeException(e); }
        });
        CompletableFuture.allOf(futureA, futureB).join();

        ctx.close();
        coordinator.close();
        agentA.close();
        agentB.close();
    }
}
