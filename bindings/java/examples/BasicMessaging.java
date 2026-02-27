/** Basic messaging: create identity, create context, send and receive messages. */

package com.limn.scp.examples;

import com.limn.scp.Context;
import com.limn.scp.Identity;
import com.limn.scp.Types.Message;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Flow;

public class BasicMessaging {
    public static void main(String[] args) throws Exception {
        // Create two identities
        var alice = Identity.create("platform").join();
        var bob = Identity.create("platform").join();
        System.out.println("Alice DID: " + alice.did());
        System.out.println("Bob DID: " + bob.did());

        // Alice creates a context
        var ctxAlice = Context.create(alice, Map.of(
            "ceiling", List.of("msg:send", "msg:receive"),
            "ttl", 3600,
            "governance", "single_admin"
        )).join();
        System.out.println("Context ID: " + ctxAlice.contextId());

        // Bob joins the context
        var ctxBob = Context.join(bob, ctxAlice.contextId()).join();

        // Alice sends a message
        ctxAlice.send("Hello Bob, this is Alice".getBytes()).join();

        // Bob receives it
        ctxBob.receive().subscribe(new Flow.Subscriber<>() {
            private Flow.Subscription subscription;

            @Override
            public void onSubscribe(Flow.Subscription s) {
                this.subscription = s;
                s.request(1);
            }

            @Override
            public void onNext(Message msg) {
                System.out.println("Bob received from " + msg.senderDid() + ": " + new String(msg.content()));
                subscription.cancel();
            }

            @Override
            public void onError(Throwable t) { t.printStackTrace(); }

            @Override
            public void onComplete() {}
        });

        // Cleanup
        ctxBob.close();
        ctxAlice.close();
        alice.close();
        bob.close();
    }
}
