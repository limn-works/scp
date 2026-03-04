# SCP Java SDK

> `com.limn:scp-sdk-java` -- Shared Context Protocol for Java

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Built on Rust via cbindgen + JNA.

## Install

Maven:

```xml
<dependency>
    <groupId>com.limn</groupId>
    <artifactId>scp-sdk-java</artifactId>
    <version>0.1.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("com.limn:scp-sdk-java:0.1.0")
```

## Quick Start

```java
import com.limn.scp.Identity;
import com.limn.scp.Context;
import com.limn.scp.Types.Message;
import java.util.Map;

public class QuickStart {
    public static void main(String[] args) throws Exception {
        // Create a cryptographic identity (DID)
        var identity = Identity.create("platform").join();
        System.out.println("DID: " + identity.did());

        // Create an encrypted context
        var ctx = Context.create(identity, Map.of(
            "ceiling", java.util.List.of("msg:send", "msg:receive"),
            "ttl", 3600
        )).join();

        // Send a message (MLS-encrypted, signed, provenance-tagged)
        ctx.send("Hello from SCP".getBytes()).join();

        // Receive messages (reactive streams)
        ctx.receive().subscribe(new java.util.concurrent.Flow.Subscriber<>() {
            public void onSubscribe(java.util.concurrent.Flow.Subscription s) {
                s.request(1);
            }
            public void onNext(Message msg) {
                System.out.println(msg.senderDid() + ": " + new String(msg.content()));
            }
            public void onError(Throwable t) { t.printStackTrace(); }
            public void onComplete() {}
        });

        ctx.close();
    }
}
```

## Requirements

- JDK >= 21
- JNA (bundled as transitive dependency)

## API Reference

Generated from source via Javadoc. Build locally:

```bash
./gradlew javadoc
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable programs:

| File | Description |
|------|-------------|
| `BasicMessaging.java` | Create identity, context, send/receive messages |
| `ToolInvocation.java` | Register and invoke a tool with test vectors |
| `McpIntegration.java` | Expose SCP tools via MCP JSON-RPC server |
| `MultiAgent.java` | Coordinate multiple agents in a shared context |

## Error Handling

All exceptions extend sealed `ScpException` with a machine-readable `getCode()` method:

```java
try {
    ctx.send(payload).join();
} catch (ContextException e) {
    System.out.println("[" + e.getCode() + "] " + e.getMessage());
}
```

## Source

- Scaffold: `.docs/scaffold/java.md`
- Standards: `.docs/standards/java.md`
- API sketch: `.docs/sketch.md`
