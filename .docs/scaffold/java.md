> Source of truth: .docs/specs/, .docs/sketch.md, .docs/adrs/. This file is downstream of those documents.

# Java SDK Scaffold

Build blueprint for the SCP Java SDK: package structure, JNA bridge, build configuration, and type definitions. See `.docs/standards/java.md` for coding standards (style rules, linting, testing, CI).

## Package Layout

```
bindings/java/
  build.gradle.kts              # Root build config
  settings.gradle.kts
  scp-java/
    build.gradle.kts
    src/
      main/java/works/limn/scp/
        Identity.java            # Identity class, DIDDocument
        Context.java             # Context class, Membership, AutoCloseable
        Tools.java               # ToolDefinition, TestVector records
        Trust.java               # evaluateTrust(), TrustEvaluation
        EventLog.java            # EventLog class, Event, Proof, Checkpoint
        ScpException.java        # Base exception
        Errors.java              # Exception hierarchy subtypes
        Transport.java           # TransportConfig, connect()
        Types.java               # Shared types: Message, Provenance, Capability
        Ucan.java                # validate(), mint(), revoke()
        Mcp.java                 # serveMcp(), McpClient
        internal/
          NativeLib.java         # JNA interface to libscp_ffi
      main/resources/
        linux-x86-64/libscp_ffi.so
        linux-aarch64/libscp_ffi.so
        darwin-x86-64/libscp_ffi.dylib
        darwin-aarch64/libscp_ffi.dylib
        win32-x86-64/scp_ffi.dll
      test/java/works/limn/scp/
        IdentityTest.java
        ContextTest.java
        ToolsTest.java
        UcanTest.java
        TransportTest.java
        EventLogTest.java
        McpTest.java
        conformance/
          ConformanceTest.java
```

## JNA Bridge (cbindgen + JNA)

### Bridge architecture

Rust -> cbindgen -> C header -> JNA -> Java

JNA (Java Native Access) loads the shared library at runtime and maps Java interface methods to C functions. No JNI boilerplate required.

### JNA interface

```java
// internal/NativeLib.java
package works.limn.scp.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

public interface NativeLib extends Library {
    NativeLib INSTANCE = Native.load("scp_ffi", NativeLib.class);

    int scp_identity_create(String custody, PointerByReference outHandle, PointerByReference outError);
    void scp_identity_free(Pointer handle);
    int scp_identity_did(Pointer handle, PointerByReference outDid);
    void scp_string_free(Pointer s);

    int scp_context_create(Pointer identity, String paramsJson, PointerByReference outHandle, PointerByReference outError);
    void scp_context_free(Pointer handle);
    int scp_context_send(Pointer handle, byte[] payload, int payloadLen, PointerByReference outError);
    int scp_context_receive(Pointer handle, PointerByReference outEnvelope, PointerByReference outError);

    int scp_tool_invoke(Pointer contextHandle, String toolId, String inputJson, PointerByReference outResult, PointerByReference outError);

    int scp_ucan_validate(Pointer contextHandle, String token, String capability, PointerByReference outError);
}
```

### Resource management

All native handles are wrapped in Java classes implementing `AutoCloseable`:

```java
public final class Identity implements AutoCloseable {
    private static final Cleaner CLEANER = Cleaner.create();

    private Pointer handle;
    private final Cleaner.Cleanable cleanable;

    private Identity(Pointer handle) {
        this.handle = handle;
        Pointer ref = handle;  // capture for cleanable (no reference to `this`)
        this.cleanable = CLEANER.register(this, () -> NativeLib.INSTANCE.scp_identity_free(ref));
    }

    @Override
    public void close() {
        if (handle != null) {
            cleanable.clean();  // idempotent — deregisters and runs action
            handle = null;
        }
    }
}
```

## build.gradle.kts

```kotlin
plugins {
    java
    `java-library`
    `maven-publish`
    id("com.diffplug.spotless") version "6.25.0"
    id("com.github.spotbugs") version "6.0.0"
}

group = "works.limn"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14+")
    implementation("com.google.code.gson:gson:2.11+")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11+")
    testImplementation("org.assertj:assertj-core:3.26+")
}

tasks.test {
    useJUnitPlatform()
}

spotless {
    java {
        googleJavaFormat()
    }
}

spotbugs {
    effort.set(com.github.spotbugs.snom.Effort.MAX)
    reportLevel.set(com.github.spotbugs.snom.Confidence.MEDIUM)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            groupId = "works.limn"
            artifactId = "scp-java"
        }
    }
}
```

## Type Definitions

### Records (value types)

```java
public record Message(
    String senderDid,
    byte[] content,
    long timestamp,
    long sequence,
    String contextId,
    Provenance provenance  // nullable
) {}

public record ToolDefinition(
    String name,
    String description,
    Map<String, Object> inputSchema,
    Map<String, Object> outputSchema,
    String operator,
    List<TestVector> testVectors,      // nullable
    byte[] implementationHash          // nullable
) {}

public record TestVector(
    Map<String, Object> input,
    Map<String, Object> expectedOutput,
    String description
) {}
```

### Sealed exception hierarchy

```java
public sealed class ScpException extends Exception
    permits IdentityException, ContextException, PermissionException,
            CryptoException, TransportException, ToolException, ValidationException {

    private final String code;

    protected ScpException(String message, String code) {
        super(message);
        this.code = code;
    }

    public String getCode() { return code; }
}

public final class IdentityException extends ScpException {
    public IdentityException(String message, String code) { super(message, code); }
}

public final class ContextException extends ScpException { ... }
public final class PermissionException extends ScpException { ... }
public final class CryptoException extends ScpException { ... }
public final class TransportException extends ScpException { ... }
public final class ToolException extends ScpException { ... }
public final class ValidationException extends ScpException { ... }
```

### Identity class

```java
public final class Identity implements AutoCloseable {
    private Pointer handle;

    public String did() {
        return NativeLib.getDid(handle);
    }

    public String custodyType() {
        return NativeLib.getCustodyType(handle);
    }

    public static CompletableFuture<Identity> create(String custody) {
        return CompletableFuture.supplyAsync(() -> {
            var ref = new PointerByReference();
            var err = new PointerByReference();
            int rc = NativeLib.INSTANCE.scp_identity_create(custody, ref, err);
            if (rc != 0) throw extractException(err);
            return new Identity(ref.getValue());
        });
    }

    public static CompletableFuture<Identity> create() {
        return create("platform");
    }

    @Override
    public void close() {
        if (handle != null) {
            NativeLib.INSTANCE.scp_identity_free(handle);
            handle = null;
        }
    }
}
```

### Context class

```java
public final class Context implements AutoCloseable {
    private static final Cleaner CLEANER = Cleaner.create();

    private Pointer handle;
    private final Cleaner.Cleanable cleanable;

    Context(Pointer handle) {
        this.handle = handle;
        Pointer ref = handle;
        this.cleanable = CLEANER.register(this, () -> NativeLib.INSTANCE.scp_context_free(ref));
    }

    public CompletableFuture<Void> send(byte[] payload) {
        return CompletableFuture.runAsync(() -> {
            var err = new PointerByReference();
            int rc = NativeLib.INSTANCE.scp_context_send(handle, payload, payload.length, err);
            if (rc != 0) throw extractException(err);
        });
    }

    public Flow.Publisher<Message> receive() {
        // Returns a reactive streams publisher
        return subscriber -> {
            // Bridge from native callback to subscriber
        };
    }
    public CompletableFuture<Map<String, Object>> invokeTool(String toolId, Map<String, Object> input) {
        return CompletableFuture.supplyAsync(() -> {
            String json = new Gson().toJson(input);
            var result = new PointerByReference();
            var err = new PointerByReference();
            int rc = NativeLib.INSTANCE.scp_tool_invoke(handle, toolId, json, result, err);
            if (rc != 0) throw extractException(err);
            return new Gson().fromJson(extractString(result), Map.class);
        });
    }

    @Override
    public void close() {
        if (handle != null) {
            cleanable.clean();
            handle = null;
        }
    }
}
```

## Maven Central Publishing

Published as `works.limn:scp-java` on Maven Central.

```xml
<!-- Consumer usage (Maven) -->
<dependency>
    <groupId>works.limn</groupId>
    <artifactId>scp-java</artifactId>
    <version>0.1.0</version>
</dependency>
```

```kotlin
// Consumer usage (Gradle)
implementation("works.limn:scp-java:0.1.0")
```

Package includes:
- Compiled Java classes (JDK 21+)
- Native libraries for Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64) bundled in JAR resources
- JNA dependency for native bridge
- Javadoc JAR
- Sources JAR
