# SCP Go SDK

> `github.com/limn/scp-go` -- Shareable Context Protocol for Go

Cryptographic identity, encrypted contexts, capability-based auth, and tool invocation for AI agents. Built on Rust via cbindgen + cgo.

## Install

```bash
go get github.com/limn/scp-go
```

Requires a C compiler (gcc/clang). Pre-built shared libraries are bundled -- no Rust toolchain needed.

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    scp "github.com/limn/scp-go"
)

func main() {
    // Initialize the runtime
    if err := scp.Init(); err != nil {
        log.Fatal(err)
    }
    defer scp.Shutdown()

    // Create a cryptographic identity (DID)
    identity, err := scp.NewIdentity("platform")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("DID:", identity.DID())

    // Create an encrypted context
    ctx, err := scp.NewContext(identity, scp.ContextParams{
        Ceiling: []string{"msg:send", "msg:receive"},
        TTL:     3600,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer ctx.Close()

    // Send a message (MLS-encrypted, signed, provenance-tagged)
    if err := ctx.Send([]byte("Hello from SCP")); err != nil {
        log.Fatal(err)
    }

    // Receive messages
    msg := <-ctx.Receive()
    fmt.Printf("%s: %s\n", msg.SenderDID, msg.Content)
}
```

## API Reference

Generated from source via `godoc`. Build locally:

```bash
godoc -http=:6060
# Browse to http://localhost:6060/pkg/github.com/limn/scp-go/
```

Published API docs are generated on every release by CI.

## Examples

See [`examples/`](./examples/) for runnable programs:

| File | Description |
|------|-------------|
| `basic_messaging.go` | Create identity, context, send/receive messages |
| `tool_invocation.go` | Register and invoke a tool with test vectors |
| `mcp_integration.go` | Expose SCP tools via MCP JSON-RPC server |
| `multi_agent.go` | Coordinate multiple agents in a shared context |

## Error Handling

All errors implement the `error` interface. Use `errors.As` for type-specific handling:

```go
var target *scp.ContextError
if errors.As(err, &target) {
    fmt.Printf("[%s] %s\n", target.Code, target.Message)
}
```

## Source

- Scaffold: `.docs/scaffold/go.md`
- Standards: `.docs/standards/go.md`
- API sketch: `.docs/sketch.md`
