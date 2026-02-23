# Go Standards

Go conventions, toolchain, and CI for the SCP Go SDK. References `sdk-common.md` for cross-language invariants and `conventions.md` for git/branch conventions. See `.docs/scaffold/go.md` for package layout, C ABI bridge, and type definitions.

## Toolchain

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.23+ | Language (required for rangefunc, enhanced type inference) |
| cgo | (bundled) | C FFI bridge to Rust shared library |
| gofmt | (bundled) | Formatter |
| golangci-lint | latest | Linter (aggregates staticcheck, errcheck, gosec, etc.) |
| go test | (bundled) | Test framework |
| go vet | (bundled) | Static analysis |

## Code Style

### Synchronous API with channels

Go does not use async/await. The SDK presents a synchronous API. Long-running operations (subscriptions, streaming) use channels and goroutines:

```go
// Receive returns a channel that yields incoming messages.
// The channel is closed when the context is closed or an error occurs.
func (c *Context) Receive() (<-chan Message, error) {
    ch := make(chan Message, 64)
    go func() {
        defer close(ch)
        for {
            msg, err := ffi.ContextReceive(c.handle)
            if err != nil {
                return // channel closed
            }
            ch <- msg.ToMessage()
        }
    }()
    return ch, nil
}
```

### Resource management

Use `io.Closer` interface and `defer`:

```go
type Context struct {
    handle *ffi.ContextHandle
}

func (c *Context) Close() error {
    if c.handle != nil {
        ffi.ContextClose(c.handle)
        c.handle = nil
    }
    return nil
}

// Usage
ctx, err := NewContext(params)
if err != nil { return err }
defer ctx.Close()
```

### Naming

- Exported types/functions: `PascalCase`
- Unexported types/functions: `camelCase`
- Constants: `PascalCase` (exported) or `camelCase` (unexported)
- Packages: `lowercase` (single word preferred)
- Files: `snake_case.go`
- Test files: `snake_case_test.go`
- Acronyms: all caps when exported (`DID`, `UCAN`, `MLS`), lowercase when unexported

## Testing

### Standard go test

```go
func TestNewIdentity(t *testing.T) {
    identity, err := NewIdentity("in_memory")
    if err != nil {
        t.Fatalf("NewIdentity failed: %v", err)
    }
    if !strings.HasPrefix(identity.DID(), "did:dht:") {
        t.Errorf("expected did:dht: prefix, got %s", identity.DID())
    }
}

func TestContextSendRequiresActiveState(t *testing.T) {
    // ...
}
```

### Race detection

All tests run with `-race` flag to detect data races:

```bash
go test -race ./...
```

### Table-driven tests

```go
func TestCapabilityValidation(t *testing.T) {
    tests := []struct {
        name       string
        capability string
        ceiling    []string
        wantErr    bool
    }{
        {"valid capability", "messages:write", []string{"messages:write"}, false},
        {"outside ceiling", "context:close", []string{"messages:write"}, true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateCapability(tt.capability, tt.ceiling)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateCapability() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Test naming

Format: `Test{Type}{Action}` or `Test{Condition}`.

## Lint Configuration

`.golangci.yml`:

```yaml
linters:
  enable:
    - errcheck
    - govet
    - staticcheck
    - gosec
    - ineffassign
    - unused
    - misspell
    - gofmt
    - goimports
    - godot
    - noctx
    - bodyclose
    - exhaustive
    - gocritic

linters-settings:
  gocritic:
    enabled-checks:
      - nestingReduce
      - unnamedResult
      - ruleguard
  gosec:
    severity: medium
  exhaustive:
    default-signifies-exhaustive: true

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
```

## CI Commands

```bash
# Format check
gofmt -l ./...

# Lint
golangci-lint run ./...

# Vet
go vet ./...

# Test with race detection
go test -race -v ./...

# Test with coverage
go test -race -coverprofile=coverage.out ./...

# Build
go build ./...
```

## CI Matrix

| Job | Runs on | Go version | Trigger |
|-----|---------|------------|---------|
| gofmt | ubuntu-latest | 1.23 | Every PR |
| golangci-lint | ubuntu-latest | 1.23 | Every PR |
| govulncheck | ubuntu-latest | 1.23 | Every PR |
| test | ubuntu-latest, macos-latest | 1.23, 1.24 | Every PR |
| test -race | ubuntu-latest | 1.23 | Every PR |
| build | ubuntu-latest, macos-latest | 1.23 | Every PR |
| conformance | ubuntu-latest | 1.23 | Every PR |
