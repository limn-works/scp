# Documentation Standards

When and how to document code.

## Philosophy

Documentation exists to accelerate human understanding. Write docs that help someone get up to speed quickly — not docs for the sake of completeness.

## When to Document

**Always document:**
- Public protocols and their contracts
- Non-obvious architectural decisions (use ADRs)
- Complex algorithms or business logic
- Module boundaries and responsibilities
- Anything requiring "learning" to use correctly

**Skip documentation for:**
- Obvious getters/setters
- Standard CRUD operations
- Self-explanatory one-liners
- Private implementation details (unless complex)
- Code that follows established patterns

## Inline Documentation (Swift)

Use `///` for API documentation. Focus on **why** and **how to use**, not **what** (the code shows what).

```swift
/// Fetches items matching the given criteria.
///
/// Results are sorted by creation date (newest first). For large result sets,
/// consider using `fetchItemsPaginated` instead.
///
/// - Parameter filter: Criteria for filtering. Pass `nil` for all items.
/// - Returns: Array of matching items.
/// - Throws: `DataError.fetchFailed` if the query cannot be executed.
func fetchItems(filter: ItemFilter?) async throws -> [Item]
```

**Document when:**
- Behavior isn't obvious from the signature
- There are important preconditions or side effects
- Errors need explanation
- Usage patterns matter

**Skip when:**
- The name says it all: `var title: String`
- It's a standard pattern: `func save() async throws`

## File-Level Documentation

Add a file header only when the file contains non-obvious architecture or is an entry point to a module.

## Module README Files

Create `README.md` in module folders when the module requires onboarding. Not every folder needs one.

**Create README when:**
- Module has non-obvious responsibilities
- There are important patterns to follow
- New contributors would need context
- Module interfaces with external systems

## Quality Checklist

Before adding documentation, ask:
- [ ] Would a new contributor need this to get started?
- [ ] Does this explain something the code can't?
- [ ] Is this the right place for this information?
- [ ] Will this stay accurate as code evolves?

If "no" to most of these, the code should speak for itself.
