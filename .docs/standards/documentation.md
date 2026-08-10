# Documentation Standards

When to document code, how to write the documentation, and which prose rules bind it.

## Philosophy

Documentation exists so a reader learns something faster than they would by reading the code. Write what a reader needs in order to use the thing correctly. Do not write documentation to make a coverage count go up.

## Prose rules (binding)

Every sentence in every document in this repository follows the Prose rules in `CLAUDE.md`. Read that section before you write documentation. Those rules require, in short: name the agent, give every verb its object, state how each clause relates to the clause beside it, write in the active voice, report rather than appraise, delete a modifier a reader cannot check, name a thing beside every identifier you cite, and write the shortest sentence that still does all of that.

Documentation adds one further requirement, from the same `CLAUDE.md` rule about contracts: **state the criterion, then label the indicators.** A doc comment that lists the conditions under which a function usually works has told the reader nothing about when the function is correct to call. Write the precondition the caller must satisfy, then list the symptoms of violating it as symptoms.

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

## Inline Documentation

Use the language's standard doc-comment syntax. Focus on **why** and **how to use**, not **what** (the code shows what).

| Language | Doc syntax | Generator |
|----------|-----------|-----------|
| Rust | `///` / `//!` | rustdoc |
| Python | `"""docstring"""` | pdoc |
| TypeScript | `/** JSDoc */` | typedoc |
| Swift | `///` | DocC |
| Kotlin | `/** KDoc */` | Dokka |
| Go | `// Comment` | godoc |
| C# | `/// <summary>` | xmldoc |
| Java | `/** Javadoc */` | Javadoc |

**Document when:**
- Behavior isn't obvious from the signature
- There are important preconditions or side effects
- Errors need explanation
- Usage patterns matter

**Skip when:**
- The name says it all (simple getters, standard CRUD)
- It's a standard pattern the team already knows

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
