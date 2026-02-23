# Tool Catalog: Single Source of Truth in Tool Definitions

**Problem**: AI tool definitions were duplicated: once as a human-readable list in the system prompt and again as structured tool definition objects. Every new tool required edits in both places, and descriptions could drift.

**Root Cause**: The API sends tool definition objects alongside messages — the model already sees the full tool catalog from the schema. Listing tools again in the system prompt is redundant.

**Fix**:
- **System prompts**: Say "You have tools for modifying [X]" without enumerating them. Keep behavioral guidelines about *when* and *how* to use tools.
- **Tool definitions**: The single source of truth for what each tool does. Include composition guidance here.
- **Guidelines that reference tool names by name** (like "use X + Y for this workflow") are fine in the prompt — they're behavioral strategy, not catalog duplication.

**Rule**: Never enumerate tool names/signatures in system prompts. Let tool definitions be the catalog; let the prompt be the strategy.
