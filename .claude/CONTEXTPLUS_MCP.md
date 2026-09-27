# Context+ MCP in SCP

The root `CLAUDE.md` names the Context+ tools this repository uses and the order it uses them in. This file records how Context+ behaves on the SCP codebase.

- `semantic_code_search` fails on this codebase with "input length exceeds context length": Context+ batches files into a request larger than the embedding model's context window. Use `semantic_identifier_search` or Grep instead.
- `propose_commit` enforces Context+'s own formatting rules: a two-line file header, a `FEATURE:` tag, and no comments. SCP code follows `.docs/standards/` instead, which requires doc comments and story-referenced stub comments. Write SCP code with the standard Edit and Write tools; use `propose_commit` only when you want its validation.
