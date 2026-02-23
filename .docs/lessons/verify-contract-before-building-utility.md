# Verify the Contract Before Building a Utility

**Rule**: Before writing a utility function, find the call site first. If no call site exists, the ticket is wrong — close it, don't implement it.

**Context**: A JSON extraction utility was built to extract JSON from LLM prose responses, but every prompt in the system asked for markdown (not JSON), and structured data flowed through the tool-use protocol natively. The method was dead on arrival — production code and tests with zero callers.
