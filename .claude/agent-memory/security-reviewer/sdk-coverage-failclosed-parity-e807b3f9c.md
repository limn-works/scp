# SDK coverage fail-closed + parity (fix/sdk-coverage-fail-closed-and-parity, HEAD e807b3f9c) -- 2026-06-22 -- APPROVED, ZERO FINDINGS

Re-verify of the b27ef7bff / 341df72cc branch family at new HEAD e807b3f9c. New commits
since 341df72cc: source_id always-present-nullable (TypedDict total vs NotRequired) + §3.2.1->§9.12
citation fix in TS bridge comment. ALL non-logic doc/type changes.

## Gate (scripts/check-sdk-coverage.py) — fail-closed strengthening, SOUND
- Real matrix: 0 errors / 223 ops, 1 coverage-exempt (add_relay_url kotlin, verifiable reason),
  exit 0. 11 self-tests pass.
- WARNING->ERROR on unmatched `true`: capability marked present w/ no locatable symbol now FAILS
  unless explicit coverage_exemptions reason. Was previously a non-blocking warning (bypass).
- Suffix/substring matching REMOVED (closed ~23-fabricated-name bypass). Matching now = exact
  ALIASES set-membership OR domain-prefixed exact (domain_snake / domain_camel / Domain.op).
  Bare op_name/camel/pascal candidates removed (a stray `migrate` anywhere satisfied Identity/migrate).
- New fail-closed errors: missing SDK key entirely (authoring gap), unexpected cell value
  (non-bool/non-null), empty/blank exemption reason, empty coverage_exemptions reason.
- ALL-EXEMPTED check BOUNDED: if every true-SDK for an op is coverage-exempt AND none statically
  verified -> ERROR. So a single-SDK true that's coverage-exempt FAILS (op_true==op_exempted,
  op_verified empty). add_relay_url is SAFE because py/ts/swift verified true; kotlin-only exempt.
- CLAUDE.md adds check-sdk-coverage.py to enforcement-files list (weakening now needs human approval).

## TS evaluateTrust (trust.ts) — byte-equivalent to Python, NO trust escalation
- PERM-3030 re-raise fires BEFORE __classifyUcanError in BOTH (ts ~/^\[SCP-PERM-3030\]/ throw;
  py startswith("[SCP-PERM-3030]") raise). Non-PERM error propagates. Classified failure sets fields
  per __PASSED_BEFORE then breaks.
- Optimistic-start (all fields true, downgrade on first failure): fields stay all-true ONLY if every
  token validates. Unknown category -> empty set -> all false (fail-safe, no escalation).
- ATTACKER-CONTROLLED ERROR STRING analysis: __classifyUcanError prefix-matches Rust UcanError Display.
  Fixed prefix ALWAYS leads (#[error("token expired")], #[error("malformed token: {0}")]); attacker
  content ({did},{e}) comes AFTER. Step ordering: SIGNATURE_CHAIN first (fewest passed) then ceiling,
  token_parse, nonce, revoked, expiry (most passed). Parse-stage MalformedToken strings ("bad base64",
  "header base64url decode failed: {e}", "missing signature segment") do NOT start with step-2 phrases
  ("DID not found"), so no early->late misclassification escalation. Worst case = 1 bool flip; AND
  evaluateTrust returns DATA NOT VERDICT (no auth decision inside). Not a vuln.
- __setBridgeForTests (internal/bridge.ts) NOT exported from index.ts; tsup DCE + exports map +
  assertTestEnvironment (test-guard.ts: frozen-at-load _IS_TEST_ENVIRONMENT, Object.hasOwn anti-
  prototype-pollution, fail-closed if process absent). Sound.

## Python SDK additions — clean
- economy_verify_payment_receipts: 10k cap ENFORCED at Rust boundary (economy.rs:485 before dispatch,
  DoS rationale = serial adapter round-trips). Python docstring accurate. Note: serde parse precedes
  len check (parse-cost bounded by normal req limits, acceptable).
- discover_contexts = passthrough to Rust context_discover (query validation in validate.rs). TypedDicts
  (DiscoveryResult/PaymentReceipt*/BridgeTrustLevel Literal) = types only. No injection/format-string/
  secrets/sensitive-logging in added lines. evaluate_trust contexts_participated=1->0 (honesty fix).
- Matrix diff: rotate_key exemption honesty (still false), Bridge/register ts true->false+exemption
  (TIGHTENING), add_relay_url kotlin coverage_exemption (3/4 verified, bounded).
