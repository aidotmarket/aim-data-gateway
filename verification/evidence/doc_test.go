//go:build evidence

// Package evidence produces checkpoint 8.1 E2/E4 evidence against the committed
// S1590/S1791 scanner and customer-to-cloud serializers. It is excluded from
// ordinary builds, including the shipped gateway and verifier images.
//
// Authority: runbooks 2870b0b6389b491aaa3089d215a9f3af5280d5ee,
// specs/BQ-DATA-VERIFICATION-S1590-CHECKPOINTS-8.1-8.2-CLOSURE.md,
// R8 and section 5.1 rows GATE2 :392 (E2) and :394 (E4).
// Scanner/serializer release candidate: 32d0efd0c5fcad1b1c58e45f476e0cfd3286f2dd.
//
// Run from the repository root:
//
//	go test -tags evidence ./verification/evidence/...
//
// To force regeneration rather than a cached test result, add -count=1.
// EVIDENCE_OUT defaults to /Users/max/koskadeux-state/s1791/cp81/captures.
// E2 writes frames plus summary.json there; E4 writes decoded attack results and
// original report frames into its sibling reconstruction directory. Files have
// private permissions. No live provider, marketplace, or production requests
// are made. Source fixtures/vectors are never changed.
//
// The harness starts with the committed gateway signed scan vector, verifies
// it, then varies local fixtures and source metadata for serializer testing.
// Private runner methods are referenced by test-only go:linkname declarations;
// there are no copied serializers or source overlays. Gateway runs through its
// real source adapter, ledger, scanner, receipt signer and audit outbox. Cloud
// runs through the real S3/R2 source adapters and native scan/encodeReport paths.
// Local fakes supply only provider bytes, a bootstrap lease and HTTP responses.
// This is wire/scanner evidence, not admission, consent, TLS or key-flow proof.
//
// E2 seeds distinctive cells, local file paths, bucket/key names, a Parquet
// footer column comment, fake AKIA credentials and a fake PEM header. Every
// captured frame is searched raw, JSON-unescaped and recursively base64/JWS
// decoded. Gateway has an inbound work instruction, not an outbound work poll;
// its outbound snapshot claims are captured. Cloud audit error evidence uses
// the real fixed refused event/hash form, not a fictitious gateway error frame.
//
// E4 checks all pinned oracle fixtures with their independent aggregate facts,
// plus one-row, two-row, nine-distinct, adversarial schema and eolymp-shaped
// fixtures, for all three runner kinds. It records exact row counts, schema,
// inferable null counts and populated bucket bounds. Low occupancies must stay
// suppressed. Column names are disclosed literally, including adversarial text.
// Whole-snapshot gateway content hashes can confirm guesses given public file
// identities; cloud member_sha256s additionally confirm per-file content and
// link equal bytes within/across reports. These are recorded successes, not
// failures. Gateway locator/object dictionary attacks include the true path,
// public identities, guessed content and several wrong/publicly derived keys;
// a customer-key positive control verifies each target preimage. Finite misses
// do not constitute a cryptographic proof. No customer commitment key is saved.
package evidence
