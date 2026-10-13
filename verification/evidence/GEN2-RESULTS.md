CP81 gen2 final-candidate results

Gateway production RC: `25779953b1c27e0dec5f39ba871422a6b81f8cff`.
Backend RC: `0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3`, detached at
`/var/tmp/cp81-backend-0f7b61ff`; backend tracked/untracked status remained clean.

Private evidence: `/Users/max/koskadeux-state/s1791/cp81/gen2/manifest.json`.
The manifest and checksum identify every generated artifact, 36 capture frames,
harness revisions, exact argv, exit code and full command log. Old CP81 artifacts
were left untouched. Captures and the 216 reconstruction fixtures were run once.
Analysis continued against the same captures after recorded failures, rather than
regenerating frames; all failed outputs remain preserved.

| Check | Result |
| --- | --- |
| Capture/keyflow/reconstruction/conformance frame identity | 36/36 identical |
| Seeded markers and live commitment keys, raw and decoded | Zero hits |
| Local entropy/input independence and source audit | All 3 runners pass |
| Reconstruction | 216/216 fixtures plus 3 captured scan reports pass |
| Symmetric corpus, retained as record | 2,130 cases; 1,126 differences (A 1,104 / B 14 / C 8) |
| Real receiver documents | 29/29 accepted; 28/29 full model-dump byte equal |
| Backend-issued signed scan/probe specs in Go VerifyScan | 2/2 pass |
| Receive-direction invalid corpus cases | 1,184/1,184 rejected |
| Raw-locator signed-binding tamper + valid control | Gateway, shared and AWS all pass |
| Go evidence suite and both vet commands | Exit 0 |
| Frame-integrity self-check | Exit 0 |
| Overall directional criterion / generation | FAIL / exit 1 |

Remaining criterion failure: `r2_verifier/registration.frame` omits optional
`image_digest`; `CloudflareRunnerRegistration.model_dump(mode="json")` inserts
`image_digest: null`. The receiver accepts the original canonical document, but
the full dump bytes differ. The criterion was not weakened using `exclude_unset`.
Cloudflare registration verifies the original decoded dictionary (see the
re-encoding audit), so this is not an observed signature bypass. It is nevertheless
a failed requested full-dump byte-equality condition at the exact RCs. Production
changes or a criterion change would require separate work/decision.

The re-encoding audit also includes gateway registration proof over the original
decoded dictionary at `app/services/verification_runner_service.py:114-137`.
Every one of the 1,126 symmetric differences has a category and closure citation;
the symmetric comparison is not described as zero-diff or as an approved substitute.

Executed Go checks (with `EVIDENCE_OUT=/Users/max/koskadeux-state/s1791/cp81/gen2/captures`):

```sh
rtk proxy go test -count=1 -tags evidence ./verification/evidence/... -v  # exit 0
rtk proxy go vet -tags evidence ./...                                 # exit 0
rtk proxy go vet ./...                                                # exit 0
```

All Python generation/receiver/standalone commands and failed setup attempts are
recorded verbatim in private `commands.json` and the manifest. The standalone
receipt run uses `.venv/bin/python` with complete backend service dependencies;
model conformance uses `.venv-ci/bin/python`. Test-only fixture signing/KMS/payment
setup does not patch production receipt validators or signature verification.
No merge or backend commit is part of this evidence PR.
