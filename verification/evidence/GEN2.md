CP81 gen2 pins the gateway production RC to `25779953b1c27e0dec5f39ba871422a6b81f8cff`
and the detached, read-only backend checkout `/var/tmp/cp81-backend-0f7b61ff` to
`0f7b61ff58463a1bd1fe40f89d824059d1bb2bc3`. No backend commit is created.

From a committed, clean evidence-only checkout descending from the gateway RC:

```sh
rtk proxy python3 verification/evidence/regenerate.py
```

The script refuses a moved main and an existing `/Users/max/koskadeux-state/s1791/cp81/gen2`.
It captures the 36 frames exactly once inside E3, while each corresponding live
commitment key exists, and searches seeded markers through raw and decoded layers.
E3 retains harness references only in memory so E4 can audit those exact reports.
The 216 reconstruction fixture results remain separately identified by their own
report hashes; they are additional scanner scenarios, not the 36 E2 frames.

Conformance preserves the full 2,130-case symmetric comparison as a record; a
nonzero symmetric diff is disclosed, not declared equivalent or approved. The
separate directional criterion requires actual emitted receiver documents to be
accepted with identical canonical bytes, current backend signed scan/probe vectors
to pass Go VerifyScan, and invalid receive-direction corpus cases to be rejected.
Every symmetric difference has a classification and closure citation. Accepted
schema mutations are positive/normalization cases, not mislabeled negatives.
The re-encoding audit includes gateway registration over the original decoded dict.

`raw_locator.py BACKEND OUTPUT` is independently executable with the backend's
`.venv/bin/python -B` (the environment with the complete service dependencies). It creates disposable local PostgreSQL databases via RC
fixture setup and calls real gateway, shared-cloud, and AWS receipt validators.
A valid receipt is the control. The same report re-signed over a binding replacing
`artifact_locator_commitment` with `raw_locator` must fail signature verification.
An extra raw-locator document field must also fail strict parsing. Missing local
PostgreSQL fails the run. Production validators/signature verification are not mocked.

`generation_manifest.py GEN2` independently checks capture inventories, key absence,
capture reconstruction, fixture report hashes, directional checks and tamper results.
The manifest inventories all artifacts and complete command logs. Its own checksum
is external in `manifest.sha256`, avoiding a recursively defined self-hash.
Private evidence is not committed. All Go harness files remain evidence build-tagged.
These local serializer/model/receipt checks do not claim live TLS, deployed cloud,
customer IAM custody, or approval of a replacement checkpoint criterion.

The generator records a failed directional check and continues the remaining
categories before exiting 1. The initial gen2 execution was continued with
`regenerate.py --resume` after that failure and standalone environment setup failures. This
continuation is allowed only after that recorded failure and never reruns captures
or Go fixture tests. Both harness revisions are retained. The manifest separates
frame-integrity self-check success from the failed directional release criterion;
the overall generator exits 1 when a recorded check failed.
