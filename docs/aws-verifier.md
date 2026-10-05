# AWS verifier release and seller setup

The verifier runs in the seller account, outside a VPC by default. It polls only
`https://api.ai.market`; its role reads the listed S3 objects/versions, its own
secret/table and log streams. It cannot list a bucket. There is no marketplace
principal, Lambda permission resource, layer or managed broad IAM policy.
The binary includes the 2b-1 Gate 3 fold; polling is configured only in Scheduler.

Supported regions: `eu-north-1`, `eu-west-1`, `eu-central-1`, `us-east-1`,
`us-west-2`. The stack region must equal the connection/bucket region. Memory is
1769 MB by default, optionally 3008 MB; timeout 900 seconds, concurrency one.
Admission remains text ≤6 GB / Parquet ≤1 GB with the shared mixed budget,
17,033 members, 780-second scan deadline and 1,920-second terminal deadline from
pickup. A free probe traverses the source and incurs AWS compute cost.

## Build and publication

An offline build requires the Go version in `go.mod` and Python 3:

```sh
bash scripts/aws-verifier-release.sh --version 0.1.0 --mode dry-run
```

It independently builds linux/arm64 `bootstrap` twice with CGO disabled, no VCS
paths/build ID, separate build caches and fixed ZIP metadata. ZIP entries consist
of one executable `bootstrap` at the root. It compares complete ZIP bytes and
prints their hex SHA-256 and base64 `CodeSha256`; `image_digest` means the ZIP
hash, not the executable hash. `dist/aws-verifier/build.json` records the source
commit, toolchain and actual compiled modules. Offline mode makes no AWS calls,
signs nothing and publishes nothing. The publish path generates a Syft SPDX
SBOM of that executable and scans fixable high/critical findings with Grype.

Tag `aws-verifier-v<semver>` triggers `.github/workflows/aws-verifier-release.yml`.
Manual dispatch performs only the double-build. The workflow uses GitHub's
Ubuntu runner with Python 3 available.
Go is pinned by `go.mod`; Syft, Grype and Cosign use the gateway release's
checksum-pinned versions. No runtime module is added.

Configure existing repository variables `AWS_VERIFIER_PUBLISH_ROLE_ARN` and
`AWS_VERIFIER_ARTIFACT_MANIFEST`. The latter is a JSON array with exactly one
entry per supported region, for example:

```json
{"region":"eu-north-1","bucket":"<existing-public-artifact-bucket>",
 "smoke_function_arn":"arn:aws:lambda:eu-north-1:<publisher-account>:function:<existing-smoke-function>"}
```

Pre-provisioning is a separate operator action. Each bucket must already have
versioning and anonymous `GetObject`/`GetObjectVersion` on release ZIP, template,
SBOM, signatures and catalog objects only, with no anonymous list/write. The
existing publisher OIDC role must be restricted to this repository/tag workflow,
the release prefix and regional smoke-function reads; it must have no permission
to delete released versions or act in seller accounts. This workflow creates
neither roles, long-lived credentials, buckets, bucket policies nor functions.

Before the publication step, an authorized operator must load the exact built
ZIP into each existing publisher-owned smoke function and exercise it with
synthetic fixtures. The release script reads each function's actual
`CodeSha256`, runtime, architecture and update state and checks against the ZIP
before any upload. It does not update/invoke functions. Retain the invocation
results separately; code identity alone does not prove registration or scanning.
Use the deterministic local build ahead of tagging to prepare those functions.

The tag workflow exchanges GitHub OIDC for the existing publisher role, signs
and verifies ZIP/template/SBOM using Cosign keyless blob bundles (issuer
`https://token.actions.githubusercontent.com`, identity pinned to the exact
workflow/tag), and publishes immutable keys:

```text
aws-verifier/<version>/<ZIP-sha256hex>/bootstrap.zip
aws-verifier/<version>/<ZIP-sha256hex>/aws-verifier.yaml
aws-verifier/<version>/<ZIP-sha256hex>/aws-verifier.spdx.json
aws-verifier/<version>/<ZIP-sha256hex>/*.sigstore.json
aws-verifier/<version>/<ZIP-sha256hex>/catalog.json
```

Every upload uses `If-None-Match:*`, requires a non-null S3 object version and
downloads that exact version anonymously for byte equality. An existing key is
never overwritten. If publication partially fails, preserve the complete local
`dist/aws-verifier` assets/receipts and rerun `publish-built` with the same version,
tag commit and manifest. Existing SBOM/signature bundles are reused, signatures
are verified again and Grype runs again. On a put precondition failure, the script
reads the existing object and adopts its non-null version only if its SHA-256
matches the local asset; the anonymous exact-version byte check still applies.
Different bytes refuse recovery. Do not delete prior versions to force a rerun.
The signed catalog records
all regional ZIP/template/SBOM/signature versions and hashes and the checked
Lambda CodeSha256. `publication.json` records the catalog/signature object
versions and download URLs. The backend must authenticate its catalog selection
through its HTTPS setup response and allowlist the scanner version/ZIP hash
before advertising availability (2c). Signature verification and real regional
smoke/public downloads are publication-time checks, not claimed by offline tests.

## Scope preflight and quick-create

Before minting a registration token or offering setup, run the compiler on the
union of the connection listings' pinned scope:

```json
{"connection_id":"11111111-1111-1111-1111-111111111111",
 "bucket":"seller-fixture","region":"eu-north-1",
 "keys":["exact.csv"],"prefixes":["workspace/approval/"],
 "sse_kms_key_arn":""}
```

```sh
python3 scripts/aws-verifier-scope.py scope.json
```

Use its `parameters` without altering scope spellings. It resolves the actual
execution policy and bounds aggregate inline-policy size using deterministic
stack resource names, a 12-digit account and the secret's six-character suffix.
It refuses >50 combined entries, >10,240 bytes (a conservative character bound),
empty scopes, wildcard or IAM policy-variable (`${`) injection and unrepresentable comma/quote/backslash/
control or trimmed-edge spellings with `aws_source_scope_unrepresentable`.
It also checks the resolved environment against [Lambda's 4 KiB serialized
environment limit](https://docs.aws.amazon.com/lambda/latest/dg/troubleshooting-deployment.html),
including escaping, key names and the maximum scanner-version length (128).
This AWS constraint can refuse a scope that fits IAM's ceiling, as required by
Amendment C-2.
Native `CommaDelimitedList` cannot round-trip those spellings. Interior spaces
and Unicode are retained. Never broaden scope to make it fit. Backend setup
must integrate this preflight in 2c; CloudFormation alone does not enforce the
aggregate ceiling. The template's 50 padded selectors per list keep IAM and
function JSON scope identical without a transform or custom resource. Template
size exceeds the inline-body limit; use its public versioned `templateURL`.

An SSE-KMS ARN adds only `kms:Decrypt` on that exact key, conditioned on
`kms:ViaService=s3.<bucket-region>.amazonaws.com`. The existing key policy may
need seller permission for the execution role; the template does not modify it.
The empty secret uses AWS managed `aws/secretsmanager` encryption without a
separate decrypt grant. The ledger is on demand with `pk` and `expires_at` TTL;
the binary sets the 30-day expiry. Logs retain 30 days. The execution role grants
only `logs:CreateLogStream` and `logs:PutLogEvents` on this group's streams;
CloudFormation creates the group, so no `logs:CreateLogGroup` grant is needed.
The binary synchronously writes bounded audit lines to stdout, refusing on a
failed or short write before source reads. Lambda delivers them to CloudWatch;
the binary has no CloudWatch Logs client (Amendment C-1). Scheduler trusts only
the seller account's regional `default` schedule group, as required by
[AWS's SourceArn rules](https://docs.aws.amazon.com/scheduler/latest/UserGuide/cross-service-confused-deputy-prevention.html).

Build the URL only inside the authenticated setup click response. Percent-encode
each value, including the complete versioned template URL and comma lists:

```text
https://<region>.console.aws.amazon.com/cloudformation/home?region=<region>#/stacks/create/review?templateURL=<encoded-versioned-template-url>&stackName=aim-aws-verifier-<connection-id>&param_ConnectionId=<uuid>&param_Bucket=<bucket>&param_BucketRegion=<region>&param_ReadKeys=<encoded-keys>&param_ReadPrefixes=<encoded-prefixes>&param_SseKmsKeyArn=<encoded-key-arn-or-empty>&param_RegistrationToken=<token>&param_PollIntervalMinutes=1&param_MemorySize=1769&param_ArtifactBucket=<regional-bucket>&param_ArtifactKey=<encoded-content-addressed-key>&param_ArtifactObjectVersion=<encoded-version>&param_ExpectedCodeHash=sha256%3A<zip-hash>&param_ScannerVersion=<version>&param_ApiBaseUrl=https%3A%2F%2Fapi.ai.market
```

This follows the [AWS quick-create parameter format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
The ordinary token parameter is intentionally not `NoEcho`; AWS ignores URL
prefill for NoEcho. It reaches only `AIM_AWS_REGISTRATION_TOKEN`, never Outputs
or Metadata. It is visible to authorized seller `DescribeStacks` users and in
browser history: a 256-bit token expires after 30 minutes, is single-use and
connection/kind/hash-bound. The template and binary require exactly 32 bytes in
canonical unpadded base64url (43 characters, including zero trailing padding bits).
A seller-account principal could win the initial
registration race. Check the displayed hash/time; remove and replace unexpected
registrations with a fresh token. Expired tokens are never renewed. Never save
the URL/token in marketplace logs, analytics, local storage or release evidence.
Ready requires backend registration and a successful poll, not stack completion.

Change only `PollIntervalMinutes` to 1, 5 or 15 through a normal stack update
using previous values for other parameters. It changes only the schedule
expression; the entire function (code, environment, role, memory), IAM, scope
and every other resolved property remain byte-identical (Amendment C-3).
The binary does not read or validate a polling interval. Longer intervals
reduce idle cost and add up to 15 minutes of pickup delay; signed consent expiry
and the 1,920-second deadline from pickup still apply.

Optional seller-managed strict networking is separate: S3/DynamoDB gateway
endpoints, Secrets Manager/KMS/Logs interface endpoints and allowlisted egress
to api.ai.market. The spec's approximately $77/month estimate excludes usage;
unrestricted NAT alone does not restrict egress. No VPC resources are in the
default template. Remove/revoke through the website before deleting the stack;
retain private evidence first. Delivery authority remains separate.

## Evidence mapping and remaining live proof

`go test ./deploy` includes:

| Requirement (§3.2 / §7 2b) | Test |
| --- | --- |
| Exactly seven resources, pinned ZIP, runtime/architecture/limits, empty secret, ledger/TTL, explicit log dependency/retention | `TestExactResourcesAndRuntime` |
| Exact Lambda/Scheduler trusts, seller group/account restrictions, all actions/scopes, no ListBucket/broad managed policy/marketplace principal, optional KMS condition, no payload/retries | `TestTrustActionsScopesAndKMS` |
| Ordinary prefilled token reaches function only; Outputs/Metadata absence; canonical 32-byte token constraints match binary; exact environment parses | `TestTokenPathAndBinaryConfigContract` |
| Supported regions/equality, memory defaults/max, fixed API, three rates/rejection and resolved resource diff for parameter-only updates | `TestRegionMemoryPollLimitsAndParameterOnlyUpdate` |
| Key/prefix ARNs, 1–50 entries, 51/combined-count/size refusal before setup, wildcard/unrepresentable scope refusal | `TestScopeCompilerLimitsAndNoWildcardBroadening` |
| Resolved environment accepts 4,095/4,096 bytes and refuses 4,097 with `aws_source_scope_unrepresentable` | `TestScopeCompilerEnvironmentBoundary` |
| No extra command/URL/scope parameters | `TestExactParameters` |
| ZIP layout/reproducibility metadata, ZIP-derived CodeSha256, regional manifest/smoke rejection, immutable versioned download equality, keyless sign/verify and direct subprocess execution | `TestReleaseOfflineContracts` (Python standard-library fixtures) |

The real dry-run separately compiles the binary twice; mocked release tests do
not substitute for publication proof. Gate 4 still requires the authorized real
seller quick-create/registration/poll journey, poll-only update, each advertised
region and second seller account, public version downloads, actual seller Lambda
CodeSha256, probe/paid scan/publication, consent/replay/mutation/KMS/deadline
cases, CloudTrail principal/object-read evidence, outbound marker checks and
removal preserving delivery. Existing 2b-1 Go code/tests own TLS pins, transport,
scanner, admission and recovery; this chunk does not reopen those contracts.
