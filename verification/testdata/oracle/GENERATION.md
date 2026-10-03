R1 adds 17 pairs using the same method as the original 47: run the
unchanged legacy `EolympConnectorV1.scan_bytes`, retain its single object,
and serialize with the unchanged legacy `canonical_json_bytes`. Refusals
have an expected `{error: <Python exception class>, facts: null}` document
and `refusal: true` in the manifest. Both input and expected bytes are
SHA-256 pinned. Go compares successful objects byte for byte and asserts
an unsupported refusal with zero facts for the refusal pairs.

Reproduce from the gateway checkout:

```sh
rtk proxy git -C /Users/max/Projects/ai-market/aim-data show 1edd9bfdab112517896c8026510b88ca0168c33e:app/services/data_verification/connectors/eolymp_v1.py > /var/tmp/s1791-eolymp_v1.py
rtk proxy git -C /Users/max/Projects/ai-market/aim-data show 1edd9bfdab112517896c8026510b88ca0168c33e:app/services/marketplace_action_signer.py > /var/tmp/s1791-marketplace_action_signer.py
rtk proxy /Users/max/koskadeux-state/s1791/oracle-venv-pandas/bin/python scripts/generate-verification-r1-oracle.py --connector /var/tmp/s1791-eolymp_v1.py --signer /var/tmp/s1791-marketplace_action_signer.py
```

The generator verifies the pinned connector digest, pyarrow 25.0.1, and
existing successful pairs before writing. It also requires the legacy
runtime's interpreter and pandas: Python 3.11 (aim-data Dockerfile
`python:3.11.11-slim-bookworm`) and pandas 2.1.4 (aim-data requirements.txt).
Create it with `python3.11 -m venv oracle-venv-pandas` and
`pip install pyarrow==25.0.1 pandas==2.1.4`. It uses an import-only
placeholder for the unavailable JWT module; none of the connector or
canonicalizer code is changed, and scan_bytes does not use JWT. The 47
original pairs reproduce byte for byte in this environment.

Observed in that environment: negative integers remain integer; leading plus
numbers infer float. Null tokens match without trimming. JSON fractional
seconds remain strings. CSV offsets normalize to UTC and retain a UTC suffix;
JSON offsets normalize to UTC with no suffix. CSV nanosecond values become
pandas Timestamps: nine fractional digits when the sub-microsecond part is
non-zero, Python microsecond precision otherwise. Without pandas the same
connector refuses those values, which is why pandas is required here.
Overflow and positive/negative infinity refuse during canonicalization with
ValueError and no facts.

S1791 chunk 1b adds `nanosecond_parquet` and `nanosecond_utc_parquet` pairs
using the same unchanged connector and canonicalizer. Both have a declared
Parquet timestamp[ns] column and forty values with non-zero sub-microsecond
parts; one is timezone-naive and one uses UTC. The generator asserts these
properties and writes input and expected-fact digests into the manifest.
The existing Go oracle test compares both complete canonical objects byte
for byte. No production scanner change was needed.
