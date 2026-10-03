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
rtk proxy /Users/max/koskadeux-state/s1791/oracle-venv/bin/python scripts/generate-verification-r1-oracle.py --connector /var/tmp/s1791-eolymp_v1.py --signer /var/tmp/s1791-marketplace_action_signer.py
```

The generator verifies the pinned connector digest, pyarrow 25.0.1, and
existing successful pairs before writing. It uses an import-only placeholder
for the unavailable JWT module; none of the connector or canonicalizer code
is changed, and scan_bytes does not use JWT.

Observed in this exact venv: negative integers remain integer; leading plus
numbers infer float. Null tokens match without trimming. JSON fractional
seconds remain strings. CSV offsets normalize to UTC and retain a UTC suffix;
JSON offsets normalize to UTC with no suffix. CSV nanosecond values divisible
by 1,000 emit Python microsecond precision. Other nanosecond values refuse
in the supplied environment because pandas is absent, so Arrow cannot safely
convert them to datetime.datetime. No pandas was installed to change that
reference behavior. Overflow and positive/negative infinity refuse during
canonicalization with ValueError and no facts.
