# Authoritative TLS pin fixtures

Downloaded unchanged from the self-signed root certificate links at
https://letsencrypt.org/certificates/ on 2026-10-05. These are public
certificates, not private keys. SHA-256 below covers the exact PEM file bytes;
`TestAuthoritativeRootSPKI` independently derives the SPKI SHA-256 pins from
these bytes and compares them with the release constants in `transport.go`.

| File | Source URL | File SHA-256 |
| --- | --- | --- |
| x1.pem | https://letsencrypt.org/certs/isrgrootx1.pem | 22b557a27055b33606b6559f37703928d3e4ad79f110b407d04986e1843543d1 |
| x2.pem | https://letsencrypt.org/certs/isrg-root-x2.pem | a13d881e11fe6df181b53841f9fa738a2d7ca9ae7be3d53c866f722b4242b013 |
| yr.pem | https://letsencrypt.org/certs/gen-y/root-yr.pem | d8a34bfb5df6b4a0592b0a9cd6b3b9a9335bd431cb2ac32243ab298cba24cbf2 |
| ye.pem | https://letsencrypt.org/certs/gen-y/root-ye.pem | b8471c8049835b4097069ae3d43ea8235b510c0aa2699dedaaab9bc10be3d2c4 |
