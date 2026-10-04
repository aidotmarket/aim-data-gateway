# R2 WASM spike

See [../README.md](../README.md) for build / runtime instructions and boundaries.
Both `make js` and `make wasi` compiled successfully on Go 1.27.1, so no compiler
error was observed. Sizes: js 39,340,479 raw / 6,538,771 gzip bytes; WASI 39,272,996
raw / 6,535,225 gzip bytes. These are ordinary Go builds, not TinyGo.
See [../results/README.md](../results/README.md) for the measured findings.
