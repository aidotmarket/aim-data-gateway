SHELL := /bin/sh
.PHONY: js wasi
js:
	rtk proxy mkdir -p dist
	rtk proxy env GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -o dist/scan-js.wasm .
	rtk proxy cp "$$(rtk proxy go env GOROOT)/lib/wasm/wasm_exec.js" dist/wasm_exec.js
	rtk proxy gzip -n -k -f dist/scan-js.wasm
	rtk proxy wc -c dist/scan-js.wasm dist/scan-js.wasm.gz
wasi:
	rtk proxy mkdir -p dist
	rtk proxy env GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -trimpath -o dist/scan-wasi.wasm .
	rtk proxy gzip -n -k -f dist/scan-wasi.wasm
	rtk proxy wc -c dist/scan-wasi.wasm dist/scan-wasi.wasm.gz
