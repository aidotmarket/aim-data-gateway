//go:build js && wasm

package main

import "syscall/js"

func run() {
	fn := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 2 {
			return `{"error":"arguments"}`
		}
		data := make([]byte, args[0].Get("byteLength").Int())
		js.CopyBytesToGo(data, args[0])
		return scan(data, args[1].String())
	})
	js.Global().Set("spikeScan", fn)
	select {}
}
