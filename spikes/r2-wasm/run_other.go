//go:build !js

package main

import (
	"fmt"
	"io"
	"os"
)

func run() {
	data, e := io.ReadAll(os.Stdin)
	if e != nil {
		panic(e)
	}
	format := "csv"
	if len(os.Args) > 1 {
		format = os.Args[1]
	}
	fmt.Println(scan(data, format))
}
