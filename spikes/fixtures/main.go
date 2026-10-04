package main

import (
	"flag"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/spikes/fixtures/generate"
	"os"
)

func main() {
	kind := flag.String("format", "csv", "csv or parquet")
	out := flag.String("out", "", "output path")
	size := flag.Int64("bytes", 50000000, "CSV bytes")
	rows := flag.Int64("rows", 200000, "Parquet rows")
	seed := flag.Int64("seed", 1791, "deterministic seed")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out required")
		os.Exit(1)
	}
	f, e := os.Create(*out)
	if e != nil {
		panic(e)
	}
	switch *kind {
	case "csv":
		e = generate.CSV(f, *size, *seed)
	case "parquet":
		e = generate.Parquet(f, *rows, *seed)
	default:
		e = fmt.Errorf("invalid format")
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		panic(e)
	}
}
