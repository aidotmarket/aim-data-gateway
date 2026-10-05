package main

import (
	"context"
	"errors"
	av "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
	"testing"
)

func TestInvalidLambdaConfigRefusesBeforeAnyService(t *testing.T) {
	t.Setenv(av.EnvAPI, "https://other.example")
	if e := handler(context.Background()); !errors.Is(e, av.ErrRefused) {
		t.Fatal(e)
	}
}
