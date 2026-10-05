package main

import (
	"context"
	"errors"
	"testing"

	av "github.com/aidotmarket/aim-data-gateway/internal/awsverification"
)

func TestInvalidLambdaConfigRefusesBeforeAnyService(t *testing.T) {
	t.Setenv(av.EnvAPI, "https://other.example")
	if e := handler(context.Background()); !errors.Is(e, av.ErrRefused) {
		t.Fatal(e)
	}
}
