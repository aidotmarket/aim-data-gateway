package main

import (
	"context"
	"encoding/json"
	"github.com/aidotmarket/aim-data-gateway/spikes/cloud"
	h "github.com/aidotmarket/aim-data-gateway/spikes/harness"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	endpoint, key, secret := os.Getenv("R2_ENDPOINT"), os.Getenv("R2_ACCESS_KEY_ID"), os.Getenv("R2_SECRET_ACCESS_KEY")
	if endpoint == "" || key == "" || secret == "" {
		log.Fatal("R2 environment required")
	}
	client := s3.NewFromConfig(aws.Config{Region: "auto", Credentials: credentials.NewStaticCredentialsProvider(key, secret, "")}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		o.RetryMaxAttempts = 1
	})
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		if !mu.TryLock() {
			http.Error(w, "busy", 429)
			return
		}
		defer mu.Unlock()
		var e h.Event
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			http.Error(w, "invalid event", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
		defer cancel()
		out := h.Run(ctx, e, cloud.Factory(client, "r2_listing"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 16 * time.Minute}
	log.Fatal(srv.ListenAndServe())
}
