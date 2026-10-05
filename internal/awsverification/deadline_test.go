package awsverification

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type delayedOutbox struct {
	Dynamo
	delay func()
}

func (d delayedOutbox) GetItem(ctx context.Context, input *dynamodb.GetItemInput, options ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if strings.HasPrefix(pk(input.Key), "outbox#") {
		d.delay()
	}
	return d.Dynamo.GetItem(ctx, input, options...)
}

func TestCommittedOutboxDeadlineBoundaryAndCrossing(t *testing.T) {
	for _, mode := range []string{"at_deadline", "after_deadline", "cross_during_load"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			job := f.job(t, 1, "scan")
			f.audit.fail = "committed"
			if f.h.Invoke(ctx) == nil || len(f.backend.reports) != 0 {
				t.Fatal("fixture must crash after commit and before intake")
			}
			record, _, err := f.h.Ledger.record(ctx, job.Text("spec_id"))
			if err != nil {
				t.Fatal(err)
			}
			saved, err := f.h.Ledger.Body(ctx, record, f.at)
			if err != nil {
				t.Fatal(err)
			}
			reads := len(f.s3.requests)
			f.audit.fail = ""
			f.backend.work = ""
			deadline := time.Unix(record.Pickup+AWS_VERIFY_TERMINAL_DEADLINE_SECONDS, 0)
			f.at = deadline
			if mode == "after_deadline" {
				f.at = deadline.Add(time.Second)
			}
			if mode == "cross_during_load" {
				f.h.Ledger.Client = delayedOutbox{Dynamo: f.db, delay: func() {
					f.at = deadline.Add(time.Second)
				}}
			}
			f.backend.deadline = deadline.Unix()
			f.backend.at = f.at
			err = f.h.Invoke(ctx)
			if mode == "at_deadline" {
				if err != nil || len(f.backend.reports) != 1 || !bytes.Equal(saved, f.backend.reports[0]) {
					t.Fatal("exact deadline must resend saved bytes", err)
				}
			} else {
				if len(f.backend.reports) != 0 {
					t.Fatal("report sent after deadline")
				}
				if mode == "cross_during_load" && err == nil {
					t.Fatal("deadline crossed during load without refusal")
				}
				// A subsequent ordinary poll settles locally; payment voiding is
				// the control plane's independent pickup-deadline responsibility.
				if err = f.h.Invoke(ctx); err != nil {
					t.Fatal(err)
				}
				record, _, err = f.h.Ledger.record(ctx, job.Text("spec_id"))
				if err != nil || record.State != "expired" {
					t.Fatal("late outbox did not expire", err, record.State)
				}
			}
			if len(f.s3.requests) != reads {
				t.Fatal("deadline recovery rescanned")
			}
		})
	}
}
