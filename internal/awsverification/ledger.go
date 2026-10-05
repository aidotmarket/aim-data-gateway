package awsverification

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Dynamo interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}
type Ledger struct {
	Client Dynamo
	Table  string
}
type Clock struct {
	Last    int64
	Version int64
	Active  string
}
type Record struct {
	Job    wire.ScanJob
	Pickup int64
	State  string
	Chunks int
	Hash   string
	Length int
}

// Observe every invocation, preserving the clock high water even on empty polls.
// Unresolved evidence is never eligible for asynchronous TTL deletion.
func (l Ledger) Observe(ctx context.Context, at time.Time) error {
	for retry := 0; retry < 5; retry++ {
		c, exists, e := l.clock(ctx)
		if e != nil || c.Last > at.Unix()+300 {
			return ErrRefused
		}
		old := c.Version
		c.Version++
		c.Last = max(c.Last, at.Unix())
		m, e := item("clock", c, at)
		if e != nil {
			return e
		}
		m["version"] = num(c.Version)
		cond := "attribute_not_exists(pk)"
		var values map[string]d.AttributeValue
		if exists {
			cond = "version = :old"
			values = map[string]d.AttributeValue{":old": num(old)}
		}
		writes := []d.TransactWriteItem{{Put: &d.Put{
			TableName:                 aws.String(l.Table),
			Item:                      m,
			ConditionExpression:       aws.String(cond),
			ExpressionAttributeValues: values,
		}}}
		_, e = l.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: writes})
		if e == nil {
			return nil
		}
	}
	return ErrRefused
}

func str(s string) d.AttributeValue {
	return &d.AttributeValueMemberS{Value: s}
}
func num(n int64) d.AttributeValue {
	return &d.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}
func key(pk string) map[string]d.AttributeValue {
	return map[string]d.AttributeValue{"pk": str(pk)}
}
func item(pk string, v any, at time.Time) (map[string]d.AttributeValue, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > 300<<10 {
		return nil, ErrRefused
	}
	m := key(pk)
	m["data"] = &d.AttributeValueMemberB{Value: b}
	m["expires_at"] = num(at.Add(30 * 24 * time.Hour).Unix())
	if pk == "clock" || pk == "bootstrap" || strings.HasPrefix(pk, "outbox#") {
		delete(m, "expires_at")
	}
	if r, ok := v.(Record); ok && r.State != "reported" {
		delete(m, "expires_at")
	}
	return m, nil
}
func (l Ledger) get(ctx context.Context, pk string, out any) (bool, error) {
	r, e := l.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(l.Table), Key: key(pk), ConsistentRead: aws.Bool(true)})
	if e != nil {
		return false, ErrRefused
	}
	if len(r.Item) == 0 {
		return false, nil
	}
	b, ok := r.Item["data"].(*d.AttributeValueMemberB)
	if !ok || json.Unmarshal(b.Value, out) != nil {
		return false, ErrRefused
	}
	return true, nil
}
func (l Ledger) put(ctx context.Context, pk string, v any, at time.Time, condition string) error {
	m, e := item(pk, v, at)
	if e != nil {
		return e
	}
	var cond *string
	if condition != "" {
		cond = aws.String(condition)
	}
	_, e = l.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(l.Table), Item: m, ConditionExpression: cond})
	if e != nil {
		return ErrRefused
	}
	return nil
}
func (l Ledger) clock(ctx context.Context) (Clock, bool, error) {
	var c Clock
	exists, e := l.get(ctx, "clock", &c)
	return c, exists, e
}
func (l Ledger) record(ctx context.Context, id string) (Record, bool, error) {
	var r Record
	exists, e := l.get(ctx, "spec#"+id, &r)
	return r, exists, e
}
func (l Ledger) Admit(ctx context.Context, j wire.ScanJob, at time.Time, pickup ...time.Time) (bool, error) {
	for retry := 0; retry < 5; retry++ {
		r, exists, e := l.record(ctx, j.Text("spec_id"))
		if e != nil {
			return false, e
		}
		if exists {
			if r.Job.Envelope.SpecHash != j.Envelope.SpecHash || r.Job.Token != j.Token {
				return false, ErrRefused
			}
			return false, nil
		}
		c, present, e := l.clock(ctx)
		if e != nil || c.Last > at.Unix()+300 || c.Active != "" {
			return false, ErrRefused
		}
		previous := c.Version
		c.Last = max(c.Last, at.Unix())
		c.Version++
		c.Active = j.Text("spec_id")
		ci, e := item("clock", c, at)
		if e != nil {
			return false, e
		}
		ci["version"] = num(c.Version)
		cond := "attribute_not_exists(pk)"
		values := map[string]d.AttributeValue(nil)
		if present {
			cond = "version = :old"
			values = map[string]d.AttributeValue{":old": num(previous)}
		}
		writes := []d.TransactWriteItem{{Put: &d.Put{
			TableName:                 aws.String(l.Table),
			Item:                      ci,
			ConditionExpression:       aws.String(cond),
			ExpressionAttributeValues: values,
		}}}
		for _, pk := range []string{"nonce#" + j.Text("nonce"), "authorization#" + j.Text("owner_authorization_id"), "spec#" + j.Text("spec_id")} {
			var v any = map[string]string{"spec_hash": j.Envelope.SpecHash}
			if pk == "spec#"+j.Text("spec_id") {
				picked := at
				if len(pickup) > 0 {
					picked = pickup[0]
				}
				if picked.After(at) {
					return false, ErrRefused
				}
				v = Record{Job: j, Pickup: picked.Unix(), State: "running"}
			}
			m, e := item(pk, v, at)
			if e != nil {
				return false, e
			}
			writes = append(writes, d.TransactWriteItem{Put: &d.Put{TableName: aws.String(l.Table), Item: m, ConditionExpression: aws.String("attribute_not_exists(pk)")}})
		}
		writes = append(writes, d.TransactWriteItem{Update: &d.Update{
			TableName:                 aws.String(l.Table),
			Key:                       key("daily#" + j.Text("listing_id") + "#" + at.UTC().Format("2006-01-02")),
			UpdateExpression:          aws.String("SET expires_at = :ttl ADD accepted_count :one"),
			ConditionExpression:       aws.String("attribute_not_exists(accepted_count) OR accepted_count < :ten"),
			ExpressionAttributeValues: map[string]d.AttributeValue{":ttl": num(at.Add(30 * 24 * time.Hour).Unix()), ":one": num(1), ":ten": num(10)},
		}})
		_, e = l.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: writes})
		if e == nil {
			return true, nil
		}
	}
	return false, ErrRefused
}

const outboxChunk = 180 << 10

func (l Ledger) Commit(ctx context.Context, r Record, body []byte, at time.Time) error {
	if len(body) == 0 || len(body) > MaxReport || at.Unix() > r.Pickup+AWS_VERIFY_TERMINAL_DEADLINE_SECONDS {
		return ErrRefused
	}
	// Chunks are immutable; no complete descriptor becomes visible until all exist.
	r.Hash = wire.Digest(body)
	r.Length = len(body)
	r.Chunks = (len(body) + outboxChunk - 1) / outboxChunk
	for i := 0; i < r.Chunks; i++ {
		pk := fmt.Sprintf("outbox#%s#%s#%d", r.Job.Text("spec_id"), r.Hash, i)
		chunk := body[i*outboxChunk : min((i+1)*outboxChunk, len(body))]
		if e := l.put(ctx, pk, chunk, at, "attribute_not_exists(pk)"); e != nil {
			var saved []byte
			ok, e := l.get(ctx, pk, &saved)
			if e != nil || !ok || string(saved) != string(chunk) {
				return ErrRefused
			}
		}
	}
	r.State = "committed"
	m, e := item("spec#"+r.Job.Text("spec_id"), r, at)
	if e != nil {
		return e
	}
	// A late/interrupted writer cannot replace a settled descriptor.
	m["state"] = str("committed")
	_, e = l.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                aws.String(l.Table),
		Item:                     m,
		ConditionExpression:      aws.String("attribute_exists(pk) AND attribute_not_exists(#state)"),
		ExpressionAttributeNames: map[string]string{"#state": "state"},
	})
	if e != nil {
		return ErrRefused
	}
	return nil
}
func (l Ledger) Body(ctx context.Context, r Record, at time.Time) ([]byte, error) {
	if r.State != "committed" || r.Chunks < 1 || r.Length > MaxReport || r.Chunks != (r.Length+outboxChunk-1)/outboxChunk {
		return nil, ErrRefused
	}
	b := make([]byte, 0, r.Length)
	for i := 0; i < r.Chunks; i++ {
		pk := fmt.Sprintf("outbox#%s#%s#%d", r.Job.Text("spec_id"), r.Hash, i)
		var part []byte
		ok, e := l.get(ctx, pk, &part)
		if e != nil || !ok || len(part) > outboxChunk {
			return nil, ErrRefused
		}
		b = append(b, part...)
	}
	if len(b) != r.Length || wire.Digest(b) != r.Hash {
		return nil, ErrRefused
	}
	return b, nil
}
func (l Ledger) Settle(ctx context.Context, r Record, at time.Time, state string) error {
	c, ok, e := l.clock(ctx)
	if e != nil || !ok || c.Active != r.Job.Text("spec_id") {
		return ErrRefused
	}
	old := c.Version
	c.Version++
	c.Active = ""
	c.Last = max(c.Last, at.Unix())
	ci, e := item("clock", c, at)
	if e != nil {
		return e
	}
	ci["version"] = num(c.Version)
	r.State = state
	ri, e := item("spec#"+r.Job.Text("spec_id"), r, at)
	if e != nil {
		return e
	}
	ri["state"] = str(state)
	writes := []d.TransactWriteItem{
		{Put: &d.Put{
			TableName:                 aws.String(l.Table),
			Item:                      ci,
			ConditionExpression:       aws.String("version = :old"),
			ExpressionAttributeValues: map[string]d.AttributeValue{":old": num(old)},
		}},
		{Put: &d.Put{TableName: aws.String(l.Table), Item: ri}},
	}
	if state == "reported" {
		for i := 0; i < r.Chunks; i++ {
			writes = append(writes, d.TransactWriteItem{Update: &d.Update{
				TableName:                 aws.String(l.Table),
				Key:                       key(fmt.Sprintf("outbox#%s#%s#%d", r.Job.Text("spec_id"), r.Hash, i)),
				UpdateExpression:          aws.String("SET expires_at = :ttl"),
				ConditionExpression:       aws.String("attribute_exists(pk)"),
				ExpressionAttributeValues: map[string]d.AttributeValue{":ttl": num(at.Add(30 * 24 * time.Hour).Unix())},
			}})
		}
	}
	_, e = l.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: writes})
	if e != nil {
		return ErrRefused
	}
	return nil
}
