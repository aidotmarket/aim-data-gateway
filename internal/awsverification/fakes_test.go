package awsverification

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	core "github.com/aidotmarket/aim-data-gateway/verification"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	d "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

const runnerID = "66666666-6666-4666-8666-666666666666"
const receiptID = "77777777-7777-4777-8777-777777777777"
const connectionID = "11111111-1111-4111-8111-111111111111"

var platformPrivate = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32))
var platformKey = wire.Key{KID: "test-only-scan-key", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(platformPrivate.Public().(ed25519.PublicKey))}

// This fake applies writes atomically and checks the actual DynamoDB conditional
// expressions; losing transactions leave nonce, auth, quota and clock untouched.
type memoryDynamo struct {
	mu        sync.Mutex
	items     map[string]map[string]d.AttributeValue
	down      bool
	failPutAt int
	puts      int
	conflicts int
}

func newDynamo() *memoryDynamo                { return &memoryDynamo{items: map[string]map[string]d.AttributeValue{}} }
func pk(m map[string]d.AttributeValue) string { return m["pk"].(*d.AttributeValueMemberS).Value }
func cloneItem(m map[string]d.AttributeValue) map[string]d.AttributeValue {
	if m == nil {
		return nil
	}
	n := map[string]d.AttributeValue{}
	for k, v := range m {
		switch v := v.(type) {
		case *d.AttributeValueMemberB:
			n[k] = &d.AttributeValueMemberB{Value: append([]byte(nil), v.Value...)}
		default:
			n[k] = v
		}
	}
	return n
}
func (m *memoryDynamo) GetItem(_ context.Context, i *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, errors.New("RAW_PROVIDER_MARKER")
	}
	if !aws.ToBool(i.ConsistentRead) {
		return nil, errors.New("not strong")
	}
	return &dynamodb.GetItemOutput{Item: cloneItem(m.items[pk(i.Key)])}, nil
}
func condition(c string, old map[string]d.AttributeValue, values map[string]d.AttributeValue) bool {
	switch c {
	case "":
		return true
	case "attribute_not_exists(pk)":
		return old == nil
	case "attribute_exists(pk)":
		return old != nil
	case "version = :old":
		return old != nil && old["version"].(*d.AttributeValueMemberN).Value == values[":old"].(*d.AttributeValueMemberN).Value
	case "attribute_not_exists(accepted_count) OR accepted_count < :ten":
		if old == nil {
			return true
		}
		v, _ := strconv.Atoi(old["accepted_count"].(*d.AttributeValueMemberN).Value)
		return v < 10
	case "attribute_exists(pk) AND attribute_not_exists(#state)":
		return old != nil && old["state"] == nil
	default:
		panic("unknown condition " + c)
	}
}
func (m *memoryDynamo) PutItem(_ context.Context, i *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if m.down || m.failPutAt == m.puts {
		return nil, ErrRefused
	}
	if !condition(aws.ToString(i.ConditionExpression), m.items[pk(i.Item)], i.ExpressionAttributeValues) {
		return nil, ErrRefused
	}
	m.items[pk(i.Item)] = cloneItem(i.Item)
	return &dynamodb.PutItemOutput{}, nil
}
func (m *memoryDynamo) TransactWriteItems(_ context.Context, i *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, ErrRefused
	}
	if m.conflicts > 0 {
		m.conflicts--
		return nil, ErrRefused
	}
	for _, w := range i.TransactItems {
		if w.Put != nil {
			if !condition(aws.ToString(w.Put.ConditionExpression), m.items[pk(w.Put.Item)], w.Put.ExpressionAttributeValues) {
				return nil, ErrRefused
			}
		} else if w.Update != nil {
			if !condition(aws.ToString(w.Update.ConditionExpression), m.items[pk(w.Update.Key)], w.Update.ExpressionAttributeValues) {
				return nil, ErrRefused
			}
		} else {
			panic("unknown transaction")
		}
	}
	for _, w := range i.TransactItems {
		if w.Put != nil {
			m.items[pk(w.Put.Item)] = cloneItem(w.Put.Item)
		} else {
			u := w.Update
			p := pk(u.Key)
			v := cloneItem(m.items[p])
			if v == nil {
				v = key(p)
			}
			v["expires_at"] = u.ExpressionAttributeValues[":ttl"]
			if strings.Contains(aws.ToString(u.UpdateExpression), "ADD accepted_count") {
				n := 0
				if v["accepted_count"] != nil {
					n, _ = strconv.Atoi(v["accepted_count"].(*d.AttributeValueMemberN).Value)
				}
				v["accepted_count"] = num(int64(n + 1))
			}
			m.items[p] = v
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

type memorySecrets struct {
	mu         sync.Mutex
	s          *Secret
	down       bool
	failSaveAt int
	saves      int
}

func copySecret(s *Secret) *Secret {
	if s == nil {
		return nil
	}
	b, _ := json.Marshal(s)
	var v Secret
	json.Unmarshal(b, &v)
	return &v
}
func (m *memorySecrets) Load(context.Context) (*Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		return nil, ErrRefused
	}
	return copySecret(m.s), nil
}
func (m *memorySecrets) Save(_ context.Context, s *Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	if m.down || m.saves == m.failSaveAt {
		return ErrRefused
	}
	m.s = copySecret(s)
	return nil
}

type memoryAudit struct {
	events []string
	fail   string
}

func (a *memoryAudit) Event(_ context.Context, event, hash string) error {
	if !hex64.MatchString(hash) {
		return ErrRefused
	}
	a.events = append(a.events, event+" "+hash)
	if event == a.fail {
		return errors.New("RAW_PROVIDER_MARKER")
	}
	return nil
}

type memoryBackend struct {
	work, snapshot                              string
	calls                                       []string
	reports                                     [][]byte
	registered                                  []byte
	ack                                         RegistrationAck
	expired, consumed, lostRegister, lostReport bool
	at                                          time.Time
	deadline                                    int64
}

func (b *memoryBackend) Register(_ context.Context, raw []byte) (RegistrationAck, error) {
	b.calls = append(b.calls, "register")
	if b.registered != nil {
		if !bytes.Equal(raw, b.registered) {
			return RegistrationAck{}, ErrRefused
		}
		return b.ack, nil
	}
	if b.expired || b.consumed {
		return RegistrationAck{}, ErrRefused
	}
	b.registered = append([]byte(nil), raw...)
	v, _ := core.ParseCanonical(raw)
	m := v.(map[string]any)
	proof, _ := base64.RawURLEncoding.DecodeString(m["key_proof"].(string))
	delete(m, "key_proof")
	body, _ := core.Canonical(m)
	pub, _ := base64.RawURLEncoding.DecodeString(m["receipt_public_key"].(string))
	if !ed25519.Verify(pub, body, proof) {
		return RegistrationAck{}, ErrRefused
	}
	issued, _ := utc(m["registered_at_utc"].(string))
	claims := map[string]any{"op": "scan_spec", "variant": "registered", "aud": runnerID, "iid": "88888888-8888-4888-8888-888888888888", "iat": issued.Unix(), "registration_nonce": m["registration_nonce"], "runner_id": runnerID, "receipt_key_id": receiptID, "scanner_version": m["scanner_version"], "image_digest": m["image_digest"]}
	token, _ := signJWS(platformPrivate, platformKey.KID, "aim-scan-runner-ack+jwt", claims)
	b.ack = RegistrationAck{Runner: runnerID, Receipt: receiptID, Keys: []wire.Key{platformKey}, JWS: token}
	b.consumed = true
	if b.lostRegister {
		return RegistrationAck{}, ErrRefused
	}
	return b.ack, nil
}
func (b *memoryBackend) Work(context.Context, *Secret) (string, error) {
	b.calls = append(b.calls, "work")
	return b.work, nil
}
func (b *memoryBackend) Snapshot(context.Context, *Secret, string) (string, error) {
	b.calls = append(b.calls, "snapshot")
	return b.snapshot, nil
}
func (b *memoryBackend) Report(_ context.Context, _ *Secret, body []byte, _ string) error {
	b.calls = append(b.calls, "report")
	b.reports = append(b.reports, append([]byte(nil), body...))
	if b.deadline != 0 && b.at.Unix() > b.deadline {
		return ErrRefused
	}
	if b.lostReport {
		return ErrRefused
	}
	return nil
}

type handlerFixture struct {
	h       Handler
	db      *memoryDynamo
	secrets *memorySecrets
	backend *memoryBackend
	audit   *memoryAudit
	s3      *fakeS3
	at      time.Time
}

func newFixture(t *testing.T) *handlerFixture {
	t.Helper()
	f := &handlerFixture{db: newDynamo(), secrets: &memorySecrets{}, backend: &memoryBackend{}, audit: &memoryAudit{}, at: time.Now().UTC().Truncate(time.Second)}
	data := []byte("field\nRAW_CELL_MARKER\n")
	f.s3 = &fakeS3{objects: map[string][]byte{"RAW_KEY_MARKER/data.csv": data}, liveETag: "RAW_ETAG_MARKER"}
	c := Config{Connection: connectionID, Bucket: "fixture-bucket", Region: "eu-north-1", Secret: "secret", Table: "table", Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Version: "0.3.0", Digest: "sha256:" + strings.Repeat("a", 64), LogGroup: "log-group", Scope: Scope{Prefixes: []string{"RAW_KEY_MARKER/"}}, PollMinutes: 15}
	f.h = Handler{Config: c, Ledger: Ledger{Client: f.db, Table: c.Table}, Store: f.secrets, Backend: f.backend, Audit: f.audit, S3: f.s3, Now: func() time.Time { return f.at }}
	return f
}
func (f *handlerFixture) job(t *testing.T, index int, variant string) wire.ScanJob {
	t.Helper()
	b, e := os.ReadFile("../../contract/vectors/verification/scan_spec.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct{ Input map[string]any }
	json.Unmarshal(b, &v)
	raw, _ := wire.DecodeDocument(v.Input["payload_b64"].(string), 40<<10)
	p, e := core.ParseCanonical(raw)
	if e != nil {
		t.Fatal(e)
	}
	payload := p.(map[string]any)
	if variant == "probe" {
		keep := map[string]any{}
		for _, k := range strings.Fields(probeFields) {
			keep[k] = payload[k]
		}
		payload = keep
		payload["probe_id"] = "99999999-9999-4999-8999-999999999999"
		delete(v.Input, "d6_b64")
		delete(v.Input, "d6_hash")
	}
	payload["spec_id"] = fmt.Sprintf("spec_%d", index)
	payload["owner_authorization_id"] = fmt.Sprintf("auth_%d", index)
	payload["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
	payload["source_kind"] = "s3_listing"
	payload["connector_type"] = "aws_s3_verifier"
	payload["connector_version"] = "aws_s3_verifier-v1"
	payload["accepted_at_utc"] = timestamp(f.at.Add(-time.Minute))
	payload["issued_at_utc"] = timestamp(f.at)
	payload["expires_at_utc"] = timestamp(f.at.Add(time.Hour))
	payload["runner_id"] = runnerID
	snap := map[string]any{"snapshot_version": "verification-source-snapshot-v1", "source_kind": "s3_listing", "connection_id": connectionID, "bucket": f.h.Config.Bucket, "listing_id": payload["listing_id"], "listing_version_id": payload["listing_version_id"], "source_handle_id": payload["source_handle_id"], "members": []any{map[string]any{"provider": "aws", "key": "RAW_KEY_MARKER/data.csv", "etag": f.s3.liveETag, "size_bytes": len(f.s3.objects["RAW_KEY_MARKER/data.csv"]), "format": "csv"}}}
	raw, _ = core.Canonical(snap)
	payload["manifest_hash"] = wire.Digest(raw)
	f.backend.snapshot, _ = signJWS(platformPrivate, platformKey.KID, "aim-scan-snapshot+jwt", map[string]any{"aud": runnerID, "runner_id": runnerID, "manifest_hash": wire.Digest(raw), "payload_b64": base64.RawURLEncoding.EncodeToString(raw)})
	raw, _ = core.Canonical(payload)
	v.Input["payload_b64"] = base64.RawURLEncoding.EncodeToString(raw)
	v.Input["spec_hash"] = wire.Digest(raw)
	v.Input["aud"] = runnerID
	v.Input["runner_id"] = runnerID
	v.Input["iat"] = f.at.Unix()
	v.Input["variant"] = variant
	v.Input["iid"] = fmt.Sprintf("88888888-8888-4888-8888-%012d", index)
	f.backend.work, e = signJWS(platformPrivate, platformKey.KID, "aim-scan-spec+jwt", v.Input)
	if e != nil {
		t.Fatal(e)
	}
	j, e := VerifyWork(f.backend.work, map[string]ed25519.PublicKey{platformKey.KID: platformPrivate.Public().(ed25519.PublicKey)}, runnerID, runnerID, f.h.Config.Version, f.at)
	if e != nil {
		t.Fatal(e)
	}
	j.ScannerVersion = f.h.Config.Version
	j.ReceiptKeyID = receiptID
	return j
}
