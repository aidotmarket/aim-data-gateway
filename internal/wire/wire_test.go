package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJWSAndInstructionKinds(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := map[string]ed25519.PublicKey{"kid": private.Public().(ed25519.PublicKey)}
	for _, op := range []string{"offer", "unoffer", "describe", "revoke", "prepare", "key_rotation", "minimum_version"} {
		in := Instruction{Op: op, Audience: "gateway", IID: "iid", IssuedAt: 1}
		typ, _, e := in.Kind()
		if e != nil {
			t.Fatal(e)
		}
		token, e := Sign(typ, "kid", in, private)
		if e != nil {
			t.Fatal(e)
		}
		var out Instruction
		if e := Verify(token, typ, keys, &out); e != nil || out.Op != op {
			t.Fatal(op, e)
		}
		if e := Verify(token, "wrong", keys, &out); e == nil {
			t.Fatal("wrong type accepted")
		}
		parts := strings.Split(token, ".")
		parts[1] = "AA"
		if e := Verify(strings.Join(parts, "."), typ, keys, &out); e == nil {
			t.Fatal("tamper accepted")
		}
	}
}
func TestInstructionRejectsForeignClaimsForEveryOperation(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := map[string]ed25519.PublicKey{"kid": private.Public().(ed25519.PublicKey)}
	id := "22222222-2222-4222-8222-222222222222"
	fid := "0123456789abcdef0123456789abcdef"
	now := time.Now().Unix()
	optional := map[string]any{"fid": fid, "sha256": strings.Repeat("a", 64), "lvid": id, "cid": id, "exp": now + 900, "jti": id, "oid": id, "keys": []Key{{KID: "new", Alg: "EdDSA", Key: base64.RawURLEncoding.EncodeToString(keys["kid"])}}, "version": "1.0.0"}
	byOp := map[string][]string{
		"offer": {"fid", "sha256", "lvid"}, "unoffer": {"fid", "sha256", "lvid"},
		"describe": {"fid", "cid", "exp"}, "revoke": {"jti"},
		"prepare": {"oid", "fid", "sha256"}, "key_rotation": {"keys"}, "minimum_version": {"version"},
	}
	for op, permitted := range byOp {
		base := map[string]any{"op": op, "aud": id, "iid": id, "iat": now}
		allowed := make(map[string]bool)
		for _, name := range permitted {
			base[name] = optional[name]
			allowed[name] = true
		}
		typ, _, err := (Instruction{Op: op}).Kind()
		if err != nil {
			t.Fatal(err)
		}
		token, err := Sign(typ, "kid", base, private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyInstruction(token, keys); err != nil {
			t.Fatalf("valid %s: %v", op, err)
		}
		for name, value := range optional {
			if allowed[name] {
				continue
			}
			base[name] = value
			token, err = Sign(typ, "kid", base, private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyInstruction(token, keys); err == nil {
				t.Fatalf("%s accepted %s", op, name)
			}
			delete(base, name)
		}
	}
}
func TestCanonical(t *testing.T) {
	b, e := Canonical(map[string]any{"z": 1, "a": map[string]any{"b": 2, "a": 1}})
	if e != nil {
		t.Fatal(e)
	}
	if string(b) != "{\"a\":{\"a\":1,\"b\":2},\"z\":1}" {
		t.Fatal(string(b))
	}
}

func TestStrictVerifiers(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := map[string]ed25519.PublicKey{"kid": priv.Public().(ed25519.PublicKey)}
	gate := "11111111-1111-4111-8111-111111111111"
	id := "22222222-2222-4222-8222-222222222222"
	fid := "0123456789abcdef0123456789abcdef"
	sha := strings.Repeat("a", 64)
	p := Permission{Audience: gate, OrderID: id, ListingVersionID: id, FileID: fid, SHA256: sha, JTI: id, IssuedAt: 1, StartDeadline: 2, TransferDeadline: 3}
	i := Instruction{Op: "offer", Audience: gate, IID: id, IssuedAt: 1, FileID: fid, SHA256: sha, ListingVersionID: id}
	check := func(t *testing.T, kind, token string, accepted bool) {
		t.Helper()
		var err error
		switch kind {
		case "permission":
			_, err = VerifyPermission(token, keys)
		case "instruction":
			_, err = VerifyInstruction(token, keys)
		default:
			err = VerifyGatewayAnswer(token, "offer_ack", keys, new(OfferAck))
		}
		if (err == nil) != accepted {
			t.Fatalf("accepted=%v error=%v", accepted, err)
		}
	}
	sign := func(t *testing.T, typ, kid string, body any) string {
		t.Helper()
		token, err := Sign(typ, kid, body, priv)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	check(t, "permission", sign(t, "aim-permission+jwt", "kid", p), true)
	check(t, "instruction", sign(t, "aim-offer+jwt", "kid", i), true)
	ack := OfferAck{IID: id, FileID: fid, Ready: true}
	check(t, "answer", sign(t, "aim-offer_ack+jwt", "kid", ack), true)
	for _, tc := range []struct{ name, kind, token string }{
		{"unknown kid", "permission", sign(t, "aim-permission+jwt", "other", p)},
		{"wrong typ", "permission", sign(t, "aim-offer+jwt", "kid", p)},
		{"op inconsistent with typ", "instruction", sign(t, "aim-describe+jwt", "kid", i)},
		{"wrong answer typ", "answer", sign(t, "aim-hello+jwt", "kid", ack)},
		{"missing required claim", "permission", signedRaw(t, priv, `{"alg":"EdDSA","typ":"aim-permission+jwt","kid":"kid"}`, `{"aud":"`+gate+`"}`)},
		{"unknown header field", "permission", signedRaw(t, priv, `{"alg":"EdDSA","typ":"aim-permission+jwt","kid":"kid","extra":1}`, jsonBody(t, p))},
		{"unknown claim", "permission", signedRaw(t, priv, `{"alg":"EdDSA","typ":"aim-permission+jwt","kid":"kid"}`, strings.TrimSuffix(jsonBody(t, p), "}")+`,"extra":1}`)},
		{"trailing data", "permission", signedRaw(t, priv, `{"alg":"EdDSA","typ":"aim-permission+jwt","kid":"kid"}`, jsonBody(t, p)+` {}`)},
		{"alg not EdDSA", "permission", signedRaw(t, priv, `{"alg":"HS256","typ":"aim-permission+jwt","kid":"kid"}`, jsonBody(t, p))},
	} {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.kind, tc.token, false) })
	}
	wrong := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32)))
	wrongToken, err := Sign("aim-permission+jwt", "kid", p, wrong)
	if err != nil {
		t.Fatal(err)
	}
	check(t, "permission", wrongToken, false)
	missing := i
	missing.FileID = ""
	check(t, "instruction", sign(t, "aim-offer+jwt", "kid", missing), false)
	expired := Instruction{Op: "describe", Audience: gate, IID: id, IssuedAt: 1, FileID: fid, ConfirmationID: id, ExpiresAt: 2}
	check(t, "instruction", sign(t, "aim-describe+jwt", "kid", expired), false)
}

func TestGatewayAnswerVocabulary(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	keys := map[string]ed25519.PublicKey{"kid": priv.Public().(ed25519.PublicKey)}
	id := "22222222-2222-4222-8222-222222222222"
	fid := "0123456789abcdef0123456789abcdef"
	sha := strings.Repeat("a", 64)
	unknown := "not_a_refusal"
	valid := "file_changed"
	revoke := RevokeAck{Op: "revoke_ack", JTI: id, StateBefore: "active"}
	prepare := PrepareAck{Op: "prepare_ack", IID: id, OrderID: id, FileID: fid, Ready: true}
	offer := OfferAck{IID: id, FileID: fid, Ready: true}
	receipt := Receipt{Op: "receipt", OrderID: id, FileID: fid, SHA256: sha, JTIs: []string{}, Transmitted: []Interval{}, Outcome: "complete"}
	for _, tc := range []struct {
		name, answer string
		body         any
		valid        bool
	}{
		{"valid revoke", "revoke_ack", revoke, true},
		{"unknown state_before", "revoke_ack", RevokeAck{Op: "revoke_ack", JTI: id, StateBefore: "not_a_state"}, false},
		{"valid prepare", "prepare_ack", prepare, true},
		{"prepare refusal", "prepare_ack", PrepareAck{Op: "prepare_ack", IID: id, OrderID: id, FileID: fid, Refusal: &valid}, true},
		{"prepare unknown refusal", "prepare_ack", PrepareAck{Op: "prepare_ack", IID: id, OrderID: id, FileID: fid, Refusal: &unknown}, false},
		{"prepare ready with refusal", "prepare_ack", PrepareAck{Op: "prepare_ack", IID: id, OrderID: id, FileID: fid, Ready: true, Refusal: &valid}, false},
		{"prepare not ready without refusal", "prepare_ack", PrepareAck{Op: "prepare_ack", IID: id, OrderID: id, FileID: fid}, false},
		{"valid offer", "offer_ack", offer, true},
		{"offer refusal", "offer_ack", OfferAck{IID: id, FileID: fid, Refusal: &valid}, true},
		{"offer unknown refusal", "offer_ack", OfferAck{IID: id, FileID: fid, Refusal: &unknown}, false},
		{"offer ready with refusal", "offer_ack", OfferAck{IID: id, FileID: fid, Ready: true, Refusal: &valid}, false},
		{"offer not ready without refusal", "offer_ack", OfferAck{IID: id, FileID: fid}, false},
		{"valid receipt", "receipt", receipt, true},
		{"unknown outcome", "receipt", Receipt{Op: "receipt", OrderID: id, FileID: fid, SHA256: sha, JTIs: []string{}, Transmitted: []Interval{}, Outcome: "not_an_outcome"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := Sign("aim-"+tc.answer+"+jwt", "kid", tc.body, priv)
			if err != nil {
				t.Fatal(err)
			}
			var out any
			switch tc.answer {
			case "revoke_ack":
				out = new(RevokeAck)
			case "prepare_ack":
				out = new(PrepareAck)
			case "offer_ack":
				out = new(OfferAck)
			case "receipt":
				out = new(Receipt)
			}
			err = VerifyGatewayAnswer(token, tc.answer, keys, out)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func signedRaw(t *testing.T, key ed25519.PrivateKey, header, payload string) string {
	t.Helper()
	b64 := base64.RawURLEncoding
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(payload))
	return input + "." + b64.EncodeToString(ed25519.Sign(key, []byte(input)))
}
