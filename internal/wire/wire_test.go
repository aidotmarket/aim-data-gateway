package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
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
