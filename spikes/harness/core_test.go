package harness

import (
	"crypto/sha256"
	v "github.com/aidotmarket/aim-data-gateway/verification"
	"testing"
)

func TestCloudCommitmentGolden(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	c := Commitments{Key: key, Kind: "s3_listing", Bucket: "bucket", Manifest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Objects: map[string]Object{"11111111111111111111111111111111": {Key: "spike/file.csv", ETag: `"etag"`}}}
	m := v.Member{Identity: "11111111111111111111111111111111", SHA256: sha256.Sum256([]byte("fixture"))}
	if c.LocatorCommitment() != "c39fafd3d470a2cf0a6a424be8462f703e4734406264cf365be15a1b618da056" {
		t.Fatal("locator preimage")
	}
	if c.ObjectID(m) != "8ccba328a671089312582c6b20cccad39d78de6717da6f2f31b82681c49cb8e1" {
		t.Fatal("object preimage")
	}
	o := c.Objects[m.Identity]
	o.VersionID = "v1"
	c.Objects[m.Identity] = o
	version := c.ObjectID(m)
	o.ETag = "ignored-for-version"
	c.Objects[m.Identity] = o
	if c.ObjectID(m) != version {
		t.Fatal("version precedence")
	}
	c.Kind = "r2_listing"
	if c.ObjectID(m) == version {
		t.Fatal("kind domain separation")
	}
}
