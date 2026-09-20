// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package dsse

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func keys(pub ed25519.PublicKey) map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{KeyID(pub): pub}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"hello":"world"}`)
	env, err := Sign(priv, KeyID(pub), PayloadTypeInTotoV1, payload)
	if err != nil {
		t.Fatal(err)
	}
	if env.PayloadType != PayloadTypeInTotoV1 {
		t.Fatalf("payload type = %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != KeyID(pub) {
		t.Fatalf("unexpected signatures: %+v", env.Signatures)
	}

	got, err := Verify(env, keys(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %s", got)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(priv, KeyID(pub), PayloadTypeInTotoV1, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, err := Verify(env, keys(pub)); err == nil {
		t.Fatal("expected verification failure for tampered payload")
	}
}

func TestVerifyRejectsUnknownKey(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(priv, "signer", PayloadTypeInTotoV1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(env, map[string]ed25519.PublicKey{KeyID(other): other}); err == nil {
		t.Fatal("expected failure when key id is not in trust root")
	}
}

func TestPAEStableAndPrefixed(t *testing.T) {
	a := PAE("text/plain", []byte("abc"))
	b := PAE("text/plain", []byte("abc"))
	if !bytes.Equal(a, b) {
		t.Fatal("PAE not deterministic")
	}
	c := PAE("text/plain", []byte("abd"))
	if bytes.Equal(a, c) {
		t.Fatal("PAE collided on different body")
	}
	d := PAE("text/json", []byte("abc"))
	if bytes.Equal(a, d) {
		t.Fatal("PAE collided on different type")
	}
	if !strings.HasPrefix(string(a), "DSSEv1") {
		t.Fatalf("PAE missing DSSEv1 prefix: %q", a)
	}
}
