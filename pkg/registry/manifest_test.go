// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package registry

import (
	"strings"
	"testing"
)

func TestEmbeddedManifestVerifiesAgainstEmbeddedTrustRoot(t *testing.T) {
	m, _, err := LoadManifest("")
	if err != nil {
		t.Fatalf("load embedded manifest: %v", err)
	}
	if m.Revision == "" {
		t.Fatal("revision empty")
	}
	if m.Signature == nil {
		t.Fatal("embedded manifest is unsigned")
	}
	root, err := LoadTrustRoot("")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifySignature(root); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}

	// The signing key must be declared with the registry-sign usage.
	if _, err := root.PublicKey(m.Signature.KeyID, "registry-sign"); err != nil {
		t.Fatalf("signing key missing from trust root: %v", err)
	}

	// All standard backends must pin commit, tree and content digest.
	for key, be := range m.Backends {
		if len(be.Commit) != 40 || len(be.Tree) != 40 {
			t.Fatalf("backend %q pins are not 40-hex SHAs", key)
		}
		if !strings.HasPrefix(be.ContentDigest, "sha256:") {
			t.Fatalf("backend %q content digest not sha256-prefixed", key)
		}
	}
}

func TestVerifySignatureRejectsTamperedManifest(t *testing.T) {
	m, _, err := LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	root, err := LoadTrustRoot("")
	if err != nil {
		t.Fatal(err)
	}
	m.Revision = m.Revision + "-evil"
	if err := m.VerifySignature(root); err == nil {
		t.Fatal("expected signature failure after tampering")
	}
}

func TestValidateRejectsIncompleteManifest(t *testing.T) {
	m, _, err := LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	m.SchemaVersion = "0.0"
	if err := m.Validate(); err == nil {
		t.Fatal("expected validation failure on bad schemaVersion")
	}
}

func TestCanonicalBytesExcludeSignature(t *testing.T) {
	m, _, err := LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\"signature\"") {
		t.Fatal("canonical bytes must not include the signature block")
	}
	d1, _ := m.Digest()
	d2, _ := m.Digest()
	if d1 != d2 {
		t.Fatal("digest not deterministic")
	}
}
