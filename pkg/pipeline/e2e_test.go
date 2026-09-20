// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package pipeline

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/security"
	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

// TestE2ECreate exercises the whole pipeline against the real network.
// Enable with CGAPP_E2E=1.
func TestE2ECreate(t *testing.T) {
	if os.Getenv("CGAPP_E2E") == "" {
		t.Skip("set CGAPP_E2E=1 to run the networked end-to-end test")
	}

	cache := t.TempDir()
	out := filepath.Join(t.TempDir(), "project")
	sel := lockfile.Selection{Backend: "fiber", Frontend: "react-ts", Proxy: "nginx"}

	report, err := Create(context.Background(), sel, Options{
		CacheRoot: cache,
		OutputDir: out,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Delivered layout.
	for _, p := range []string{
		"backend/main.go",
		"backend/go.mod",
		"frontend/package.json",
		"hosts.ini",
		"playbook.yml",
		"roles/nginx/tasks/main.yml",
		"roles/backend/tasks/main.yml",
		"cgapp.lock",
		".cgapp/sbom.cdx.json",
		".cgapp/provenance.intoto.json",
		".cgapp/attestor.pub.json",
	} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Errorf("expected output %s: %v", p, err)
		}
	}
	// Unused proxy role must have been removed.
	if _, err := os.Stat(filepath.Join(out, "roles/traefik")); !os.IsNotExist(err) {
		t.Errorf("roles/traefik should be absent for nginx, err=%v", err)
	}
	// Provenance evidence directories must be stripped from the output.
	for _, p := range []string{"backend/.git", "backend/.github", "frontend/.git"} {
		if _, err := os.Stat(filepath.Join(out, p)); !os.IsNotExist(err) {
			t.Errorf("%s should be stripped, err=%v", p, err)
		}
	}

	// Lock on disk validates its self-digest.
	l, err := lockfile.Read(filepath.Join(out, "cgapp.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Selection.Frontend != "react-ts" {
		t.Fatalf("lock selection wrong: %+v", l.Selection)
	}
	for _, mat := range l.Materials {
		if mat.Trust != "verified" {
			t.Errorf("material %s trust=%s, want verified", mat.ID, mat.Trust)
		}
	}

	// The DSSE attestation must verify against the published attestor key
	// and assert the delivered output digest.
	kf := &dsse.KeyFile{}
	if data, err := os.ReadFile(filepath.Join(out, ".cgapp/attestor.pub.json")); err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(data, kf); err != nil {
		t.Fatal(err)
	}
	pub, err := dsse.LoadPublicKey(kf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	envData, err := os.ReadFile(filepath.Join(out, ".cgapp/provenance.intoto.json"))
	if err != nil {
		t.Fatal(err)
	}
	env := &dsse.Envelope{}
	if err := json.Unmarshal(envData, env); err != nil {
		t.Fatal(err)
	}
	_, _, err = security.VerifyAttestation(env,
		map[string]ed25519.PublicKey{kf.KeyID: pub},
		security.ProvenancePolicy{
			AllowedBuilders: []string{"pkg:github/create-go-app/cli@v" + l.Generator.MinVersion},
			ExpectedSubjects: []security.Resource{{
				Name:   "project",
				Digest: map[string]string{"sha256": strings.TrimPrefix(report.OutputDigest, "sha256:")},
			}},
		})
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	// Re-run fully offline against the now-warm cache: identical output.
	out2 := filepath.Join(t.TempDir(), "project")
	report2, err := Create(context.Background(), sel, Options{
		CacheRoot: cache,
		OutputDir: out2,
		Offline:   true,
	})
	if err != nil {
		t.Fatalf("offline Create: %v", err)
	}
	if report2.OutputDigest != report.OutputDigest {
		t.Fatalf("offline rebuild changed output: %s != %s", report2.OutputDigest, report.OutputDigest)
	}
}
