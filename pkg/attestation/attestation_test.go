// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package attestation

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/registry"
	"github.com/create-go-app/cli/v4/pkg/security"
	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

func TestBuildSignVerifyRoundtrip(t *testing.T) {
	m, _, err := registry.LoadManifest("")
	if err != nil {
		t.Fatal(err)
	}
	l, err := lockfile.Resolve(m, lockfile.Selection{
		Backend: "fiber", Frontend: "react-ts", Proxy: "nginx",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Finalize(); err != nil {
		t.Fatal(err)
	}

	a, err := NewEphemeralAttestor()
	if err != nil {
		t.Fatal(err)
	}
	if !a.Ephemeral || a.KeyID != dsse.KeyID(a.Public()) {
		t.Fatal("ephemeral attestor not initialized correctly")
	}

	stmt := BuildStatement(Inputs{
		Lock: l,
		Outputs: []security.Resource{
			{Name: "project", Digest: map[string]string{"sha256": "cafe"}},
		},
		SBOM: security.Resource{
			Name:   ".cgapp/sbom.cdx.json",
			Digest: map[string]string{"sha256": "babe"},
		},
		OSConfinement: "seatbelt",
		OfflineBuild:  true,
		Started:       time.Now().Add(-time.Second),
		Finished:      time.Now(),
	})
	if stmt.Type != security.StatementTypeV1 || stmt.PredicateType != security.PredicateSLSAProvenanceV1 {
		t.Fatalf("unexpected statement types: %q %q", stmt.Type, stmt.PredicateType)
	}
	if len(stmt.Subject) != 2 {
		t.Fatalf("expected output+sbom subjects, got %d", len(stmt.Subject))
	}

	env, err := Sign(stmt, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != a.KeyID {
		t.Fatalf("unexpected envelope signatures: %+v", env.Signatures)
	}

	keys := map[string]ed25519.PublicKey{a.KeyID: a.Public()}
	gotStmt, prov, err := security.VerifyAttestation(env, keys, security.ProvenancePolicy{
		AllowedBuilders: []string{"pkg:github/create-go-app/cli@v" + m.Generator.MinVersion},
		ExpectedSubjects: []security.Resource{
			{Name: "project", Digest: map[string]string{"sha256": "cafe"}},
		},
		ExpectedSources: []string{l.Materials[0].Source},
	})
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	// The pinned commit must be carried in the resolved dependency digests.
	found := false
	for _, dep := range prov.BuildDefinition.ResolvedDependencies {
		if dep.Digest["git-commit-sha1"] == "286d0d84d3373668634fcc30a3cec60740a8f4dc" {
			found = true
		}
	}
	if !found {
		t.Fatal("pinned commit missing from provenance resolvedDependencies")
	}
	if len(gotStmt.Subject) != 2 {
		t.Fatal("subject count changed through serialization")
	}
	if prov.BuildDefinition.ExternalParameters["backend"] != "fiber" {
		t.Fatalf("external parameters wrong: %+v", prov.BuildDefinition.ExternalParameters)
	}
	if prov.BuildDefinition.InternalParameters["osConfinement"] != "seatbelt" {
		t.Fatalf("internal parameters wrong: %+v", prov.BuildDefinition.InternalParameters)
	}
}
