// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package security

import (
	"encoding/json"
	"testing"
)

func validStatement(t *testing.T) *Statement {
	t.Helper()
	prov := SLSAProvenanceV1{
		BuildDefinition: BuildDefinition{
			BuildType: "https://create-go.app/buildtypes/v1",
			ResolvedDependencies: []Resource{
				{
					Name: "git+https://github.com/create-go-app/fiber-go-template@286d0d84d3373668634fcc30a3cec60740a8f4dc",
					Digest: map[string]string{
						"sha256":        "014365aa1af1e92091a6fda2ee69ba9905cb023a16a32c4d476e08b90b2f80b6",
						"git-tree-sha1": "fc162c303eee13d09e213b1f30418d03b7ed1bea",
					},
				},
			},
		},
		RunDetails: RunDetails{
			Builder: Builder{ID: "pkg:github/create-go-app/cli@v4.1.0"},
		},
	}
	pred, err := json.Marshal(prov)
	if err != nil {
		t.Fatal(err)
	}
	return &Statement{
		Type:          StatementTypeV1,
		PredicateType: PredicateSLSAProvenanceV1,
		Subject: []Resource{
			{
				Name:   "project",
				Digest: map[string]string{"sha256": "deadbeef"},
			},
		},
		Predicate: pred,
	}
}

func policy() ProvenancePolicy {
	return ProvenancePolicy{
		AllowedBuilders:   []string{"pkg:github/create-go-app/cli@v4.1.0"},
		AllowedBuildTypes: []string{"https://create-go.app/buildtypes/v1"},
		ExpectedSubjects: []Resource{
			{Name: "project", Digest: map[string]string{"sha256": "deadbeef"}},
		},
		ExpectedSources: []string{
			"git+https://github.com/create-go-app/fiber-go-template@286d0d84d3373668634fcc30a3cec60740a8f4dc",
		},
	}
}

func TestVerifyStatementAcceptsConforming(t *testing.T) {
	if _, err := VerifyStatement(validStatement(t), policy()); err != nil {
		t.Fatalf("VerifyStatement: %v", err)
	}
}

func TestVerifyStatementRejectsFailures(t *testing.T) {
	// Unknown builder.
	stmt := validStatement(t)
	bad := policy()
	bad.AllowedBuilders = []string{"pkg:github/evil@v1"}
	if _, err := VerifyStatement(stmt, bad); err == nil {
		t.Fatal("expected untrusted builder error")
	}

	// Subject mismatch.
	stmt = validStatement(t)
	bad2 := policy()
	bad2.ExpectedSubjects[0].Digest["sha256"] = "00"
	if _, err := VerifyStatement(stmt, bad2); err == nil {
		t.Fatal("expected subject mismatch error")
	}

	// Missing pinned source.
	stmt = validStatement(t)
	bad3 := policy()
	bad3.ExpectedSources = []string{"git+https://example.com/nope@abcd"}
	if _, err := VerifyStatement(stmt, bad3); err == nil {
		t.Fatal("expected source mismatch error")
	}

	// Wrong statement type.
	stmt = validStatement(t)
	stmt.Type = "https://in-toto.io/Statement/v0"
	if _, err := VerifyStatement(stmt, policy()); err == nil {
		t.Fatal("expected statement type error")
	}
}
