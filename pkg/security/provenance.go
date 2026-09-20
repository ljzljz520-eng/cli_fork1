// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package security

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

// ITE-6 / in-toto statement and SLSA provenance v1 media types.
const (
	StatementTypeV1           = "https://in-toto.io/Statement/v1"
	PredicateSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"
)

// Resource is a named object with a set of content digests
// (algorithm -> hex/base64 digest), as used by in-toto subjects and
// SLSA resolvedDependencies.
type Resource struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto v1 attestation statement.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Resource      `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// Builder identifies the transitive build platform that produced provenance.
type Builder struct {
	ID string `json:"id"`
	// Version, BuilderDependencies omitted: only the fields the policy
	// evaluates are modelled, unknown JSON fields are preserved.
}

// BuildDefinition is the SLSA v1 build definition.
type BuildDefinition struct {
	BuildType            string         `json:"buildType"`
	ExternalParameters   map[string]any `json:"externalParameters"`
	InternalParameters   map[string]any `json:"internalParameters"`
	ResolvedDependencies []Resource     `json:"resolvedDependencies"`
}

// BuildMetadata carries the provenance execution metadata.
type BuildMetadata struct {
	StartedAt  string `json:"startedAt,omitempty"`
	FinishedAt string `json:"finishedAt,omitempty"`
}

// RunDetails is the SLSA v1 run details block.
type RunDetails struct {
	Builder    Builder       `json:"builder"`
	Metadata   BuildMetadata `json:"metadata,omitempty"`
	Byproducts []Resource    `json:"byproducts,omitempty"`
}

// SLSAProvenanceV1 is the predicate at https://slsa.dev/provenance/v1.
type SLSAProvenanceV1 struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// ProvenancePolicy defines what an accepted attestation must satisfy.
type ProvenancePolicy struct {
	// AllowedBuilders lists acceptable runDetails.builder.id values
	// (exact match). Required for SLSA provenance.
	AllowedBuilders []string
	// ExpectedSubjects: at least one statement subject must match one
	// expected resource by name AND contain every expected digest.
	ExpectedSubjects []Resource
	// ExpectedSources are material URIs (e.g.
	// "git+https://github.com/org/repo@<sha>") that must appear in
	// buildDefinition.resolvedDependencies. Empty means "do not check".
	ExpectedSources []string
	// AllowedBuildTypes restricts buildDefinition.buildType. Empty allows any.
	AllowedBuildTypes []string
}

var (
	// ErrProvenanceType is returned for unexpected statement/predicate types.
	ErrProvenanceType = errors.New("security: unexpected attestation type")
	// ErrProvenanceSubject is returned when no subject matches the artifact.
	ErrProvenanceSubject = errors.New("security: provenance subject mismatch")
	// ErrProvenanceBuilder is returned for an untrusted builder id.
	ErrProvenanceBuilder = errors.New("security: builder id is not allowed")
	// ErrProvenanceSource is returned when pinned sources are absent.
	ErrProvenanceSource = errors.New("security: resolved source not found")
)

// VerifyStatement validates an in-toto statement against policy.
func VerifyStatement(stmt *Statement, policy ProvenancePolicy) (*SLSAProvenanceV1, error) {
	if stmt.Type != StatementTypeV1 {
		return nil, fmt.Errorf("%w: _type=%q", ErrProvenanceType, stmt.Type)
	}
	if stmt.PredicateType != PredicateSLSAProvenanceV1 {
		return nil, fmt.Errorf("%w: predicateType=%q", ErrProvenanceType, stmt.PredicateType)
	}

	prov := &SLSAProvenanceV1{}
	if err := json.Unmarshal(stmt.Predicate, prov); err != nil {
		return nil, fmt.Errorf("security: decode slsa predicate: %w", err)
	}

	if len(policy.AllowedBuilders) > 0 && !contains(policy.AllowedBuilders, prov.RunDetails.Builder.ID) {
		return nil, fmt.Errorf("%w: %q", ErrProvenanceBuilder, prov.RunDetails.Builder.ID)
	}

	if len(policy.AllowedBuildTypes) > 0 && !contains(policy.AllowedBuildTypes, prov.BuildDefinition.BuildType) {
		return nil, fmt.Errorf("security: build type %q is not allowed", prov.BuildDefinition.BuildType)
	}

	if len(policy.ExpectedSubjects) > 0 && !subjectCovered(stmt.Subject, policy.ExpectedSubjects) {
		return nil, ErrProvenanceSubject
	}

	if len(policy.ExpectedSources) > 0 && !sourceCovered(prov.BuildDefinition.ResolvedDependencies, policy.ExpectedSources) {
		return nil, ErrProvenanceSource
	}

	return prov, nil
}

// VerifyAttestation verifies a DSSE-wrapped in-toto attestation against the
// trusted keys and the supplied SLSA policy.
func VerifyAttestation(env *dsse.Envelope, keys map[string]ed25519.PublicKey, policy ProvenancePolicy) (*Statement, *SLSAProvenanceV1, error) {
	payload, err := dsse.Verify(env, keys)
	if err != nil {
		return nil, nil, err
	}
	stmt := &Statement{}
	if err := json.Unmarshal(payload, stmt); err != nil {
		return nil, nil, fmt.Errorf("security: decode in-toto statement: %w", err)
	}
	prov, err := VerifyStatement(stmt, policy)
	if err != nil {
		return nil, nil, err
	}
	return stmt, prov, nil
}

func subjectCovered(actual []Resource, expected []Resource) bool {
	for _, want := range expected {
		for _, got := range actual {
			if got.Name != want.Name {
				continue
			}
			ok := true
			for alg, val := range want.Digest {
				if got.Digest[alg] != val {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

func sourceCovered(deps []Resource, uris []string) bool {
	for _, uri := range uris {
		found := false
		for _, dep := range deps {
			if dep.Name == uri {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
