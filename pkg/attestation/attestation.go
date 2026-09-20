// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package attestation produces the signed in-toto attestation that
// accompanies every generated project: an ITE-6 Statement v1 with an
// SLSA provenance v1 predicate, wrapped in a DSSE envelope.
package attestation

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"time"

	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/security"
	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

// BuildType identifies cgapp builds in provenance buildDefinition.
const BuildType = "https://create-go.app/build/v1"

// Inputs collects everything needed to describe one build.
type Inputs struct {
	// Outputs are the delivered artifacts (project tree, sbom...), at least
	// the project tree.
	Outputs []security.Resource
	// Lock is the finalized material lock.
	Lock *lockfile.Lock
	// OSConfinement records the sandbox backend that was active ("" none).
	OSConfinement string
	// OfflineBuild reports whether the build stage was offline.
	OfflineBuild bool
	// SBOM byproduct digest/name.
	SBOM security.Resource
	// Started/Finished wall-clock times.
	Started  time.Time
	Finished time.Time
}

// Attestor is the signing identity for a build.
type Attestor struct {
	PrivateKey ed25519.PrivateKey
	KeyID      string
	// Ephemeral marks a per-run generated key (published alongside).
	Ephemeral bool
}

// NewEphemeralAttestor generates a one-off Ed25519 key. The public key must
// be published next to the attestation so verifiers can check it; supply a
// persistent key via LoadAttestor for stable builder identity.
func NewEphemeralAttestor() (*Attestor, error) {
	pub, priv, err := dsse.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Attestor{PrivateKey: priv, KeyID: dsse.KeyID(pub), Ephemeral: true}, nil
}

// LoadAttestor reads a dsse.KeyFile JSON from path.
func LoadAttestor(path string) (*Attestor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kf := &dsse.KeyFile{}
	if err := json.Unmarshal(data, kf); err != nil {
		return nil, err
	}
	priv, err := dsse.LoadPrivateKey(kf)
	if err != nil {
		return nil, err
	}
	return &Attestor{PrivateKey: priv, KeyID: kf.KeyID}, nil
}

// Public returns the attestor's raw public key.
func (a *Attestor) Public() ed25519.PublicKey {
	pub, _ := a.PrivateKey.Public().(ed25519.PublicKey)
	return pub
}

// BuildStatement assembles the unsigned in-toto statement.
func BuildStatement(in Inputs) *security.Statement {
	subjects := append([]security.Resource{}, in.Outputs...)
	subjects = append(subjects, in.SBOM)

	materials := make([]security.Resource, 0, len(in.Lock.Materials))
	for _, m := range in.Lock.Materials {
		name := m.Source
		if name == "" {
			name = "embedded:" + m.Name
		}
		digests := map[string]string{}
		for k, v := range m.ObservedDigest {
			digests[k] = digestValue(v)
		}
		if len(digests) == 0 {
			for k, v := range m.ExpectedDigest {
				digests[k] = digestValue(v)
			}
		}
		if m.Commit != "" {
			digests["git-commit-sha1"] = m.Commit
		}
		materials = append(materials, security.Resource{Name: name, Digest: digests})
	}

	return &security.Statement{
		Type:          security.StatementTypeV1,
		Subject:       subjects,
		PredicateType: security.PredicateSLSAProvenanceV1,
		Predicate: mustMarshal(security.SLSAProvenanceV1{
			BuildDefinition: security.BuildDefinition{
				BuildType: BuildType,
				ExternalParameters: map[string]any{
					"backend":  in.Lock.Selection.Backend,
					"frontend": in.Lock.Selection.Frontend,
					"proxy":    in.Lock.Selection.Proxy,
					"custom":   in.Lock.Selection.Custom,
				},
				InternalParameters: map[string]any{
					"manifest":      in.Lock.Manifest.Digest,
					"manifestKeyID": in.Lock.Manifest.SignatureKeyID,
					"lock":          in.Lock.Digest,
					"generator":     in.Lock.Generator.Name + "@" + in.Lock.Generator.MinVersion,
					"osConfinement": in.OSConfinement,
					"offlineBuild":  in.OfflineBuild,
				},
				ResolvedDependencies: materials,
			},
			RunDetails: security.RunDetails{
				Builder: security.Builder{
					ID: "pkg:github/create-go-app/cli@v" + in.Lock.Generator.MinVersion,
				},
				Metadata: security.BuildMetadata{
					StartedAt:  in.Started.UTC().Format(time.RFC3339),
					FinishedAt: in.Finished.UTC().Format(time.RFC3339),
				},
				Byproducts: []security.Resource{in.SBOM},
			},
		}),
	}
}

// Sign wraps the statement in a signed DSSE envelope.
func Sign(stmt *security.Statement, a *Attestor) (*dsse.Envelope, error) {
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	return dsse.Sign(a.PrivateKey, a.KeyID, dsse.PayloadTypeInTotoV1, payload)
}

func mustMarshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// digestValue strips the "alg:" prefix when a lock digest carried one.
func digestValue(v string) string {
	for _, prefix := range []string{"sha256:", "sha512:", "sha1:"} {
		if len(v) > len(prefix) && v[:len(prefix)] == prefix {
			return v[len(prefix):]
		}
	}
	return v
}
