// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package lockfile builds and consumes cgapp.lock: the fully resolved,
// digest-pinned bill of materials for one project creation. The lock is
// produced before execution and is the reproducibility contract: re-running
// with the same lock must fetch and run byte-identical inputs.
package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/create-go-app/cli/v4/pkg/registry"
)

// LockVersion is the current cgapp.lock schema.
const LockVersion = "1.0"

// Selection is the user's resolved template choice.
type Selection struct {
	Backend           string `json:"backend"`
	Frontend          string `json:"frontend"`
	RequestedFrontend string `json:"requestedFrontend,omitempty"`
	Proxy             string `json:"proxy"`
	Custom            bool   `json:"custom"`
}

// Lock is the on-disk cgapp.lock content. It deliberately carries no
// wall-clock fields: the same selection against the same signed manifest
// must produce a byte-identical lock (build timestamps live in the signed
// attestation metadata instead).
type Lock struct {
	LockVersion string                `json:"lockVersion"`
	Generator   registry.GeneratorRef `json:"generator"`
	Selection   Selection             `json:"selection"`
	Manifest    ManifestRef           `json:"manifest"`
	Toolchains  ToolchainSnapshot     `json:"toolchains"`
	Materials   []Material            `json:"materials"`
	// Digest is the sha256 of the canonical JSON with this field empty.
	Digest string `json:"digest,omitempty"`
}

// ManifestRef pins which signed registry produced this lock.
type ManifestRef struct {
	Name           string `json:"name"`
	Revision       string `json:"revision"`
	Digest         string `json:"digest"`
	SignatureKeyID string `json:"signatureKeyID"`
}

// ToolchainSnapshot records the version constraints that were enforced.
type ToolchainSnapshot struct {
	Go      string `json:"go"`
	Node    string `json:"node,omitempty"`
	Ansible string `json:"ansible"`
}

// Material is one pinned input to the build.
type Material struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Kind    string `json:"kind"`
	Source  string `json:"source,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Tree    string `json:"tree,omitempty"`
	License string `json:"license,omitempty"`
	// ExpectedDigest is the pin from the signed manifest.
	ExpectedDigest map[string]string `json:"expectedDigest,omitempty"`
	// ObservedDigest is measured after fetching (must equal expected for
	// verified materials).
	ObservedDigest map[string]string `json:"observedDigest,omitempty"`
	// Integrity is the npm-style "sha512-<base64>" pin.
	Integrity  string          `json:"integrity,omitempty"`
	Provenance ProvenanceState `json:"provenance"`
	// Trust is "verified" (signature+digest proven),
	// "trusted-first-use" (custom template, TOFU) or "unverified".
	Trust string   `json:"trust"`
	Notes []string `json:"notes,omitempty"`
}

// ProvenanceState records how provenance was established.
type ProvenanceState struct {
	Type      string `json:"type"`
	Verified  bool   `json:"verified"`
	KeyID     string `json:"keyID,omitempty"`
	BuilderID string `json:"builderID,omitempty"`
}

// Resolve creates a lock with expected pins from a verified manifest.
// frontend may be "none". Alias entries are followed and recorded in
// RequestedFrontend.
func Resolve(m *registry.Manifest, sel Selection) (*Lock, error) {
	lock := &Lock{
		LockVersion: LockVersion,
		Generator:   m.Generator,
		Selection:   sel,
	}

	manifestDigest, err := m.Digest()
	if err != nil {
		return nil, err
	}
	lock.Manifest = ManifestRef{
		Name:           m.Name,
		Revision:       m.Revision,
		Digest:         manifestDigest,
		SignatureKeyID: signatureKey(m),
	}

	// Toolchain snapshot: Go floor is the greater of the global floor and
	// the selected backend requirement; Node is the per-generator engine
	// constraint when present.
	goReq := m.Toolchains.Go.MinVersion
	if sel.Backend != "" && !sel.Custom {
		be, ok := m.Backends[sel.Backend]
		if !ok {
			return nil, fmt.Errorf("unknown backend %q", sel.Backend)
		}
		if greaterVersion(be.GoVersion, goReq) {
			goReq = be.GoVersion
		}
	}
	lock.Toolchains = ToolchainSnapshot{
		Go:      ">=" + goReq,
		Ansible: ">=" + m.Toolchains.Ansible.MinVersion,
	}

	// Backend material.
	if sel.Backend != "" && !sel.Custom {
		be, ok := m.Backends[sel.Backend]
		if !ok {
			return nil, fmt.Errorf("unknown backend %q", sel.Backend)
		}
		lock.Materials = append(lock.Materials, Material{
			ID:      "backend",
			Role:    "backend",
			Kind:    be.Kind,
			Source:  be.Source,
			Name:    be.Source,
			Commit:  be.Commit,
			Tree:    be.Tree,
			License: be.License,
			ExpectedDigest: map[string]string{
				"sha256":        be.ContentDigest,
				"git-tree-sha1": be.Tree,
			},
			Provenance: ProvenanceState{Type: be.Provenance.Type},
			Trust:      "pending",
		})
	}

	// Frontend material (with alias resolution).
	if sel.Frontend != "" && sel.Frontend != "none" && !sel.Custom {
		key := sel.Frontend
		requested := key
		visited := map[string]bool{}
		var aliasTrail []string
		for {
			if visited[key] {
				return nil, fmt.Errorf("frontend alias loop at %q", key)
			}
			visited[key] = true
			fe, ok := m.Frontends[key]
			if !ok {
				return nil, fmt.Errorf("unknown frontend %q", key)
			}
			switch fe.Status {
			case registry.FrontendRetired:
				return nil, fmt.Errorf("frontend %q is retired: %s", key, fe.Reason)
			case registry.FrontendAlias:
				aliasTrail = append(aliasTrail, key)
				key = fe.Replacement
				continue
			}
			sel.Frontend = key
			if requested != key {
				sel.RequestedFrontend = requested
			}
			g := fe.Generator
			lock.Materials = append(lock.Materials, Material{
				ID:      "frontend-generator",
				Role:    "frontend-generator",
				Kind:    g.Kind,
				Source:  g.Registry,
				Name:    g.Name,
				Version: g.Version,
				License: fe.License,
				ExpectedDigest: map[string]string{
					"sha512": g.Integrity,
				},
				Integrity:  g.Integrity,
				Provenance: ProvenanceState{Type: registry.ProvenanceRegistryAttested},
				Trust:      "pending",
				Notes:      aliasTrail,
			})
			if fe.Node != "" {
				lock.Toolchains.Node = fe.Node
			}
			break
		}
	}

	// Embedded Ansible materials (pinned as subtree digests).
	lock.Materials = append(lock.Materials,
		embeddedMaterial("ansible-roles", m.Embedded.Roles, m.Embedded.License),
		embeddedMaterial("ansible-templates", m.Embedded.Templates, m.Embedded.License),
		embeddedMaterial("ansible-misc", m.Embedded.Misc, m.Embedded.License),
	)

	lock.Selection = sel
	return lock, nil
}

func embeddedMaterial(id string, a registry.EmbeddedAsset, license string) Material {
	return Material{
		ID:             id,
		Role:           id,
		Kind:           "embedded",
		Name:           a.Path,
		Version:        registry.CLIVersion,
		License:        license,
		ExpectedDigest: map[string]string{"sha256": a.Digest},
		Provenance:     ProvenanceState{Type: registry.ProvenanceRegistryAttested},
		Trust:          "pending",
	}
}

// Finalize computes the self-digest of the lock and must be called before
// writing.
func (l *Lock) Finalize() error {
	digest, err := l.SelfDigest()
	if err != nil {
		return err
	}
	l.Digest = digest
	return nil
}

// SelfDigest returns sha256 of canonical lock JSON with Digest left empty.
func (l *Lock) SelfDigest() (string, error) {
	copy := *l
	copy.Digest = ""
	raw, err := json.Marshal(&copy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Write finalizes and writes the lock.
func (l *Lock) Write(path string) error {
	if err := l.Finalize(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// Read loads and validates a lock digest.
func Read(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l := &Lock{}
	if err := json.Unmarshal(data, l); err != nil {
		return nil, fmt.Errorf("parse lock: %w", err)
	}
	want := l.Digest
	got, err := l.SelfDigest()
	if err != nil {
		return nil, err
	}
	if want != got {
		return nil, fmt.Errorf("lock %q is tampered: digest %s != %s", path, got, want)
	}
	return l, nil
}

// Matches reports whether the lock can serve this selection/manifest.
func (l *Lock) Matches(sel Selection, manifestDigest string) bool {
	return l.Manifest.Digest == manifestDigest &&
		l.Selection.Backend == sel.Backend &&
		l.Selection.Frontend == sel.Frontend &&
		l.Selection.Proxy == sel.Proxy &&
		l.Selection.Custom == sel.Custom
}

func signatureKey(m *registry.Manifest) string {
	if m.Signature != nil {
		return m.Signature.KeyID
	}
	return ""
}

// greaterVersion compares bare "1.2.3" versions numerically.
func greaterVersion(a, b string) bool {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) [3]int {
	var out [3]int
	parts := strings.Split(v, ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}
