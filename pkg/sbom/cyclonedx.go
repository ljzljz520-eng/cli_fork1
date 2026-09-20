// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package sbom produces a merged CycloneDX 1.5 SBOM for a generated
// project: the cgapp generator itself, the pinned git backend, the npm
// initializer, discovered Go modules and npm dependencies, and the
// embedded Ansible assets. Components are de-duplicated by bom-ref
// (Package URL) and their hashes/properties are merged.
package sbom

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// BOM is a minimal CycloneDX 1.5 document.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata is the BOM metadata block.
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     *Tools `json:"tools,omitempty"`
}

// Tools holds tool components (CycloneDX >=1.5).
type Tools struct {
	Components []Component `json:"components"`
}

// Component is a CycloneDX component.
type Component struct {
	Type        string          `json:"type"`
	BOMRef      string          `json:"bom-ref"`
	Name        string          `json:"name"`
	Version     string          `json:"version,omitempty"`
	PackageURL  string          `json:"purl,omitempty"`
	Description string          `json:"description,omitempty"`
	Hashes      []Hash          `json:"hashes,omitempty"`
	Licenses    []LicenseChoice `json:"licenses,omitempty"`
	Properties  []Property      `json:"properties,omitempty"`
}

// Hash is an algorithm-tagged content hash.
type Hash struct {
	Algorithm string `json:"alg"`
	Value     string `json:"content"`
}

// LicenseChoice wraps a license id or expression.
type LicenseChoice struct {
	License *License `json:"license,omitempty"`
}

// License references an SPDX license id.
type License struct {
	ID string `json:"id"`
}

// Property is a named component property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency is a CycloneDX dependency edge.
type Dependency struct {
	Ref          string   `json:"ref"`
	Dependencies []string `json:"dependsOn,omitempty"`
}

// Builder accumulates and merges components.
type Builder struct {
	bom *BOM
	idx map[string]int
}

// New creates a BOM builder stamped with the generator tool component.
func New(generatorName, generatorVersion string) *Builder {
	b := &Builder{
		bom: &BOM{
			BOMFormat:    "CycloneDX",
			SpecVersion:  "1.5",
			SerialNumber: "urn:uuid:" + uuidV4(),
			Version:      1,
			Metadata: Metadata{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Tools: &Tools{Components: []Component{{
					Type:       "application",
					BOMRef:     "pkg:github/create-go-app/cli@v" + generatorVersion,
					Name:       generatorName,
					Version:    generatorVersion,
					PackageURL: "pkg:github/create-go-app/cli@v" + generatorVersion,
				}}},
			},
		},
		idx: map[string]int{},
	}
	return b
}

// Add inserts a component or merges hashes/licenses/properties into the
// component with the same bom-ref.
func (b *Builder) Add(c Component) Component {
	if c.BOMRef == "" {
		c.BOMRef = c.PackageURL
	}
	if i, ok := b.idx[c.BOMRef]; ok {
		existing := b.bom.Components[i]
		existing.Hashes = mergeHashes(existing.Hashes, c.Hashes)
		existing.Licenses = mergeLicenses(existing.Licenses, c.Licenses)
		existing.Properties = mergeProps(existing.Properties, c.Properties)
		if existing.Version == "" {
			existing.Version = c.Version
		}
		b.bom.Components[i] = existing
		return existing
	}
	b.idx[c.BOMRef] = len(b.bom.Components)
	b.bom.Components = append(b.bom.Components, c)
	return c
}

// AddDependency records a dependency edge.
func (b *Builder) AddDependency(ref string, deps ...string) {
	for i := range b.bom.Dependencies {
		if b.bom.Dependencies[i].Ref == ref {
			b.bom.Dependencies[i].Dependencies = appendUnique(b.bom.Dependencies[i].Dependencies, deps)
			return
		}
	}
	b.bom.Dependencies = append(b.bom.Dependencies, Dependency{Ref: ref, Dependencies: appendUnique(nil, deps)})
}

// Finalize returns the assembled BOM with a stable component order.
func (b *Builder) Finalize() *BOM {
	sort.SliceStable(b.bom.Components, func(i, j int) bool {
		return b.bom.Components[i].BOMRef < b.bom.Components[j].BOMRef
	})
	return b.bom
}

// JSON renders the BOM as indented JSON.
func (b *Builder) JSON() ([]byte, error) {
	return json.MarshalIndent(b.Finalize(), "", "  ")
}

// NpmIntegrityToHash converts an npm integrity string ("sha512-<b64>") into
// a CycloneDX hash with hex content.
func NpmIntegrityToHash(integrity string) (Hash, bool) {
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 || parts[0] != "sha512" {
		return Hash{}, false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return Hash{}, false
	}
	return Hash{Algorithm: "SHA-512", Value: hex.EncodeToString(raw)}, true
}

// GitPurl builds the Package URL of a git-hosted source at a commit.
func GitPurl(sourceURL, commit string) string {
	// pkg:github/<owner>/<repo>@<commit>
	u := strings.TrimPrefix(sourceURL, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(strings.TrimPrefix(u, "github.com/"), ".git")
	return "pkg:github/" + u + "@" + commit
}

func mergeHashes(a, b []Hash) []Hash {
	seen := map[string]int{}
	for i, h := range a {
		seen[h.Algorithm] = i
	}
	for _, h := range b {
		if i, ok := seen[h.Algorithm]; ok {
			a[i] = h
			continue
		}
		seen[h.Algorithm] = len(a)
		a = append(a, h)
	}
	return a
}

func mergeLicenses(a, b []LicenseChoice) []LicenseChoice {
	seen := map[string]bool{}
	for _, l := range a {
		if l.License != nil {
			seen[l.License.ID] = true
		}
	}
	for _, l := range b {
		if l.License != nil && !seen[l.License.ID] {
			seen[l.License.ID] = true
			a = append(a, l)
		}
	}
	return a
}

func mergeProps(a, b []Property) []Property {
	seen := map[string]bool{}
	for _, p := range a {
		seen[p.Name] = true
	}
	for _, p := range b {
		if !seen[p.Name] {
			seen[p.Name] = true
			a = append(a, p)
		}
	}
	return a
}

func appendUnique(list, add []string) []string {
	seen := map[string]bool{}
	for _, x := range list {
		seen[x] = true
	}
	for _, x := range add {
		if !seen[x] {
			seen[x] = true
			list = append(list, x)
		}
	}
	return list
}

func uuidV4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
