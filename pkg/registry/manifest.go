// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package registry

import (
	"crypto/ed25519"
	cryptoSha256 "crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

const (
	// ManifestSchemaVersion is the current registry manifest schema.
	ManifestSchemaVersion = "1.0"
	// ManifestMediaType identifies the signed registry manifest.
	ManifestMediaType = "application/vnd.cgapp.registry-manifest.v1+json"

	// ProvenanceRegistryAttested means the manifest signature itself is the
	// attestation of record for a material: the registry signer asserts the
	// pinned commit, tree and content digest. Verified offline.
	ProvenanceRegistryAttested = "registry-attested"
	// ProvenanceSigstoreKey means a DSSE in-toto attestation signed with a
	// trusted static key (Sigstore "cosign attest --key" flow).
	ProvenanceSigstoreKey = "sigstore-key"
	// ProvenanceSigstoreKeyless means a Sigstore bundle carrying a Fulcio
	// certificate and a Rekor transparency log entry.
	ProvenanceSigstoreKeyless = "sigstore-keyless"
)

var (
	//go:embed registry.json
	embeddedRegistry []byte
	//go:embed trust/root.json
	embeddedTrustRoot []byte

	// ErrManifestSignature means the manifest signature failed verification.
	ErrManifestSignature = errors.New("registry: manifest signature verification failed")
	// ErrManifestValidation means the manifest is structurally invalid.
	ErrManifestValidation = errors.New("registry: manifest validation failed")
)

// Manifest is the signed registry of every material `cgapp create` can use.
// Every mutable input (git templates, npm generator packages, embedded
// Ansible assets) is pinned by cryptographic digest and covered by one
// Ed25519 signature stored in Signature.
type Manifest struct {
	SchemaVersion string        `json:"schemaVersion"`
	MediaType     string        `json:"mediaType"`
	Name          string        `json:"name"`
	Revision      string        `json:"revision"`
	GeneratedAt   string        `json:"generatedAt"`
	Generator     GeneratorRef  `json:"generator"`
	Toolchains    Toolchains    `json:"toolchains"`
	LicensePolicy LicensePolicy `json:"licensePolicy"`
	Embedded      EmbeddedRef   `json:"embedded"`
	// Backends maps the survey framework key ("fiber", "net/http", "chi")
	// to a pinned git template.
	Backends map[string]GitTemplate `json:"backends"`
	// Frontends maps the survey frontend option ("react-ts", "next-ts")
	// to a pinned npm generator or an alias/retirement entry.
	Frontends map[string]FrontendEntry `json:"frontends"`
	// Signature covers the canonical JSON encoding of the manifest with
	// this field removed.
	Signature *SignatureBlock `json:"signature,omitempty"`
}

// GeneratorRef identifies the cgapp generator this manifest is valid for.
type GeneratorRef struct {
	Name       string `json:"name"`
	MinVersion string `json:"minVersion"`
}

// Toolchains pins the tool families used to materialize a project.
type Toolchains struct {
	Go      Toolchain `json:"go"`
	Node    Toolchain `json:"node"`
	Ansible Toolchain `json:"ansible"`
}

// Toolchain declares a tool version policy (semver constraint) and, when
// known, the distribution digest of the endorsed toolchain binary.
type Toolchain struct {
	MinVersion string `json:"minVersion"`
	SHA256     string `json:"sha256,omitempty"`
}

// LicensePolicy is evaluated against every material before execution.
type LicensePolicy struct {
	// Mode is "allowlist" (everything must be explicitly allowed) or
	// "denylist" (anything except denied licenses is accepted).
	Mode string `json:"mode"`
	// Scope is "direct" (direct materials only) or "all"
	// (including discovered transitive components).
	Scope        string   `json:"scope"`
	Allowed      []string `json:"allowed"`
	Denied       []string `json:"denied"`
	AllowUnknown bool     `json:"allowUnknown"`
}

// EmbeddedRef pins the Ansible assets embedded into the generator binary.
type EmbeddedRef struct {
	AnsibleVersion string        `json:"ansibleVersion"`
	License        string        `json:"license"`
	Roles          EmbeddedAsset `json:"roles"`
	Templates      EmbeddedAsset `json:"templates"`
	Misc           EmbeddedAsset `json:"misc"`
}

// EmbeddedAsset is a pinned embedded file-system subtree.
type EmbeddedAsset struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// GitTemplate pins a backend git repository.
type GitTemplate struct {
	Source        string        `json:"source"`
	Kind          string        `json:"kind"`
	Commit        string        `json:"commit"`
	Tree          string        `json:"tree"`
	ContentDigest string        `json:"contentDigest"`
	License       string        `json:"license"`
	GoVersion     string        `json:"goVersion"`
	StripPaths    []string      `json:"stripPaths"`
	Provenance    ProvenanceRef `json:"provenance"`
}

// ProvenanceRef tells the verifier where and how provenance is established.
type ProvenanceRef struct {
	// Type is one of the Provenance* constants.
	Type string `json:"type"`
	// Attestation is a file://, https:// or "embedded:<material>" URL.
	Attestation string `json:"attestation,omitempty"`
	// KeyID selects a trusted key for sigstore-key attestations.
	KeyID string `json:"keyID,omitempty"`
	// BuilderIDs are accepted runDetails.builder.id values.
	BuilderIDs []string `json:"builderIDs,omitempty"`
	// RekorURL overrides the transparency log for keyless verification.
	RekorURL string `json:"rekorURL,omitempty"`
}

// FrontendStatus values.
const (
	FrontendAvailable = "available"
	FrontendAlias     = "alias"
	FrontendRetired   = "retired"
)

// FrontendEntry is a frontend survey option.
type FrontendEntry struct {
	Status      string        `json:"status"`
	Replacement string        `json:"replacement,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Generator   *NpmGenerator `json:"generator,omitempty"`
	// Node is the per-entry Node engine constraint.
	Node    string `json:"node,omitempty"`
	License string `json:"license,omitempty"`
	// Bin is the executable the package exposes.
	Bin string `json:"bin,omitempty"`
	// Args are appended after the binary name, executed inside the
	// network-denied sandbox work directory.
	Args []string `json:"args,omitempty"`
}

// NpmGenerator pins an npm initializer package by version and tarball
// integrity (the same sha512 value the npm registry publishes and that
// npm itself verifies on install).
type NpmGenerator struct {
	Kind      string `json:"kind"`
	Registry  string `json:"registry"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Tarball   string `json:"tarball"`
	Integrity string `json:"integrity"`
}

// SignatureBlock is the detached Ed25519 signature over canonical bytes.
type SignatureBlock struct {
	KeyID     string `json:"keyid"`
	Algorithm string `json:"algorithm"`
	Sig       string `json:"sig"`
}

// TrustRoot is the embedded root of trust for manifest/attestation keys.
type TrustRoot struct {
	SchemaVersion string       `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Keys          []TrustedKey `json:"keys"`
}

// TrustedKey is one Ed25519 public key in the trust root.
type TrustedKey struct {
	KeyID      string   `json:"keyid"`
	KeyType    string   `json:"keyType"`
	PublicKey  string   `json:"publicKey"`
	Issuer     string   `json:"issuer,omitempty"`
	Usages     []string `json:"usages"`
	ValidFrom  string   `json:"validFrom,omitempty"`
	ValidUntil string   `json:"validUntil,omitempty"`
}

// LoadManifest loads a manifest: "" means the embedded default manifest,
// "http(s)://..." a remote manifest, anything else a local file path.
func LoadManifest(locator string) (*Manifest, []byte, error) {
	var (
		data []byte
		err  error
	)
	switch {
	case locator == "":
		data, err = embeddedRegistry, error(nil)
	case strings.HasPrefix(locator, "http://"), strings.HasPrefix(locator, "https://"):
		data, err = httpGet(locator)
	default:
		data, err = os.ReadFile(locator)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("registry: load manifest %q: %w", locator, err)
	}
	m, err := ParseManifest(data)
	return m, data, err
}

func httpGet(locator string) ([]byte, error) {
	u, err := url.Parse(locator)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", ManifestMediaType)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d fetching manifest", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// ParseManifest decodes and validates manifest data.
func ParseManifest(data []byte) (*Manifest, error) {
	m := &Manifest{}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrManifestValidation, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate checks schema-level invariants of the manifest.
func (m *Manifest) Validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("%w: unsupported schemaVersion %q", ErrManifestValidation, m.SchemaVersion)
	}
	if m.MediaType != ManifestMediaType {
		return fmt.Errorf("%w: unexpected mediaType %q", ErrManifestValidation, m.MediaType)
	}
	if m.Generator.Name == "" || m.Generator.MinVersion == "" {
		return fmt.Errorf("%w: generator reference incomplete", ErrManifestValidation)
	}
	if m.LicensePolicy.Mode != "allowlist" && m.LicensePolicy.Mode != "denylist" {
		return fmt.Errorf("%w: licensePolicy.mode must be allowlist or denylist", ErrManifestValidation)
	}
	if len(m.Backends) == 0 {
		return fmt.Errorf("%w: no backends defined", ErrManifestValidation)
	}
	for key, b := range m.Backends {
		if b.Source == "" || !isHexSHA1(b.Commit) || !isHexSHA1(b.Tree) || b.ContentDigest == "" {
			return fmt.Errorf("%w: backend %q pins incomplete", ErrManifestValidation, key)
		}
		if b.Provenance.Type == "" {
			return fmt.Errorf("%w: backend %q provenance type empty", ErrManifestValidation, key)
		}
	}
	for key, f := range m.Frontends {
		switch f.Status {
		case FrontendAvailable:
			g := f.Generator
			if g == nil || g.Name == "" || g.Version == "" ||
				!strings.HasPrefix(g.Integrity, "sha512-") {
				return fmt.Errorf("%w: frontend %q generator pin incomplete", ErrManifestValidation, key)
			}
		case FrontendAlias:
			if f.Replacement == "" {
				return fmt.Errorf("%w: frontend alias %q has no replacement", ErrManifestValidation, key)
			}
		case FrontendRetired:
			// reason is optional but recommended
		default:
			return fmt.Errorf("%w: frontend %q has invalid status %q", ErrManifestValidation, key, f.Status)
		}
	}
	for _, sub := range []EmbeddedAsset{m.Embedded.Roles, m.Embedded.Templates, m.Embedded.Misc} {
		if sub.Path == "" || !strings.HasPrefix(sub.Digest, "sha256:") {
			return fmt.Errorf("%w: embedded asset pin incomplete", ErrManifestValidation)
		}
	}
	return nil
}

// CanonicalBytes returns the canonical signing bytes: the compact JSON
// encoding of the manifest with the signature block removed.
func (m *Manifest) CanonicalBytes() ([]byte, error) {
	copy := *m
	copy.Signature = nil
	return json.Marshal(&copy)
}

// Digest returns "sha256:<hex>" of the canonical bytes.
func (m *Manifest) Digest() (string, error) {
	raw, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256Sum(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// VerifySignature validates the manifest signature against the trust root.
func (m *Manifest) VerifySignature(root *TrustRoot) error {
	if m.Signature == nil {
		return fmt.Errorf("%w: manifest is unsigned", ErrManifestSignature)
	}
	if m.Signature.Algorithm != dsse.AlgorithmEd25519 {
		return fmt.Errorf("%w: unsupported algorithm %q", ErrManifestSignature, m.Signature.Algorithm)
	}
	key, err := root.publicKey(m.Signature.KeyID, "registry-sign")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifestSignature, err)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrManifestSignature, err)
	}
	raw, err := m.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("%w: canonicalize: %v", ErrManifestSignature, err)
	}
	if !ed25519.Verify(key, raw, sig) {
		return fmt.Errorf("%w: signature does not match", ErrManifestSignature)
	}
	return nil
}

// Sign signs the canonical manifest bytes with priv and attaches the block.
func (m *Manifest) Sign(priv ed25519.PrivateKey) error {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("registry: signer public key is not ed25519")
	}
	raw, err := m.CanonicalBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, raw)
	m.Signature = &SignatureBlock{
		KeyID:     dsse.KeyID(pub),
		Algorithm: dsse.AlgorithmEd25519,
		Sig:       base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

// LoadTrustRoot loads the embedded trust root, or a custom one from path.
func LoadTrustRoot(path string) (*TrustRoot, error) {
	data := embeddedTrustRoot
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("registry: load trust root: %w", err)
		}
		data = raw
	}
	root := &TrustRoot{}
	if err := json.Unmarshal(data, root); err != nil {
		return nil, fmt.Errorf("registry: parse trust root: %w", err)
	}
	return root, nil
}

// PublicKey resolves a key id with the requested usage (validity checked).
func (root *TrustRoot) PublicKey(keyID, usage string) (ed25519.PublicKey, error) {
	return root.publicKey(keyID, usage)
}

// KeyMap returns all keys valid for usage as keyid -> key.
func (root *TrustRoot) KeyMap(usage string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	now := time.Now().UTC()
	for _, k := range root.Keys {
		if !hasUsage(k.Usages, usage) {
			continue
		}
		if k.ValidFrom != "" {
			from, err := time.Parse(time.RFC3339, k.ValidFrom)
			if err != nil || now.Before(from) {
				continue
			}
		}
		if k.ValidUntil != "" {
			until, err := time.Parse(time.RFC3339, k.ValidUntil)
			if err != nil || now.After(until) {
				continue
			}
		}
		key, err := dsse.LoadPublicKey(k.PublicKey)
		if err != nil {
			return nil, err
		}
		out[k.KeyID] = key
	}
	return out, nil
}

func (root *TrustRoot) publicKey(keyID, usage string) (ed25519.PublicKey, error) {
	keys, err := root.KeyMap(usage)
	if err != nil {
		return nil, err
	}
	key, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("keyid %q not valid for usage %q", keyID, usage)
	}
	return key, nil
}

// EmbeddedFS exposes the embedded registries (used by tests and tooling).
func EmbeddedFS() (registry, trust []byte) {
	return embeddedRegistry, embeddedTrustRoot
}

func sha256Sum(raw []byte) [32]byte {
	return cryptoSha256.Sum256(raw)
}

func hasUsage(usages []string, want string) bool {
	for _, u := range usages {
		if u == want || u == "*" {
			return true
		}
	}
	return false
}

func isHexSHA1(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
