// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package pipeline orchestrates the secure project creation flow:
//
//	load signed manifest -> resolve cgapp.lock -> verify provenance/hashes
//	-> execute offline in an isolated sandbox -> emit merged SBOM and a
//	signed in-toto attestation -> deliver artifacts.
//
// Nothing from the network reaches the build stage before its digest and
// provenance have been verified, and the build stage itself is denied
// network access.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/create-go-app/cli/v4/pkg/attestation"
	"github.com/create-go-app/cli/v4/pkg/cgapp"
	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/policy"
	"github.com/create-go-app/cli/v4/pkg/registry"
	"github.com/create-go-app/cli/v4/pkg/sandbox"
	"github.com/create-go-app/cli/v4/pkg/security"
	"github.com/create-go-app/cli/v4/pkg/security/dsse"
	"github.com/create-go-app/cli/v4/pkg/sources"
)

// Options configure a Create run.
type Options struct {
	// ManifestLocator selects the registry ("" embedded, path or https URL).
	ManifestLocator string
	// TrustRootPath overrides the embedded root of trust.
	TrustRootPath string
	// LockPath is the delivered lock file name (default "cgapp.lock").
	LockPath string
	// CacheRoot pins the persistent fetch cache (default user cache dir).
	CacheRoot string
	// Offline refuses all network fetches and requires a warm cache.
	Offline bool
	// Strict fails when OS-level sandboxing is unavailable.
	Strict bool
	// NoOSSandbox disables the OS sandbox (dir/env isolation remains).
	NoOSSandbox bool
	// AttestationKeyPath loads a persistent Ed25519 builder key.
	AttestationKeyPath string
	// OutputDir is the delivery target (default current working directory).
	OutputDir string
}

// Report summarizes a successful run.
type Report struct {
	Lock              *lockfile.Lock
	OutputDigest      string
	LockPath          string
	SBOMPath          string
	AttestationPath   string
	AttestorPublicKey string
	OSConfinement     string
	VerifiedMaterials int
	Warnings          []string
}

// Create runs the full secure creation pipeline for one selection.
func Create(ctx context.Context, sel lockfile.Selection, opts Options) (*Report, error) {
	started := time.Now()
	warnings := []string{}

	if opts.OutputDir == "" {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		opts.OutputDir = dir
	}
	if opts.LockPath == "" {
		opts.LockPath = "cgapp.lock"
	}
	if opts.CacheRoot == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			opts.CacheRoot = filepath.Join(dir, "cgapp")
		} else {
			opts.CacheRoot = filepath.Join(os.TempDir(), "cgapp-cache")
		}
	}

	// 1. Load and verify the signed registry manifest.
	cgapp.ShowMessage("info", "Loading signed registry manifest...", true, false)
	manifest, _, err := registry.LoadManifest(opts.ManifestLocator)
	if err != nil {
		return nil, err
	}
	trustRoot, err := registry.LoadTrustRoot(opts.TrustRootPath)
	if err != nil {
		return nil, err
	}
	if err := manifest.VerifySignature(trustRoot); err != nil {
		return nil, err
	}
	manifestDigest, _ := manifest.Digest()
	cgapp.ShowMessage("success",
		fmt.Sprintf("Manifest %s verified (%s, key %s)", manifest.Revision, manifestDigest, manifest.Signature.KeyID),
		false, false)

	// 2. Resolve the lock from the manifest pins.
	cgapp.ShowMessage("info", "Resolving pinned materials into cgapp.lock...", false, false)
	lock, err := resolveLock(manifest, sel, opts.Offline)
	if err != nil {
		return nil, err
	}

	// 3. Toolchain preflight (Ansible is a deploy-time tool: warn only).
	tools := policy.Probe(ctx)
	violations := policy.Check(tools, lock.Toolchains.Go, lock.Toolchains.Node, "")
	if ans := tools["ansible"]; !ans.Found {
		warnings = append(warnings, "ansible not found in PATH: required later by `cgapp deploy` ("+lock.Toolchains.Ansible+")")
	} else if !policy.Satisfies(ans.Version, strings.TrimPrefix(lock.Toolchains.Ansible, ">=")) {
		warnings = append(warnings, fmt.Sprintf("ansible %q does not satisfy %s (needed for deploy)", ans.Version, lock.Toolchains.Ansible))
	}
	if len(violations) > 0 {
		return nil, fmt.Errorf("toolchain policy:\n  - %s", strings.Join(violations, "\n  - "))
	}

	// 4. Prepare the isolated sandbox.
	sb, err := sandbox.Prepare(sandbox.Options{
		CacheRoot: opts.CacheRoot,
		Strict:    opts.Strict,
		DisableOS: opts.NoOSSandbox,
	})
	if err != nil {
		return nil, err
	}
	defer sb.Cleanup()
	if sb.OSConfinement() != "" {
		cgapp.ShowMessage("success", "OS sandbox active ("+sb.OSConfinement()+"); build stage is network-denied", false, false)
	} else {
		msg := "OS sandbox unavailable; using scratch-dir + scrubbed-env isolation"
		warnings = append(warnings, msg)
		cgapp.ShowMessage("info", msg, false, false)
	}

	// 5. Fetch + verify every material BEFORE anything can execute.
	cgapp.ShowMessage("info", "Verifying sources, integrity and provenance...", false, false)
	if sel.Custom {
		if err := acquireCustom(lock, opts, sb, sel, &warnings); err != nil {
			return nil, err
		}
	} else {
		if err := acquireBackend(lock, opts, sb, manifest); err != nil {
			return nil, err
		}
		if err := acquireFrontend(ctx, lock, opts, sb, manifest, sel.Frontend); err != nil {
			return nil, err
		}
	}
	if err := verifyEmbeddedAll(lock); err != nil {
		return nil, err
	}
	if err := enforceLicense(lock, manifest, sel.Custom, &warnings); err != nil {
		return nil, err
	}
	countVerified(lock)

	// 6. Persist the lock (self-digested) into the work tree.
	lockFileInWork := filepath.Join(sb.Work, opts.LockPath)
	if err := lock.Write(lockFileInWork); err != nil {
		return nil, err
	}

	// 7. Build offline inside the sandbox.
	cgapp.ShowMessage("info", "Executing verified generators in the offline sandbox...", false, false)
	if err := build(ctx, lock, sb, manifest, sel); err != nil {
		return nil, err
	}

	// 8. Hash the delivered output tree.
	outputDigest, err := sources.DigestTree(sb.Work)
	if err != nil {
		return nil, err
	}

	// 9. Build the merged SBOM.
	cgapp.ShowMessage("info", "Generating merged CycloneDX SBOM...", false, false)
	if err := os.MkdirAll(filepath.Join(sb.Work, ".cgapp"), 0o750); err != nil {
		return nil, err
	}
	sbomBytes, err := buildSBOM(lock, sb.Work, sel)
	if err != nil {
		return nil, err
	}
	sbomPath := filepath.Join(sb.Work, ".cgapp", "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, sbomBytes, 0o600); err != nil {
		return nil, err
	}
	sbomDigest, err := sources.DigestFile(sbomPath)
	if err != nil {
		return nil, err
	}

	// 10. Sign the in-toto/SLSA attestation.
	cgapp.ShowMessage("info", "Writing signed in-toto attestation...", false, false)
	attestor, err := loadOrCreateAttestor(opts.AttestationKeyPath)
	if err != nil {
		return nil, err
	}
	finished := time.Now()
	stmt := attestation.BuildStatement(attestation.Inputs{
		Outputs: []security.Resource{{
			Name:   filepath.Base(opts.OutputDir),
			Digest: map[string]string{"sha256": strings.TrimPrefix(outputDigest, "sha256:")},
		}},
		Lock:          lock,
		OSConfinement: sb.OSConfinement(),
		OfflineBuild:  true,
		SBOM: security.Resource{
			Name:   ".cgapp/sbom.cdx.json",
			Digest: map[string]string{"sha256": strings.TrimPrefix(sbomDigest, "sha256:")},
		},
		Started:  started,
		Finished: finished,
	})
	envelope, err := attestation.Sign(stmt, attestor)
	if err != nil {
		return nil, err
	}
	attBytes, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	attPath := filepath.Join(sb.Work, ".cgapp", "provenance.intoto.json")
	if err := os.WriteFile(attPath, append(attBytes, '\n'), 0o600); err != nil {
		return nil, err
	}
	pubFile := filepath.Join(sb.Work, ".cgapp", "attestor.pub.json")
	pubData, _ := json.MarshalIndent(&dsse.KeyFile{
		KeyType:   dsse.AlgorithmEd25519,
		KeyID:     attestor.KeyID,
		PublicKey: encodeB64(attestor.Public()),
	}, "", "  ")
	if err := os.WriteFile(pubFile, append(pubData, '\n'), 0o600); err != nil {
		return nil, err
	}

	// 11. Deliver into the destination, refusing to overwrite.
	if err := deliver(sb.Work, opts.OutputDir); err != nil {
		return nil, err
	}

	verified := 0
	for _, m := range lock.Materials {
		if m.Trust == "verified" {
			verified++
		}
	}
	return &Report{
		Lock:              lock,
		OutputDigest:      outputDigest,
		LockPath:          filepath.Join(opts.OutputDir, opts.LockPath),
		SBOMPath:          filepath.Join(opts.OutputDir, ".cgapp", "sbom.cdx.json"),
		AttestationPath:   filepath.Join(opts.OutputDir, ".cgapp", "provenance.intoto.json"),
		AttestorPublicKey: filepath.Join(opts.OutputDir, ".cgapp", "attestor.pub.json"),
		OSConfinement:     sb.OSConfinement(),
		VerifiedMaterials: verified,
		Warnings:          warnings,
	}, nil
}

// resolveLock builds the lock for standard and custom selections.
func resolveLock(m *registry.Manifest, sel lockfile.Selection, offline bool) (*lockfile.Lock, error) {
	if !sel.Custom {
		return lockfile.Resolve(m, sel)
	}
	// Custom mode: registry still anchors embedded assets and policy; the
	// user-provided repositories are pinned by trust-on-first-use below.
	lock := &lockfile.Lock{
		LockVersion: lockfile.LockVersion,
		Generator:   m.Generator,
		Selection:   sel,
		Toolchains: lockfile.ToolchainSnapshot{
			Go:      ">=" + m.Toolchains.Go.MinVersion,
			Ansible: ">=" + m.Toolchains.Ansible.MinVersion,
		},
	}
	digest, _ := m.Digest()
	lock.Manifest = lockfile.ManifestRef{
		Name: m.Name, Revision: m.Revision, Digest: digest,
		SignatureKeyID: m.Signature.KeyID,
	}
	lock.Materials = append(lock.Materials,
		lockfile.Material{ID: "backend", Role: "backend", Kind: "git",
			Source: sel.Backend, Name: sel.Backend, Trust: "pending",
			Provenance: lockfile.ProvenanceState{Type: "trusted-first-use"}},
	)
	if sel.Frontend != "" && sel.Frontend != "none" {
		lock.Materials = append(lock.Materials, lockfile.Material{
			ID: "frontend", Role: "frontend", Kind: "git",
			Source: sel.Frontend, Name: sel.Frontend, Trust: "pending",
			Provenance: lockfile.ProvenanceState{Type: "trusted-first-use"},
		})
	}
	for _, x := range []struct {
		id string
		a  registry.EmbeddedAsset
	}{
		{"ansible-roles", m.Embedded.Roles},
		{"ansible-templates", m.Embedded.Templates},
		{"ansible-misc", m.Embedded.Misc},
	} {
		lock.Materials = append(lock.Materials, lockfile.Material{
			ID: x.id, Role: x.id, Kind: "embedded", Name: x.a.Path,
			Version: registry.CLIVersion, License: m.Embedded.License,
			ExpectedDigest: map[string]string{"sha256": x.a.Digest},
			Provenance:     lockfile.ProvenanceState{Type: registry.ProvenanceRegistryAttested},
			Trust:          "pending",
		})
	}
	return lock, nil
}

func findMaterial(l *lockfile.Lock, id string) *lockfile.Material {
	for i := range l.Materials {
		if l.Materials[i].ID == id {
			return &l.Materials[i]
		}
	}
	return nil
}

func acquireBackend(l *lockfile.Lock, opts Options, sb *sandbox.Sandbox, m *registry.Manifest) error {
	be := m.Backends[l.Selection.Backend]
	res, err := sources.AcquireGit(opts.CacheRoot, sources.GitSpec{
		URL:           be.Source,
		Commit:        be.Commit,
		Tree:          be.Tree,
		ContentDigest: be.ContentDigest,
		AllowOffline:  opts.Offline,
	})
	if err != nil {
		return err
	}
	mat := findMaterial(l, "backend")
	mat.ObservedDigest = map[string]string{
		"sha256":        strings.TrimPrefix(res.ContentDigest, "sha256:"),
		"git-tree-sha1": res.Tree,
	}
	if err := verifyProvenance(be.Provenance, trustSubjects(be.Source, res), sb, opts); err != nil {
		return err
	}
	mat.Provenance.Verified = true
	mat.Trust = "verified"
	return nil
}

func trustSubjects(source string, res *sources.GitResult) []security.Resource {
	return []security.Resource{{
		Name:   "git+" + source + "@" + res.Commit,
		Digest: map[string]string{"sha256": strings.TrimPrefix(res.ContentDigest, "sha256:")},
	}}
}

func acquireFrontend(ctx context.Context, l *lockfile.Lock, opts Options, sb *sandbox.Sandbox, m *registry.Manifest, key string) error {
	if key == "" || key == "none" {
		return nil
	}
	fe := m.Frontends[l.Selection.Frontend]
	if fe.Generator == nil {
		return fmt.Errorf("frontend %q has no pinned generator", l.Selection.Frontend)
	}
	spec := sources.NpmSpec{
		Registry:  fe.Generator.Registry,
		Name:      fe.Generator.Name,
		Version:   fe.Generator.Version,
		Tarball:   fe.Generator.Tarball,
		Integrity: fe.Generator.Integrity,
	}
	res, err := sources.FetchNpm(ctx, nil, opts.CacheRoot, spec)
	if err != nil {
		return err
	}
	// Warm npm's own cache (its own integrity checks run as well) while the
	// network is still permitted; the build stage only gets --offline.
	if !opts.Offline {
		if err := sb.Run(ctx, sandbox.StageFetch, sb.Work, "npm", sources.NpmCacheAddArgs(spec)...); err != nil {
			return err
		}
	}
	mat := findMaterial(l, "frontend-generator")
	if mat == nil {
		return errors.New("pipeline: frontend-generator material missing")
	}
	mat.ObservedDigest = map[string]string{"sha512": res.SHA512Hex}
	mat.Provenance.Verified = true
	mat.Trust = "verified"
	return nil
}

func acquireCustom(l *lockfile.Lock, opts Options, sb *sandbox.Sandbox, sel lockfile.Selection, warnings *[]string) error {
	res, ref, err := sources.AcquireGitAtHead(opts.CacheRoot, sel.Backend)
	if err != nil {
		return err
	}
	mat := findMaterial(l, "backend")
	mat.Commit = res.Commit
	mat.Tree = res.Tree
	mat.ObservedDigest = map[string]string{
		"sha256":        strings.TrimPrefix(res.ContentDigest, "sha256:"),
		"git-tree-sha1": res.Tree,
	}
	mat.Trust = "trusted-first-use"
	*warnings = append(*warnings, fmt.Sprintf(
		"custom backend pinned at %s (%s): no registry provenance, first-use trust recorded in cgapp.lock", res.Commit, ref))
	if sel.Frontend != "" && sel.Frontend != "none" {
		fres, fref, err := sources.AcquireGitAtHead(opts.CacheRoot, sel.Frontend)
		if err != nil {
			return err
		}
		fmat := findMaterial(l, "frontend")
		fmat.Commit = fres.Commit
		fmat.Tree = fres.Tree
		fmat.ObservedDigest = map[string]string{
			"sha256":        strings.TrimPrefix(fres.ContentDigest, "sha256:"),
			"git-tree-sha1": fres.Tree,
		}
		fmat.Trust = "trusted-first-use"
		*warnings = append(*warnings, fmt.Sprintf("custom frontend pinned at %s (%s), first-use trust", fres.Commit, fref))
	}
	return nil
}

// verifyProvenance handles non-default provenance references. The default
// "registry-attested" type is established by manifest verification + digest
// equality checked in the acquire steps.
func verifyProvenance(ref registry.ProvenanceRef, subjects []security.Resource, sb *sandbox.Sandbox, opts Options) error {
	switch ref.Type {
	case registry.ProvenanceRegistryAttested:
		return nil
	case registry.ProvenanceSigstoreKey:
		data, err := readAttestation(ref.Attestation)
		if err != nil {
			return err
		}
		root, err := registry.LoadTrustRoot(opts.TrustRootPath)
		if err != nil {
			return err
		}
		keys, err := root.KeyMap("attestor")
		if err != nil {
			return err
		}
		env := &dsse.Envelope{}
		if err := json.Unmarshal(data, env); err != nil {
			return err
		}
		_, _, err = security.VerifyAttestation(env, keys, security.ProvenancePolicy{
			AllowedBuilders:  ref.BuilderIDs,
			ExpectedSubjects: subjects,
		})
		return err
	case registry.ProvenanceSigstoreKeyless:
		// Keyless verification needs a Fulcio root and Rekor endpoint; the
		// plumbing lives in the security package. Defaults ship no keyless
		// material, so this is an explicit opt-in path.
		return fmt.Errorf("sigstore-keyless provenance configured but not enabled: supply Fulcio roots via CGAPP_FULCIO_ROOTS")
	default:
		return fmt.Errorf("unknown provenance type %q", ref.Type)
	}
}

func readAttestation(locator string) ([]byte, error) {
	switch {
	case strings.HasPrefix(locator, "https://"), strings.HasPrefix(locator, "http://"):
		return httpFetch(locator)
	case strings.HasPrefix(locator, "file://"):
		return os.ReadFile(strings.TrimPrefix(locator, "file://"))
	default:
		return os.ReadFile(locator)
	}
}

func verifyEmbeddedAll(l *lockfile.Lock) error {
	checks := []struct {
		id   string
		root string
		fsys fs.FS
	}{
		{"ansible-roles", "roles", registry.EmbedRoles},
		{"ansible-templates", "templates", registry.EmbedTemplates},
		{"ansible-misc", "misc", registry.EmbedMiscFiles},
	}
	for _, c := range checks {
		got, err := sources.DigestFSRel(c.fsys, c.root)
		if err != nil {
			return err
		}
		mat := findMaterial(l, c.id)
		if mat == nil {
			return fmt.Errorf("pipeline: material %q missing", c.id)
		}
		want := strings.TrimPrefix(mat.ExpectedDigest["sha256"], "sha256:")
		gotHex := strings.TrimPrefix(got, "sha256:")
		if want != gotHex {
			return fmt.Errorf("embedded asset %q digest mismatch: got %s want %s", c.id, gotHex, want)
		}
		mat.ObservedDigest = map[string]string{"sha256": gotHex}
		mat.Provenance.Verified = true
		mat.Trust = "verified"
	}
	return nil
}

func enforceLicense(l *lockfile.Lock, m *registry.Manifest, custom bool, warnings *[]string) error {
	var licenses []string
	for _, mat := range l.Materials {
		licenses = append(licenses, mat.License)
	}
	decision := policy.EvaluateLicenses(m.LicensePolicy, licenses...)
	if custom {
		// Custom sources are operator-trusted: deny list still fails,
		// unknown licenses are warned rather than blocked.
		if len(decision.Denied) > 0 {
			return fmt.Errorf("license policy denied: %s", strings.Join(decision.Denied, ", "))
		}
		if len(decision.Unknown) > 0 {
			*warnings = append(*warnings, "custom materials without allow-listed licenses (recorded as first-use trust): "+
				strings.Join(decision.Unknown, ", "))
		}
		return nil
	}
	if !decision.Allowed {
		return fmt.Errorf("license policy violated: denied=[%s] unknown=[%s]",
			strings.Join(decision.Denied, ","), strings.Join(decision.Unknown, ","))
	}
	return nil
}

func countVerified(l *lockfile.Lock) {
	for _, mat := range l.Materials {
		if mat.Trust == "verified" {
			cgapp.ShowMessage("success",
				fmt.Sprintf("verified %s (%s)", mat.ID, digestSummary(mat)), false, false)
		}
	}
}

func digestSummary(m lockfile.Material) string {
	switch m.Kind {
	case "git":
		return "commit " + m.Commit
	case "npm":
		return m.Name + "@" + m.Version
	default:
		return m.Name
	}
}
