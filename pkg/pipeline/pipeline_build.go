// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package pipeline

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/create-go-app/cli/v4/pkg/attestation"
	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/registry"
	"github.com/create-go-app/cli/v4/pkg/sandbox"
	"github.com/create-go-app/cli/v4/pkg/sbom"
	"github.com/create-go-app/cli/v4/pkg/sources"
)

// build materializes the project inside the sandbox work directory. Every
// command here runs in StageBuild: network denied, npm --offline.
func build(ctx context.Context, l *lockfile.Lock, sb *sandbox.Sandbox, m *registry.Manifest, sel lockfile.Selection) error {
	// Backend: export the verified checkout, applying the manifest's strip
	// list (recorded before stripping via the lock provenance).
	backendMat := findMaterial(l, "backend")
	strip := []string{".git", ".github"}
	if !sel.Custom {
		strip = m.Backends[sel.Backend].StripPaths
	}
	cacheDir := sources.GitCacheDir(sb.Cache, backendMat.Source)
	if err := sources.ExportTree(cacheDir, filepath.Join(sb.Work, "backend"), strip); err != nil {
		return err
	}

	// Frontend.
	if sel.Frontend != "" && sel.Frontend != "none" {
		if sel.Custom {
			fmat := findMaterial(l, "frontend")
			fcache := sources.GitCacheDir(sb.Cache, fmat.Source)
			if err := sources.ExportTree(fcache, filepath.Join(sb.Work, "frontend"), []string{".git", ".github"}); err != nil {
				return err
			}
		} else {
			fe := m.Frontends[sel.Frontend]
			g := fe.Generator
			spec := sources.NpmSpec{Registry: g.Registry, Name: g.Name, Version: g.Version, Integrity: g.Integrity}
			args := sources.NpmExecArgs(spec, fe.Bin, fe.Args)
			if err := sb.RunOpts(ctx, sandbox.RunOpts{
				Stage: sandbox.StageBuild,
				Dir:   sb.Work,
				Name:  "npm",
				Args:  args,
			}); err != nil {
				return err
			}
			// Defensive: generators must not seed a nested VCS repo.
			_ = os.RemoveAll(filepath.Join(sb.Work, "frontend", ".git"))
			_ = os.RemoveAll(filepath.Join(sb.Work, "frontend", ".github"))
		}
	}

	// Ansible inventory/playbook templates, then roles and misc assets.
	if err := emitAnsible(sb.Work, sel.Proxy); err != nil {
		return err
	}

	// Remove proxy roles that are not used.
	for _, role := range unusedProxyRoles(sel.Proxy) {
		_ = os.RemoveAll(filepath.Join(sb.Work, "roles", role))
	}
	return nil
}

// emitAnsible copies embedded templates/roles/misc into work and renders the
// inventory and playbook.
func emitAnsible(work, proxy string) error {
	// Inventory + playbook templates land at the work root.
	if err := copyEmbedded(registry.EmbedTemplates, "templates", work, true); err != nil {
		return err
	}
	inventory := registry.AnsibleInventoryVariables[proxy].List
	playbook := registry.AnsiblePlaybookVariables[proxy].List
	for _, p := range []struct {
		file string
		vars map[string]interface{}
	}{
		{"hosts.ini.tmpl", inventory},
		{"playbook.yml.tmpl", playbook},
	} {
		if err := renderTemplate(filepath.Join(work, p.file), p.vars); err != nil {
			return err
		}
	}
	// Roles keep their "roles/..." hierarchy.
	if err := copyEmbedded(registry.EmbedRoles, "roles", work, false); err != nil {
		return err
	}
	// Misc files land at the work root (.gitignore, Makefile, ...).
	return copyEmbedded(registry.EmbedMiscFiles, "misc", work, true)
}

// copyEmbedded mirrors the historic CopyFromEmbeddedFS behavior rooted at
// dst: skipTopDir=true flattens the first path element.
func copyEmbedded(fsys fs.FS, root, dst string, skipTopDir bool) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dst, path)
		if skipTopDir {
			target = filepath.Join(dst, d.Name())
		}
		if d.IsDir() {
			if skipTopDir {
				return nil
			}
			return os.MkdirAll(target, 0o750)
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

func renderTemplate(tmplPath string, vars map[string]interface{}) error {
	data, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}
	tmpl, err := template.New(filepath.Base(tmplPath)).Parse(string(data))
	if err != nil {
		return err
	}
	outPath := strings.TrimSuffix(tmplPath, ".tmpl")
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := tmpl.Execute(out, vars); err != nil {
		return err
	}
	return os.Remove(tmplPath)
}

func unusedProxyRoles(proxy string) []string {
	switch proxy {
	case "traefik", "traefik-acme-dns":
		return []string{"nginx"}
	case "nginx":
		return []string{"traefik"}
	default:
		return []string{"traefik", "nginx"}
	}
}

// buildSBOM assembles the merged CycloneDX document.
func buildSBOM(l *lockfile.Lock, work string, sel lockfile.Selection) ([]byte, error) {
	b := sbom.New("cgapp", registry.CLIVersion)

	// Direct materials.
	for _, mat := range l.Materials {
		switch mat.Role {
		case "backend":
			c := sbom.Component{
				Type:       "application",
				BOMRef:     sbom.GitPurl(mat.Source, mat.Commit),
				Name:       repoName(mat.Source),
				Version:    mat.Commit,
				PackageURL: sbom.GitPurl(mat.Source, mat.Commit),
				Properties: []sbom.Property{
					{Name: "cgapp:git-tree-sha1", Value: mat.Tree},
				},
			}
			if v, ok := mat.ObservedDigest["sha256"]; ok {
				c.Hashes = append(c.Hashes, sbom.Hash{Algorithm: "SHA-256", Value: v})
			}
			if mat.License != "" {
				c.Licenses = []sbom.LicenseChoice{{License: &sbom.License{ID: mat.License}}}
			}
			b.Add(c)
		case "frontend-generator":
			c := sbom.Component{
				Type:       "application",
				BOMRef:     "pkg:npm/" + mat.Name + "@" + mat.Version,
				Name:       mat.Name,
				Version:    mat.Version,
				PackageURL: "pkg:npm/" + mat.Name + "@" + mat.Version,
			}
			if v, ok := mat.ObservedDigest["sha512"]; ok {
				c.Hashes = append(c.Hashes, sbom.Hash{Algorithm: "SHA-512", Value: v})
			}
			if mat.License != "" {
				c.Licenses = []sbom.LicenseChoice{{License: &sbom.License{ID: mat.License}}}
			}
			b.Add(c)
		case "ansible-roles", "ansible-templates", "ansible-misc":
			c := sbom.Component{
				Type:       "data",
				BOMRef:     "pkg:generic/create-go-app/" + mat.ID + "@" + mat.Version,
				Name:       mat.Name,
				Version:    mat.Version,
				PackageURL: "pkg:generic/create-go-app/" + mat.ID + "@" + mat.Version,
			}
			if v, ok := mat.ObservedDigest["sha256"]; ok {
				c.Hashes = append(c.Hashes, sbom.Hash{Algorithm: "SHA-256", Value: v})
			}
			if mat.License != "" {
				c.Licenses = []sbom.LicenseChoice{{License: &sbom.License{ID: mat.License}}}
			}
			b.Add(c)
		}
	}

	// Discovered Go modules (present when the template ships a go.sum).
	if mod, err := os.ReadFile(filepath.Join(work, "backend", "go.mod")); err == nil {
		var sums []byte
		if data, err := os.ReadFile(filepath.Join(work, "backend", "go.sum")); err == nil {
			sums = data
		}
		for _, c := range sbom.ParseGoInputs(mod, sums) {
			b.Add(c)
		}
	}

	// Discovered npm dependencies (present if the initializer wrote a lock).
	if lockData, err := os.ReadFile(filepath.Join(work, "frontend", "package-lock.json")); err == nil {
		comps, err := sbom.ParsePackageLock(lockData)
		if err != nil {
			return nil, err
		}
		for _, c := range comps {
			b.Add(c)
		}
	}

	return b.JSON()
}

func repoName(source string) string {
	s := strings.TrimSuffix(source, ".git")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// deliver copies the finished work tree into dst without overwriting.
func deliver(work, dst string) error {
	entries, err := os.ReadDir(work)
	if err != nil {
		return err
	}
	for _, e := range entries {
		target := filepath.Join(dst, e.Name())
		if _, err := os.Lstat(target); err == nil {
			return fmt.Errorf("refusing to overwrite existing %q (move it aside and re-run)", target)
		}
	}
	for _, e := range entries {
		if err := sources.CopyTree(filepath.Join(work, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func loadOrCreateAttestor(keyPath string) (*attestation.Attestor, error) {
	if keyPath != "" {
		return attestation.LoadAttestor(keyPath)
	}
	return attestation.NewEphemeralAttestor()
}

func encodeB64(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

func httpFetch(locator string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(locator)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: http %d", locator, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}
