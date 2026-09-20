// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/create-go-app/cli/v4/pkg/registry"
)

func loadManifest(t *testing.T) *registry.Manifest {
	t.Helper()
	m, err := func() (*registry.Manifest, error) {
		mm, _, e := registry.LoadManifest("")
		return mm, e
	}()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func findMat(l *Lock, role string) *Material {
	for i := range l.Materials {
		if l.Materials[i].Role == role {
			return &l.Materials[i]
		}
	}
	return nil
}

func TestResolvePinsAllMaterials(t *testing.T) {
	m := loadManifest(t)
	l, err := Resolve(m, Selection{Backend: "fiber", Frontend: "react-ts", Proxy: "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	be := findMat(l, "backend")
	if be == nil || be.Commit == "" || be.Tree == "" {
		t.Fatal("backend not fully pinned")
	}
	if be.ExpectedDigest["sha256"] == "" || be.ExpectedDigest["git-tree-sha1"] == "" {
		t.Fatal("backend expected digests missing")
	}
	fe := findMat(l, "frontend-generator")
	if fe == nil || fe.Name != "create-vite" || fe.Version == "" {
		t.Fatalf("frontend generator not pinned: %+v", fe)
	}
	if !strings.HasPrefix(fe.ExpectedDigest["sha512"], "sha512-") {
		t.Fatal("npm integrity pin missing")
	}
	if len(l.Materials) < 4 {
		t.Fatalf("expected backend+npm+3 embedded, got %d materials", len(l.Materials))
	}
	if l.Toolchains.Go == "" || l.Toolchains.Node == "" || l.Toolchains.Ansible == "" {
		t.Fatalf("toolchain snapshot incomplete: %+v", l.Toolchains)
	}
	if l.Manifest.Digest == "" || l.Manifest.SignatureKeyID == "" {
		t.Fatal("manifest reference not recorded")
	}
}

func TestResolveFollowsAlias(t *testing.T) {
	m := loadManifest(t)
	l, err := Resolve(m, Selection{Backend: "fiber", Frontend: "react-swc-ts", Proxy: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Selection.Frontend != "react-ts" {
		t.Fatalf("alias not resolved: %q", l.Selection.Frontend)
	}
	if l.Selection.RequestedFrontend != "react-swc-ts" {
		t.Fatalf("requested frontend not recorded: %q", l.Selection.RequestedFrontend)
	}
	fe := findMat(l, "frontend-generator")
	if fe == nil || fe.Name != "create-vite" {
		t.Fatalf("unexpected generator after alias: %+v", fe)
	}
}

func TestResolveRejectsRetiredAndUnknown(t *testing.T) {
	m := loadManifest(t)
	if _, err := Resolve(m, Selection{Backend: "fiber", Frontend: "sveltekit"}); err == nil {
		t.Fatal("expected error for retired frontend")
	}
	if _, err := Resolve(m, Selection{Backend: "does-not-exist"}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestWriteReadRoundtripAndTamper(t *testing.T) {
	m := loadManifest(t)
	l, err := Resolve(m, Selection{Backend: "chi", Frontend: "none", Proxy: "none"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "cgapp.lock")
	if err := l.Write(p); err != nil {
		t.Fatal(err)
	}
	if l.Digest == "" {
		t.Fatal("Write did not set digest")
	}
	got, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Manifest.Digest != l.Manifest.Digest {
		t.Fatal("roundtrip changed manifest digest")
	}

	// Tamper with the file: self-digest must detect it.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytesReplace(raw, "\"chi\"", "\"fiber\""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Fatal("tampered lock accepted")
	}
}

func TestMatches(t *testing.T) {
	m := loadManifest(t)
	l, err := Resolve(m, Selection{Backend: "fiber", Frontend: "react-ts", Proxy: "traefik"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := m.Digest()
	if !l.Matches(Selection{Backend: "fiber", Frontend: "react-ts", Proxy: "traefik"}, d) {
		t.Fatal("identical selection should match")
	}
	if l.Matches(Selection{Backend: "fiber", Frontend: "vue-ts", Proxy: "traefik"}, d) {
		t.Fatal("different frontend must not match")
	}
}

func bytesReplace(raw []byte, old, new string) []byte {
	return []byte(strings.Replace(string(raw), old, new, 1))
}
