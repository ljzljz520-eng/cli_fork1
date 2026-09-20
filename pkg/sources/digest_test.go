// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sources

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDigestTreeDeterministic(t *testing.T) {
	files := map[string]string{
		"a.txt":            "alpha",
		"dir/b.txt":        "beta",
		"dir/nested/c.txt": "gamma",
		".git/HEAD":        "ref: refs/heads/main",
		"README.md":        "# demo",
	}
	d1 := digestFixture(t, files, nil)
	d2 := digestFixture(t, files, nil)
	if d1 != d2 {
		t.Fatalf("digest not deterministic: %s != %s", d1, d2)
	}

	// Content change changes digest.
	changed := map[string]string{}
	for k, v := range files {
		changed[k] = v
	}
	changed["a.txt"] = "ALPHA"
	if d3 := digestFixture(t, changed, nil); d3 == d1 {
		t.Fatal("digest unchanged after content modification")
	}

	// Default .git exclusion: same digest whether .git exists or not.
	noGit := map[string]string{
		"a.txt":            "alpha",
		"dir/b.txt":        "beta",
		"dir/nested/c.txt": "gamma",
		"README.md":        "# demo",
	}
	if d4 := digestFixture(t, noGit, nil); d4 != d1 {
		t.Fatalf("default .git exclusion failed: %s != %s", d4, d1)
	}

	// Explicit skip list also works.
	withSkip := digestFixture(t, map[string]string{
		"a.txt":    "alpha",
		"vendor/v": "x",
	}, []string{"vendor"})
	without := digestFixture(t, map[string]string{
		"a.txt": "alpha",
	}, nil)
	if withSkip != without {
		t.Fatalf("skipDirs not honored: %s != %s", withSkip, without)
	}
}

func TestDigestTreeSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.txt": "hello"})
	if err := os.Symlink("a.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	d1, err := DigestTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Retargeting the symlink must change the digest (links are entries).
	if err := os.Remove(filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README.md", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	d2, err := DigestTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("symlink target change not detected")
	}
}

func digestFixture(t *testing.T, files map[string]string, skip []string) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
	d, err := DigestTree(dir, skip...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
