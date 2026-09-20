// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sources

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyTreeSingleFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "cgapp.lock")
	if err := os.WriteFile(src, []byte("locked"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "out", "cgapp.lock")
	if err := CopyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "locked" {
		t.Fatalf("content = %q", got)
	}
}

func TestCopyTreeDirectoryKeepsFiles(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"a.txt": "a", "sub/b.txt": "b"})
	dst := filepath.Join(t.TempDir(), "dst")
	if err := CopyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a.txt", "sub/b.txt"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}
