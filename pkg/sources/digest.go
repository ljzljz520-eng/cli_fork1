// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tree digest encoding (v1). Every regular file and symbolic link in the
// tree is encoded, sorted by its slash-separated relative path, into one
// SHA-256 hash:
//
//	relpath NUL kind NUL decimal-byte-length NUL content NUL
//
// kind is "file" (content = bytes) or "symlink" (content = target string).
// Directories contribute no bytes; their existence is implied by paths.
// The encoding is unambiguous and independent of inode metadata, mtimes and
// filesystem ordering, which makes the digest reproducible across machines.

const treeDigestVersion = "cgapp-tree-v1"

type treeEntry struct {
	path    string
	kind    string
	content []byte
}

// DigestTree returns "sha256:<hex>" of an on-disk tree. Directories named in
// skipDirs (matched by base name) are excluded; ".git" is skipped by default.
func DigestTree(root string, skipDirs ...string) (string, error) {
	skip := map[string]bool{".git": true}
	for _, d := range skipDirs {
		skip[d] = true
	}
	entries := []treeEntry{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if d.IsDir() && skip[d.Name()] {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entries = append(entries, treeEntry{rel, "symlink", []byte(target)})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			// Skip sockets/devices/etc.
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		entries = append(entries, treeEntry{rel, "file", data})
		return nil
	})
	if err != nil {
		return "", err
	}
	return encodeTree(entries), nil
}

// DigestFS returns the tree digest of an fs.FS subtree.
func DigestFS(fsys fs.FS, root string) (string, error) {
	entries := []treeEntry{}
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			// Embedded/FS inputs in this project contain no symlinks.
			return nil
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		entries = append(entries, treeEntry{path: filepath.ToSlash(path), kind: "file", content: data})
		return nil
	})
	if err != nil {
		return "", err
	}
	return encodeTree(entries), nil
}

// DigestFSRel returns the tree digest of an fs.FS subtree using paths
// relative to root (so digesting embed.FS root "roles" yields entries named
// "backend/tasks/main.yml", matching an on-disk digest of that directory).
func DigestFSRel(fsys fs.FS, root string) (string, error) {
	entries := []treeEntry{}
	prefix := root
	if root != "." && root != "" {
		prefix = root + "/"
	}
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(path, prefix)
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		entries = append(entries, treeEntry{path: filepath.ToSlash(rel), kind: "file", content: data})
		return nil
	})
	if err != nil {
		return "", err
	}
	return encodeTree(entries), nil
}

// DigestFile returns the sha256 of a single file.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func encodeTree(entries []treeEntry) string {
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00", treeDigestVersion, len(entries))
	for _, e := range entries {
		h.Write([]byte(e.path))
		h.Write([]byte{0})
		h.Write([]byte(e.kind))
		h.Write([]byte{0})
		h.Write([]byte(fmt.Sprintf("%d", len(e.content))))
		h.Write([]byte{0})
		h.Write(e.content)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
