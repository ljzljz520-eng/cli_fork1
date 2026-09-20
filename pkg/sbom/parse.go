// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sbom

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// packageLock is the subset of an npm package-lock.json (v2/v3) consumed.
type packageLock struct {
	Name     string                    `json:"name"`
	Version  string                    `json:"version"`
	Packages map[string]packageLockPkg `json:"packages"`
}

type packageLockPkg struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	License   string `json:"license"`
	Dev       bool   `json:"dev"`
	Link      bool   `json:"link"`
}

// ParsePackageLock extracts components from an npm package-lock.json.
func ParsePackageLock(data []byte) ([]Component, error) {
	lock := packageLock{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&lock); err != nil {
		return nil, err
	}
	var out []Component
	for path, pkg := range lock.Packages {
		if path == "" {
			// The generated application itself.
			if lock.Name != "" {
				out = append(out, Component{
					Type:       "application",
					BOMRef:     "generated:frontend:" + lock.Name,
					Name:       lock.Name,
					Version:    lock.Version,
					PackageURL: "pkg:npm/" + npmEscaped(lock.Name) + "@" + lock.Version,
				})
			}
			continue
		}
		if pkg.Link || pkg.Version == "" || strings.Contains(path, "node_modules/.") {
			continue
		}
		name := npmNameFromPath(path)
		if name == "" {
			continue
		}
		c := Component{
			Type:       "library",
			BOMRef:     "pkg:npm/" + npmEscaped(name) + "@" + pkg.Version,
			Name:       name,
			Version:    pkg.Version,
			PackageURL: "pkg:npm/" + npmEscaped(name) + "@" + pkg.Version,
		}
		if h, ok := NpmIntegrityToHash(pkg.Integrity); ok {
			c.Hashes = []Hash{h}
		}
		if pkg.License != "" {
			c.Licenses = []LicenseChoice{{License: &License{ID: pkg.License}}}
		}
		if pkg.Dev {
			c.Properties = []Property{{Name: "cgapp:dev", Value: "true"}}
		}
		out = append(out, c)
	}
	return out, nil
}

// npmNameFromPath resolves a package-lock packages key to its package name:
// "node_modules/a/node_modules/@scope/b" -> "@scope/b".
func npmNameFromPath(p string) string {
	idx := strings.LastIndex(p, "node_modules/")
	if idx < 0 {
		return ""
	}
	return p[idx+len("node_modules/"):]
}

func npmEscaped(name string) string {
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 {
		return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	}
	return url.PathEscape(name)
}

type goSumHash struct {
	h1 string
}

// ParseGoInputs extracts Go module components from go.mod requirements and
// go.sum hashes. hashes from go.sum (the h1: directory hash) are attached
// as properties because they are not standard file digests.
func ParseGoInputs(goMod, goSum []byte) []Component {
	hashes := map[string]goSumHash{}
	scanner := bufio.NewScanner(bytes.NewReader(goSum))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		path, version, hash := fields[0], fields[1], fields[2]
		if strings.HasPrefix(hash, "h1:") {
			h := hashes[path+"@"+version]
			h.h1 = strings.TrimPrefix(hash, "h1:")
			hashes[path+"@"+version] = h
		}
	}

	var out []Component
	seen := map[string]bool{}
	for module := range goRequireLines(goMod) {
		id := module.path + "@" + module.version
		if seen[id] {
			continue
		}
		seen[id] = true
		c := Component{
			Type:       "library",
			BOMRef:     "pkg:golang/" + module.path + "@" + module.version,
			Name:       module.path,
			Version:    module.version,
			PackageURL: "pkg:golang/" + module.path + "@" + module.version,
		}
		if h, ok := hashes[id]; ok && h.h1 != "" {
			c.Properties = []Property{{Name: "cgapp:go.sum:h1", Value: h.h1}}
		}
		out = append(out, c)
	}
	return out
}

type goModule struct{ path, version string }

// goRequireLines returns every module in require blocks (including the
// single-line form), skipping "// indirect" comments are kept (the lock
// records all modules needed for reproducible builds).
func goRequireLines(goMod []byte) func(func(goModule) bool) {
	lines := strings.Split(string(goMod), "\n")
	var mods []goModule
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inBlock = true
			continue
		case inBlock && trimmed == ")":
			inBlock = false
			continue
		case strings.HasPrefix(trimmed, "require "):
			mods = append(mods, parseGoModule(strings.TrimPrefix(trimmed, "require ")))
			continue
		case inBlock:
			mods = append(mods, parseGoModule(trimmed))
		}
	}
	return func(yield func(goModule) bool) {
		for _, m := range mods {
			if m.path != "" && m.version != "" {
				if !yield(m) {
					return
				}
			}
		}
	}
}

func parseGoModule(s string) goModule {
	s = strings.SplitN(s, "//", 2)[0]
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) < 2 {
		return goModule{}
	}
	return goModule{path: fields[0], version: strings.TrimSuffix(fields[1], "//")}
}
