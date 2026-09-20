// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sources

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// NpmSpec is an integrity-pinned npm initializer from the manifest.
type NpmSpec struct {
	Registry  string // https://registry.npmjs.org
	Name      string // create-vite (scoped names like "@scope/pkg" allowed)
	Version   string // 9.2.1 (exact, never "latest")
	Tarball   string
	Integrity string // sha512-<base64>
}

// NpmResult is the independently verified tarball.
type NpmResult struct {
	TarballPath string
	SHA512Hex   string
	License     string
	Bin         map[string]string
}

var (
	// ErrNpmIntegrity is returned on registry/local tarball digest mismatch.
	ErrNpmIntegrity = errors.New("sources: npm integrity mismatch")
)

type npmPackumentVersion struct {
	Dist struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
	} `json:"dist"`
	License string          `json:"license"`
	Bin     json.RawMessage `json:"bin"`
}

// FetchNpm downloads the pinned npm tarball into cacheRoot and verifies its
// sha512 integrity independently of npm itself. A cached copy is reused when
// it already verifies; it is never trusted on name alone.
func FetchNpm(ctx context.Context, client *http.Client, cacheRoot string, spec NpmSpec) (*NpmResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	want, err := ParseIntegrity(spec.Integrity)
	if err != nil {
		return nil, err
	}

	local := filepath.Join(cacheRoot, "npm", tarballFileName(spec.Name, spec.Version))
	if digest, ok := fileSHA512(local); ok && digest == want.hex {
		return &NpmResult{TarballPath: local, SHA512Hex: digest}, nil
	}

	docURL, err := packumentURL(spec.Registry, spec.Name, spec.Version)
	if err != nil {
		return nil, err
	}
	doc := npmPackumentVersion{}
	if err := getJSON(ctx, client, docURL, &doc); err != nil {
		return nil, err
	}
	if doc.Dist.Integrity != spec.Integrity {
		return nil, fmt.Errorf("%w: registry now publishes %s for %s@%s, pin requires %s",
			ErrNpmIntegrity, doc.Dist.Integrity, spec.Name, spec.Version, spec.Integrity)
	}
	tarball := spec.Tarball
	if tarball == "" {
		tarball = doc.Dist.Tarball
	}
	if tarball == "" {
		return nil, fmt.Errorf("sources: no tarball url for %s@%s", spec.Name, spec.Version)
	}

	if err := os.MkdirAll(filepath.Dir(local), 0o750); err != nil {
		return nil, err
	}
	if err := download(ctx, client, tarball, local); err != nil {
		return nil, err
	}
	got, ok := fileSHA512(local)
	if !ok || got != want.hex {
		return nil, fmt.Errorf("%w: downloaded %s@%s digest %s, want %s",
			ErrNpmIntegrity, spec.Name, spec.Version, got, want.hex)
	}

	res := &NpmResult{TarballPath: local, SHA512Hex: got, License: doc.License}
	_ = json.Unmarshal(doc.Bin, &res.Bin)
	return res, nil
}

// IntegrityValue is a parsed npm "alg-base64" integrity string.
type IntegrityValue struct {
	alg string
	b64 string
	hex string
}

// ParseIntegrity decodes an npm subresource-integrity value ("sha512-b64").
func ParseIntegrity(integrity string) (IntegrityValue, error) {
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 || parts[0] != "sha512" {
		return IntegrityValue{}, fmt.Errorf("sources: unsupported integrity %q (only sha512)", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || sha512.Size != len(raw) {
		return IntegrityValue{}, fmt.Errorf("sources: malformed integrity %q", integrity)
	}
	return IntegrityValue{alg: parts[0], b64: parts[1], hex: hex.EncodeToString(raw)}, nil
}

// NpmCacheAddArgs pre-populates an npm cache directory with the pinned
// package (executed in the network-enabled fetch stage).
func NpmCacheAddArgs(spec NpmSpec) []string {
	return []string{"cache", "add", spec.Name + "@" + spec.Version}
}

// NpmExecArgs builds the offline, fully pinned npm invocation executed in
// the network-denied build stage:
//
//	npm exec --yes --offline --package name@version -- bin args...
func NpmExecArgs(spec NpmSpec, bin string, args []string) []string {
	out := []string{"exec", "--yes", "--offline", "--package", spec.Name + "@" + spec.Version, "--"}
	out = append(out, bin)
	out = append(out, args...)
	return out
}

func packumentURL(registry, name, version string) (string, error) {
	base := strings.TrimRight(registry, "/")
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, name, version)
	return u.String(), nil
}

func tarballFileName(name, version string) string {
	flat := strings.ReplaceAll(name, "/", "__")
	return flat + "-" + version + ".tgz"
}

func fileSHA512(p string) (string, bool) {
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: http %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

func download(ctx context.Context, client *http.Client, u, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: http %d", u, resp.StatusCode)
	}
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(resp.Body, 512<<20)); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
