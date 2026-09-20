// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// GitSpec is a commit-pinned git template from the registry manifest.
type GitSpec struct {
	URL           string
	Commit        string
	Tree          string
	ContentDigest string // "sha256:..." expected working-tree digest (without .git)
	AllowOffline  bool   // reuse cache without fetching
}

// GitResult is the verified local checkout.
type GitResult struct {
	CacheDir      string
	Commit        string
	Tree          string
	ContentDigest string
}

// Errors.
var (
	ErrCommitMismatch = errors.New("sources: HEAD is not the pinned commit")
	ErrTreeMismatch   = errors.New("sources: git tree object is not the pinned tree")
	ErrDigestMismatch = errors.New("sources: content digest mismatch")
)

// AcquireGit clones (or reuses) the template repository in cacheRoot, checks
// out the exact pinned commit and verifies commit, tree object and working
// tree content digest. No branch or tag is ever resolved: only the 40-hex
// SHA from the signed manifest is accepted.
func AcquireGit(cacheRoot string, spec GitSpec) (*GitResult, error) {
	if spec.URL == "" || len(spec.Commit) != 40 || len(spec.Tree) != 40 {
		return nil, fmt.Errorf("sources: incomplete git pin for %q", spec.URL)
	}
	cacheDir := filepath.Join(cacheRoot, "git", cacheKey(spec.URL))

	repo, err := openOrClone(cacheDir, spec)
	if err != nil {
		return nil, err
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("sources: worktree: %w", err)
	}
	if err := wt.Checkout(&git.CheckoutOptions{
		Hash:  plumbing.NewHash(spec.Commit),
		Force: true,
	}); err != nil {
		return nil, fmt.Errorf("sources: checkout %s: %w", spec.Commit, err)
	}

	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	if head.Hash().String() != spec.Commit {
		return nil, fmt.Errorf("%w: got %s", ErrCommitMismatch, head.Hash())
	}
	commitObj, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}
	if commitObj.TreeHash.String() != spec.Tree {
		return nil, fmt.Errorf("%w: got %s want %s", ErrTreeMismatch, commitObj.TreeHash, spec.Tree)
	}

	digest, err := DigestTree(cacheDir, ".git")
	if err != nil {
		return nil, err
	}
	if spec.ContentDigest != "" && digest != spec.ContentDigest {
		return nil, fmt.Errorf("%w: got %s want %s (%s)", ErrDigestMismatch, digest, spec.ContentDigest, spec.URL)
	}

	return &GitResult{
		CacheDir:      cacheDir,
		Commit:        spec.Commit,
		Tree:          spec.Tree,
		ContentDigest: digest,
	}, nil
}

// AcquireGitAtHead is the trust-on-first-use path for custom repositories:
// clone, resolve the remote default branch HEAD, report its exact commit.
func AcquireGitAtHead(cacheRoot, rawURL string) (*GitResult, string, error) {
	cacheDir := filepath.Join(cacheRoot, "git", cacheKey(rawURL))
	repo, err := openOrClone(cacheDir, GitSpec{URL: rawURL, AllowOffline: false})
	if err != nil {
		return nil, "", err
	}
	head, err := repo.Head()
	if err != nil {
		return nil, "", err
	}
	commitObj, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, "", err
	}
	digest, err := DigestTree(cacheDir, ".git")
	if err != nil {
		return nil, "", err
	}
	return &GitResult{
		CacheDir:      cacheDir,
		Commit:        head.Hash().String(),
		Tree:          commitObj.TreeHash.String(),
		ContentDigest: digest,
	}, head.Name().String(), nil
}

func openOrClone(cacheDir string, spec GitSpec) (*git.Repository, error) {
	if _, err := os.Stat(filepath.Join(cacheDir, ".git")); err == nil {
		repo, err := git.PlainOpen(cacheDir)
		if err != nil {
			return nil, err
		}
		if spec.Commit != "" {
			// Verify the pinned object exists; if not, fetch (network stage).
			if _, err := repo.CommitObject(plumbing.NewHash(spec.Commit)); err != nil {
				if spec.AllowOffline {
					return nil, fmt.Errorf("sources: pinned commit missing from offline cache: %w", err)
				}
				if err := repo.Fetch(&git.FetchOptions{
					RemoteName: git.DefaultRemoteName,
					RefSpecs: []config.RefSpec{
						"+refs/heads/*:refs/remotes/origin/*",
						"+refs/tags/*:refs/tags/*",
					},
					Tags: git.AllTags,
				}); err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
					return nil, fmt.Errorf("sources: fetch: %w", err)
				}
			}
		}
		return repo, nil
	}
	if err := os.MkdirAll(filepath.Dir(cacheDir), 0o750); err != nil {
		return nil, err
	}
	repo, err := git.PlainClone(cacheDir, false, &git.CloneOptions{
		URL: absoluteURL(spec.URL),
	})
	if err != nil {
		return nil, fmt.Errorf("sources: clone %q: %w", spec.URL, err)
	}
	return repo, nil
}

// ExportTree copies the verified working tree (without .git) from cacheDir
// into dst. Existing destination content is replaced.
func ExportTree(cacheDir, dst string, stripPaths []string) error {
	skip := map[string]bool{".git": true}
	for _, p := range stripPaths {
		skip[p] = true
	}
	return copyTree(cacheDir, dst, skip)
}

// GitCacheDir returns the deterministic on-disk cache location for a URL.
func GitCacheDir(cacheRoot, rawURL string) string {
	return filepath.Join(cacheRoot, "git", cacheKey(rawURL))
}

func cacheKey(rawURL string) string {
	u := absoluteURL(rawURL)
	sum := sha256.Sum256([]byte(u))
	return hex.EncodeToString(sum[:16])
}

func absoluteURL(templateURL string) string {
	templateURL = strings.TrimSpace(templateURL)
	u, err := url.Parse(templateURL)
	if err != nil || u.Scheme == "" {
		return "https://" + strings.TrimPrefix(templateURL, "https://")
	}
	return u.String()
}
