// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Command signregistry maintains the signed cgapp template registry:
//
//	go run ./hack/signregistry genkey -issuer <name>
//	go run ./hack/signregistry sign   -key hack/cgapp-registry-key.json
//	go run ./hack/signregistry verify
//
// The private key is intentionally kept outside of the repository
// (see .gitignore). In production it must live in an HSM/KMS; the public
// half is the only thing embedded as the root of trust.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/create-go-app/cli/v4/pkg/registry"
	"github.com/create-go-app/cli/v4/pkg/security/dsse"
)

const (
	defaultKeyPath  = "hack/cgapp-registry-key.json"
	defaultRootPath = "pkg/registry/trust/root.json"
	defaultManifest = "pkg/registry/registry.json"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: signregistry genkey|sign|verify [flags]")
	os.Exit(2)
}

func genkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	keyPath := fs.String("key", defaultKeyPath, "output path for the private key file")
	rootPath := fs.String("root", defaultRootPath, "output path for the public trust root")
	issuer := fs.String("issuer", "https://create-go.app/registry/dev", "key issuer label")
	years := fs.Int("valid-years", 5, "public key validity in years")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, priv, err := dsse.GenerateKey()
	if err != nil {
		return err
	}
	kf, err := dsse.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeJSON(*keyPath, 0o600, kf); err != nil {
		return err
	}

	root := &registry.TrustRoot{
		SchemaVersion: "1",
		MediaType:     "application/vnd.cgapp.trust-root.v1+json",
		Keys: []registry.TrustedKey{{
			KeyID:      kf.KeyID,
			KeyType:    dsse.AlgorithmEd25519,
			PublicKey:  kf.PublicKey,
			Issuer:     *issuer,
			Usages:     []string{"registry-sign", "attestor"},
			ValidFrom:  time.Now().UTC().Format(time.RFC3339),
			ValidUntil: time.Now().UTC().AddDate(*years, 0, 0).Format(time.RFC3339),
		}},
	}
	if err := writeJSON(*rootPath, 0o644, root); err != nil {
		return err
	}
	fmt.Printf("wrote private key %s and trust root %s (keyid=%s)\n", *keyPath, *rootPath, kf.KeyID)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", defaultKeyPath, "private key file (KeyFile JSON)")
	manifestPath := fs.String("manifest", defaultManifest, "manifest file to sign in place")
	if err := fs.Parse(args); err != nil {
		return err
	}

	kfRaw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	kf := &dsse.KeyFile{}
	if err := json.Unmarshal(kfRaw, kf); err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	priv, err := dsse.LoadPrivateKey(kf)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	m, err := registry.ParseManifest(raw)
	if err != nil {
		return err
	}
	if err := m.Sign(priv); err != nil {
		return err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(*manifestPath, out, 0o644); err != nil {
		return err
	}
	digest, _ := m.Digest()
	fmt.Printf("signed %s with keyid=%s manifest %s\n", *manifestPath, m.Signature.KeyID, digest)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	rootPath := fs.String("root", defaultRootPath, "trust root file")
	manifestPath := fs.String("manifest", "", "manifest file (empty = embedded default)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root, err := registry.LoadTrustRoot(*rootPath)
	if err != nil {
		return err
	}
	var m *registry.Manifest
	if *manifestPath == "" {
		m, _, err = registry.LoadManifest("")
	} else {
		m, _, err = registry.LoadManifest(*manifestPath)
	}
	if err != nil {
		return err
	}
	if err := m.VerifySignature(root); err != nil {
		return err
	}
	digest, _ := m.Digest()
	fmt.Printf("OK: manifest signature valid (revision=%s, %s, keyid=%s)\n", m.Revision, digest, m.Signature.KeyID)
	return nil
}

func writeJSON(path string, perm os.FileMode, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(fileDir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	return nil
}

func fileDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
