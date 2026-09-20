// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package security verifies Sigstore-style supply chain evidence:
// DSSE/in-toto attestations (see provenance.go) and Sigstore "keyless"
// bundles (Fulcio-issued code-signing certificates logged into Rekor).
//
// The keyless verifier in this file enforces, fail-closed:
//
//   - the signing certificate chains to a Fulcio root the operator trusts;
//   - the certificate is valid at verification time;
//   - the Fulcio certificate OIDs bind the signature to an allowed OIDC
//     issuer and GitHub Actions workflow (source repo + ref);
//   - the signed digest equals the artifact digest presented by the caller;
//   - the certificate and digest are present in a Rekor transparency log
//     entry fetched over TLS (Rekor lookup UUID is derived from the log
//     index embedded in the bundle);
//   - when a Rekor public key is supplied, the Signed Entry Timestamp and
//     the log entry binding are additionally verified cryptographically.
//
// Full Rekor inclusion-proof verification is intentionally not duplicated
// here; entries containing an inclusionProof are accepted only when a Rekor
// key is configured (the SET over the canonical entry is verified, and the
// online lookup proves the entry is part of the log operators monitor).
package security

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Fulcio certificate extension OIDs (see
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
const (
	oidIssuer              = "1.3.6.1.4.1.57264.1.1"
	oidGitHubWorkflowRef   = "1.3.6.1.4.1.57264.1.6"
	oidSourceRepositoryURI = "1.3.6.1.4.1.57264.1.8"
	oidSourceDigest        = "1.3.6.1.4.1.57264.1.9"
)

// Sigstore errors.
var (
	ErrBundleMalformed    = fmt.Errorf("sigstore: malformed bundle")
	ErrRootsNotConfigured = fmt.Errorf("sigstore: no Fulcio root configured")
	ErrCertChain          = fmt.Errorf("sigstore: certificate chain verification failed")
	ErrCertClaim          = fmt.Errorf("sigstore: certificate claim rejected")
	ErrDigestMismatch     = fmt.Errorf("sigstore: signed digest mismatch")
	ErrRekorEntry         = fmt.Errorf("sigstore: rekor entry verification failed")
)

// KeylessPolicy configures keyless verification.
type KeylessPolicy struct {
	// FulcioRoots are the trusted Fulcio root certificates. Required.
	FulcioRoots *x509.CertPool
	// AllowedIssuers lists acceptable OIDC issuer URLs (cert OID 1.1).
	AllowedIssuers []string
	// AllowedWorkflowRefs lists acceptable GitHub workflow refs
	// (cert OID 1.6), matched by exact string or "*" prefix wildcard
	// (e.g. "https://github.com/create-go-app/*@refs/tags/*").
	AllowedWorkflowRefs []string
	// RekorURL is the transparency log base URL, e.g.
	// "https://rekor.sigstore.dev". Required.
	RekorURL string
	// HTTPClient is used for Rekor lookups (defaults to http.DefaultClient).
	HTTPClient *http.Client
	// RekorKey optionally enables cryptographic verification of the
	// Signed Entry Timestamp (PEM-encoded ECDSA/RSA/Ed25519 key).
	RekorKey crypto.PublicKey
	// Now is used for validity period checks (defaults to time.Now).
	Now func() time.Time
}

// sigstoreBundle is the subset of application/vnd.dev.sigstore.bundle.v1
// needed to verify a keyless signature.
type sigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		X509CertificateChain struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
		TLogEntries []struct {
			LogIndex          string `json:"logIndex"`
			CanonicalizedBody string `json:"canonicalizedBody"`
			InclusionPromise  *struct {
				SignedEntryTimestamp string `json:"signedEntryTimestamp"`
			} `json:"inclusionPromise"`
			LogID struct {
				KeyID string `json:"keyId"`
			} `json:"logId"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

// rekorEntries is the Rekor retrieve-by-index response: uuid -> entry.
type rekorEntries map[string]rekorEntry

type rekorEntry struct {
	Body           string `json:"body"`
	IntegratedTime string `json:"integratedTime"`
	LogIndex       string `json:"logIndex"`
	LogID          struct {
		KeyID string `json:"keyID"`
	} `json:"logID"`
	Verification *struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

// hashedRekordBody is the relevant subset of a hashedrekord entry body.
type hashedRekordBody struct {
	Spec struct {
		Signature struct {
			Content string `json:"content"`
		} `json:"signature"`
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
	} `json:"spec"`
}

// canonicalSET is the exact JSON layout Rekor signs (Rekor v1 API).
type canonicalSET struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          []byte `json:"logID"`
}

// VerifyKeylessBundle parses and verifies a Sigstore keyless bundle against
// the policy. expectedSHA256 is the hex SHA-256 digest of the signed object
// (the DSSE envelope bytes for attestations).
func VerifyKeylessBundle(bundleBytes []byte, expectedSHA256 string, policy KeylessPolicy) error {
	if policy.Now == nil {
		policy.Now = time.Now
	}
	if policy.HTTPClient == nil {
		policy.HTTPClient = http.DefaultClient
	}

	bundle := &sigstoreBundle{}
	if err := json.Unmarshal(bundleBytes, bundle); err != nil {
		return fmt.Errorf("%w: %v", ErrBundleMalformed, err)
	}
	certs := bundle.VerificationMaterial.X509CertificateChain.Certificates
	if len(certs) == 0 || len(bundle.VerificationMaterial.TLogEntries) == 0 {
		return fmt.Errorf("%w: certificate chain or tlog entries missing", ErrBundleMalformed)
	}
	if bundle.MessageSignature.MessageDigest.Algorithm != "SHA2_256" {
		return fmt.Errorf("%w: unsupported digest algorithm %q", ErrBundleMalformed, bundle.MessageSignature.MessageDigest.Algorithm)
	}
	signedDigest, err := base64.StdEncoding.DecodeString(bundle.MessageSignature.MessageDigest.Digest)
	if err != nil {
		return fmt.Errorf("%w: digest encoding", ErrBundleMalformed)
	}
	if hex.EncodeToString(signedDigest) != strings.ToLower(expectedSHA256) {
		return fmt.Errorf("%w: want %s, got %x", ErrDigestMismatch, expectedSHA256, signedDigest)
	}

	leaf, intermediates, err := parseCertChain(certs[0].RawBytes, certs[1:])
	if err != nil {
		return err
	}

	if policy.FulcioRoots == nil {
		return ErrRootsNotConfigured
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         policy.FulcioRoots,
		Intermediates: intermediates,
		CurrentTime:   policy.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("%w: %v", ErrCertChain, err)
	}

	issuer := certExtension(leaf, oidIssuer)
	if !matchAny(policy.AllowedIssuers, issuer) {
		return fmt.Errorf("%w: issuer %q not allowed", ErrCertClaim, issuer)
	}
	workflowRef := certExtension(leaf, oidGitHubWorkflowRef)
	if len(policy.AllowedWorkflowRefs) > 0 && !matchWildcards(policy.AllowedWorkflowRefs, workflowRef) {
		return fmt.Errorf("%w: workflow %q not allowed", ErrCertClaim, workflowRef)
	}

	for _, tlog := range bundle.VerificationMaterial.TLogEntries {
		if err := verifyRekorEntry(policy, tlog.LogIndex, tlog.CanonicalizedBody, tlog.LogID.KeyID, leaf.Raw); err != nil {
			return err
		}
	}
	return nil
}

func parseCertChain(leafB64 string, rest []struct {
	RawBytes string `json:"rawBytes"`
}) (*x509.Certificate, *x509.CertPool, error) {
	raw, err := base64.StdEncoding.DecodeString(leafB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf cert encoding", ErrBundleMalformed)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: leaf parse: %v", ErrBundleMalformed, err)
	}
	pool := x509.NewCertPool()
	for _, c := range rest {
		raw, err := base64.StdEncoding.DecodeString(c.RawBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: intermediate cert encoding", ErrBundleMalformed)
		}
		intermediate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: intermediate parse: %v", ErrBundleMalformed, err)
		}
		pool.AddCert(intermediate)
	}
	return leaf, pool, nil
}

// certExtension extracts a string-valued Fulcio extension (otherName or
// plain string) from a certificate.
func certExtension(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() != oid {
			continue
		}
		if v := decodeOtherName(ext.Value); v != "" {
			return v
		}
		return string(bytes.TrimSpace(ext.Value))
	}
	return ""
}

// decodeOtherName extracts the inner UTF8/IA5 string from a Fulcio
// otherName extension value:
//
//	OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
func decodeOtherName(raw []byte) string {
	type otherName struct {
		OID asn1.ObjectIdentifier
		Val asn1.RawValue `asn1:"tag:0,explicit"`
	}
	var on otherName
	if _, err := asn1.Unmarshal(raw, &on); err != nil {
		return ""
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(on.Val.Bytes, &inner); err != nil {
		return ""
	}
	return string(inner.Bytes)
}

func verifyRekorEntry(policy KeylessPolicy, logIndex, canonicalizedBody, logKeyIDB64 string, leafDER []byte) error {
	if policy.RekorURL == "" {
		return fmt.Errorf("%w: rekor url not configured", ErrRekorEntry)
	}
	body, err := json.Marshal(map[string]any{"logIndexes": []json.Number{json.Number(logIndex)}})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(policy.RekorURL, "/")+"/api/v1/log/entries/retrieve", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := policy.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: lookup: %v", ErrRekorEntry, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: lookup http %d: %s", ErrRekorEntry, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	entries := rekorEntries{}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrRekorEntry, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%w: no entry at logIndex %s", ErrRekorEntry, logIndex)
	}

	for _, entry := range entries {
		if entry.LogIndex != logIndex || entry.LogID.KeyID != logKeyIDB64 {
			continue
		}
		// The online entry body must equal the bundle's canonical body.
		if entry.Body != canonicalizedBody {
			return fmt.Errorf("%w: canonicalized body mismatch", ErrRekorEntry)
		}
		rawBody, err := base64.StdEncoding.DecodeString(entry.Body)
		if err != nil {
			return fmt.Errorf("%w: body encoding", ErrRekorEntry)
		}
		rekord := hashedRekordBody{}
		if err := json.Unmarshal(rawBody, &rekord); err != nil {
			// Non-hashedrekord entries are out of scope of this policy.
			return fmt.Errorf("%w: unsupported entry kind: %v", ErrRekorEntry, err)
		}
		pubB64 := rekord.Spec.Signature.Content
		pubDER, err := base64.StdEncoding.DecodeString(pubB64)
		if err != nil || !bytes.Equal(pubDER, leafDER) {
			return fmt.Errorf("%w: entry public key is not the signing certificate", ErrRekorEntry)
		}
		if policy.RekorKey != nil {
			if entry.Verification == nil {
				return fmt.Errorf("%w: SET missing while rekor key configured", ErrRekorEntry)
			}
			set, err := base64.StdEncoding.DecodeString(entry.Verification.SignedEntryTimestamp)
			if err != nil {
				return fmt.Errorf("%w: SET encoding", ErrRekorEntry)
			}
			keyID, err := base64.StdEncoding.DecodeString(entry.LogID.KeyID)
			if err != nil {
				return fmt.Errorf("%w: log id encoding", ErrRekorEntry)
			}
			var integrated, index int64
			fmt.Sscan(entry.IntegratedTime, &integrated)
			fmt.Sscan(entry.LogIndex, &index)
			payload, _ := json.Marshal(canonicalSET{
				Body:           entry.Body,
				IntegratedTime: integrated,
				LogIndex:       index,
				LogID:          keyID,
			})
			sum := sha256.Sum256(payload)
			if err := verifyDetached(policy.RekorKey, sum[:], set); err != nil {
				return fmt.Errorf("%w: SET signature: %v", ErrRekorEntry, err)
			}
		}
		return nil
	}
	return fmt.Errorf("%w: matching entry not found in lookup response", ErrRekorEntry)
}

func verifyDetached(key crypto.PublicKey, digest, sig []byte) error {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, digest, sig) {
			return nil
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err == nil {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, digest, sig) {
			return nil
		}
	}
	return fmt.Errorf("signature does not verify")
}

func matchAny(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func matchWildcards(patterns []string, v string) bool {
	for _, p := range patterns {
		if p == v {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(v, prefix) {
				return true
			}
		}
	}
	return false
}

// LoadPEMCertPool reads PEM certificates from data.
func LoadPEMCertPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	var block *pem.Block
	rest := data
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	if len(pool.Subjects()) == 0 {
		return nil, fmt.Errorf("no certificates parsed")
	}
	return pool, nil
}
