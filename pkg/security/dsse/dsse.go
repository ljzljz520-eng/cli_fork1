// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package dsse implements the Dead Simple Signing Envelope format
// (https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
// with Ed25519 signatures. DSSE is the envelope format used by in-toto
// attestations and by Sigstore ("cosign attest --key").
package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// PayloadTypeInTotoV1 is the DSSE payload type for in-toto statements.
	PayloadTypeInTotoV1 = "application/vnd.in-toto+json"

	// AlgorithmEd25519 is the signature algorithm identifier for Ed25519.
	AlgorithmEd25519 = "ed25519"
)

var (
	// ErrNoValidSignature is returned when none of the envelope signatures
	// match a trusted key.
	ErrNoValidSignature = errors.New("dsse: no valid signature from a trusted key")
	// ErrKeyNotFound is returned when the required key id is absent.
	ErrKeyNotFound = errors.New("dsse: signing key not found")
)

// Signature is a single signature on the DSSE envelope payload.
type Signature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
}

// Envelope is a DSSE signing envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// PAE returns the DSSE "Pre-Authentication Encoding" of the payload type
// and body: "DSSEv1" SP len(type) type SP len(body) body ...
func PAE(payloadType string, body []byte) []byte {
	var buf []byte
	buf = append(buf, "DSSEv1"...)
	buf = append(buf, ' ')
	buf = append(buf, fmt.Sprintf("%d", len(payloadType))...)
	buf = append(buf, ' ')
	buf = append(buf, payloadType...)
	buf = append(buf, ' ')
	buf = append(buf, fmt.Sprintf("%d", len(body))...)
	buf = append(buf, ' ')
	buf = append(buf, body...)
	return buf
}

// Sign wraps payload of payloadType into a signed DSSE envelope.
func Sign(signer ed25519.PrivateKey, keyID, payloadType string, payload []byte) (*Envelope, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("dsse: invalid ed25519 private key size: %d", len(signer))
	}
	sig, err := signer.Sign(rand.Reader, PAE(payloadType, payload), &ed25519.Options{})
	if err != nil {
		return nil, fmt.Errorf("dsse: sign: %w", err)
	}
	return &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID:     keyID,
			Signature: base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

// Verify checks the envelope signatures against trustedKeys (keyid -> key),
// decodes the payload and returns it. At least one signature must be valid.
func Verify(env *Envelope, trustedKeys map[string]ed25519.PublicKey) ([]byte, error) {
	if env == nil {
		return nil, errors.New("dsse: nil envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("dsse: decode payload: %w", err)
	}
	pae := PAE(env.PayloadType, payload)
	for _, sig := range env.Signatures {
		key, ok := trustedKeys[sig.KeyID]
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			continue
		}
		if ed25519.Verify(key, pae, raw) {
			return payload, nil
		}
	}
	return nil, ErrNoValidSignature
}

// MarshalCanonical returns the compact canonical JSON form of v.
func MarshalCanonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

// KeyID derives the stable key identifier "sha256-hex" of an Ed25519 key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// KeyFile is the on-disk JSON representation of an Ed25519 key pair.
// Private key is PKCS#8 DER, base64 standard encoded.
type KeyFile struct {
	KeyType    string `json:"keyType"`
	KeyID      string `json:"keyid"`
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey,omitempty"`
}

// GenerateKey creates a new Ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalPrivateKey serializes a private key into the KeyFile JSON form.
func MarshalPrivateKey(priv ed25519.PrivateKey) (*KeyFile, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("dsse: marshal private key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("dsse: public key is not ed25519")
	}
	return &KeyFile{
		KeyType:    AlgorithmEd25519,
		KeyID:      KeyID(pub),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(der),
	}, nil
}

// LoadPrivateKey reads a private key from a KeyFile.
func LoadPrivateKey(kf *KeyFile) (ed25519.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("dsse: decode private key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("dsse: parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("dsse: stored key is not ed25519")
	}
	return priv, nil
}

// LoadPublicKey decodes a base64 raw Ed25519 public key.
func LoadPublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("dsse: decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dsse: invalid ed25519 public key size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// EncodePublicKeyPEM returns the PEM (SPKI) form of a public key, useful for
// interop with cosign's "cosign public-key --key key.pub".
func EncodePublicKeyPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
