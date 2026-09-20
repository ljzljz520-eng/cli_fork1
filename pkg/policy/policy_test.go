// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package policy

import (
	"testing"

	"github.com/create-go-app/cli/v4/pkg/registry"
)

func TestSatisfies(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"1.24.0", "^1.20.0", true},
		{"2.0.0", "^1.20.0", false},
		{"1.24.5", "~1.24.0", true},
		{"1.25.0", "~1.24.0", false},
		{"1.24.0", ">=1.21.0", true},
		{"1.20.0", ">=1.21.0", false},
		{"1.24.0", ">=1.21.0 <2.0.0", true},
		{"2.1.0", ">=1.21.0 <2.0.0", false},
		{"20.19.0", "^20.19.0 || >=22.12.0", true},
		{"22.12.0", "^20.19.0 || >=22.12.0", true},
		{"21.0.0", "^20.19.0 || >=22.12.0", false},
		// Versions must be complete x.y.z triples; "1.24" fails closed.
		{"1.24", "^1.24.0", false},
	}
	for _, c := range cases {
		if got := Satisfies(c.version, c.constraint); got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v, want %v", c.version, c.constraint, got, c.want)
		}
	}
}

func TestParseVersionRejectsGarbage(t *testing.T) {
	if _, ok := ParseVersion(""); ok {
		t.Fatal("empty string should not parse")
	}
	if _, ok := ParseVersion("not-a-version"); ok {
		t.Fatal("garbage should not parse")
	}
	v, ok := ParseVersion("go version go1.24.1 darwin/arm64")
	if !ok || v.Major != 1 || v.Minor != 24 || v.Patch != 1 {
		t.Fatalf("did not extract version: %+v ok=%v", v, ok)
	}
}

func TestEvaluateLicensesAllowlist(t *testing.T) {
	p := registry.LicensePolicy{
		Mode:         "allowlist",
		Allowed:      []string{"Apache-2.0", "MIT", "ISC"},
		Denied:       []string{"GPL-3.0"},
		AllowUnknown: false,
	}
	d := EvaluateLicenses(p, "Apache-2.0", "MIT")
	if !d.Allowed {
		t.Fatal("permitted licenses rejected")
	}
	d = EvaluateLicenses(p, "Apache-2.0", "GPL-3.0")
	if d.Allowed || len(d.Denied) != 1 {
		t.Fatalf("denied license accepted: %+v", d)
	}
	d = EvaluateLicenses(p, "Apache-2.0", "WTFPL")
	if d.Allowed || len(d.Unknown) != 1 {
		t.Fatalf("unknown license should fail closed: %+v", d)
	}
	p.AllowUnknown = true
	d = EvaluateLicenses(p, "WTFPL")
	if !d.Allowed {
		t.Fatal("AllowUnknown should admit non-denied licenses")
	}
}

func TestEvaluateLicensesDenylist(t *testing.T) {
	p := registry.LicensePolicy{
		Mode:   "denylist",
		Denied: []string{"GPL-3.0"},
	}
	d := EvaluateLicenses(p, "Apache-2.0", "WTFPL")
	if !d.Allowed {
		t.Fatal("denylist mode should admit non-denied licenses")
	}
	d = EvaluateLicenses(p, "GPL-3.0")
	if d.Allowed {
		t.Fatal("denylist must reject denied license")
	}
}
