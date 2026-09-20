// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package policy enforces the manifest's license and toolchain policies.
package policy

import (
	"strings"

	"github.com/create-go-app/cli/v4/pkg/registry"
)

// LicenseDecision is the outcome of evaluating material licenses.
type LicenseDecision struct {
	Allowed bool
	Denied  []string
	Unknown []string
}

// EvaluateLicenses checks every supplied SPDX license id against the
// manifest policy. Empty license strings count as unknown.
func EvaluateLicenses(p registry.LicensePolicy, licenses ...string) LicenseDecision {
	d := LicenseDecision{Allowed: true}
	for _, raw := range licenses {
		id := strings.TrimSpace(raw)
		if id == "" || strings.EqualFold(id, "NOASSERTION") {
			d.Unknown = append(d.Unknown, id)
			continue
		}
		if contains(p.Denied, id) {
			d.Denied = append(d.Denied, id)
			continue
		}
		switch p.Mode {
		case "allowlist":
			if !contains(p.Allowed, id) {
				d.Unknown = append(d.Unknown, id)
			}
		}
	}
	if len(d.Denied) > 0 {
		d.Allowed = false
	}
	if len(d.Unknown) > 0 && !p.AllowUnknown {
		d.Allowed = false
	}
	return d
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
