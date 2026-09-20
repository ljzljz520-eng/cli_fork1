// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package policy

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Version is a parsed semantic-ish version (major.minor.patch, prerelease
// ignored).
type Version struct {
	Major, Minor, Patch int
}

// ParseVersion extracts the first x.y.z numeric triple from s, tolerating
// prefixes like "go", "v", "ansible [core " and trailing pre-release text.
func ParseVersion(s string) (Version, bool) {
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	nums := [3]int{}
	for i := 1; i <= 3; i++ {
		n, _ := strconv.Atoi(m[i])
		nums[i-1] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}, true
}

// Compare returns -1/0/1 comparing two versions.
func (v Version) Compare(other Version) int {
	switch {
	case v.Major != other.Major:
		if v.Major > other.Major {
			return 1
		}
		return -1
	case v.Minor != other.Minor:
		if v.Minor > other.Minor {
			return 1
		}
		return -1
	case v.Patch != other.Patch:
		if v.Patch > other.Patch {
			return 1
		}
		return -1
	}
	return 0
}

// Satisfies reports whether version satisfies a constraint expression:
//
//	<constraint>   := <or-group> ( "||" <or-group> )*
//	<or-group>     := <comparator> ( whitespace <comparator> )*
//	<comparator>   := <op><version> | <version> | "^"<version> | "~"<version>
//
// "^1.2.3" means >=1.2.0 <2.0.0 (or >=0.x rules), "~1.2.3" means >=1.2.3
// <1.3.0. Whitespace-separated comparators are AND-combined.
func Satisfies(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || constraint == "*" {
		return true
	}
	v, ok := ParseVersion(version)
	if !ok {
		return false
	}
	for _, group := range strings.Split(constraint, "||") {
		if satisfiesAND(v, strings.TrimSpace(group)) {
			return true
		}
	}
	return false
}

func satisfiesAND(v Version, group string) bool {
	if group == "" {
		return false
	}
	for _, part := range strings.Fields(group) {
		if !satisfiesOne(v, part) {
			return false
		}
	}
	return true
}

func satisfiesOne(v Version, c string) bool {
	switch {
	case strings.HasPrefix(c, "^"):
		base, ok := ParseVersion(c[1:])
		if !ok {
			return false
		}
		return caretRange(v, base)
	case strings.HasPrefix(c, "~"):
		base, ok := ParseVersion(c[1:])
		if !ok {
			return false
		}
		return v.Compare(base) >= 0 && v.Major == base.Major && v.Minor == base.Minor
	case strings.HasPrefix(c, ">="):
		return cmpParsed(v, c[2:]) >= 0
	case strings.HasPrefix(c, "<="):
		return cmpParsed(v, c[2:]) <= 0
	case strings.HasPrefix(c, ">"):
		return cmpParsed(v, c[1:]) > 0
	case strings.HasPrefix(c, "<"):
		return cmpParsed(v, c[1:]) < 0
	case strings.HasPrefix(c, "="):
		return cmpParsed(v, c[1:]) == 0
	default:
		return cmpParsed(v, c) == 0
	}
}

func cmpParsed(v Version, s string) int {
	base, ok := ParseVersion(strings.TrimSpace(s))
	if !ok {
		return -2
	}
	return v.Compare(base)
}

// caretRange implements npm/semver caret semantics.
func caretRange(v, base Version) bool {
	if v.Compare(base) < 0 {
		return false
	}
	switch {
	case base.Major > 0:
		return v.Major == base.Major
	case base.Minor > 0:
		return v.Major == 0 && v.Minor == base.Minor
	default:
		return v.Major == 0 && v.Minor == 0 && v.Patch == base.Patch
	}
}

// Tool describes a probed local tool.
type Tool struct {
	Name    string
	Version string
	Found   bool
}

// Probe detects installed go, node and ansible versions. Missing tools are
// returned with Found=false rather than an error so callers can aggregate
// all violations before failing.
func Probe(ctx context.Context) map[string]Tool {
	out := map[string]Tool{}
	if v, err := exec.CommandContext(ctx, "go", "version").CombinedOutput(); err == nil {
		out["go"] = Tool{Name: "go", Version: string(v), Found: true}
	} else {
		out["go"] = Tool{Name: "go"}
	}
	if v, err := exec.CommandContext(ctx, "node", "--version").CombinedOutput(); err == nil {
		out["node"] = Tool{Name: "node", Version: strings.TrimSpace(string(v)), Found: true}
	} else {
		out["node"] = Tool{Name: "node"}
	}
	if v, err := exec.CommandContext(ctx, "ansible", "--version").CombinedOutput(); err == nil {
		out["ansible"] = Tool{Name: "ansible", Version: firstLine(v), Found: true}
	} else {
		out["ansible"] = Tool{Name: "ansible"}
	}
	return out
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// Check validates the lock's toolchain constraints against probed tools.
// The returned violations are human readable; an empty slice means success.
func Check(tools map[string]Tool, goConstraint, nodeConstraint, ansibleConstraint string) []string {
	var violations []string
	check := func(name, constraint string, needed bool) {
		if constraint == "" {
			return
		}
		tool := tools[name]
		if !needed {
			return
		}
		if !tool.Found {
			violations = append(violations, fmt.Sprintf("%s is required (%s) but was not found in PATH", name, constraint))
			return
		}
		if !Satisfies(tool.Version, constraint) {
			violations = append(violations, fmt.Sprintf("%s version %q does not satisfy %s", name, tool.Version, constraint))
		}
	}
	check("go", goConstraint, true)
	check("node", nodeConstraint, nodeConstraint != "")
	check("ansible", ansibleConstraint, true)
	return violations
}
