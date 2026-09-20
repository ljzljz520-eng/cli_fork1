// Copyright 2026 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

// Package sandbox executes build steps in isolation:
//
//   - a private per-run root directory (work/home/tmp), never the user's cwd;
//   - an environment rebuilt from a tiny allowlist (HOME/TMPDIR/npm config
//     are redirected into the root, inherited secrets are dropped);
//   - a two-stage network policy: fetch may talk to the network, build
//     denies it (npm runs --offline, git is already in cache);
//   - on macOS a Seatbelt (sandbox-exec) profile confines writes to the
//     scratch roots, on Linux bubblewrap is used when available, else the
//     run fails in strict mode.
package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Stage selects the network policy for a command.
type Stage string

const (
	// StageFetch may use the network (cloning, tarball/cache warm-up).
	StageFetch Stage = "fetch"
	// StageBuild is fully offline and used to materialize the project.
	StageBuild Stage = "build"
)

// ErrNoOSSandbox indicates OS-level confinement is unavailable.
var ErrNoOSSandbox = errors.New("sandbox: no OS confinement backend available (install sandbox-exec/bubblewrap or disable strict mode)")

// Options configures sandbox preparation.
type Options struct {
	// BaseDir hosts the per-run root (defaults to os.TempDir()).
	BaseDir string
	// CacheRoot is the persistent, scratch-bound cache for git/npm.
	CacheRoot string
	// Strict fails when OS-level confinement is unavailable.
	Strict bool
	// DisableOS turns off the OS sandbox (dir/env isolation remains).
	DisableOS bool
	// Stdout receives streamed child output (defaults to os.Stdout).
	Stdout io.Writer
}

// Sandbox is a prepared isolated execution environment.
type Sandbox struct {
	Root      string
	Home      string
	Work      string
	Tmp       string
	Cache     string
	Strict    bool
	DisableOS bool
	useOS     bool
	osKind    string
	stdout    io.Writer
}

// Prepare creates the sandbox layout.
func Prepare(opts Options) (*Sandbox, error) {
	base := opts.BaseDir
	if base == "" {
		base = os.TempDir()
	}
	cache := opts.CacheRoot
	if cache == "" {
		cache = filepath.Join(os.TempDir(), "cgapp-cache")
	}
	root, err := os.MkdirTemp(base, ".cgapp-work-*")
	if err != nil {
		return nil, err
	}
	// Resolve symlinks: on macOS /var -> /private/var, and Seatbelt
	// evaluates write-subpath policies against the real path.
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	if real, err := filepath.EvalSymlinks(cache); err == nil {
		cache = real
	}
	s := &Sandbox{
		Root:      root,
		Home:      filepath.Join(root, "home"),
		Work:      filepath.Join(root, "work"),
		Tmp:       filepath.Join(root, "tmp"),
		Cache:     cache,
		Strict:    opts.Strict,
		DisableOS: opts.DisableOS,
		stdout:    opts.Stdout,
	}
	if s.stdout == nil {
		s.stdout = os.Stdout
	}
	for _, d := range []string{s.Home, s.Work, s.Tmp, filepath.Join(cache, "npm"), filepath.Join(cache, "git")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
	}
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			s.useOS, s.osKind = true, "seatbelt"
		}
	case "linux":
		if _, err := exec.LookPath("bwrap"); err == nil {
			s.useOS, s.osKind = true, "bubblewrap"
		}
	}
	if opts.Strict && !s.useOS {
		_ = os.RemoveAll(root)
		return nil, ErrNoOSSandbox
	}
	return s, nil
}

// OSConfinement reports whether OS-level sandboxing is active ("" if not).
func (s *Sandbox) OSConfinement() string {
	if s.useOS {
		return s.osKind
	}
	return ""
}

// Run executes name with args in the sandbox for the given stage.
func (s *Sandbox) Run(ctx context.Context, stage Stage, dir string, name string, args ...string) error {
	return s.RunOpts(ctx, RunOpts{Stage: stage, Dir: dir, Name: name, Args: args})
}

// RunOpts are options for Run.
type RunOpts struct {
	Stage  Stage
	Dir    string
	Name   string
	Args   []string
	Silent bool
}

// RunOpts executes a command with explicit options.
func (s *Sandbox) RunOpts(ctx context.Context, opts RunOpts) error {
	if opts.Dir == "" {
		opts.Dir = s.Work
	}
	if _, err := os.Stat(opts.Dir); err != nil {
		return fmt.Errorf("sandbox: work dir: %w", err)
	}
	bin := opts.Name
	cmdArgs := opts.Args
	if s.useOS && !s.DisableOS {
		switch s.osKind {
		case "seatbelt":
			bin = "/usr/bin/sandbox-exec"
			cmdArgs = append([]string{"-p", s.seatbeltProfile(opts.Stage)}, opts.Name)
			cmdArgs = append(cmdArgs, opts.Args...)
		case "bubblewrap":
			bin = "bwrap"
			cmdArgs = append(s.bwrapArgs(opts.Stage), opts.Name)
			cmdArgs = append(cmdArgs, opts.Args...)
		}
	}
	cmd := exec.CommandContext(ctx, bin, cmdArgs...) // #nosec G204 -- args come from pinned manifest
	cmd.Dir = opts.Dir
	cmd.Env = s.env(opts.Stage)
	cmd.Stderr = s.stdout
	if opts.Silent {
		cmd.Stdout = nil
	} else {
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			fmt.Fprintln(s.stdout, scanner.Text())
		}
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("sandbox: %s %s: %w", opts.Name, strings.Join(opts.Args, " "), err)
		}
		return nil
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sandbox: %s %s: %w", opts.Name, strings.Join(opts.Args, " "), err)
	}
	return nil
}

// Cleanup removes the per-run root. The shared cache is intentionally kept.
func (s *Sandbox) Cleanup() error {
	return os.RemoveAll(s.Root)
}

// env builds the scrubbed process environment.
func (s *Sandbox) env(stage Stage) []string {
	env := []string{
		"HOME=" + s.Home,
		"TMPDIR=" + s.Tmp,
		"TEMP=" + s.Tmp,
		"TMP=" + s.Tmp,
		"XDG_CONFIG_HOME=" + filepath.Join(s.Home, ".config"),
		"XDG_CACHE_HOME=" + s.Cache,
		"CI=true",
		// Git: never prompt, never use interactive credential managers.
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
		"GIT_CONFIG_NOSYSTEM=1",
		// npm: redirected cache, non-interactive, no audit/fund noise.
		"npm_config_cache=" + filepath.Join(s.Cache, "npm"),
		"npm_config_update_notifier=false",
		"npm_config_fund=false",
		"npm_config_audit=false",
		// Ansible.
		"ANSIBLE_NOCOWS=1",
	}
	if stage == StageBuild {
		env = append(env, "npm_config_offline=true", "npm_config_prefer_offline=true")
	}
	// Minimal inherited variables needed to locate binaries and locales.
	for _, key := range []string{"PATH", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME"} {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	return env
}

// seatbeltProfile returns the macOS Seatbelt profile for the stage.
func (s *Sandbox) seatbeltProfile(stage Stage) string {
	var b strings.Builder
	b.WriteString("(version 1)(deny default)")
	b.WriteString("(allow process*)(allow process-info*)")
	b.WriteString("(allow signal (target self))")
	b.WriteString("(allow sysctl-read)(allow system-info)(allow mach*)(allow ipc*)")
	b.WriteString("(allow file-read* (subpath \"/\"))")
	for _, d := range []string{s.Root, s.Cache} {
		fmt.Fprintf(&b, "(allow file-write* (subpath %q))", d)
	}
	b.WriteString(`(allow file-write* (literal "/dev/null")(literal "/dev/stdout")(literal "/dev/stderr")(literal "/dev/tty")(literal "/dev/dtracehelper"))`)
	if stage == StageFetch {
		b.WriteString("(allow network*)")
	}
	return b.String()
}

// bwrapArgs returns the bubblewrap arguments for the stage.
func (s *Sandbox) bwrapArgs(stage Stage) []string {
	args := []string{
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", s.Root, s.Root,
		"--bind", s.Cache, s.Cache,
		"--die-with-parent",
	}
	if stage == StageBuild {
		args = append(args, "--unshare-net")
	}
	return args
}
