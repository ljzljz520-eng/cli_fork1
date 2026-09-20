// Copyright 2023 Vic Shóstak and Create Go App Contributors. All rights reserved.
// Use of this source code is governed by Apache 2.0 license
// that can be found in the LICENSE file.

package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"github.com/create-go-app/cli/v4/pkg/cgapp"
	"github.com/create-go-app/cli/v4/pkg/lockfile"
	"github.com/create-go-app/cli/v4/pkg/pipeline"
	"github.com/create-go-app/cli/v4/pkg/registry"
)

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.Flags().BoolVarP(
		&useCustomTemplate,
		"template", "t", false,
		"enables to use custom backend and frontend templates",
	)
	createCmd.Flags().StringVarP(&manifestLocator, "manifest", "m", "",
		"signed registry manifest (embedded default; local path or https URL)")
	createCmd.Flags().StringVarP(&trustRootPath, "trust-root", "", "",
		"override the embedded root of trust (Ed25519 keys JSON)")
	createCmd.Flags().StringVarP(&lockPath, "lock", "l", "cgapp.lock",
		"output path of the resolved, digest-pinned lock file")
	createCmd.Flags().BoolVar(&offlineMode, "offline", false,
		"refuse network fetches; require a warm local cache")
	createCmd.Flags().BoolVar(&strictSandbox, "strict-sandbox", false,
		"fail when OS-level sandboxing (seatbelt/bubblewrap) is unavailable")
	createCmd.Flags().BoolVar(&noSandbox, "no-sandbox", false,
		"disable OS-level sandboxing (scratch-dir/env isolation still applies)")
}

var (
	manifestLocator string
	trustRootPath   string
	lockPath        string
	offlineMode     bool
	strictSandbox   bool
	noSandbox       bool
)

// createCmd represents the `create` command.
var createCmd = &cobra.Command{
	Use:     "create",
	Aliases: []string{"new"},
	Short:   "Create a new project via interactive UI",
	Long:    "\nCreate a new project via interactive UI.",
	RunE:    runCreateCmd,
}

// runCreateCmd represents runner for the `create` command.
func runCreateCmd(cmd *cobra.Command, args []string) error {
	// Start message.
	cgapp.ShowMessage(
		"",
		fmt.Sprintf(
			"Create a new project via Create Go App CLI v%v...",
			registry.CLIVersion,
		),
		true, true,
	)

	// Start survey.
	var sel lockfile.Selection
	if useCustomTemplate {
		// Custom survey.
		if err := survey.Ask(
			registry.CustomCreateQuestions,
			&customCreateAnswers,
			survey.WithIcons(surveyIconsConfig),
		); err != nil {
			return cgapp.ShowError(err.Error())
		}
		sel = lockfile.Selection{
			Custom:   true,
			Backend:  customCreateAnswers.Backend,
			Frontend: customCreateAnswers.Frontend,
			Proxy:    customCreateAnswers.Proxy,
		}
	} else {
		// Default survey.
		if err := survey.Ask(
			registry.CreateQuestions,
			&createAnswers,
			survey.WithIcons(surveyIconsConfig),
		); err != nil {
			return cgapp.ShowError(err.Error())
		}
		sel = lockfile.Selection{
			Backend:  createAnswers.Backend,
			Frontend: createAnswers.Frontend,
			Proxy:    createAnswers.Proxy,
		}
	}

	// Catch the cancel action (hit "n" in the last question).
	if (!createAnswers.AgreeCreation && !useCustomTemplate) || (!customCreateAnswers.AgreeCreation && useCustomTemplate) {
		cgapp.ShowMessage(
			"",
			"Oh no! You said \"no\", so I won't create anything. Hope to see you soon!",
			true, true,
		)
		return nil
	}

	// Start timer.
	startTimer := time.Now()

	report, err := pipeline.Create(context.Background(), sel, pipeline.Options{
		ManifestLocator:    manifestLocator,
		TrustRootPath:      trustRootPath,
		LockPath:           filepathBase(lockPath),
		CacheRoot:          os.Getenv("CGAPP_CACHE_DIR"),
		Offline:            offlineMode,
		Strict:             strictSandbox,
		NoOSSandbox:        noSandbox,
		AttestationKeyPath: os.Getenv("CGAPP_ATTESTATION_KEY"),
	})
	if err != nil {
		return cgapp.ShowError(err.Error())
	}

	for _, w := range report.Warnings {
		cgapp.ShowMessage("info", "warning: "+w, false, false)
	}

	cgapp.ShowMessage("success",
		fmt.Sprintf("Backend was created with template `%v`!", sel.Backend), true, false)
	if sel.Frontend != "" && sel.Frontend != "none" {
		label := sel.Frontend
		if report.Lock.Selection.RequestedFrontend != "" {
			label = fmt.Sprintf("%s (resolved alias -> %s)", report.Lock.Selection.RequestedFrontend, sel.Frontend)
		}
		cgapp.ShowMessage("success",
			fmt.Sprintf("Frontend was created with pinned generator `%v`!", label), false, false)
	}
	if sel.Proxy != "none" {
		cgapp.ShowMessage("success",
			fmt.Sprintf("Web/Proxy server configuration for `%v` was created!", sel.Proxy), false, false)
	}

	// Stop timer.
	stopTimer := cgapp.CalculateDurationTime(startTimer)
	cgapp.ShowMessage("info",
		fmt.Sprintf("Completed in %v seconds!", stopTimer), true, false)

	cgapp.ShowMessage("success",
		fmt.Sprintf("Supply chain artifacts: %s, %s, %s",
			report.LockPath, report.SBOMPath, report.AttestationPath),
		false, false)
	cgapp.ShowMessage("info",
		fmt.Sprintf("Output digest: %s (verified materials: %d, sandbox: %s)",
			report.OutputDigest, report.VerifiedMaterials, sandboxLabel(report.OSConfinement)),
		false, true)

	// Ending messages.
	cgapp.ShowMessage(
		"",
		"* Please put credentials into the Ansible inventory file (`hosts.ini`) before you start deploying a project!",
		false, false,
	)
	cgapp.ShowMessage(
		"",
		"* Frontend dependencies are not installed (offline sandbox); run `npm install` in ./frontend when ready.",
		false, false,
	)
	cgapp.ShowMessage(
		"",
		"* Commit cgapp.lock to your repository: it pins every input for reproducible, verifiable re-runs.",
		false, false,
	)
	cgapp.ShowMessage(
		"",
		"* A helpful documentation and next steps with your project is here https://github.com/create-go-app/cli/wiki",
		false, true,
	)
	cgapp.ShowMessage("", "Have a happy new project! :)", false, true)

	return nil
}

// filepathBase keeps the lock inside the project directory even when an
// absolute -l path is passed (delivery always targets cwd).
func filepathBase(p string) string {
	if p == "" {
		return "cgapp.lock"
	}
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func sandboxLabel(s string) string {
	if s == "" {
		return "dir+env"
	}
	return s
}
