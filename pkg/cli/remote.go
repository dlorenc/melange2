// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/types"
)

const defaultServerURL = "http://localhost:8080"

func remoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Interact with a melange build server",
		Long:  `Commands for submitting builds and checking status on a remote melange-server.`,
	}

	cmd.AddCommand(remoteSubmitCmd())
	cmd.AddCommand(remoteStatusCmd())
	cmd.AddCommand(remoteListCmd())
	cmd.AddCommand(remoteWaitCmd())
	cmd.AddCommand(remoteBackendsCmd())

	return cmd
}

func remoteSubmitCmd() *cobra.Command {
	var serverURL string
	var arch string
	var withTest bool
	var debug bool
	var wait bool
	var backendSelector []string
	var mode string
	// Git source options
	var gitRepo string
	var gitRef string
	var gitPattern string
	var gitPath string

	cmd := &cobra.Command{
		Use:   "submit [config.yaml...]",
		Short: "Submit build(s) to the server",
		Long: `Submit package configuration file(s) for building on a remote melange-server.

Supports three input modes:
1. Single config: melange remote submit config.yaml
2. Multiple configs: melange remote submit pkg1.yaml pkg2.yaml pkg3.yaml
3. Git source: melange remote submit --git-repo https://github.com/org/packages

Build scheduling modes:
- flat (default): Build all packages in parallel without dependency ordering.
  Use this for full rebuilds where dependencies are in external repositories.
- dag: Build packages in dependency order based on environment.contents.packages.
  Note: DAG mode requires incremental APKINDEX support to be fully effective.

Convention-based defaults (automatically included if present):
- Pipelines from ./pipelines/ directory
- Source files from $pkgname/ directory for each package`,
		Example: `  # Submit a single build
  melange remote submit mypackage.yaml --server http://localhost:8080

  # Submit multiple packages (flat mode - all in parallel)
  melange remote submit lib-a.yaml lib-b.yaml app.yaml

  # Submit with DAG-based dependency ordering
  melange remote submit lib-a.yaml lib-b.yaml app.yaml --mode dag

  # Submit from git repository
  melange remote submit --git-repo https://github.com/wolfi-dev/os --git-pattern "*.yaml"

  # Submit and wait for completion
  melange remote submit mypackage.yaml --wait

  # Submit with specific architecture
  melange remote submit mypackage.yaml --arch aarch64

  # Submit with backend selector
  melange remote submit mypackage.yaml --backend-selector tier=high-memory`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Convention: auto-load pipelines from ./pipelines/ if it exists
			pipelines, err := loadPipelinesFromConvention()
			if err != nil {
				return fmt.Errorf("loading pipelines: %w", err)
			}

			// Parse backend selector
			selector := parseSelector(backendSelector)

			// Parse build mode
			var buildMode types.BuildMode
			switch mode {
			case "", "flat":
				buildMode = types.BuildModeFlat
			case "dag":
				buildMode = types.BuildModeDAG
			default:
				return fmt.Errorf("invalid mode %q: must be 'flat' or 'dag'", mode)
			}

			c := client.New(serverURL)

			// Build the request based on input mode
			req := types.CreateBuildRequest{
				Pipelines:       pipelines,
				Arch:            arch,
				BackendSelector: selector,
				WithTest:        withTest,
				Debug:           debug,
				Mode:            buildMode,
			}

			// Determine mode: git source, multi-config, or single config
			switch {
			case gitRepo != "":
				// Git source mode
				req.GitSource = &types.GitSource{
					Repository: gitRepo,
					Ref:        gitRef,
					Pattern:    gitPattern,
					Path:       gitPath,
				}
			case len(args) == 0:
				return fmt.Errorf("no config files specified (use --git-repo for git source)")
			case len(args) == 1:
				// Single config mode
				configData, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("reading config file: %w", err)
				}
				req.ConfigYAML = string(configData)

				// Convention: auto-load source files from $pkgname/ if it exists
				sourceFiles, err := loadSourceFilesFromConvention([]string{args[0]})
				if err != nil {
					return fmt.Errorf("loading source files: %w", err)
				}
				req.SourceFiles = sourceFiles
			default:
				// Multi-config mode
				configs := make([]string, 0, len(args))
				for _, path := range args {
					data, err := os.ReadFile(path)
					if err != nil {
						return fmt.Errorf("reading %s: %w", path, err)
					}
					configs = append(configs, string(data))
				}
				req.Configs = configs

				// Convention: auto-load source files from $pkgname/ for each package
				sourceFiles, err := loadSourceFilesFromConvention(args)
				if err != nil {
					return fmt.Errorf("loading source files: %w", err)
				}
				req.SourceFiles = sourceFiles
			}

			resp, err := c.SubmitBuild(cmd.Context(), req)
			if err != nil {
				return fmt.Errorf("submitting build: %w", err)
			}

			fmt.Printf("Build submitted: %s\n", resp.ID)
			fmt.Printf("Packages (%d): %s\n", len(resp.Packages), strings.Join(resp.Packages, ", "))
			if len(pipelines) > 0 {
				fmt.Printf("Included %d pipeline(s) from ./pipelines/\n", len(pipelines))
			}
			if len(req.SourceFiles) > 0 {
				var pkgCount int
				for range req.SourceFiles {
					pkgCount++
				}
				fmt.Printf("Included source files for %d package(s)\n", pkgCount)
			}

			if wait {
				fmt.Println("Waiting for build to complete...")
				build, err := c.WaitForBuild(cmd.Context(), resp.ID, 2*time.Second)
				if err != nil {
					return fmt.Errorf("waiting for build: %w", err)
				}
				printBuildDetails(build)
				if build.Status == types.BuildStatusFailed {
					return fmt.Errorf("build failed")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().StringVar(&arch, "arch", "", "target architecture (default: server decides)")
	cmd.Flags().BoolVar(&withTest, "test", false, "run tests after build")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for build to complete")
	cmd.Flags().StringSliceVar(&backendSelector, "backend-selector", nil, "backend label selector (key=value)")
	cmd.Flags().StringVar(&mode, "mode", "flat", "build scheduling mode: 'flat' (parallel, no deps) or 'dag' (dependency order)")
	// Git source options
	cmd.Flags().StringVar(&gitRepo, "git-repo", "", "git repository URL for package configs")
	cmd.Flags().StringVar(&gitRef, "git-ref", "", "git ref (branch/tag/commit) to checkout")
	cmd.Flags().StringVar(&gitPattern, "git-pattern", "*.yaml", "glob pattern for config files in git repo")
	cmd.Flags().StringVar(&gitPath, "git-path", "", "subdirectory within git repo to search")

	return cmd
}

// parseSelector parses key=value pairs into a map.
func parseSelector(selectors []string) map[string]string {
	if len(selectors) == 0 {
		return nil
	}
	result := make(map[string]string)
	for _, s := range selectors {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}

// loadPipelinesFromConvention loads pipelines from ./pipelines/ if it exists.
// This implements the convention-based approach where pipelines are automatically
// included from the conventional location.
func loadPipelinesFromConvention() (map[string]string, error) {
	const conventionalPipelineDir = "pipelines"

	// Check if the conventional pipeline directory exists
	info, err := os.Stat(conventionalPipelineDir)
	if os.IsNotExist(err) {
		return nil, nil // No pipelines directory, that's fine
	}
	if err != nil {
		return nil, fmt.Errorf("checking pipelines directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil // Not a directory, skip
	}

	return loadPipelinesFromDir(conventionalPipelineDir)
}

// loadPipelinesFromDir reads all YAML files from a directory and returns
// a map of relative paths to their content.
func loadPipelinesFromDir(dir string) (map[string]string, error) {
	pipelines := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// Only process .yaml files
		if filepath.Ext(path) != ".yaml" {
			return nil
		}

		// Get relative path from the pipeline dir
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}

		// Read the file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		pipelines[relPath] = string(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", dir, err)
	}

	return pipelines, nil
}

// loadSourceFilesFromConvention loads source files for packages using the convention
// that source files are located in a directory named after the package.
// For example, if the config is "curl.yaml" and package name is "curl", it will
// look for source files in ./curl/ directory.
func loadSourceFilesFromConvention(configPaths []string) (map[string]map[string]string, error) {
	sourceFiles := make(map[string]map[string]string)

	for _, configPath := range configPaths {
		// Extract package name from the config file
		pkgName, err := extractPackageName(configPath)
		if err != nil {
			// If we can't extract the package name, skip this config
			continue
		}

		// Check if a directory named after the package exists
		sourceDir := pkgName
		info, err := os.Stat(sourceDir)
		if os.IsNotExist(err) {
			continue // No source directory, that's fine
		}
		if err != nil {
			return nil, fmt.Errorf("checking source directory %s: %w", sourceDir, err)
		}
		if !info.IsDir() {
			continue // Not a directory, skip
		}

		// Load all files from the source directory
		files, err := loadFilesFromDir(sourceDir)
		if err != nil {
			return nil, fmt.Errorf("loading source files from %s: %w", sourceDir, err)
		}

		if len(files) > 0 {
			sourceFiles[pkgName] = files
		}
	}

	if len(sourceFiles) == 0 {
		return nil, nil
	}
	return sourceFiles, nil
}

// extractPackageName extracts the package name from a melange config file.
func extractPackageName(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}

	// Simple YAML parsing to extract package.name
	// We use a minimal struct to avoid importing the full config package
	var cfg struct {
		Package struct {
			Name string `yaml:"name"`
		} `yaml:"package"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}

	if cfg.Package.Name == "" {
		return "", fmt.Errorf("package name not found in %s", configPath)
	}

	return cfg.Package.Name, nil
}

// loadFilesFromDir reads all files from a directory and returns a map of
// relative paths to their content. Skips binary files and very large files.
func loadFilesFromDir(dir string) (map[string]string, error) {
	const maxFileSize = 10 * 1024 * 1024 // 10MB limit per file

	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Get file info for size check
		info, err := d.Info()
		if err != nil {
			return err
		}

		// Skip files that are too large
		if info.Size() > maxFileSize {
			return nil
		}

		// Get relative path from the source dir
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}

		// Read the file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		// Skip binary files (simple heuristic: check for null bytes in first 8KB)
		checkSize := len(content)
		if checkSize > 8192 {
			checkSize = 8192
		}
		for i := 0; i < checkSize; i++ {
			if content[i] == 0 {
				// Likely a binary file, skip
				return nil
			}
		}

		files[relPath] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func remoteStatusCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "status <build-id>",
		Short: "Get the status of a build",
		Long:  `Retrieve the current status and per-package details of a build.`,
		Example: `  melange remote status bld-abc123
  melange remote status bld-abc123 --server http://myserver:8080`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			buildID := args[0]

			c := client.New(serverURL)
			build, err := c.GetBuild(cmd.Context(), buildID)
			if err != nil {
				return fmt.Errorf("getting build: %w", err)
			}

			printBuildDetails(build)
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")

	return cmd
}

func remoteListCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all builds",
		Long:  `List all builds on the server.`,
		Example: `  melange remote list
  melange remote list --server http://myserver:8080`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(serverURL)
			builds, err := c.ListBuilds(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing builds: %w", err)
			}

			if len(builds) == 0 {
				fmt.Println("No builds found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tPACKAGES\tCREATED")
			for _, build := range builds {
				fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
					build.ID,
					build.Status,
					len(build.Packages),
					build.CreatedAt.Format(time.RFC3339),
				)
			}
			w.Flush()

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")

	return cmd
}

func remoteWaitCmd() *cobra.Command {
	var serverURL string
	var pollInterval time.Duration

	cmd := &cobra.Command{
		Use:   "wait <build-id>",
		Short: "Wait for a build to complete",
		Long:  `Wait for a build to complete, polling the server at regular intervals.`,
		Example: `  melange remote wait bld-abc123
  melange remote wait bld-abc123 --poll-interval 5s`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			buildID := args[0]

			c := client.New(serverURL)
			fmt.Printf("Waiting for build %s...\n", buildID)

			build, err := c.WaitForBuild(cmd.Context(), buildID, pollInterval)
			if err != nil {
				return fmt.Errorf("waiting for build: %w", err)
			}

			printBuildDetails(build)

			if build.Status == types.BuildStatusFailed {
				return fmt.Errorf("build failed")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().DurationVar(&pollInterval, "poll-interval", 2*time.Second, "interval between status checks")

	return cmd
}

func remoteBackendsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backends",
		Short: "Manage BuildKit backends",
		Long:  `Commands for listing, adding, and removing BuildKit backends on the server.`,
	}

	cmd.AddCommand(remoteBackendsListCmd())
	cmd.AddCommand(remoteBackendsAddCmd())
	cmd.AddCommand(remoteBackendsRemoveCmd())

	return cmd
}

func remoteBackendsListCmd() *cobra.Command {
	var serverURL string
	var arch string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available BuildKit backends",
		Long:  `List all available BuildKit backends on the server, with their architectures and labels.`,
		Example: `  # List all backends
  melange remote backends list

  # List backends for a specific architecture
  melange remote backends list --arch aarch64`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(serverURL)
			resp, err := c.ListBackends(cmd.Context(), arch)
			if err != nil {
				return fmt.Errorf("listing backends: %w", err)
			}

			if len(resp.Backends) == 0 {
				fmt.Println("No backends found")
				return nil
			}

			fmt.Printf("Available architectures: %v\n\n", resp.Architectures)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ADDR\tARCH\tLABELS")
			for _, b := range resp.Backends {
				labels := "-"
				if len(b.Labels) > 0 {
					var parts []string
					for k, v := range b.Labels {
						parts = append(parts, fmt.Sprintf("%s=%s", k, v))
					}
					labels = strings.Join(parts, ",")
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", b.Addr, b.Arch, labels)
			}
			w.Flush()

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().StringVar(&arch, "arch", "", "filter by architecture")

	return cmd
}

func remoteBackendsAddCmd() *cobra.Command {
	var serverURL string
	var addr string
	var arch string
	var labels []string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new BuildKit backend",
		Long:  `Add a new BuildKit backend to the server's pool.`,
		Example: `  # Add a basic backend
  melange remote backends add --addr tcp://buildkit:1234 --arch x86_64

  # Add a backend with labels
  melange remote backends add --addr tcp://buildkit:1234 --arch aarch64 --label tier=high-memory --label sandbox=privileged`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if addr == "" {
				return fmt.Errorf("--addr is required")
			}
			if arch == "" {
				return fmt.Errorf("--arch is required")
			}

			// Parse labels
			labelMap := parseSelector(labels)

			c := client.New(serverURL)
			backend, err := c.AddBackend(cmd.Context(), buildkit.Backend{
				Addr:   addr,
				Arch:   arch,
				Labels: labelMap,
			})
			if err != nil {
				return fmt.Errorf("adding backend: %w", err)
			}

			fmt.Printf("Added backend: %s (arch: %s)\n", backend.Addr, backend.Arch)
			if len(backend.Labels) > 0 {
				var parts []string
				for k, v := range backend.Labels {
					parts = append(parts, fmt.Sprintf("%s=%s", k, v))
				}
				fmt.Printf("Labels: %s\n", strings.Join(parts, ", "))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().StringVar(&addr, "addr", "", "BuildKit daemon address (e.g., tcp://buildkit:1234)")
	cmd.Flags().StringVar(&arch, "arch", "", "architecture (e.g., x86_64, aarch64)")
	cmd.Flags().StringSliceVar(&labels, "label", nil, "backend label in key=value format (can be specified multiple times)")

	_ = cmd.MarkFlagRequired("addr")
	_ = cmd.MarkFlagRequired("arch")

	return cmd
}

func remoteBackendsRemoveCmd() *cobra.Command {
	var serverURL string
	var addr string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a BuildKit backend",
		Long:  `Remove a BuildKit backend from the server's pool.`,
		Example: `  # Remove a backend by address
  melange remote backends remove --addr tcp://buildkit:1234`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if addr == "" {
				return fmt.Errorf("--addr is required")
			}

			c := client.New(serverURL)
			if err := c.RemoveBackend(cmd.Context(), addr); err != nil {
				return fmt.Errorf("removing backend: %w", err)
			}

			fmt.Printf("Removed backend: %s\n", addr)
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().StringVar(&addr, "addr", "", "BuildKit daemon address to remove")

	_ = cmd.MarkFlagRequired("addr")

	return cmd
}

func printBuildDetails(build *types.Build) {
	fmt.Printf("Build ID:   %s\n", build.ID)
	fmt.Printf("Status:     %s\n", build.Status)
	fmt.Printf("Created:    %s\n", build.CreatedAt.Format(time.RFC3339))

	if build.Spec.Mode != "" {
		fmt.Printf("Mode:       %s\n", build.Spec.Mode)
	}

	if build.Spec.Arch != "" {
		fmt.Printf("Arch:       %s\n", build.Spec.Arch)
	}

	if build.StartedAt != nil {
		fmt.Printf("Started:    %s\n", build.StartedAt.Format(time.RFC3339))
	}

	if build.FinishedAt != nil {
		fmt.Printf("Finished:   %s\n", build.FinishedAt.Format(time.RFC3339))
		if build.StartedAt != nil {
			duration := build.FinishedAt.Sub(*build.StartedAt)
			fmt.Printf("Duration:   %s\n", duration.Round(time.Second))
		}
	}

	fmt.Printf("\nPackages (%d):\n", len(build.Packages))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  NAME\tSTATUS\tDURATION\tERROR")
	for _, pkg := range build.Packages {
		duration := "-"
		if pkg.StartedAt != nil && pkg.FinishedAt != nil {
			duration = pkg.FinishedAt.Sub(*pkg.StartedAt).Round(time.Second).String()
		}
		errStr := pkg.Error
		if len(errStr) > 40 {
			errStr = errStr[:37] + "..."
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
			pkg.Name, pkg.Status, duration, errStr)
	}
	w.Flush()
}
