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

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/types"
)

const defaultServerURL = "http://localhost:8080"

func remoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Interact with a melange build server",
		Long:  `Commands for submitting jobs and checking status on a remote melange-server.`,
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
	var pipelineDirs []string
	var backendSelector []string

	cmd := &cobra.Command{
		Use:   "submit <config.yaml>",
		Short: "Submit a build job to the server",
		Long:  `Submit a package configuration file for building on a remote melange-server.`,
		Example: `  # Submit a build job
  melange remote submit mypackage.yaml --server http://localhost:8080

  # Submit and wait for completion
  melange remote submit mypackage.yaml --wait

  # Submit with specific architecture
  melange remote submit mypackage.yaml --arch aarch64

  # Submit with custom pipelines directory
  melange remote submit mypackage.yaml --pipeline-dir ./pipelines

  # Submit with backend selector (requires specific backend labels)
  melange remote submit mypackage.yaml --backend-selector tier=high-memory`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := args[0]

			// Read the config file
			configData, err := os.ReadFile(configPath)
			if err != nil {
				return fmt.Errorf("reading config file: %w", err)
			}

			// Load pipelines from directories
			pipelines, err := loadPipelinesFromDirs(pipelineDirs)
			if err != nil {
				return fmt.Errorf("loading pipelines: %w", err)
			}

			// Parse backend selector
			selector := parseSelector(backendSelector)

			c := client.New(serverURL)

			// Submit the job
			resp, err := c.SubmitJob(cmd.Context(), types.CreateJobRequest{
				ConfigYAML:      string(configData),
				Pipelines:       pipelines,
				Arch:            arch,
				BackendSelector: selector,
				WithTest:        withTest,
				Debug:           debug,
			})
			if err != nil {
				return fmt.Errorf("submitting job: %w", err)
			}

			fmt.Printf("Job submitted: %s\n", resp.ID)
			if len(pipelines) > 0 {
				fmt.Printf("Included %d pipeline(s)\n", len(pipelines))
			}
			if len(selector) > 0 {
				fmt.Printf("Backend selector: %v\n", selector)
			}

			if wait {
				fmt.Println("Waiting for job to complete...")
				job, err := c.WaitForJob(cmd.Context(), resp.ID, 2*time.Second)
				if err != nil {
					return fmt.Errorf("waiting for job: %w", err)
				}
				printJobDetails(job)
				if job.Status == types.JobStatusFailed {
					return fmt.Errorf("job failed: %s", job.Error)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", defaultServerURL, "melange-server URL")
	cmd.Flags().StringVar(&arch, "arch", "", "target architecture (default: server decides)")
	cmd.Flags().BoolVar(&withTest, "test", false, "run tests after build")
	cmd.Flags().BoolVar(&debug, "debug", false, "enable debug logging")
	cmd.Flags().BoolVar(&wait, "wait", false, "wait for job to complete")
	cmd.Flags().StringSliceVar(&pipelineDirs, "pipeline-dir", nil, "directory containing pipeline YAML files (can be specified multiple times)")
	cmd.Flags().StringSliceVar(&backendSelector, "backend-selector", nil, "backend label selector in key=value format (can be specified multiple times)")

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

// loadPipelinesFromDirs reads all YAML files from the given directories and returns
// a map of relative paths to their content.
func loadPipelinesFromDirs(dirs []string) (map[string]string, error) {
	if len(dirs) == 0 {
		return nil, nil
	}

	pipelines := make(map[string]string)
	for _, dir := range dirs {
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
	}

	return pipelines, nil
}

func remoteStatusCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "status <job-id>",
		Short: "Get the status of a build job",
		Long:  `Retrieve the current status and details of a build job.`,
		Example: `  melange remote status job-abc123
  melange remote status job-abc123 --server http://myserver:8080`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID := args[0]

			c := client.New(serverURL)
			job, err := c.GetJob(cmd.Context(), jobID)
			if err != nil {
				return fmt.Errorf("getting job: %w", err)
			}

			printJobDetails(job)
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
		Short: "List all build jobs",
		Long:  `List all build jobs on the server.`,
		Example: `  melange remote list
  melange remote list --server http://myserver:8080`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := client.New(serverURL)
			jobs, err := c.ListJobs(cmd.Context())
			if err != nil {
				return fmt.Errorf("listing jobs: %w", err)
			}

			if len(jobs) == 0 {
				fmt.Println("No jobs found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tCREATED\tARCH")
			for _, job := range jobs {
				arch := job.Spec.Arch
				if arch == "" {
					arch = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					job.ID,
					job.Status,
					job.CreatedAt.Format(time.RFC3339),
					arch,
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
		Use:   "wait <job-id>",
		Short: "Wait for a job to complete",
		Long:  `Wait for a build job to complete, polling the server at regular intervals.`,
		Example: `  melange remote wait job-abc123
  melange remote wait job-abc123 --poll-interval 5s`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jobID := args[0]

			c := client.New(serverURL)
			fmt.Printf("Waiting for job %s...\n", jobID)

			job, err := c.WaitForJob(cmd.Context(), jobID, pollInterval)
			if err != nil {
				return fmt.Errorf("waiting for job: %w", err)
			}

			printJobDetails(job)

			if job.Status == types.JobStatusFailed {
				return fmt.Errorf("job failed: %s", job.Error)
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

func printJobDetails(job *types.Job) {
	fmt.Printf("Job ID:     %s\n", job.ID)
	fmt.Printf("Status:     %s\n", job.Status)
	fmt.Printf("Created:    %s\n", job.CreatedAt.Format(time.RFC3339))

	if job.Spec.Arch != "" {
		fmt.Printf("Arch:       %s\n", job.Spec.Arch)
	}

	if job.Backend != nil {
		fmt.Printf("Backend:    %s (%s)\n", job.Backend.Addr, job.Backend.Arch)
		if len(job.Backend.Labels) > 0 {
			var parts []string
			for k, v := range job.Backend.Labels {
				parts = append(parts, fmt.Sprintf("%s=%s", k, v))
			}
			fmt.Printf("Labels:     %s\n", strings.Join(parts, ", "))
		}
	}

	if job.StartedAt != nil {
		fmt.Printf("Started:    %s\n", job.StartedAt.Format(time.RFC3339))
	}

	if job.FinishedAt != nil {
		fmt.Printf("Finished:   %s\n", job.FinishedAt.Format(time.RFC3339))
		if job.StartedAt != nil {
			duration := job.FinishedAt.Sub(*job.StartedAt)
			fmt.Printf("Duration:   %s\n", duration.Round(time.Second))
		}
	}

	if job.Error != "" {
		fmt.Printf("Error:      %s\n", job.Error)
	}

	if job.LogPath != "" {
		fmt.Printf("Log:        %s\n", job.LogPath)
	}

	if job.OutputPath != "" {
		fmt.Printf("Output:     %s\n", job.OutputPath)
	}
}
