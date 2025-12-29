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
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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

	return cmd
}

func remoteSubmitCmd() *cobra.Command {
	var serverURL string
	var arch string
	var withTest bool
	var debug bool
	var wait bool

	cmd := &cobra.Command{
		Use:   "submit <config.yaml>",
		Short: "Submit a build job to the server",
		Long:  `Submit a package configuration file for building on a remote melange-server.`,
		Example: `  # Submit a build job
  melange remote submit mypackage.yaml --server http://localhost:8080

  # Submit and wait for completion
  melange remote submit mypackage.yaml --wait

  # Submit with specific architecture
  melange remote submit mypackage.yaml --arch aarch64`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := args[0]

			// Read the config file
			configData, err := os.ReadFile(configPath)
			if err != nil {
				return fmt.Errorf("reading config file: %w", err)
			}

			c := client.New(serverURL)

			// Submit the job
			resp, err := c.SubmitJob(cmd.Context(), types.CreateJobRequest{
				ConfigYAML: string(configData),
				Arch:       arch,
				WithTest:   withTest,
				Debug:      debug,
			})
			if err != nil {
				return fmt.Errorf("submitting job: %w", err)
			}

			fmt.Printf("Job submitted: %s\n", resp.ID)

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

	return cmd
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

func printJobDetails(job *types.Job) {
	fmt.Printf("Job ID:     %s\n", job.ID)
	fmt.Printf("Status:     %s\n", job.Status)
	fmt.Printf("Created:    %s\n", job.CreatedAt.Format(time.RFC3339))

	if job.Spec.Arch != "" {
		fmt.Printf("Arch:       %s\n", job.Spec.Arch)
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
