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

// Package api provides the HTTP API server for the melange service.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/dlorenc/melange2/pkg/service/dag"
	svcerrors "github.com/dlorenc/melange2/pkg/service/errors"
	"github.com/dlorenc/melange2/pkg/service/git"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
	"github.com/dlorenc/melange2/pkg/service/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"
)

// Server is the HTTP API server.
// In Phase 4+ microservices deployment, the API server only handles build/package
// state management. Backend management is handled by the orchestrator.
type Server struct {
	buildStore store.BuildStore
	mux        *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(buildStore store.BuildStore) *Server {
	s := &Server{
		buildStore: buildStore,
		mux:        http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/api/v1/builds", s.handleBuilds)
	s.mux.HandleFunc("/api/v1/builds/active", s.handleActiveBuilds)
	s.mux.HandleFunc("/api/v1/builds/", s.handleBuild)
	s.mux.HandleFunc("/healthz", s.handleHealth)
}

// BuildMetricsResponse is the response body for the build metrics endpoint.
type BuildMetricsResponse struct {
	BuildID       string                 `json:"build_id"`
	TotalDuration string                 `json:"total_duration"`
	Packages      []PackageMetricsSummary `json:"packages"`
	Summary       MetricsSummary         `json:"summary"`
}

// PackageMetricsSummary contains metrics for a single package.
type PackageMetricsSummary struct {
	Name              string `json:"name"`
	Status            string `json:"status"`
	TotalDuration     string `json:"total_duration,omitempty"`
	SetupDuration     string `json:"setup_duration,omitempty"`
	BackendWait       string `json:"backend_wait,omitempty"`
	InitDuration      string `json:"init_duration,omitempty"`
	BuildKitDuration  string `json:"buildkit_duration,omitempty"`
	StorageSyncDuration string `json:"storage_sync_duration,omitempty"`
	ApkoDuration      string `json:"apko_duration,omitempty"`
	ApkoCacheHit      bool   `json:"apko_cache_hit,omitempty"`
	ApkoLayerCount    int    `json:"apko_layer_count,omitempty"`
}

// MetricsSummary contains aggregate metrics for a build.
type MetricsSummary struct {
	AvgTotal      string `json:"avg_total"`
	AvgBuildKit   string `json:"avg_buildkit"`
	AvgApko       string `json:"avg_apko"`
	P50Total      string `json:"p50_total"`
	P95Total      string `json:"p95_total"`
	P99Total      string `json:"p99_total"`
	TotalPackages int    `json:"total_packages"`
	Completed     int    `json:"completed"`
	Failed        int    `json:"failed"`
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// MaxBodySize is the maximum allowed request body size (10MB).
const MaxBodySize = 10 << 20

// handleBuilds handles POST /api/v1/builds (create build) and GET /api/v1/builds (list builds).
func (s *Server) handleBuilds(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createBuild(w, r)
	case http.MethodGet:
		s.listBuilds(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBuild handles routes under /api/v1/builds/:id
// - GET /api/v1/builds/:id - get build details
// - PUT /api/v1/builds/:id - update build status
// - GET /api/v1/builds/:id/metrics - get build metrics
// - POST /api/v1/builds/:id/packages/claim - claim any ready package
// - POST /api/v1/builds/:id/packages/:name/claim - claim a specific package
// - PUT /api/v1/builds/:id/packages/:name - update package status
func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/builds/
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/builds/")
	if path == "" {
		http.Error(w, "build ID required", http.StatusBadRequest)
		return
	}

	// Check for package-level routes: /api/v1/builds/:id/packages[/:name][/claim]
	if strings.Contains(path, "/packages") {
		s.handlePackageRoute(w, r, path)
		return
	}

	// Check if this is a metrics request
	if strings.HasSuffix(path, "/metrics") {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		buildID := strings.TrimSuffix(path, "/metrics")
		s.handleBuildMetrics(w, r, buildID)
		return
	}

	// Build-level routes: GET (get) or PUT (update)
	switch r.Method {
	case http.MethodGet:
		build, err := s.buildStore.GetBuild(r.Context(), path)
		if err != nil {
			if errors.Is(err, svcerrors.ErrBuildNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(build)

	case http.MethodPut:
		s.handleUpdateBuild(w, r, path)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBuildMetrics returns detailed metrics for a build.
// GET /api/v1/builds/:id/metrics
func (s *Server) handleBuildMetrics(w http.ResponseWriter, r *http.Request, buildID string) {
	build, err := s.buildStore.GetBuild(r.Context(), buildID)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Collect metrics from all packages
	packages := make([]PackageMetricsSummary, 0, len(build.Packages))
	var totalDurations []int64
	var buildkitDurations []int64
	var apkoDurations []int64
	completed := 0
	failed := 0

	for _, pkg := range build.Packages {
		summary := PackageMetricsSummary{
			Name:   pkg.Name,
			Status: string(pkg.Status),
		}

		if pkg.Status == types.PackageStatusSuccess {
			completed++
		} else if pkg.Status == types.PackageStatusFailed {
			failed++
		}

		if pkg.Metrics != nil {
			summary.TotalDuration = formatDuration(pkg.Metrics.TotalDurationMs)
			summary.SetupDuration = formatDuration(pkg.Metrics.SetupDurationMs)
			summary.BackendWait = formatDuration(pkg.Metrics.BackendWaitMs)
			summary.InitDuration = formatDuration(pkg.Metrics.InitDurationMs)
			summary.BuildKitDuration = formatDuration(pkg.Metrics.BuildKitDurationMs)
			summary.StorageSyncDuration = formatDuration(pkg.Metrics.StorageSyncMs)
			summary.ApkoDuration = formatDuration(pkg.Metrics.ApkoDurationMs)
			summary.ApkoCacheHit = pkg.Metrics.ApkoCacheHit
			summary.ApkoLayerCount = pkg.Metrics.ApkoLayerCount

			totalDurations = append(totalDurations, pkg.Metrics.TotalDurationMs)
			buildkitDurations = append(buildkitDurations, pkg.Metrics.BuildKitDurationMs)
			if pkg.Metrics.ApkoDurationMs > 0 {
				apkoDurations = append(apkoDurations, pkg.Metrics.ApkoDurationMs)
			}
		} else if pkg.StartedAt != nil && pkg.FinishedAt != nil {
			// Calculate from timestamps if metrics not available
			duration := pkg.FinishedAt.Sub(*pkg.StartedAt)
			summary.TotalDuration = duration.String()
			totalDurations = append(totalDurations, duration.Milliseconds())
		}

		packages = append(packages, summary)
	}

	// Calculate summary statistics
	var totalDuration string
	if build.StartedAt != nil && build.FinishedAt != nil {
		totalDuration = build.FinishedAt.Sub(*build.StartedAt).String()
	} else if build.StartedAt != nil {
		totalDuration = "in progress"
	}

	response := BuildMetricsResponse{
		BuildID:       build.ID,
		TotalDuration: totalDuration,
		Packages:      packages,
		Summary: MetricsSummary{
			AvgTotal:      formatDuration(average(totalDurations)),
			AvgBuildKit:   formatDuration(average(buildkitDurations)),
			AvgApko:       formatDuration(average(apkoDurations)),
			P50Total:      formatDuration(percentile(totalDurations, 50)),
			P95Total:      formatDuration(percentile(totalDurations, 95)),
			P99Total:      formatDuration(percentile(totalDurations, 99)),
			TotalPackages: len(build.Packages),
			Completed:     completed,
			Failed:        failed,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// UpdateBuildRequest is the request body for updating a build.
type UpdateBuildRequest struct {
	Status types.BuildStatus `json:"status"`
}

// handleUpdateBuild handles PUT /api/v1/builds/:id
// Updates the overall build status (used by orchestrator).
func (s *Server) handleUpdateBuild(w http.ResponseWriter, r *http.Request, buildID string) {
	var req UpdateBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get the current build
	build, err := s.buildStore.GetBuild(r.Context(), buildID)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get build: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update status
	if req.Status != "" {
		build.Status = req.Status
	}

	// Set started time if transitioning to running
	if build.Status == types.BuildStatusRunning && build.StartedAt == nil {
		now := time.Now()
		build.StartedAt = &now
	}

	// Set finished time if status is terminal
	if build.Status == types.BuildStatusSuccess || build.Status == types.BuildStatusFailed || build.Status == types.BuildStatusPartial {
		if build.FinishedAt == nil {
			now := time.Now()
			build.FinishedAt = &now
		}
	}

	if err := s.buildStore.UpdateBuild(r.Context(), build); err != nil {
		http.Error(w, "failed to update build: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(build)
}

// formatDuration formats milliseconds as a human-readable duration string.
func formatDuration(ms int64) string {
	if ms == 0 {
		return ""
	}
	d := time.Duration(ms) * time.Millisecond
	return d.String()
}

// average calculates the average of a slice of int64.
func average(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	var sum int64
	for _, v := range values {
		sum += v
	}
	return sum / int64(len(values))
}

// percentile calculates the p-th percentile of a slice of int64.
func percentile(values []int64, p int) int64 {
	if len(values) == 0 {
		return 0
	}
	// Make a copy and sort using O(n log n) algorithm
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	// Calculate index
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// createBuild creates a new build.
// Supports single config, multiple configs, or git source.
func (s *Server) createBuild(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracing.StartSpan(r.Context(), "api.createBuild",
		trace.WithAttributes(attribute.String("http.method", r.Method)),
	)
	defer span.End()

	timer := tracing.NewTimer(ctx, "createBuild")
	defer timer.Stop()

	log := clog.FromContext(ctx)

	// Limit request body size to prevent OOM
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)

	var req types.CreateBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "request body too large (max 10MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Collect configs from single config, multiple configs, or git source
	var configs []string
	var err error

	switch {
	case req.GitSource != nil:
		gitTimer := tracing.NewTimer(ctx, "load_git_configs")
		if err := git.ValidateSource(req.GitSource); err != nil {
			http.Error(w, "invalid git source: "+err.Error(), http.StatusBadRequest)
			return
		}
		source := git.NewSourceFromGitSource(req.GitSource)
		configs, err = source.LoadConfigs(ctx)
		gitTimer.Stop()
		if err != nil {
			http.Error(w, "failed to load configs from git: "+err.Error(), http.StatusBadRequest)
			return
		}
		log.Infof("loaded %d configs from git", len(configs))
	case len(req.Configs) > 0:
		configs = req.Configs
	case req.ConfigYAML != "":
		// Single config - treat as a build with one package
		configs = []string{req.ConfigYAML}
	default:
		http.Error(w, "config_yaml, configs, or git_source is required", http.StatusBadRequest)
		return
	}

	if len(configs) == 0 {
		http.Error(w, "no configs provided", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.Int("config_count", len(configs)))

	// Determine build mode (default to flat)
	mode := req.Mode
	if mode == "" {
		mode = types.BuildModeFlat
	}

	span.SetAttributes(attribute.String("build_mode", string(mode)))

	// Parse configs to extract package info
	dagTimer := tracing.NewTimer(ctx, "build_dag")
	nodes, err := s.parseConfigDependencies(configs)
	if err != nil {
		http.Error(w, "failed to parse configs: "+err.Error(), http.StatusBadRequest)
		return
	}

	var sorted []dag.Node

	if mode == types.BuildModeDAG {
		// Build the DAG and topologically sort
		graph := dag.NewGraph()
		for _, node := range nodes {
			if err := graph.AddNode(node.Name, node.ConfigYAML, node.Dependencies); err != nil {
				http.Error(w, "failed to build dependency graph: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		// Topological sort
		sorted, err = graph.TopologicalSort()
		if err != nil {
			http.Error(w, "dependency error: "+err.Error(), http.StatusBadRequest)
			return
		}
		log.Infof("created build DAG with %d packages (dag mode)", len(sorted))
	} else {
		// Flat mode: use nodes as-is without dependency ordering
		// Clear dependencies since they won't be enforced
		sorted = make([]dag.Node, len(nodes))
		for i, node := range nodes {
			sorted[i] = dag.Node{
				Name:         node.Name,
				ConfigYAML:   node.ConfigYAML,
				Dependencies: nil, // Don't track dependencies in flat mode
			}
		}
		log.Infof("created build with %d packages (flat mode)", len(sorted))
	}
	dagTimer.Stop()

	span.SetAttributes(attribute.Int("package_count", len(sorted)))

	// Create build spec
	spec := types.BuildSpec{
		Configs:         configs,
		GitSource:       req.GitSource,
		Pipelines:       req.Pipelines,
		SourceFiles:     req.SourceFiles,
		Arch:            req.Arch,
		BackendSelector: req.BackendSelector,
		WithTest:        req.WithTest,
		Debug:           req.Debug,
		Mode:            mode,
		Env:             req.Env,
	}

	// Create build in store
	storeTimer := tracing.NewTimer(ctx, "store_create_build")
	build, err := s.buildStore.CreateBuild(ctx, sorted, spec)
	storeTimer.Stop()
	if err != nil {
		http.Error(w, "failed to create build: "+err.Error(), http.StatusInternalServerError)
		return
	}

	span.SetAttributes(attribute.String("build_id", build.ID))
	log.Infof("created build %s with %d packages", build.ID, len(sorted))

	// Collect package names for response
	packageNames := make([]string, len(sorted))
	for i, node := range sorted {
		packageNames[i] = node.Name
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(types.CreateBuildResponse{
		ID:       build.ID,
		Packages: packageNames,
	})
}

// configDependencies is a minimal struct for parsing package dependencies from YAML.
type configDependencies struct {
	Package struct {
		Name string `yaml:"name"`
	} `yaml:"package"`
	Environment struct {
		Contents struct {
			Packages []string `yaml:"packages"`
		} `yaml:"contents"`
	} `yaml:"environment"`
}

// parseConfigDependencies parses configs to extract package names and their dependencies.
func (s *Server) parseConfigDependencies(configs []string) ([]dag.Node, error) {
	nodes := make([]dag.Node, 0, len(configs))

	for _, configYAML := range configs {
		var cfg configDependencies
		if err := yaml.Unmarshal([]byte(configYAML), &cfg); err != nil {
			return nil, err
		}

		if cfg.Package.Name == "" {
			return nil, &configError{msg: "config missing package name"}
		}

		nodes = append(nodes, dag.Node{
			Name:         cfg.Package.Name,
			ConfigYAML:   configYAML,
			Dependencies: cfg.Environment.Contents.Packages,
		})
	}

	return nodes, nil
}

// configError is a simple error type for config parsing errors.
type configError struct {
	msg string
}

func (e *configError) Error() string {
	return e.msg
}

// listBuilds lists all builds.
func (s *Server) listBuilds(w http.ResponseWriter, r *http.Request) {
	builds, err := s.buildStore.ListBuilds(r.Context())
	if err != nil {
		http.Error(w, "failed to list builds: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(builds)
}

// handleActiveBuilds returns non-terminal builds (pending/running).
// GET /api/v1/builds/active
// This is optimized for frequent polling by the orchestrator.
func (s *Server) handleActiveBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	builds, err := s.buildStore.ListActiveBuilds(r.Context())
	if err != nil {
		http.Error(w, "failed to list active builds: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(builds)
}

// UpdatePackageRequest is the request body for updating a package job.
type UpdatePackageRequest struct {
	Status     types.PackageStatus `json:"status"`
	Error      string              `json:"error,omitempty"`
	LogPath    string              `json:"log_path,omitempty"`
	OutputPath string              `json:"output_path,omitempty"`
}

// handlePackageRoute routes package-level requests.
// - POST /api/v1/builds/:id/packages/claim - claim any ready package
// - POST /api/v1/builds/:id/packages/:name/claim - claim a specific package
// - PUT /api/v1/builds/:id/packages/:name - update package status
// - GET /api/v1/builds/:id/packages/:name - get package details
func (s *Server) handlePackageRoute(w http.ResponseWriter, r *http.Request, path string) {
	// Parse path: {buildID}/packages[/{packageName}][/claim]
	parts := strings.Split(path, "/packages")
	if len(parts) != 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	buildID := parts[0]
	packagePath := strings.TrimPrefix(parts[1], "/")

	// Handle /packages/claim (claim any ready package)
	if packagePath == "claim" {
		s.handleClaimReadyPackage(w, r, buildID)
		return
	}

	// Handle /packages/:name/claim (claim specific package)
	if strings.HasSuffix(packagePath, "/claim") {
		packageName := strings.TrimSuffix(packagePath, "/claim")
		s.handleClaimPackage(w, r, buildID, packageName)
		return
	}

	// Package name is the rest of the path
	packageName := packagePath
	if packageName == "" {
		http.Error(w, "package name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetPackage(w, r, buildID, packageName)
	case http.MethodPut:
		s.handleUpdatePackage(w, r, buildID, packageName)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleClaimReadyPackage handles POST /api/v1/builds/:id/packages/claim
// Claims any ready package for execution (used by orchestrator).
// Returns 204 No Content if no packages are ready.
func (s *Server) handleClaimReadyPackage(w http.ResponseWriter, r *http.Request, buildID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pkg, err := s.buildStore.ClaimReadyPackage(r.Context(), buildID)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "failed to claim package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// No ready packages
	if pkg == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pkg)
}

// handleClaimPackage handles POST /api/v1/builds/:id/packages/:name/claim
// Claims a specific package for execution.
func (s *Server) handleClaimPackage(w http.ResponseWriter, r *http.Request, buildID, packageName string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pkg, err := s.buildStore.ClaimPackage(r.Context(), buildID, packageName)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if errors.Is(err, svcerrors.ErrPackageNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if errors.Is(err, svcerrors.ErrPackageNotReady) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if errors.Is(err, svcerrors.ErrPackageAlreadyClaimed) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "failed to claim package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pkg)
}

// handleGetPackage handles GET /api/v1/builds/:id/packages/:name
// Returns details for a specific package.
func (s *Server) handleGetPackage(w http.ResponseWriter, r *http.Request, buildID, packageName string) {
	pkg, err := s.buildStore.GetPackage(r.Context(), buildID, packageName)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if errors.Is(err, svcerrors.ErrPackageNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pkg)
}

// handleUpdatePackage handles PUT /api/v1/builds/:id/packages/:name
// Updates the status of a package job.
func (s *Server) handleUpdatePackage(w http.ResponseWriter, r *http.Request, buildID, packageName string) {
	var req UpdatePackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get the current package to update
	pkg, err := s.buildStore.GetPackage(r.Context(), buildID, packageName)
	if err != nil {
		if errors.Is(err, svcerrors.ErrBuildNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if errors.Is(err, svcerrors.ErrPackageNotFound) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update fields from request
	if req.Status != "" {
		pkg.Status = req.Status
	}
	if req.Error != "" {
		pkg.Error = req.Error
	}
	if req.LogPath != "" {
		pkg.LogPath = req.LogPath
	}
	if req.OutputPath != "" {
		pkg.OutputPath = req.OutputPath
	}

	// Set finished time if status is terminal
	if pkg.Status == types.PackageStatusSuccess || pkg.Status == types.PackageStatusFailed || pkg.Status == types.PackageStatusSkipped {
		now := time.Now()
		pkg.FinishedAt = &now
	}

	if err := s.buildStore.UpdatePackageJob(r.Context(), buildID, pkg); err != nil {
		http.Error(w, "failed to update package: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pkg)
}
