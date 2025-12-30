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
	"net/http"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/git"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
	"github.com/dlorenc/melange2/pkg/service/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"
)

// Server is the HTTP API server.
type Server struct {
	buildStore store.BuildStore
	pool       *buildkit.Pool
	mux        *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(buildStore store.BuildStore, pool *buildkit.Pool) *Server {
	s := &Server{
		buildStore: buildStore,
		pool:       pool,
		mux:        http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/api/v1/builds", s.handleBuilds)
	s.mux.HandleFunc("/api/v1/builds/", s.handleBuild)
	s.mux.HandleFunc("/api/v1/backends", s.handleBackends)
	s.mux.HandleFunc("/api/v1/backends/status", s.handleBackendsStatus)
	s.mux.HandleFunc("/healthz", s.handleHealth)
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

// handleBackends handles backend management:
// GET /api/v1/backends - list available backends
// POST /api/v1/backends - add a new backend
// DELETE /api/v1/backends - remove a backend
func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listBackends(w, r)
	case http.MethodPost:
		s.addBackend(w, r)
	case http.MethodDelete:
		s.removeBackend(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listBackends lists available backends.
func (s *Server) listBackends(w http.ResponseWriter, r *http.Request) {
	// Support optional architecture filter
	arch := r.URL.Query().Get("arch")

	var backends []buildkit.Backend
	if arch != "" {
		backends = s.pool.ListByArch(arch)
	} else {
		backends = s.pool.List()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"backends":      backends,
		"architectures": s.pool.Architectures(),
	})
}

// AddBackendRequest is the request body for adding a backend.
type AddBackendRequest struct {
	Addr   string            `json:"addr"`
	Arch   string            `json:"arch"`
	Labels map[string]string `json:"labels,omitempty"`
}

// addBackend adds a new backend to the pool.
func (s *Server) addBackend(w http.ResponseWriter, r *http.Request) {
	var req AddBackendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	backend := buildkit.Backend{
		Addr:   req.Addr,
		Arch:   req.Arch,
		Labels: req.Labels,
	}

	if err := s.pool.Add(backend); err != nil {
		// Check if it's a validation error vs duplicate
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(backend)
}

// RemoveBackendRequest is the request body for removing a backend.
type RemoveBackendRequest struct {
	Addr string `json:"addr"`
}

// removeBackend removes a backend from the pool.
func (s *Server) removeBackend(w http.ResponseWriter, r *http.Request) {
	var req RemoveBackendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Addr == "" {
		http.Error(w, "addr is required", http.StatusBadRequest)
		return
	}

	if err := s.pool.Remove(req.Addr); err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleBackendsStatus returns detailed status of all backends including
// active jobs, circuit breaker state, and failure counts.
// GET /api/v1/backends/status
func (s *Server) handleBackendsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := s.pool.Status()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"backends": status,
	})
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

// handleBuild handles GET /api/v1/builds/:id.
func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract build ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/builds/")
	if path == "" {
		http.Error(w, "build ID required", http.StatusBadRequest)
		return
	}

	build, err := s.buildStore.GetBuild(r.Context(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(build)
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
