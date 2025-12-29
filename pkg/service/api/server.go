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

	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Server is the HTTP API server.
type Server struct {
	store store.JobStore
	mux   *http.ServeMux
}

// NewServer creates a new API server.
func NewServer(store store.JobStore) *Server {
	s := &Server{
		store: store,
		mux:   http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/api/v1/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/v1/jobs/", s.handleJob)
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

// handleJobs handles POST /api/v1/jobs (create job) and GET /api/v1/jobs (list jobs).
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createJob(w, r)
	case http.MethodGet:
		s.listJobs(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleJob handles GET /api/v1/jobs/:id.
func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/")
	if path == "" {
		http.Error(w, "job ID required", http.StatusBadRequest)
		return
	}

	job, err := s.store.Get(r.Context(), path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

// MaxBodySize is the maximum allowed request body size (10MB).
const MaxBodySize = 10 << 20

// createJob creates a new build job.
func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent OOM
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)

	var req types.CreateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "request body too large (max 10MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.ConfigYAML == "" {
		http.Error(w, "config_yaml is required", http.StatusBadRequest)
		return
	}

	job, err := s.store.Create(r.Context(), types.JobSpec(req))
	if err != nil {
		http.Error(w, "failed to create job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(types.CreateJobResponse{ID: job.ID})
}

// listJobs lists all jobs.
func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list jobs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jobs)
}
