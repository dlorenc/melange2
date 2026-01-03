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

package buildkit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPCServer implements the BuildKitManagerService gRPC server.
// It wraps a Manager implementation to expose it over gRPC.
type GRPCServer struct {
	UnimplementedBuildKitManagerServiceServer

	manager Manager

	// acquiredWorkers maps worker IDs to their Worker objects for release.
	// This is needed because the gRPC client only has the worker ID.
	mu              sync.RWMutex
	acquiredWorkers map[string]*Worker
}

// GRPCServerConfig configures the gRPC server.
type GRPCServerConfig struct {
	// Manager is the underlying manager implementation.
	Manager Manager
}

// NewGRPCServer creates a new BuildKit Manager gRPC server.
func NewGRPCServer(cfg GRPCServerConfig) *GRPCServer {
	return &GRPCServer{
		manager:         cfg.Manager,
		acquiredWorkers: make(map[string]*Worker),
	}
}

// RequestWorker implements the RequestWorker RPC.
func (s *GRPCServer) RequestWorker(ctx context.Context, req *RequestWorkerRequest) (*RequestWorkerResponse, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("buildkit-manager-service").Start(ctx, "RequestWorker")
	defer span.End()

	span.SetAttributes(
		attribute.String("arch", req.Arch),
		attribute.String("job_id", req.JobId),
		attribute.Int("priority", int(req.Priority)),
	)

	// Validate request
	if req.Arch == "" {
		return nil, status.Error(codes.InvalidArgument, "arch is required")
	}

	// Convert proto request to internal type
	workerReq := WorkerRequest{
		Arch:     req.Arch,
		JobID:    req.JobId,
		Selector: req.Selector,
		Priority: int(req.Priority),
	}

	if req.Resources != nil {
		workerReq.Resources = ResourceRequirements{
			MemoryMB: req.Resources.MemoryMb,
			CPUCores: req.Resources.CpuCores,
			DiskGB:   req.Resources.DiskGb,
			Timeout:  time.Duration(req.Resources.TimeoutSeconds) * time.Second,
		}
	}

	log.Infof("requesting worker for arch=%s job_id=%s", req.Arch, req.JobId)

	// Request worker from underlying manager
	worker, err := s.manager.Request(ctx, workerReq)
	if err != nil {
		span.RecordError(err)
		// Map common errors to appropriate gRPC status codes
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "timed out waiting for worker")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "request canceled")
		}
		return nil, status.Errorf(codes.Unavailable, "failed to acquire worker: %v", err)
	}

	// Store the worker for later release
	s.mu.Lock()
	s.acquiredWorkers[worker.ID] = worker
	s.mu.Unlock()

	log.Infof("acquired worker id=%s addr=%s for job_id=%s", worker.ID, worker.Addr, req.JobId)

	// Convert to proto response
	return &RequestWorkerResponse{
		Worker: &WorkerInfo{
			Id:             worker.ID,
			Addr:           worker.Addr,
			Arch:           worker.Arch,
			Labels:         worker.Labels,
			AcquiredAtUnix: worker.AcquiredAt.Unix(),
		},
	}, nil
}

// ReleaseWorker implements the ReleaseWorker RPC.
func (s *GRPCServer) ReleaseWorker(ctx context.Context, req *ReleaseWorkerRequest) (*ReleaseWorkerResponse, error) {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("buildkit-manager-service").Start(ctx, "ReleaseWorker")
	defer span.End()

	span.SetAttributes(
		attribute.String("worker_id", req.WorkerId),
	)

	if req.WorkerId == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id is required")
	}

	// Get the worker from our tracking map
	s.mu.Lock()
	worker, ok := s.acquiredWorkers[req.WorkerId]
	if ok {
		delete(s.acquiredWorkers, req.WorkerId)
	}
	s.mu.Unlock()

	if !ok {
		// Worker not found in our map - this could happen if the server restarted
		// or if the worker was already released. Return success anyway to be idempotent.
		log.Warnf("release requested for unknown worker id=%s", req.WorkerId)
		return &ReleaseWorkerResponse{Released: false}, nil
	}

	// Convert proto result to internal type
	var result BuildResult
	if req.Result != nil {
		result = BuildResult{
			Success:  req.Result.Success,
			Duration: time.Duration(req.Result.DurationMs) * time.Millisecond,
			Error:    req.Result.Error,
		}
		span.SetAttributes(
			attribute.Bool("success", result.Success),
			attribute.Int64("duration_ms", req.Result.DurationMs),
		)
	}

	log.Infof("releasing worker id=%s success=%v", req.WorkerId, result.Success)

	// Release the worker
	s.manager.Release(worker, result)

	return &ReleaseWorkerResponse{Released: true}, nil
}

// GetStatus implements the GetStatus RPC.
func (s *GRPCServer) GetStatus(ctx context.Context, req *GetStatusRequest) (*GetStatusResponse, error) {
	_, span := otel.Tracer("buildkit-manager-service").Start(ctx, "GetStatus")
	defer span.End()

	managerStatus := s.manager.Status()

	// Convert to proto
	workers := make([]*WorkerStatusInfo, len(managerStatus.Workers))
	for i, w := range managerStatus.Workers {
		var lastFailureUnix int64
		if !w.LastFailure.IsZero() {
			lastFailureUnix = w.LastFailure.Unix()
		}
		workers[i] = &WorkerStatusInfo{
			Id:              w.ID,
			Addr:            w.Addr,
			Arch:            w.Arch,
			Labels:          w.Labels,
			ActiveJobs:      int32(w.ActiveJobs),
			MaxJobs:         int32(w.MaxJobs),
			CircuitOpen:     w.CircuitOpen,
			Failures:        int32(w.Failures),
			LastFailureUnix: lastFailureUnix,
		}
	}

	return &GetStatusResponse{
		Status: &ManagerStatusInfo{
			Type:             managerStatus.Type,
			TotalWorkers:     int32(managerStatus.TotalWorkers),
			AvailableWorkers: int32(managerStatus.AvailableWorkers),
			ActiveJobs:       int32(managerStatus.ActiveJobs),
			Workers:          workers,
		},
	}, nil
}

// GetCapacity implements the GetCapacity RPC.
func (s *GRPCServer) GetCapacity(ctx context.Context, req *GetCapacityRequest) (*GetCapacityResponse, error) {
	_, span := otel.Tracer("buildkit-manager-service").Start(ctx, "GetCapacity")
	defer span.End()

	return &GetCapacityResponse{
		TotalCapacity: int32(s.manager.TotalCapacity()),
	}, nil
}

// GetArchitectures implements the GetArchitectures RPC.
func (s *GRPCServer) GetArchitectures(ctx context.Context, req *GetArchitecturesRequest) (*GetArchitecturesResponse, error) {
	_, span := otel.Tracer("buildkit-manager-service").Start(ctx, "GetArchitectures")
	defer span.End()

	return &GetArchitecturesResponse{
		Architectures: s.manager.Architectures(),
	}, nil
}

// Health implements the Health RPC.
func (s *GRPCServer) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	managerStatus := s.manager.Status()

	return &HealthResponse{
		Status:           HealthResponse_SERVING,
		ManagerType:      managerStatus.Type,
		TotalWorkers:     int32(managerStatus.TotalWorkers),
		AvailableWorkers: int32(managerStatus.AvailableWorkers),
		ActiveJobs:       int32(managerStatus.ActiveJobs),
	}, nil
}

// Close closes the server and underlying manager.
func (s *GRPCServer) Close() error {
	return s.manager.Close()
}
