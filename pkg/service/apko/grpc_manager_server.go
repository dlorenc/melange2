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

package apko

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

// ManagerGRPCServer implements the ApkoManagerService gRPC server.
// It wraps a Manager implementation to expose it over gRPC.
type ManagerGRPCServer struct {
	UnimplementedApkoManagerServiceServer

	manager Manager

	// acquiredInstances maps instance IDs to their Instance objects for release.
	// This is needed because the gRPC client only has the instance ID.
	mu                sync.RWMutex
	acquiredInstances map[string]*Instance
}

// ManagerGRPCServerConfig configures the gRPC server.
type ManagerGRPCServerConfig struct {
	// Manager is the underlying manager implementation.
	Manager Manager
}

// NewManagerGRPCServer creates a new Apko Manager gRPC server.
func NewManagerGRPCServer(cfg ManagerGRPCServerConfig) *ManagerGRPCServer {
	return &ManagerGRPCServer{
		manager:           cfg.Manager,
		acquiredInstances: make(map[string]*Instance),
	}
}

// RequestInstance implements the RequestInstance RPC.
func (s *ManagerGRPCServer) RequestInstance(ctx context.Context, req *RequestInstanceRequest) (*RequestInstanceResponse, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-manager-service").Start(ctx, "RequestInstance")
	defer span.End()

	span.SetAttributes(
		attribute.String("job_id", req.JobId),
		attribute.Int("priority", int(req.Priority)),
	)

	// Convert proto request to internal type
	instanceReq := InstanceRequest{
		JobID:             req.JobId,
		EstimatedDuration: time.Duration(req.EstimatedDurationMs) * time.Millisecond,
		Priority:          int(req.Priority),
	}

	log.Infof("requesting apko instance for job_id=%s", req.JobId)

	// Request instance from underlying manager
	instance, err := s.manager.Request(ctx, instanceReq)
	if err != nil {
		span.RecordError(err)
		// Map common errors to appropriate gRPC status codes
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "timed out waiting for instance")
		}
		if errors.Is(err, context.Canceled) {
			return nil, status.Error(codes.Canceled, "request canceled")
		}
		return nil, status.Errorf(codes.Unavailable, "failed to acquire instance: %v", err)
	}

	// Store the instance for later release
	s.mu.Lock()
	s.acquiredInstances[instance.ID] = instance
	s.mu.Unlock()

	log.Infof("acquired apko instance id=%s addr=%s for job_id=%s", instance.ID, instance.Addr, req.JobId)

	// Convert to proto response
	return &RequestInstanceResponse{
		Instance: &InstanceInfo{
			Id:             instance.ID,
			Addr:           instance.Addr,
			MaxConcurrent:  int32(instance.MaxConcurrent),
			AcquiredAtUnix: instance.AcquiredAt.Unix(),
		},
	}, nil
}

// ReleaseInstance implements the ReleaseInstance RPC.
func (s *ManagerGRPCServer) ReleaseInstance(ctx context.Context, req *ReleaseInstanceRequest) (*ReleaseInstanceResponse, error) {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("apko-manager-service").Start(ctx, "ReleaseInstance")
	defer span.End()

	span.SetAttributes(
		attribute.String("instance_id", req.InstanceId),
	)

	if req.InstanceId == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
	}

	// Get the instance from our tracking map
	s.mu.Lock()
	instance, ok := s.acquiredInstances[req.InstanceId]
	if ok {
		delete(s.acquiredInstances, req.InstanceId)
	}
	s.mu.Unlock()

	if !ok {
		// Instance not found in our map - this could happen if the server restarted
		// or if the instance was already released. Return success anyway to be idempotent.
		log.Warnf("release requested for unknown instance id=%s", req.InstanceId)
		return &ReleaseInstanceResponse{Released: false}, nil
	}

	// Convert proto result to internal type
	var result BuildResult
	if req.Result != nil {
		result = BuildResult{
			Success:  req.Result.Success,
			Duration: time.Duration(req.Result.DurationMs) * time.Millisecond,
			Error:    req.Result.Error,
			CacheHit: req.Result.CacheHit,
		}
		span.SetAttributes(
			attribute.Bool("success", result.Success),
			attribute.Int64("duration_ms", req.Result.DurationMs),
			attribute.Bool("cache_hit", result.CacheHit),
		)
	}

	log.Infof("releasing apko instance id=%s success=%v cache_hit=%v", req.InstanceId, result.Success, result.CacheHit)

	// Release the instance
	s.manager.Release(instance, result)

	return &ReleaseInstanceResponse{Released: true}, nil
}

// GetStatus implements the GetStatus RPC.
func (s *ManagerGRPCServer) GetStatus(ctx context.Context, req *GetManagerStatusRequest) (*GetManagerStatusResponse, error) {
	_, span := otel.Tracer("apko-manager-service").Start(ctx, "GetStatus")
	defer span.End()

	managerStatus := s.manager.Status()

	// Convert to proto
	instances := make([]*InstanceStatusInfo, len(managerStatus.Instances))
	for i, inst := range managerStatus.Instances {
		var lastFailureUnix int64
		if !inst.LastFailure.IsZero() {
			lastFailureUnix = inst.LastFailure.Unix()
		}
		instances[i] = &InstanceStatusInfo{
			Id:              inst.ID,
			Addr:            inst.Addr,
			ActiveBuilds:    int32(inst.ActiveBuilds),
			MaxConcurrent:   int32(inst.MaxConcurrent),
			CircuitOpen:     inst.CircuitOpen,
			Failures:        int32(inst.Failures),
			LastFailureUnix: lastFailureUnix,
			CacheHits:       inst.CacheHits,
			CacheMisses:     inst.CacheMisses,
		}
	}

	return &GetManagerStatusResponse{
		Status: &ManagerStatusInfo{
			Type:           managerStatus.Type,
			TotalInstances: int32(managerStatus.TotalInstances),
			TotalCapacity:  int32(managerStatus.TotalCapacity),
			ActiveBuilds:   int32(managerStatus.ActiveBuilds),
			Instances:      instances,
			CacheHits:      managerStatus.CacheHits,
			CacheMisses:    managerStatus.CacheMisses,
		},
	}, nil
}

// GetCapacity implements the GetCapacity RPC.
func (s *ManagerGRPCServer) GetCapacity(ctx context.Context, req *GetManagerCapacityRequest) (*GetManagerCapacityResponse, error) {
	_, span := otel.Tracer("apko-manager-service").Start(ctx, "GetCapacity")
	defer span.End()

	return &GetManagerCapacityResponse{
		TotalCapacity:     int32(s.manager.TotalCapacity()),
		AvailableCapacity: int32(s.manager.AvailableCapacity()),
	}, nil
}

// Health implements the Health RPC.
func (s *ManagerGRPCServer) Health(ctx context.Context, req *ManagerHealthRequest) (*ManagerHealthResponse, error) {
	managerStatus := s.manager.Status()

	return &ManagerHealthResponse{
		Status:         ManagerHealthResponse_SERVING,
		ManagerType:    managerStatus.Type,
		TotalInstances: int32(managerStatus.TotalInstances),
		TotalCapacity:  int32(managerStatus.TotalCapacity),
		ActiveBuilds:   int32(managerStatus.ActiveBuilds),
	}, nil
}

// Close closes the server and underlying manager.
func (s *ManagerGRPCServer) Close() error {
	return s.manager.Close()
}
