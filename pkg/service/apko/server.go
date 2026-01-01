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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// Server implements the ApkoService gRPC server.
type Server struct {
	UnimplementedApkoServiceServer

	// Registry is the registry URL for storing built images.
	Registry string

	// RegistryInsecure allows HTTP connections to the registry.
	RegistryInsecure bool

	// ApkCacheDir is the directory for APK package cache.
	ApkCacheDir string

	// MaxConcurrent is the maximum number of concurrent builds.
	MaxConcurrent int

	// semaphore controls concurrent builds.
	sem chan struct{}

	// activeRequests tracks the number of active requests.
	activeRequests atomic.Int32

	// metrics tracks cache hits and misses.
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// ServerConfig configures the apko server.
type ServerConfig struct {
	// Registry is the registry URL for storing built images.
	Registry string

	// RegistryInsecure allows HTTP connections to the registry.
	RegistryInsecure bool

	// ApkCacheDir is the directory for APK package cache.
	ApkCacheDir string

	// MaxConcurrent is the maximum number of concurrent builds.
	// Default: 16
	MaxConcurrent int
}

// NewServer creates a new apko gRPC server.
func NewServer(cfg ServerConfig) *Server {
	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 16
	}

	return &Server{
		Registry:         cfg.Registry,
		RegistryInsecure: cfg.RegistryInsecure,
		ApkCacheDir:      cfg.ApkCacheDir,
		MaxConcurrent:    maxConcurrent,
		sem:              make(chan struct{}, maxConcurrent),
	}
}

// BuildLayers implements the BuildLayers RPC.
func (s *Server) BuildLayers(ctx context.Context, req *BuildLayersRequest) (*BuildLayersResponse, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-service").Start(ctx, "BuildLayers")
	defer span.End()

	// Add request attributes to span
	span.SetAttributes(
		attribute.String("arch", req.Arch),
		attribute.String("request_id", req.RequestId),
		attribute.Int("max_layers", int(req.MaxLayers)),
	)

	// Validate request
	if req.ImageConfigYaml == "" {
		return nil, status.Error(codes.InvalidArgument, "image_config_yaml is required")
	}
	if req.Arch == "" {
		return nil, status.Error(codes.InvalidArgument, "arch is required")
	}

	// Parse image configuration
	var imgConfig apko_types.ImageConfiguration
	if err := yaml.Unmarshal([]byte(req.ImageConfigYaml), &imgConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse image config: %v", err)
	}

	// Acquire semaphore
	select {
	case s.sem <- struct{}{}:
		s.activeRequests.Add(1)
		defer func() {
			<-s.sem
			s.activeRequests.Add(-1)
		}()
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request canceled while waiting for capacity")
	}

	log.Infof("building layers for arch=%s request_id=%s", req.Arch, req.RequestId)
	startTime := time.Now()

	// Build the layers
	imageRef, layerCount, cacheHit, lockedConfig, err := s.buildLayers(ctx, &imgConfig, req)
	if err != nil {
		span.RecordError(err)
		return nil, status.Errorf(codes.Internal, "failed to build layers: %v", err)
	}

	durationMs := time.Since(startTime).Milliseconds()
	log.Infof("built layers: image_ref=%s layers=%d cache_hit=%v duration_ms=%d", imageRef, layerCount, cacheHit, durationMs)

	// Serialize locked config
	lockedYAML, err := yaml.Marshal(lockedConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize locked config: %v", err)
	}

	return &BuildLayersResponse{
		ImageRef:         imageRef,
		LayerCount:       int32(layerCount),
		CacheHit:         cacheHit,
		LockedConfigYaml: string(lockedYAML),
		DurationMs:       durationMs,
	}, nil
}

// buildLayers builds the apko layers and returns the image reference.
func (s *Server) buildLayers(ctx context.Context, imgConfig *apko_types.ImageConfiguration, req *BuildLayersRequest) (string, int, bool, *apko_types.ImageConfiguration, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-service").Start(ctx, "buildLayers")
	defer span.End()

	// Set architecture
	arch := apko_types.ParseArchitecture(req.Arch)
	imgConfig.Archs = []apko_types.Architecture{arch}

	// Set layering configuration
	maxLayers := int(req.MaxLayers)
	if maxLayers == 0 {
		maxLayers = 50
	}
	imgConfig.Layering = &apko_types.Layering{
		Strategy: "origin",
		Budget:   maxLayers,
	}

	// Inject extra repos/keys if none specified
	if len(imgConfig.Contents.Repositories) == 0 && len(req.ExtraRepos) > 0 {
		imgConfig.Contents.Repositories = append(imgConfig.Contents.Repositories, req.ExtraRepos...)
	}
	if len(imgConfig.Contents.Keyring) == 0 && len(req.ExtraKeys) > 0 {
		imgConfig.Contents.Keyring = append(imgConfig.Contents.Keyring, req.ExtraKeys...)
	}

	// Check cache first
	cacheTag := s.hashConfig(*imgConfig)
	cacheRef := fmt.Sprintf("%s:%s", s.Registry, cacheTag)

	if cacheHit, err := s.checkCache(ctx, cacheRef); err == nil && cacheHit {
		s.cacheHits.Add(1)
		log.Infof("cache hit: %s", cacheRef)
		// Return cache hit - we don't have the exact layer count without fetching manifest
		// but that's okay for cache hits
		return cacheRef, maxLayers, true, imgConfig, nil
	}
	s.cacheMisses.Add(1)

	// Create temp directory for apko build
	tmp, err := os.MkdirTemp("", "apko-service-*")
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	// Build options
	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(*imgConfig),
		apko_build.WithArch(arch),
		apko_build.WithExtraKeys(req.ExtraKeys),
		apko_build.WithExtraBuildRepos(req.ExtraRepos),
		apko_build.WithExtraPackages(req.ExtraPackages),
		apko_build.WithTempDir(tmp),
		apko_build.WithIgnoreSignatures(req.IgnoreSignatures),
	}

	// Add APK cache if configured
	if s.ApkCacheDir != "" {
		opts = append(opts, apko_build.WithCache(s.ApkCacheDir, false, apk.NewCache(true)))
	}

	// Lock image configuration
	configs, warn, err := apko_build.LockImageConfiguration(ctx, *imgConfig, opts...)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("locking image configuration: %w", err)
	}

	for k, v := range warn {
		log.Warnf("unable to lock package %s: %s", k, v)
	}

	locked, ok := configs["index"]
	if !ok {
		return "", 0, false, nil, errors.New("missing locked config")
	}

	// Preserve layering in locked config
	locked.Layering = imgConfig.Layering
	opts = append(opts, apko_build.WithImageConfiguration(*locked))

	// Build layers
	guestFS := tarfs.New()
	bc, err := apko_build.New(ctx, guestFS, opts...)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("creating build context: %w", err)
	}

	layers, err := bc.BuildLayers(ctx)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("building layers: %w", err)
	}
	log.Infof("apko generated %d layers", len(layers))

	// Push to registry
	imageRef, err := s.pushImage(ctx, cacheRef, layers)
	if err != nil {
		return "", 0, false, nil, fmt.Errorf("pushing image: %w", err)
	}

	// Clear pools after build to free memory
	apko_build.ClearPools()

	return imageRef, len(layers), false, locked, nil
}

// hashConfig creates a deterministic hash of the image configuration.
func (s *Server) hashConfig(cfg apko_types.ImageConfiguration) string {
	hashInput := struct {
		Contents apko_types.ImageContents  `json:"contents"`
		Archs    []apko_types.Architecture `json:"archs"`
		Layering *apko_types.Layering      `json:"layering,omitempty"`
	}{
		Contents: cfg.Contents,
		Archs:    cfg.Archs,
		Layering: cfg.Layering,
	}

	data, err := json.Marshal(hashInput)
	if err != nil {
		data, _ = json.Marshal(cfg)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:16]
}

// checkCache checks if an image exists in the cache registry.
func (s *Server) checkCache(ctx context.Context, ref string) (bool, error) {
	opts := []name.Option{}
	if s.RegistryInsecure {
		opts = append(opts, name.Insecure)
	}

	imgRef, err := name.ParseReference(ref, opts...)
	if err != nil {
		return false, err
	}

	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if s.RegistryInsecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	_, err = remote.Head(imgRef, remoteOpts...)
	if err == nil {
		return true, nil
	}

	// Check if it's a 404
	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
		return false, nil
	}

	return false, err
}

// pushImage pushes layers to the registry and returns the image reference.
func (s *Server) pushImage(ctx context.Context, ref string, layers []v1.Layer) (string, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-service").Start(ctx, "pushImage")
	defer span.End()

	opts := []name.Option{}
	if s.RegistryInsecure {
		opts = append(opts, name.Insecure)
	}

	imgRef, err := name.ParseReference(ref, opts...)
	if err != nil {
		return "", fmt.Errorf("parsing ref %q: %w", ref, err)
	}

	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if s.RegistryInsecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	// Build image from layers (use variadic form to avoid O(n^2) memory)
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return "", fmt.Errorf("appending %d layers: %w", len(layers), err)
	}

	// Push image
	pushStart := time.Now()
	if err := remote.Write(imgRef, img, remoteOpts...); err != nil {
		return "", fmt.Errorf("pushing image: %w", err)
	}
	log.Infof("pushed image in %s", time.Since(pushStart))

	return ref, nil
}

// Health implements the Health RPC.
func (s *Server) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	return &HealthResponse{
		Status:         HealthResponse_SERVING,
		ActiveRequests: s.activeRequests.Load(),
		MaxConcurrent:  int32(s.MaxConcurrent),
	}, nil
}

// Stats returns server statistics.
func (s *Server) Stats() ServerStats {
	return ServerStats{
		ActiveRequests: int(s.activeRequests.Load()),
		MaxConcurrent:  s.MaxConcurrent,
		CacheHits:      s.cacheHits.Load(),
		CacheMisses:    s.cacheMisses.Load(),
	}
}

// ServerStats contains server statistics.
type ServerStats struct {
	ActiveRequests int   `json:"active_requests"`
	MaxConcurrent  int   `json:"max_concurrent"`
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`
}
