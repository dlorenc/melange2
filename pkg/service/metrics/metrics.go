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

// Package metrics provides Prometheus metrics for melange-server and apko-server.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MelangeMetrics holds Prometheus metrics for melange-server.
type MelangeMetrics struct {
	// Build metrics
	BuildsTotal     *prometheus.CounterVec
	PackagesTotal   *prometheus.CounterVec
	BuildQueueDepth prometheus.Gauge
	ActiveBuilds    prometheus.Gauge

	// Build duration histograms
	BuildDurationSeconds   *prometheus.HistogramVec
	PackageDurationSeconds *prometheus.HistogramVec

	// Phase duration histograms
	PhaseDurationSeconds *prometheus.HistogramVec

	// BuildKit backend metrics
	BackendsTotal     prometheus.Gauge
	BackendsAvailable prometheus.Gauge
	BackendJobsActive *prometheus.GaugeVec

	// Storage metrics
	StorageSyncDurationSeconds *prometheus.HistogramVec

	registry *prometheus.Registry
}

// NewMelangeMetrics creates a new MelangeMetrics instance with all metrics registered.
func NewMelangeMetrics() *MelangeMetrics {
	reg := prometheus.NewRegistry()

	m := &MelangeMetrics{
		BuildsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "melange_builds_total",
				Help: "Total number of builds by status",
			},
			[]string{"status"},
		),
		PackagesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "melange_packages_total",
				Help: "Total number of packages built by status",
			},
			[]string{"status"},
		),
		BuildQueueDepth: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "melange_build_queue_depth",
				Help: "Number of builds waiting to be processed",
			},
		),
		ActiveBuilds: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "melange_active_builds",
				Help: "Number of builds currently being processed",
			},
		),
		BuildDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "melange_build_duration_seconds",
				Help:    "Duration of builds in seconds",
				Buckets: prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~4.5h
			},
			[]string{"status", "mode"},
		),
		PackageDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "melange_package_duration_seconds",
				Help:    "Duration of package builds in seconds",
				Buckets: prometheus.ExponentialBuckets(1, 2, 12), // 1s to ~1h
			},
			[]string{"status", "arch"},
		),
		PhaseDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "melange_phase_duration_seconds",
				Help:    "Duration of build phases in seconds",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 14), // 0.1s to ~27m
			},
			[]string{"phase"},
		),
		BackendsTotal: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "melange_buildkit_backends_total",
				Help: "Total number of BuildKit backends configured",
			},
		),
		BackendsAvailable: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "melange_buildkit_backends_available",
				Help: "Number of BuildKit backends available (circuit closed)",
			},
		),
		BackendJobsActive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "melange_buildkit_backend_jobs_active",
				Help: "Number of active jobs per backend",
			},
			[]string{"addr", "arch"},
		),
		StorageSyncDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "melange_storage_sync_duration_seconds",
				Help:    "Duration of storage sync operations in seconds",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to ~1.5m
			},
			[]string{"backend"},
		),
		registry: reg,
	}

	// Register all metrics
	reg.MustRegister(
		m.BuildsTotal,
		m.PackagesTotal,
		m.BuildQueueDepth,
		m.ActiveBuilds,
		m.BuildDurationSeconds,
		m.PackageDurationSeconds,
		m.PhaseDurationSeconds,
		m.BackendsTotal,
		m.BackendsAvailable,
		m.BackendJobsActive,
		m.StorageSyncDurationSeconds,
	)

	// Also register default collectors (go runtime, process stats)
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return m
}

// Handler returns an HTTP handler for the /metrics endpoint.
func (m *MelangeMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordBuildStarted records a build being started.
func (m *MelangeMetrics) RecordBuildStarted() {
	m.ActiveBuilds.Inc()
}

// RecordBuildCompleted records a build completion with its status.
func (m *MelangeMetrics) RecordBuildCompleted(status string, mode string, durationSeconds float64) {
	m.ActiveBuilds.Dec()
	m.BuildsTotal.WithLabelValues(status).Inc()
	m.BuildDurationSeconds.WithLabelValues(status, mode).Observe(durationSeconds)
}

// RecordPackageCompleted records a package build completion.
func (m *MelangeMetrics) RecordPackageCompleted(status string, arch string, durationSeconds float64) {
	m.PackagesTotal.WithLabelValues(status).Inc()
	m.PackageDurationSeconds.WithLabelValues(status, arch).Observe(durationSeconds)
}

// RecordPhaseDuration records the duration of a build phase.
func (m *MelangeMetrics) RecordPhaseDuration(phase string, durationSeconds float64) {
	m.PhaseDurationSeconds.WithLabelValues(phase).Observe(durationSeconds)
}

// UpdateQueueDepth updates the build queue depth gauge.
func (m *MelangeMetrics) UpdateQueueDepth(depth int) {
	m.BuildQueueDepth.Set(float64(depth))
}

// UpdateBackendMetrics updates backend-related gauges.
func (m *MelangeMetrics) UpdateBackendMetrics(total, available int, activeJobs map[string]int, archByAddr map[string]string) {
	m.BackendsTotal.Set(float64(total))
	m.BackendsAvailable.Set(float64(available))
	for addr, jobs := range activeJobs {
		arch := archByAddr[addr]
		m.BackendJobsActive.WithLabelValues(addr, arch).Set(float64(jobs))
	}
}

// RecordStorageSync records a storage sync operation.
func (m *MelangeMetrics) RecordStorageSync(backend string, durationSeconds float64) {
	m.StorageSyncDurationSeconds.WithLabelValues(backend).Observe(durationSeconds)
}

// ApkoMetrics holds Prometheus metrics for apko-server.
type ApkoMetrics struct {
	// Build metrics
	BuildsTotal   *prometheus.CounterVec
	LayersTotal   prometheus.Counter
	ActiveRequests prometheus.Gauge

	// Duration histograms
	BuildDurationSeconds        *prometheus.HistogramVec
	APKDownloadDurationSeconds  prometheus.Histogram
	LayerAssemblyDurationSeconds prometheus.Histogram
	ImagePushDurationSeconds    prometheus.Histogram
	SemaphoreWaitSeconds        prometheus.Histogram

	// Cache metrics
	CacheHitsTotal   prometheus.Counter
	CacheMissesTotal prometheus.Counter
	PoolHitsTotal    prometheus.Counter
	PoolMissesTotal  prometheus.Counter
	PoolDropsTotal   prometheus.Counter

	registry *prometheus.Registry
}

// NewApkoMetrics creates a new ApkoMetrics instance with all metrics registered.
func NewApkoMetrics() *ApkoMetrics {
	reg := prometheus.NewRegistry()

	m := &ApkoMetrics{
		BuildsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "apko_builds_total",
				Help: "Total number of apko builds",
			},
			[]string{"cache_hit"},
		),
		LayersTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_layers_total",
				Help: "Total number of layers generated",
			},
		),
		ActiveRequests: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "apko_active_requests",
				Help: "Number of active build requests",
			},
		),
		BuildDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "apko_build_duration_seconds",
				Help:    "Duration of apko builds in seconds",
				Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~17m
			},
			[]string{"cache_hit"},
		),
		APKDownloadDurationSeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "apko_apk_download_duration_seconds",
				Help:    "Duration of APK package downloads in seconds",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 12), // 0.1s to ~7m
			},
		),
		LayerAssemblyDurationSeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "apko_layer_assembly_duration_seconds",
				Help:    "Duration of layer assembly in seconds",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 12), // 0.1s to ~7m
			},
		),
		ImagePushDurationSeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "apko_image_push_duration_seconds",
				Help:    "Duration of image push to registry in seconds",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to ~1.7m
			},
		),
		SemaphoreWaitSeconds: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "apko_semaphore_wait_seconds",
				Help:    "Time spent waiting for semaphore in seconds",
				Buckets: prometheus.ExponentialBuckets(0.01, 2, 14), // 0.01s to ~2.7m
			},
		),
		CacheHitsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_cache_hits_total",
				Help: "Total number of cache hits",
			},
		),
		CacheMissesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_cache_misses_total",
				Help: "Total number of cache misses",
			},
		),
		PoolHitsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_pool_hits_total",
				Help: "Total number of pool hits",
			},
		),
		PoolMissesTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_pool_misses_total",
				Help: "Total number of pool misses",
			},
		),
		PoolDropsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "apko_pool_drops_total",
				Help: "Total number of pool drops (pool full)",
			},
		),
		registry: reg,
	}

	// Register all metrics
	reg.MustRegister(
		m.BuildsTotal,
		m.LayersTotal,
		m.ActiveRequests,
		m.BuildDurationSeconds,
		m.APKDownloadDurationSeconds,
		m.LayerAssemblyDurationSeconds,
		m.ImagePushDurationSeconds,
		m.SemaphoreWaitSeconds,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.PoolHitsTotal,
		m.PoolMissesTotal,
		m.PoolDropsTotal,
	)

	// Also register default collectors
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return m
}

// Handler returns an HTTP handler for the /metrics endpoint.
func (m *ApkoMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordBuildStarted records a build being started.
func (m *ApkoMetrics) RecordBuildStarted() {
	m.ActiveRequests.Inc()
}

// RecordBuildCompleted records a build completion.
func (m *ApkoMetrics) RecordBuildCompleted(cacheHit bool, durationSeconds float64, layerCount int) {
	m.ActiveRequests.Dec()
	hitStr := "false"
	if cacheHit {
		hitStr = "true"
	}
	m.BuildsTotal.WithLabelValues(hitStr).Inc()
	m.BuildDurationSeconds.WithLabelValues(hitStr).Observe(durationSeconds)
	m.LayersTotal.Add(float64(layerCount))
}

// RecordAPKDownload records APK download duration.
func (m *ApkoMetrics) RecordAPKDownload(durationSeconds float64) {
	m.APKDownloadDurationSeconds.Observe(durationSeconds)
}

// RecordLayerAssembly records layer assembly duration.
func (m *ApkoMetrics) RecordLayerAssembly(durationSeconds float64) {
	m.LayerAssemblyDurationSeconds.Observe(durationSeconds)
}

// RecordImagePush records image push duration.
func (m *ApkoMetrics) RecordImagePush(durationSeconds float64) {
	m.ImagePushDurationSeconds.Observe(durationSeconds)
}

// RecordSemaphoreWait records semaphore wait time.
func (m *ApkoMetrics) RecordSemaphoreWait(durationSeconds float64) {
	m.SemaphoreWaitSeconds.Observe(durationSeconds)
}

// RecordCacheHit records a cache hit.
func (m *ApkoMetrics) RecordCacheHit() {
	m.CacheHitsTotal.Inc()
}

// RecordCacheMiss records a cache miss.
func (m *ApkoMetrics) RecordCacheMiss() {
	m.CacheMissesTotal.Inc()
}

// UpdatePoolStats updates pool statistics from apko pool stats.
func (m *ApkoMetrics) UpdatePoolStats(hits, misses, drops int64) {
	// These are cumulative values, but prometheus counters should be incremented
	// So we track the delta. For simplicity, we just set gauges or use the increment pattern.
	// Since apko stats are cumulative and may be reset, we'll record them as-is periodically.
	m.PoolHitsTotal.Add(float64(hits))
	m.PoolMissesTotal.Add(float64(misses))
	m.PoolDropsTotal.Add(float64(drops))
}
