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

// Package tracing provides OpenTelemetry tracing setup for melange-server.
package tracing

import (
	"context"
	"os"
	"time"

	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the name of the tracer used throughout melange-server.
	TracerName = "github.com/dlorenc/melange2/pkg/service"
)

// Tracer returns the tracer for melange-server.
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// Config holds tracing configuration.
type Config struct {
	// ServiceName is the name of the service.
	ServiceName string
	// ServiceVersion is the version of the service.
	ServiceVersion string
	// Enabled controls whether tracing is enabled.
	Enabled bool
}

// Setup initializes the OpenTelemetry tracer provider.
// Returns a shutdown function that should be called on exit.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		// Return a no-op shutdown function
		return func(context.Context) error { return nil }, nil
	}

	log := clog.FromContext(ctx)

	// Create stdout exporter for now (can be replaced with OTLP exporter)
	exporter, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithWriter(os.Stderr),
	)
	if err != nil {
		return nil, err
	}

	// Create resource with service info
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	log.Info("tracing enabled")

	return tp.Shutdown, nil
}

// StartSpan starts a new span with the given name.
// Returns the context with the span and the span itself.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent adds an event to the current span.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetAttributes sets attributes on the current span.
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// RecordError records an error on the current span.
func RecordError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
}

// Timer provides a simple way to measure and log durations.
type Timer struct {
	name      string
	start     time.Time
	ctx       context.Context
	logged    bool
	threshold time.Duration
}

// NewTimer creates a new timer with the given name.
// The timer starts immediately.
func NewTimer(ctx context.Context, name string) *Timer {
	return &Timer{
		name:      name,
		start:     time.Now(),
		ctx:       ctx,
		threshold: 0,
	}
}

// WithThreshold sets a minimum duration before logging.
// Durations below the threshold are not logged.
func (t *Timer) WithThreshold(d time.Duration) *Timer {
	t.threshold = d
	return t
}

// Stop stops the timer and logs the duration.
// Returns the duration for use in other contexts.
func (t *Timer) Stop() time.Duration {
	if t.logged {
		return time.Since(t.start)
	}
	t.logged = true

	duration := time.Since(t.start)

	// Add event to span
	span := trace.SpanFromContext(t.ctx)
	span.AddEvent(t.name+" completed",
		trace.WithAttributes(attribute.String("duration", duration.String())),
	)

	// Log if above threshold
	if duration >= t.threshold {
		log := clog.FromContext(t.ctx)
		log.Infof("%s took %s", t.name, duration)
	}

	return duration
}

// StopWithAttrs stops the timer and logs the duration with additional attributes.
func (t *Timer) StopWithAttrs(attrs ...attribute.KeyValue) time.Duration {
	if t.logged {
		return time.Since(t.start)
	}
	t.logged = true

	duration := time.Since(t.start)

	// Add event to span with duration and extra attrs
	allAttrs := append([]attribute.KeyValue{
		attribute.String("duration", duration.String()),
	}, attrs...)

	span := trace.SpanFromContext(t.ctx)
	span.AddEvent(t.name+" completed", trace.WithAttributes(allAttrs...))

	// Log if above threshold
	if duration >= t.threshold {
		log := clog.FromContext(t.ctx)
		log.Infof("%s took %s", t.name, duration)
	}

	return duration
}

// Duration returns the elapsed time without stopping the timer.
func (t *Timer) Duration() time.Duration {
	return time.Since(t.start)
}

// Elapsed returns a formatted string of the elapsed time.
func (t *Timer) Elapsed() string {
	return time.Since(t.start).String()
}
