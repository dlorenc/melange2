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

package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
	"github.com/google/uuid"
)

//go:embed migrations/*.sql
var migrations embed.FS

// PostgresBuildStoreConfig configures the PostgreSQL build store.
type PostgresBuildStoreConfig struct {
	// DSN is the PostgreSQL connection string.
	// Example: "postgres://user:pass@localhost:5432/melange?sslmode=disable"
	DSN string

	// MaxConns is the maximum number of connections in the pool.
	MaxConns int32

	// MinConns is the minimum number of connections to keep open.
	MinConns int32

	// MaxConnIdleTime is how long a connection can be idle before being closed.
	MaxConnIdleTime time.Duration
}

// PostgresBuildStore implements BuildStore using PostgreSQL.
type PostgresBuildStore struct {
	pool   *pgxpool.Pool
	config PostgresBuildStoreConfig
}

// PostgresBuildStoreOption configures a PostgresBuildStore.
type PostgresBuildStoreOption func(*PostgresBuildStore)

// WithPostgresMaxConns sets the maximum connections.
func WithPostgresMaxConns(n int32) PostgresBuildStoreOption {
	return func(s *PostgresBuildStore) {
		s.config.MaxConns = n
	}
}

// WithPostgresMinConns sets the minimum connections.
func WithPostgresMinConns(n int32) PostgresBuildStoreOption {
	return func(s *PostgresBuildStore) {
		s.config.MinConns = n
	}
}

// RunMigrations applies all pending database migrations.
func RunMigrations(dsn string) error {
	d, err := iofs.New(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", d, dsn)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	return nil
}

// NewPostgresBuildStore creates a new PostgreSQL-backed build store.
func NewPostgresBuildStore(ctx context.Context, dsn string, opts ...PostgresBuildStoreOption) (*PostgresBuildStore, error) {
	s := &PostgresBuildStore{
		config: PostgresBuildStoreConfig{
			DSN:             dsn,
			MaxConns:        25,
			MinConns:        5,
			MaxConnIdleTime: 5 * time.Minute,
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	// Configure connection pool
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}

	poolConfig.MaxConns = s.config.MaxConns
	poolConfig.MinConns = s.config.MinConns
	poolConfig.MaxConnIdleTime = s.config.MaxConnIdleTime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	// Verify connectivity
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	s.pool = pool
	return s, nil
}

// Close closes the connection pool.
func (s *PostgresBuildStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Ping checks database connectivity.
func (s *PostgresBuildStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// CreateBuild creates a new multi-package build.
func (s *PostgresBuildStore) CreateBuild(ctx context.Context, packages []dag.Node, spec types.BuildSpec) (*types.Build, error) {
	buildID := "bld-" + uuid.New().String()[:8]
	now := time.Now()

	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshaling spec: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Insert build
	_, err = tx.Exec(ctx, `
		INSERT INTO builds (id, status, created_at, spec)
		VALUES ($1, 'pending', $2, $3)
	`, buildID, now, specJSON)
	if err != nil {
		return nil, fmt.Errorf("inserting build: %w", err)
	}

	// Insert package jobs
	for i, node := range packages {
		pipelinesJSON, err := json.Marshal(spec.Pipelines)
		if err != nil {
			return nil, fmt.Errorf("marshaling pipelines: %w", err)
		}

		sourceFilesJSON := []byte("{}")
		if spec.SourceFiles != nil {
			if sf, ok := spec.SourceFiles[node.Name]; ok {
				sourceFilesJSON, err = json.Marshal(sf)
				if err != nil {
					return nil, fmt.Errorf("marshaling source files: %w", err)
				}
			}
		}

		// Ensure dependencies is never nil (PostgreSQL requires non-null)
		deps := node.Dependencies
		if deps == nil {
			deps = []string{}
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO package_jobs (build_id, name, status, config_yaml, dependencies, pipelines, source_files, position)
			VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7)
		`, buildID, node.Name, node.ConfigYAML, deps, pipelinesJSON, sourceFilesJSON, i)
		if err != nil {
			return nil, fmt.Errorf("inserting package job %s: %w", node.Name, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	// Return the created build
	return s.GetBuild(ctx, buildID)
}

// GetBuild retrieves a build by ID.
func (s *PostgresBuildStore) GetBuild(ctx context.Context, id string) (*types.Build, error) {
	var build types.Build
	var specJSON []byte

	err := s.pool.QueryRow(ctx, `
		SELECT id, status, created_at, started_at, finished_at, spec
		FROM builds WHERE id = $1
	`, id).Scan(
		&build.ID, &build.Status, &build.CreatedAt,
		&build.StartedAt, &build.FinishedAt, &specJSON,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("build not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("querying build: %w", err)
	}

	if err := json.Unmarshal(specJSON, &build.Spec); err != nil {
		return nil, fmt.Errorf("unmarshaling spec: %w", err)
	}

	// Query package jobs
	rows, err := s.pool.Query(ctx, `
		SELECT name, status, config_yaml, dependencies, started_at, finished_at,
		       error, log_path, output_path, backend, pipelines, source_files, metrics
		FROM package_jobs
		WHERE build_id = $1
		ORDER BY position
	`, id)
	if err != nil {
		return nil, fmt.Errorf("querying package jobs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		pkg, err := scanPackageJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning package job: %w", err)
		}
		build.Packages = append(build.Packages, *pkg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating package jobs: %w", err)
	}

	return &build, nil
}

// UpdateBuild updates an existing build.
func (s *PostgresBuildStore) UpdateBuild(ctx context.Context, build *types.Build) error {
	result, err := s.pool.Exec(ctx, `
		UPDATE builds
		SET status = $2, started_at = $3, finished_at = $4
		WHERE id = $1
	`, build.ID, build.Status, build.StartedAt, build.FinishedAt)

	if err != nil {
		return fmt.Errorf("updating build: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("build not found: %s", build.ID)
	}
	return nil
}

// ListBuilds returns all builds.
func (s *PostgresBuildStore) ListBuilds(ctx context.Context) ([]*types.Build, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM builds
		ORDER BY created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("querying builds: %w", err)
	}
	defer rows.Close()

	var builds []*types.Build
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning build id: %w", err)
		}
		build, err := s.GetBuild(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("getting build %s: %w", id, err)
		}
		builds = append(builds, build)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating builds: %w", err)
	}

	return builds, nil
}

// ListActiveBuilds returns only non-terminal builds (pending/running).
func (s *PostgresBuildStore) ListActiveBuilds(ctx context.Context) ([]*types.Build, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id FROM builds
		WHERE status IN ('pending', 'running')
		ORDER BY created_at
	`)
	if err != nil {
		return nil, fmt.Errorf("querying active builds: %w", err)
	}
	defer rows.Close()

	var builds []*types.Build
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning build id: %w", err)
		}
		build, err := s.GetBuild(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("getting build %s: %w", id, err)
		}
		builds = append(builds, build)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating active builds: %w", err)
	}

	// Sort by CreatedAt for deterministic ordering
	sort.Slice(builds, func(i, j int) bool {
		return builds[i].CreatedAt.Before(builds[j].CreatedAt)
	})

	return builds, nil
}

// ClaimReadyPackage atomically claims a package that is ready to build.
// A package is ready when all its in-graph dependencies have succeeded.
// Uses SELECT FOR UPDATE SKIP LOCKED for concurrent safety.
func (s *PostgresBuildStore) ClaimReadyPackage(ctx context.Context, buildID string) (*types.PackageJob, error) {
	// Use a transaction with FOR UPDATE SKIP LOCKED for atomic claiming
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// First, build a map of package statuses for dependency checking
	// (must complete this query before starting another)
	statusRows, err := tx.Query(ctx, `
		SELECT name, status FROM package_jobs WHERE build_id = $1
	`, buildID)
	if err != nil {
		return nil, fmt.Errorf("querying package statuses: %w", err)
	}

	statusMap := make(map[string]types.PackageStatus)
	inBuild := make(map[string]bool)
	for statusRows.Next() {
		var name string
		var status types.PackageStatus
		if err := statusRows.Scan(&name, &status); err != nil {
			statusRows.Close()
			return nil, fmt.Errorf("scanning status: %w", err)
		}
		statusMap[name] = status
		inBuild[name] = true
	}
	statusRows.Close()
	if err := statusRows.Err(); err != nil {
		return nil, fmt.Errorf("iterating statuses: %w", err)
	}

	// Now get all pending packages for this build, locking them
	rows, err := tx.Query(ctx, `
		SELECT id, name, dependencies
		FROM package_jobs
		WHERE build_id = $1 AND status = 'pending'
		ORDER BY position
		FOR UPDATE SKIP LOCKED
	`, buildID)
	if err != nil {
		return nil, fmt.Errorf("querying pending packages: %w", err)
	}

	// Find first ready package
	var claimID int
	var claimName string
	found := false

	for rows.Next() {
		var id int
		var name string
		var dependencies []string

		if err := rows.Scan(&id, &name, &dependencies); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning pending package: %w", err)
		}

		// Check if all in-graph dependencies have succeeded
		ready := true
		for _, dep := range dependencies {
			// Only check dependencies that are in this build
			if !inBuild[dep] {
				continue
			}
			if statusMap[dep] != types.PackageStatusSuccess {
				ready = false
				break
			}
		}

		if ready {
			claimID = id
			claimName = name
			found = true
			break
		}
	}
	rows.Close()

	if !found {
		return nil, nil
	}

	// Claim the package by updating its status
	now := time.Now()
	_, err = tx.Exec(ctx, `
		UPDATE package_jobs
		SET status = 'running', started_at = $2
		WHERE id = $1
	`, claimID, now)
	if err != nil {
		return nil, fmt.Errorf("claiming package: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing claim: %w", err)
	}

	// Fetch the full package job to return
	var pkg types.PackageJob
	var backendJSON, pipelinesJSON, sourceFilesJSON, metricsJSON []byte
	var errorStr, logPath, outputPath *string

	err = s.pool.QueryRow(ctx, `
		SELECT name, status, config_yaml, dependencies, started_at, finished_at,
		       error, log_path, output_path, backend, pipelines, source_files, metrics
		FROM package_jobs
		WHERE build_id = $1 AND name = $2
	`, buildID, claimName).Scan(
		&pkg.Name, &pkg.Status, &pkg.ConfigYAML, &pkg.Dependencies,
		&pkg.StartedAt, &pkg.FinishedAt, &errorStr, &logPath,
		&outputPath, &backendJSON, &pipelinesJSON, &sourceFilesJSON, &metricsJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("fetching claimed package: %w", err)
	}

	if errorStr != nil {
		pkg.Error = *errorStr
	}
	if logPath != nil {
		pkg.LogPath = *logPath
	}
	if outputPath != nil {
		pkg.OutputPath = *outputPath
	}

	if len(backendJSON) > 0 && string(backendJSON) != "null" {
		if err := json.Unmarshal(backendJSON, &pkg.Backend); err != nil {
			return nil, fmt.Errorf("unmarshaling backend: %w", err)
		}
	}
	if len(pipelinesJSON) > 0 {
		if err := json.Unmarshal(pipelinesJSON, &pkg.Pipelines); err != nil {
			return nil, fmt.Errorf("unmarshaling pipelines: %w", err)
		}
	}
	if len(sourceFilesJSON) > 0 {
		if err := json.Unmarshal(sourceFilesJSON, &pkg.SourceFiles); err != nil {
			return nil, fmt.Errorf("unmarshaling source files: %w", err)
		}
	}
	if len(metricsJSON) > 0 && string(metricsJSON) != "null" {
		if err := json.Unmarshal(metricsJSON, &pkg.Metrics); err != nil {
			return nil, fmt.Errorf("unmarshaling metrics: %w", err)
		}
	}

	return &pkg, nil
}

// UpdatePackageJob updates a package job within a build.
func (s *PostgresBuildStore) UpdatePackageJob(ctx context.Context, buildID string, pkg *types.PackageJob) error {
	var backendJSON, metricsJSON, pipelinesJSON, sourceFilesJSON []byte
	var err error

	if pkg.Backend != nil {
		backendJSON, err = json.Marshal(pkg.Backend)
		if err != nil {
			return fmt.Errorf("marshaling backend: %w", err)
		}
	}

	if pkg.Metrics != nil {
		metricsJSON, err = json.Marshal(pkg.Metrics)
		if err != nil {
			return fmt.Errorf("marshaling metrics: %w", err)
		}
	}

	if pkg.Pipelines != nil {
		pipelinesJSON, err = json.Marshal(pkg.Pipelines)
		if err != nil {
			return fmt.Errorf("marshaling pipelines: %w", err)
		}
	}

	if pkg.SourceFiles != nil {
		sourceFilesJSON, err = json.Marshal(pkg.SourceFiles)
		if err != nil {
			return fmt.Errorf("marshaling source files: %w", err)
		}
	}

	// Convert empty string to nil for error field
	var errorPtr *string
	if pkg.Error != "" {
		errorPtr = &pkg.Error
	}

	result, err := s.pool.Exec(ctx, `
		UPDATE package_jobs
		SET status = $3, started_at = $4, finished_at = $5, error = $6,
		    log_path = $7, output_path = $8, backend = $9, pipelines = COALESCE($10, pipelines),
		    source_files = COALESCE($11, source_files), metrics = $12
		WHERE build_id = $1 AND name = $2
	`, buildID, pkg.Name, pkg.Status, pkg.StartedAt, pkg.FinishedAt, errorPtr,
		pkg.LogPath, pkg.OutputPath, backendJSON, pipelinesJSON, sourceFilesJSON, metricsJSON)

	if err != nil {
		return fmt.Errorf("updating package job: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("package not found: %s", pkg.Name)
	}
	return nil
}

// scanPackageJob scans a package job from a database row.
func scanPackageJob(rows pgx.Rows) (*types.PackageJob, error) {
	var pkg types.PackageJob
	var backendJSON, pipelinesJSON, sourceFilesJSON, metricsJSON []byte
	var errorStr, logPath, outputPath *string

	err := rows.Scan(
		&pkg.Name, &pkg.Status, &pkg.ConfigYAML, &pkg.Dependencies,
		&pkg.StartedAt, &pkg.FinishedAt, &errorStr, &logPath,
		&outputPath, &backendJSON, &pipelinesJSON, &sourceFilesJSON, &metricsJSON,
	)
	if err != nil {
		return nil, err
	}

	if errorStr != nil {
		pkg.Error = *errorStr
	}
	if logPath != nil {
		pkg.LogPath = *logPath
	}
	if outputPath != nil {
		pkg.OutputPath = *outputPath
	}

	if len(backendJSON) > 0 && string(backendJSON) != "null" {
		if err := json.Unmarshal(backendJSON, &pkg.Backend); err != nil {
			return nil, fmt.Errorf("unmarshaling backend: %w", err)
		}
	}
	if len(pipelinesJSON) > 0 {
		if err := json.Unmarshal(pipelinesJSON, &pkg.Pipelines); err != nil {
			return nil, fmt.Errorf("unmarshaling pipelines: %w", err)
		}
	}
	if len(sourceFilesJSON) > 0 {
		if err := json.Unmarshal(sourceFilesJSON, &pkg.SourceFiles); err != nil {
			return nil, fmt.Errorf("unmarshaling source files: %w", err)
		}
	}
	if len(metricsJSON) > 0 && string(metricsJSON) != "null" {
		if err := json.Unmarshal(metricsJSON, &pkg.Metrics); err != nil {
			return nil, fmt.Errorf("unmarshaling metrics: %w", err)
		}
	}

	return &pkg, nil
}
