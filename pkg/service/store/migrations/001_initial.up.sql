-- Migration: 001_initial
-- Description: Create initial schema for melange build store

-- Enum types for status tracking
CREATE TYPE build_status AS ENUM ('pending', 'running', 'success', 'failed', 'partial');
CREATE TYPE package_status AS ENUM ('pending', 'blocked', 'running', 'success', 'failed', 'skipped');

-- Main builds table
CREATE TABLE builds (
    id VARCHAR(36) PRIMARY KEY,
    status build_status NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    -- BuildSpec stored as JSONB for flexibility
    -- Contains: configs, git_source, pipelines, source_files, arch,
    -- backend_selector, with_test, debug, mode
    spec JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Indexes for efficient queries
CREATE INDEX idx_builds_status ON builds(status);
CREATE INDEX idx_builds_created_at ON builds(created_at);
-- Partial index for active builds (used by ListActiveBuilds)
CREATE INDEX idx_builds_active ON builds(status)
    WHERE status IN ('pending', 'running');

-- Package jobs table (normalized from Build.Packages)
CREATE TABLE package_jobs (
    id SERIAL PRIMARY KEY,
    build_id VARCHAR(36) NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status package_status NOT NULL DEFAULT 'pending',
    config_yaml TEXT NOT NULL,
    dependencies TEXT[] NOT NULL DEFAULT '{}',
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    error TEXT,
    log_path TEXT,
    output_path TEXT,
    -- Backend info stored as JSONB (nullable)
    backend JSONB,
    -- Pipelines map: path -> content
    pipelines JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Source files map: path -> content
    source_files JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Metrics stored as JSONB (nullable)
    metrics JSONB,
    -- Position in build order (for deterministic iteration)
    position INT NOT NULL,
    UNIQUE(build_id, name)
);

-- Indexes for package_jobs
CREATE INDEX idx_package_jobs_build_id ON package_jobs(build_id);
CREATE INDEX idx_package_jobs_status ON package_jobs(status);
-- Composite index for ClaimReadyPackage
CREATE INDEX idx_package_jobs_build_status ON package_jobs(build_id, status);
