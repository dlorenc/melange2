-- Migration: 001_initial (rollback)
-- Description: Drop initial schema for melange build store

DROP TABLE IF EXISTS package_jobs;
DROP TABLE IF EXISTS builds;
DROP TYPE IF EXISTS package_status;
DROP TYPE IF EXISTS build_status;
