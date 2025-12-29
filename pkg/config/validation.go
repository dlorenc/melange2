// Copyright 2022 Chainguard, Inc.
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

package config

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/chainguard-dev/clog"
)

// ErrInvalidConfiguration is returned when a configuration is invalid.
type ErrInvalidConfiguration struct {
	Problem error
}

func (e ErrInvalidConfiguration) Error() string {
	return fmt.Sprintf("build configuration is invalid: %v", e.Problem)
}

func (e ErrInvalidConfiguration) Unwrap() error {
	return e.Problem
}

var packageNameRegex = regexp.MustCompile(`^[a-zA-Z\d][a-zA-Z\d+_.-]*$`)

func (cfg Configuration) validate(ctx context.Context) error {
	if !packageNameRegex.MatchString(cfg.Package.Name) {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("package name must match regex %q", packageNameRegex)}
	}

	if cfg.Package.Version == "" {
		return ErrInvalidConfiguration{Problem: errors.New("package version must not be empty")}
	}

	// Note: Version format validation is complex - versions can contain variables,
	// pre-release tags, etc. Consider adding semver-like validation in the future.

	if err := validateDependenciesPriorities(cfg.Package.Dependencies); err != nil {
		return ErrInvalidConfiguration{Problem: errors.New("priority must convert to integer")}
	}
	if err := validatePipelines(ctx, cfg.Pipeline); err != nil {
		return ErrInvalidConfiguration{Problem: err}
	}
	if err := validateCapabilities(cfg.Package.SetCap); err != nil {
		return ErrInvalidConfiguration{Problem: err}
	}

	saw := map[string]int{cfg.Package.Name: -1}
	for i, sp := range cfg.Subpackages {
		if extant, ok := saw[sp.Name]; ok {
			if extant == -1 {
				return ErrInvalidConfiguration{
					Problem: fmt.Errorf("subpackage[%d] has same name as main package: %q", i, sp.Name),
				}
			} else {
				return ErrInvalidConfiguration{
					Problem: fmt.Errorf("saw duplicate subpackage name %q (subpackages index: %d and %d)", sp.Name, extant, i),
				}
			}
		}

		saw[sp.Name] = i

		if !packageNameRegex.MatchString(sp.Name) {
			return ErrInvalidConfiguration{Problem: fmt.Errorf("subpackage name %q (subpackages index: %d) must match regex %q", sp.Name, i, packageNameRegex)}
		}
		if err := validateDependenciesPriorities(sp.Dependencies); err != nil {
			return ErrInvalidConfiguration{Problem: errors.New("priority must convert to integer")}
		}
		if err := validatePipelines(ctx, sp.Pipeline); err != nil {
			return ErrInvalidConfiguration{Problem: err}
		}
		if err := validateCapabilities(sp.SetCap); err != nil {
			return ErrInvalidConfiguration{Problem: err}
		}
	}

	if err := validateCPE(cfg.Package.CPE); err != nil {
		return ErrInvalidConfiguration{Problem: fmt.Errorf("CPE validation: %w", err)}
	}

	return nil
}

func pipelineName(p Pipeline, i int) string {
	if p.Name != "" {
		return strconv.Quote(p.Name)
	}

	if p.Uses != "" {
		return strconv.Quote(p.Uses)
	}

	return fmt.Sprintf("[%d]", i)
}

func validatePipelines(ctx context.Context, ps []Pipeline) error {
	log := clog.FromContext(ctx)
	for i, p := range ps {
		if p.With != nil && p.Uses == "" {
			return fmt.Errorf("pipeline contains with but no uses")
		}

		if p.Uses != "" && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both uses %q and runs", p.Uses)
		}

		if p.Uses != "" && len(p.Pipeline) > 0 {
			log.Warnf("pipeline %s contains both uses and a pipeline", pipelineName(p, i))
		}

		if len(p.With) > 0 && p.Runs != "" {
			return fmt.Errorf("pipeline cannot contain both with and runs")
		}

		if err := validatePipelines(ctx, p.Pipeline); err != nil {
			return fmt.Errorf("validating pipeline %s children: %w", pipelineName(p, i), err)
		}
	}
	return nil
}

func validateDependenciesPriorities(deps Dependencies) error {
	priorities := []string{deps.ProviderPriority, deps.ReplacesPriority}
	for _, priority := range priorities {
		if priority == "" {
			continue
		}
		_, err := strconv.Atoi(priority)
		if err != nil {
			return err
		}
	}
	return nil
}

func validateCPE(cpe CPE) error {
	if cpe.Part != "" && cpe.Part != "a" {
		return fmt.Errorf("invalid CPE part (must be 'a' for application, if specified): %q", cpe.Part)
	}

	if (cpe.Vendor == "") != (cpe.Product == "") {
		return errors.New("vendor and product must each be set if the other is set")
	}

	const all = "*"
	if cpe.Vendor == all {
		return fmt.Errorf("invalid CPE vendor: %q", cpe.Vendor)
	}
	if cpe.Product == all {
		return fmt.Errorf("invalid CPE product: %q", cpe.Product)
	}

	if err := validateCPEField(cpe.Vendor); err != nil {
		return fmt.Errorf("invalid vendor: %w", err)
	}
	if err := validateCPEField(cpe.Product); err != nil {
		return fmt.Errorf("invalid product: %w", err)
	}
	if err := validateCPEField(cpe.Edition); err != nil {
		return fmt.Errorf("invalid edition: %w", err)
	}
	if err := validateCPEField(cpe.Language); err != nil {
		return fmt.Errorf("invalid language: %w", err)
	}
	if err := validateCPEField(cpe.SWEdition); err != nil {
		return fmt.Errorf("invalid software edition: %w", err)
	}
	if err := validateCPEField(cpe.TargetSW); err != nil {
		return fmt.Errorf("invalid target software: %w", err)
	}
	if err := validateCPEField(cpe.TargetHW); err != nil {
		return fmt.Errorf("invalid target hardware: %w", err)
	}
	if err := validateCPEField(cpe.Other); err != nil {
		return fmt.Errorf("invalid other field: %w", err)
	}

	return nil
}

var cpeFieldRegex = regexp.MustCompile(`^[a-z\d][a-z\d+_.-]*$`)

func validateCPEField(val string) error {
	if val == "" {
		return nil
	}

	if !cpeFieldRegex.MatchString(val) {
		return fmt.Errorf("invalid CPE field value %q, must match regex %q", val, cpeFieldRegex.String())
	}

	return nil
}
