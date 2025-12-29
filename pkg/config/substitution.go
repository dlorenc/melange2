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
	"fmt"
	"sort"
	"strconv"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"github.com/dlorenc/melange2/pkg/util"
)

// buildConfigMap builds a map used to prepare a replacer for variable substitution.
func buildConfigMap(cfg *Configuration) map[string]string {
	out := map[string]string{
		SubstitutionPackageName:        cfg.Package.Name,
		SubstitutionPackageVersion:     cfg.Package.Version,
		SubstitutionPackageDescription: cfg.Package.Description,
		SubstitutionPackageEpoch:       strconv.FormatUint(cfg.Package.Epoch, 10),
		SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%d", cfg.Package.Version, cfg.Package.Epoch),
	}

	for k, v := range cfg.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)
		out[nk] = v
	}

	return out
}

func replacerFromMap(with map[string]string) *strings.Replacer {
	replacements := []string{}
	for k, v := range with {
		replacements = append(replacements, k, v)
	}
	return strings.NewReplacer(replacements...)
}

func replaceAll(r *strings.Replacer, in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.Replace(s)
	}
	return out
}

func replaceNeeds(r *strings.Replacer, in *Needs) *Needs {
	if in == nil {
		return nil
	}
	return &Needs{
		Packages: replaceAll(r, in.Packages),
	}
}

func replaceMap(r *strings.Replacer, in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}

	replacedWith := make(map[string]string, len(in))
	for key, value := range in {
		replacedWith[key] = r.Replace(value)
	}
	return replacedWith
}

func replaceEntrypoint(r *strings.Replacer, in apko_types.ImageEntrypoint) apko_types.ImageEntrypoint {
	return apko_types.ImageEntrypoint{
		Type:          in.Type,
		Command:       r.Replace(in.Command),
		ShellFragment: r.Replace(in.ShellFragment),
		Services:      replaceMap(r, in.Services),
	}
}

func replaceImageContents(r *strings.Replacer, in apko_types.ImageContents) apko_types.ImageContents {
	return apko_types.ImageContents{
		BuildRepositories: replaceAll(r, in.BuildRepositories),
		Repositories:      replaceAll(r, in.Repositories),
		Keyring:           replaceAll(r, in.Keyring),
		Packages:          replaceAll(r, in.Packages),
		BaseImage:         in.BaseImage, // BaseImage is an ImageRef, not a simple string to replace
	}
}

func replaceImageConfig(r *strings.Replacer, in apko_types.ImageConfiguration) apko_types.ImageConfiguration {
	return apko_types.ImageConfiguration{
		Contents:    replaceImageContents(r, in.Contents),
		Entrypoint:  replaceEntrypoint(r, in.Entrypoint),
		Cmd:         r.Replace(in.Cmd),
		StopSignal:  r.Replace(in.StopSignal),
		WorkDir:     r.Replace(in.WorkDir),
		Accounts:    in.Accounts, // Complex struct, typically not variable-substituted
		Archs:       in.Archs,    // Architecture list, not variable-substituted
		Environment: replaceMap(r, in.Environment),
		Paths:       in.Paths, // Complex struct with file permissions, not variable-substituted
		VCSUrl:      r.Replace(in.VCSUrl),
		Annotations: replaceMap(r, in.Annotations),
		Include:     in.Include, //nolint:staticcheck // Deprecated field preserved for compatibility
		Volumes:     replaceAll(r, in.Volumes),
	}
}

func replacePipeline(r *strings.Replacer, in Pipeline) Pipeline {
	return Pipeline{
		Name:        r.Replace(in.Name),
		Uses:        in.Uses,
		With:        replaceMap(r, in.With),
		Runs:        r.Replace(in.Runs),
		Pipeline:    replacePipelines(r, in.Pipeline),
		Inputs:      in.Inputs,
		Needs:       replaceNeeds(r, in.Needs),
		Label:       in.Label,
		If:          r.Replace(in.If),
		Assertions:  in.Assertions,
		WorkDir:     r.Replace(in.WorkDir),
		Environment: replaceMap(r, in.Environment),
	}
}

func replacePipelines(r *strings.Replacer, in []Pipeline) []Pipeline {
	if in == nil {
		return nil
	}

	out := make([]Pipeline, 0, len(in))
	for _, p := range in {
		out = append(out, replacePipeline(r, p))
	}
	return out
}

func replaceTest(r *strings.Replacer, in *Test) *Test {
	if in == nil {
		return nil
	}
	return &Test{
		Environment: replaceImageConfig(r, in.Environment),
		Pipeline:    replacePipelines(r, in.Pipeline),
	}
}

func replaceScriptlets(r *strings.Replacer, in *Scriptlets) *Scriptlets {
	if in == nil {
		return nil
	}

	return &Scriptlets{
		Trigger: Trigger{
			Script: r.Replace(in.Trigger.Script),
			Paths:  replaceAll(r, in.Trigger.Paths),
		},
		PreInstall:    r.Replace(in.PreInstall),
		PostInstall:   r.Replace(in.PostInstall),
		PreDeinstall:  r.Replace(in.PreDeinstall),
		PostDeinstall: r.Replace(in.PostDeinstall),
		PreUpgrade:    r.Replace(in.PreUpgrade),
		PostUpgrade:   r.Replace(in.PostUpgrade),
	}
}

// replaceCommit defaults to value of in parameter unless commit is explicitly specified.
func replaceCommit(commit string, in string) string {
	if in == "" {
		return commit
	}
	return in
}

func replaceDependencies(r *strings.Replacer, in Dependencies) Dependencies {
	return Dependencies{
		Runtime:          replaceAll(r, in.Runtime),
		Provides:         replaceAll(r, in.Provides),
		Replaces:         replaceAll(r, in.Replaces),
		ProviderPriority: r.Replace(in.ProviderPriority),
		ReplacesPriority: r.Replace(in.ReplacesPriority),
	}
}

func replacePackage(r *strings.Replacer, commit string, in Package) Package {
	return Package{
		Name:               r.Replace(in.Name),
		Version:            r.Replace(in.Version),
		Epoch:              in.Epoch,
		Description:        r.Replace(in.Description),
		Annotations:        replaceMap(r, in.Annotations),
		URL:                r.Replace(in.URL),
		Commit:             replaceCommit(commit, in.Commit),
		TargetArchitecture: replaceAll(r, in.TargetArchitecture),
		Copyright:          in.Copyright,
		Dependencies:       replaceDependencies(r, in.Dependencies),
		Options:            in.Options,
		Scriptlets:         replaceScriptlets(r, in.Scriptlets),
		Checks:             in.Checks,
		CPE:                in.CPE,
		Timeout:            in.Timeout,
		Resources:          in.Resources,
		TestResources:      in.TestResources,
		SetCap:             in.SetCap,
	}
}

func replaceSubpackage(r *strings.Replacer, detectedCommit string, in Subpackage) Subpackage {
	return Subpackage{
		If:           r.Replace(in.If),
		Name:         r.Replace(in.Name),
		Pipeline:     replacePipelines(r, in.Pipeline),
		Dependencies: replaceDependencies(r, in.Dependencies),
		Options:      in.Options,
		Scriptlets:   replaceScriptlets(r, in.Scriptlets),
		Description:  r.Replace(in.Description),
		URL:          r.Replace(in.URL),
		Commit:       replaceCommit(detectedCommit, in.Commit),
		Checks:       in.Checks,
		Test:         replaceTest(r, in.Test),
	}
}

// mutateSlice applies substitutions to a slice of strings in place.
func mutateSlice(subst map[string]string, slice []string, fieldName string) error {
	for i, val := range slice {
		mutated, err := util.MutateStringFromMap(subst, val)
		if err != nil {
			return fmt.Errorf("failed to apply replacement to %s %q: %w", fieldName, val, err)
		}
		slice[i] = mutated
	}
	return nil
}

// mutateString applies substitutions to a single string pointer.
func mutateString(subst map[string]string, ptr *string, fieldName string) error {
	mutated, err := util.MutateStringFromMap(subst, *ptr)
	if err != nil {
		return fmt.Errorf("failed to apply replacement to %s %q: %w", fieldName, *ptr, err)
	}
	*ptr = mutated
	return nil
}

// ApplyDependencySubstitutions applies variable substitutions to all dependency fields
// in the main package and subpackages.
func (cfg *Configuration) ApplyDependencySubstitutions() error {
	subst := buildConfigMap(cfg)
	if err := cfg.PerformVarSubstitutions(subst); err != nil {
		return fmt.Errorf("applying variable substitutions: %w", err)
	}

	// Apply substitutions to main package dependencies
	deps := &cfg.Package.Dependencies
	if err := mutateSlice(subst, deps.Provides, "provides"); err != nil {
		return err
	}
	if err := mutateSlice(subst, deps.Runtime, "runtime dependency"); err != nil {
		return err
	}
	if err := mutateSlice(subst, deps.Replaces, "replaces"); err != nil {
		return err
	}
	if err := mutateString(subst, &deps.ProviderPriority, "provider priority"); err != nil {
		return err
	}
	if err := mutateString(subst, &deps.ReplacesPriority, "replaces priority"); err != nil {
		return err
	}

	// Apply substitutions to subpackage dependencies
	for i := range cfg.Subpackages {
		sp := &cfg.Subpackages[i]
		spDeps := &sp.Dependencies
		if err := mutateSlice(subst, spDeps.Provides, fmt.Sprintf("%q provides", sp.Name)); err != nil {
			return err
		}
		if err := mutateSlice(subst, spDeps.Runtime, fmt.Sprintf("%q runtime dependency", sp.Name)); err != nil {
			return err
		}
		if err := mutateSlice(subst, spDeps.Replaces, fmt.Sprintf("%q replaces", sp.Name)); err != nil {
			return err
		}
		if err := mutateString(subst, &spDeps.ProviderPriority, fmt.Sprintf("%q provider priority", sp.Name)); err != nil {
			return err
		}
		if err := mutateString(subst, &spDeps.ReplacesPriority, fmt.Sprintf("%q replaces priority", sp.Name)); err != nil {
			return err
		}
	}

	return nil
}

// ApplyPackageSubstitutions applies variable substitutions to environment package lists.
func (cfg *Configuration) ApplyPackageSubstitutions() error {
	subst := buildConfigMap(cfg)
	if err := cfg.PerformVarSubstitutions(subst); err != nil {
		return fmt.Errorf("applying variable substitutions for packages: %w", err)
	}

	// Apply to main environment packages
	if err := mutateSlice(subst, cfg.Environment.Contents.Packages, "package"); err != nil {
		return err
	}

	// Apply to test environment packages
	if cfg.Test != nil {
		if err := mutateSlice(subst, cfg.Test.Environment.Contents.Packages, "test package"); err != nil {
			return err
		}
	}

	// Apply to subpackage test environment packages
	for i := range cfg.Subpackages {
		sp := &cfg.Subpackages[i]
		if sp.Test != nil {
			if err := mutateSlice(subst, sp.Test.Environment.Contents.Packages, fmt.Sprintf("subpackage %q test", sp.Name)); err != nil {
				return err
			}
		}
	}

	return nil
}

func replaceSubpackages(r *strings.Replacer, datas map[string]DataItems, cfg Configuration, in []Subpackage) ([]Subpackage, error) {
	out := make([]Subpackage, 0, len(in))

	for i, sp := range in {
		if sp.Commit == "" {
			sp.Commit = cfg.Package.Commit
		}

		if sp.Range == "" {
			out = append(out, replaceSubpackage(r, cfg.Package.Commit, sp))
			continue
		}

		items, ok := datas[sp.Range]
		if !ok {
			return nil, fmt.Errorf("subpackages[%d] (%q) specified undefined range: %q", i, sp.Name, sp.Range)
		}

		// Ensure iterating over items is deterministic by sorting keys alphabetically
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		configMap := buildConfigMap(&cfg)
		if err := cfg.PerformVarSubstitutions(configMap); err != nil {
			return nil, fmt.Errorf("applying variable substitutions: %w", err)
		}

		for _, k := range keys {
			v := items[k]
			configMap["${{range.key}}"] = k
			configMap["${{range.value}}"] = v
			r := replacerFromMap(configMap)

			thingToAdd := replaceSubpackage(r, cfg.Package.Commit, sp)

			out = append(out, thingToAdd)
		}
	}

	return out, nil
}
