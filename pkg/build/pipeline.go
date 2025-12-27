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

package build

import (
	"embed"
	"fmt"
	"maps"
	"strconv"
	"strings"

	apkoTypes "chainguard.dev/apko/pkg/build/types"

	"github.com/dlorenc/melange2/pkg/cond"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/util"
)

const WorkDir = "/home/build"

func (sm *SubstitutionMap) MutateWith(with map[string]string) (map[string]string, error) {
	nw := maps.Clone(sm.Substitutions)

	for k, v := range with {
		// already mutated?
		if strings.HasPrefix(k, "${{") {
			nw[k] = v
		} else {
			nk := fmt.Sprintf("${{inputs.%s}}", k)
			nw[nk] = v
		}
	}

	// do the actual mutations
	for k, v := range nw {
		nval, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}
		nw[k] = nval
	}

	return nw, nil
}

type SubstitutionMap struct {
	Substitutions map[string]string
}

func (sm *SubstitutionMap) Subpackage(subpkg *config.Subpackage) *SubstitutionMap {
	nw := maps.Clone(sm.Substitutions)
	nw[config.SubstitutionSubPkgName] = subpkg.Name
	nw[config.SubstitutionContextName] = subpkg.Name
	nw[config.SubstitutionSubPkgDir] = fmt.Sprintf("/home/build/melange-out/%s", subpkg.Name)
	nw[config.SubstitutionTargetsContextdir] = nw[config.SubstitutionSubPkgDir]

	return &SubstitutionMap{nw}
}

func NewSubstitutionMap(cfg *config.Configuration, arch apkoTypes.Architecture, flavor string, buildOpts []string) (*SubstitutionMap, error) {
	pkg := cfg.Package

	nw := map[string]string{
		config.SubstitutionPackageName:        pkg.Name,
		config.SubstitutionPackageVersion:     pkg.Version,
		config.SubstitutionPackageEpoch:       strconv.FormatUint(pkg.Epoch, 10),
		config.SubstitutionPackageFullVersion: fmt.Sprintf("%s-r%d", pkg.Version, pkg.Epoch),
		config.SubstitutionPackageSrcdir:      "/home/build",
		config.SubstitutionTargetsOutdir:      "/home/build/melange-out",
		config.SubstitutionTargetsDestdir:     fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionTargetsContextdir:  fmt.Sprintf("/home/build/melange-out/%s", pkg.Name),
		config.SubstitutionContextName:        pkg.Name,
	}

	nw[config.SubstitutionHostTripletGnu] = arch.ToTriplet(flavor)
	nw[config.SubstitutionHostTripletRust] = arch.ToRustTriplet(flavor)
	nw[config.SubstitutionCrossTripletGnuGlibc] = arch.ToTriplet("gnu")
	nw[config.SubstitutionCrossTripletGnuMusl] = arch.ToTriplet("musl")
	nw[config.SubstitutionCrossTripletRustGlibc] = arch.ToRustTriplet("gnu")
	nw[config.SubstitutionCrossTripletRustMusl] = arch.ToRustTriplet("musl")
	nw[config.SubstitutionBuildArch] = arch.ToAPK()
	nw[config.SubstitutionBuildGoArch] = arch.String()

	// Retrieve vars from config
	subst_nw, err := cfg.GetVarsFromConfig()
	if err != nil {
		return nil, err
	}

	maps.Copy(nw, subst_nw)

	// Perform substitutions on current map
	if err := cfg.PerformVarSubstitutions(nw); err != nil {
		return nil, err
	}

	packageNames := []string{pkg.Name}
	for _, sp := range cfg.Subpackages {
		packageNames = append(packageNames, sp.Name)
	}

	for _, pn := range packageNames {
		k := fmt.Sprintf("${{targets.package.%s}}", pn)
		nw[k] = fmt.Sprintf("/home/build/melange-out/%s", pn)
	}

	for k := range cfg.Options {
		nk := fmt.Sprintf("${{options.%s.enabled}}", k)
		nw[nk] = "false"
	}

	for _, opt := range buildOpts {
		nk := fmt.Sprintf("${{options.%s.enabled}}", opt)
		nw[nk] = "true"
	}

	return &SubstitutionMap{nw}, nil
}

func validateWith(data map[string]string, inputs map[string]config.Input) (map[string]string, error) {
	if data == nil {
		data = make(map[string]string)
	}
	for k, v := range inputs {
		if data[k] == "" {
			data[k] = v.Default
		}
		if data[k] != "" {
			switch k {
			case "expected-sha256", "expected-sha512":
				if !matchValidShaChars(data[k]) || len(data[k]) != expectedShaLength(k) {
					return data, fmt.Errorf("checksum input %q for pipeline, invalid length", k)
				}
			case "expected-commit":
				if !matchValidShaChars(data[k]) || len(data[k]) != expectedShaLength(k) {
					return data, fmt.Errorf("expected commit %q for pipeline contains invalid characters or invalid sha length", k)
				}
			}
		}
		if v.Required && data[k] == "" {
			return data, fmt.Errorf("required input %q for pipeline is missing", k)
		}
	}

	return data, nil
}

func matchValidShaChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func shouldRun(ifs string) (bool, error) {
	if ifs == "" {
		return true, nil
	}

	result, err := cond.Evaluate(ifs)
	if err != nil {
		return false, fmt.Errorf("evaluating if-conditional %q: %w", ifs, err)
	}

	return result, nil
}

func expectedShaLength(shaType string) int {
	switch shaType {
	case "expected-sha256":
		return 64
	case "expected-sha512":
		return 128
	case "expected-commit":
		return 40
	}
	return 0
}

//go:embed pipelines/*
var PipelinesFS embed.FS
