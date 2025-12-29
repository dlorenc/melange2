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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Capability stores paths and an associated map of capabilities and justification to include in a package.
// These capabilities will be set after pipelines run to avoid permissions issues with `setcap`.
// Empty justifications will result in an error.
type Capability struct {
	Path   string            `json:"path,omitempty" yaml:"path,omitempty"`
	Add    map[string]string `json:"add,omitempty" yaml:"add,omitempty"`
	Reason string            `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// validCapabilities contains a list of _in-use_ capabilities and their respective bits from existing package specs.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h#L106-L422
var validCapabilities = map[string]uint32{
	"cap_net_bind_service": 10,
	"cap_net_admin":        12,
	"cap_net_raw":          13,
	"cap_ipc_lock":         14,
	"cap_sys_admin":        21,
}

func getCapabilityValue(attr string) uint32 {
	if value, ok := validCapabilities[attr]; ok {
		return 1 << value
	}
	return 0
}

func validateCapabilities(setcap []Capability) error {
	var errs []error

	for _, cap := range setcap {
		for add := range cap.Add {
			// Allow for multiple capabilities per addition
			// e.g., cap_net_raw,cap_net_admin,cap_net_bind_service+eip
			for p := range strings.SplitSeq(add, ",") {
				if _, ok := validCapabilities[p]; !ok {
					errs = append(errs, fmt.Errorf("invalid capability %q for path %q", p, cap.Path))
				}
			}
		}
		if cap.Reason == "" {
			errs = append(errs, fmt.Errorf("unjustified reason for capability %q", cap.Add))
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errors.Join(errs...)
}

type capabilityData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

// ParseCapabilities processes all capabilities for a given path.
func ParseCapabilities(caps []Capability) (map[string]capabilityData, error) {
	pathCapabilities := map[string]capabilityData{}

	for _, c := range caps {
		for attrs, data := range c.Add {
			for attr := range strings.SplitSeq(attrs, ",") {
				capValues := getCapabilityValue(attr)
				effective, permitted, inheritable := parseCapability(data)

				caps, ok := pathCapabilities[c.Path]
				if !ok {
					caps = struct {
						Effective   uint32
						Permitted   uint32
						Inheritable uint32
					}{}
				}

				if effective {
					caps.Effective |= capValues
				}
				if permitted {
					caps.Permitted |= capValues
				}
				if inheritable {
					caps.Inheritable |= capValues
				}

				pathCapabilities[c.Path] = caps
			}
		}
	}

	return pathCapabilities, nil
}

// parseCapability determines which bits are set for a given capability.
func parseCapability(capFlag string) (effective, permitted, inheritable bool) {
	for _, c := range capFlag {
		switch c {
		case 'e':
			effective = true
		case 'p':
			permitted = true
		case 'i':
			inheritable = true
		}
	}
	return effective, permitted, inheritable
}

// EncodeCapability returns the byte slice necessary to set the final capability xattr.
func EncodeCapability(effectiveBits, permittedBits, inheritableBits uint32) []byte {
	revision := uint32(0x03000000)

	var flags uint32 = 0
	if effectiveBits != 0 {
		flags = 0x01
	}
	magic := revision | flags

	data := make([]byte, 24)

	binary.LittleEndian.PutUint32(data[0:4], magic)
	binary.LittleEndian.PutUint32(data[4:8], permittedBits)
	binary.LittleEndian.PutUint32(data[8:12], inheritableBits)

	binary.LittleEndian.PutUint32(data[12:16], 0)
	binary.LittleEndian.PutUint32(data[16:20], 0)
	binary.LittleEndian.PutUint32(data[20:24], 0)

	return data
}
