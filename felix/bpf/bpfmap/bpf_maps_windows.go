// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package bpfmap

import (
	"fmt"
	"os"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/state"
)

func CreateBPFMapContext(ipsetsMapSize, natFEMapSize, natBEMapSize, natAffMapSize, routeMapSize, ctMapSize int, repinEnabled bool) *bpf.MapContext {
	bpfMapContext := &bpf.MapContext{
		RepinningEnabled: repinEnabled,
		MapSizes:         map[string]uint32{},
	}
	bpfMapContext.MapSizes[ipsets.MapParameters.VersionedName()] = uint32(ipsetsMapSize)

	bpfMapContext.MapSizes[state.MapParameters.VersionedName()] = uint32(state.MapParameters.MaxEntries)
	bpfMapContext.MapSizes[failsafes.MapParams.VersionedName()] = uint32(failsafes.MapParams.MaxEntries)

	return bpfMapContext
}

func MigrateDataFromOldMap(mc *bpf.MapContext) {
	return
}

func DestroyBPFMaps(mc *bpf.MapContext) {
	maps := []bpf.Map{mc.IpsetsMap, mc.StateMap, mc.ArpMap, mc.FailsafesMap, mc.FrontendMap,
		mc.BackendMap, mc.AffinityMap, mc.RouteMap, mc.CtMap, mc.SrMsgMap, mc.CtNatsMap}
	for _, m := range maps {
		os.Remove(m.(*bpf.PinnedMap).Path())
		m.(*bpf.PinnedMap).Close()
	}
}

func CreateBPFMaps(mc *bpf.MapContext) error {
	maps := []bpf.Map{}

	mc.IpsetsMap = ipsets.Map(mc)
	maps = append(maps, mc.IpsetsMap)

	mc.StateMap = state.Map(mc)
	maps = append(maps, mc.StateMap)

	mc.FailsafesMap = failsafes.Map(mc)
	maps = append(maps, mc.FailsafesMap)

	for _, bpfMap := range maps {
		err := bpfMap.EnsureExists()
		if err != nil {
			return fmt.Errorf("Failed to create %s map, err=%w", bpfMap.GetName(), err)
		}
	}
	return nil
}
