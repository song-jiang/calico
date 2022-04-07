// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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

package ebpfwin

// #include "libbpf_api.h"
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/projectcalico/calico/felix/bpf/bpfutils"
)

type Obj struct {
	obj *C.struct_bpf_object
}

type Map struct {
	bpfMap *C.struct_bpf_map
	bpfObj *C.struct_bpf_object
}

const MapTypeProgrArray = C.BPF_MAP_TYPE_PROG_ARRAY

type QdiskHook string

const (
	QdiskIngress QdiskHook = "ingress"
	QdiskEgress  QdiskHook = "egress"
)

// real functions
func (m *Map) Name() string {
	name := C.bpf_map__name(m.bpfMap)
	if name == nil {
		return ""
	}
	return C.GoString(name)
}

func (m *Map) Type() int {
	mapType := C.bpf_map__type(m.bpfMap)
	return int(mapType)
}

func (m *Map) SetPinPath(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	errno := C.bpf_map_set_pin_path(m.bpfMap, cPath)
	if errno != 0 {
		err := syscall.Errno(errno)
		return fmt.Errorf("pinning map failed %w", err)
	}
	return nil
}

func (m *Map) SetMapSize(size uint32) error {
	_, err := C.bpf_map__set_max_entries(m.bpfMap, C.uint(size))
	if err != nil {
		return fmt.Errorf("setting %s map size failed %w", m.Name(), err)
	}
	return nil
}

func (m *Map) IsMapInternal() bool {
	return bool(C.bpf_map__is_internal(m.bpfMap))
}

func OpenObject(filename string) (*Obj, error) {
	bpfutils.IncreaseLockedMemoryQuota()
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj, err := C.bpf_obj_open(cFilename)
	if obj == nil || err != nil {
		return nil, fmt.Errorf("error opening libbpf object %w", err)
	}
	return &Obj{obj: obj}, nil
}

func (o *Obj) Load() error {
	_, err := C.bpf_obj_load(o.obj)
	if err != nil {
		return fmt.Errorf("error loading object %w", err)
	}
	return nil
}

// FirstMap returns first bpf map of the object.
// Returns error if the map is nil.
func (o *Obj) FirstMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(nil, o.obj)
	if bpfMap == nil || err != nil {
		return nil, fmt.Errorf("error getting first map %w", err)
	}
	return &Map{bpfMap: bpfMap, bpfObj: o.obj}, nil
}

// NextMap returns the successive maps given the first map.
// Returns nil, no error at the end of the list.
func (m *Map) NextMap() (*Map, error) {
	bpfMap, err := C.bpf_map__next(m.bpfMap, m.bpfObj)
	if err != nil {
		return nil, fmt.Errorf("error getting next map %w", err)
	}
	if bpfMap == nil {
		return nil, nil
	}
	return &Map{bpfMap: bpfMap, bpfObj: m.bpfObj}, nil
}

type Link struct {
	link *C.struct_bpf_link
}

func (l *Link) Close() error {
	if l.link != nil {
		err := C.bpf_link_destroy(l.link)
		if err != 0 {
			return fmt.Errorf("error destroying link: %v", err)
		}
		l.link = nil
		return nil
	}
	return fmt.Errorf("link nil")
}

func (o *Obj) UpdateJumpMap(mapName, progName string, mapIndex int) error {
	cMapName := C.CString(mapName)
	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cMapName))
	defer C.free(unsafe.Pointer(cProgName))
	_, err := C.bpf_update_jump_map(o.obj, cMapName, cProgName, C.int(mapIndex))
	if err != nil {
		return fmt.Errorf("Error updating %s at index %d: %w", mapName, mapIndex, err)
	}
	return nil
}

func (o *Obj) Close() error {
	if o.obj != nil {
		C.bpf_object__close(o.obj)
		o.obj = nil
		return nil
	}
	return fmt.Errorf("error: libbpf obj nil")
}

func NumPossibleCPUs() (int, error) {
	ncpus := int(C.num_possible_cpu())
	if ncpus < 0 {
		return ncpus, fmt.Errorf("Invalid number of CPUs: %d", ncpus)
	}
	return ncpus, nil
}

// The following is the function for syscall_windows

func GetMapInfo(fd int) (int, int, int, int, error) {
	var map_info C.struct_bpf_map_info
	_, err := C.bpf_map_get_info(C.int(fd), &map_info)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("Error get map info with fd %d: %w", fd, err)
	}
	return int(map_info._type),
		int(map_info.key_size),
		int(map_info.value_size),
		int(map_info.max_entries),
		nil
}
