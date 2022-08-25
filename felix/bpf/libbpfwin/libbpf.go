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

package libbpfwin

// #include "libbpf_api.h"
import "C"
import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/bpfutils"
)

type Obj struct {
	obj *C.struct_bpf_object

	xdpProgFD int
	xdpProgID string

	jumpMapFD int
}

type Map struct {
	bpfMap *C.struct_bpf_map
	bpfObj *C.struct_bpf_object
}

type Program struct {
	bpfProgram *C.struct_bpf_program
	bpfObj     *C.struct_bpf_object
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

func (m *Map) Fd() int {
	cMapName := C.CString(m.Name())
	defer C.free(unsafe.Pointer(cMapName))
	mapFD := C.bpf_map__get_map_fd_by_name(m.bpfObj, cMapName)
	return int(mapFD)
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

var xdpObj *Obj

func LoadXDPObject(filename string, showStats bool) (string, error) {
	var err error
	xdpObj, err = LoadObject(filename)
	if err != nil {
		return "", fmt.Errorf("error loading libbpf object %w", err)
	}
	log.Infof("XDP object file loaded %s", filename)

	err = ShowObjectDetails(xdpObj)
	if err != nil {
		return "", fmt.Errorf("error showing libbpf object %w", err)
	}

	cMapName := C.CString("cali_jump")
	defer C.free(unsafe.Pointer(cMapName))
	mapFD := C.bpf_map__get_map_fd_by_name(xdpObj.obj, cMapName)
	if mapFD <= 0 {
		return "", fmt.Errorf("Failed to get mapFD")
	}
	log.Infof("Got cali_jump mapFD %d", mapFD)
	xdpObj.jumpMapFD = int(mapFD)

	cProg0 := C.CString("calico_xdp_norm_pol_tail")
	defer C.free(unsafe.Pointer(cProg0))
	errno := C.bpf_update_jump_map(xdpObj.obj, cMapName, cProg0, 0)
	if errno < 0 {
		return "", fmt.Errorf("Failed to update jump map index 0")
	}

	cProg1 := C.CString("calico_xdp_accepted_entrypoint")
	defer C.free(unsafe.Pointer(cProg1))
	errno = C.bpf_update_jump_map(xdpObj.obj, cMapName, cProg1, 1)
	if errno < 0 {
		return "", fmt.Errorf("Failed to update jump map index 1")
	}

	cMapName = C.CString("trace_map")
	mapFD = C.bpf_map__get_map_fd_by_name(xdpObj.obj, cMapName)
	if mapFD <= 0 {
		return "", fmt.Errorf("Failed to get mapFD")
	}
	log.Infof("Got trace_map mapFD %d", mapFD)

	log.Info("Start to attach the program")
	cProgName := C.CString("xdp_calico_entry")
	defer C.free(unsafe.Pointer(cProgName))
	progFD := C.bpf_program__get_fd(xdpObj.obj, cProgName)

	if progFD <= 0 {
		return "", fmt.Errorf("Failed to get progFD")
	}

	log.Infof("Get progFD %d for xdp_calico_entry", progFD)

	ifindex := 16
	result := C.bpf_program__xdp_attach(xdpObj.obj, cProgName, C.int(ifindex))
	if result < 0 {
		log.Errorf("attach program failed %d", result)
		return "", fmt.Errorf("Failed to attach program")
	}
	log.Infof("Attach program done. ifindex %d", ifindex)

	if showStats {
		for {
			C.show_stats(C.int(mapFD))
			time.Sleep(10 * time.Second)
		}
	}

	return fmt.Sprintf("%d", xdpObj.jumpMapFD), nil
}

func LoadObject(filename string) (*Obj, error) {
	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))
	obj, err := C.bpf_program__xdp_load(cFilename)
	if obj == nil || err != nil {
		return nil, fmt.Errorf("error loading libbpf object %w", err)
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

// FirstProgram returns first bpf program of the object.
// Returns error if the program is nil.
func (o *Obj) FirstProgram() (*Program, error) {
	bpfProgram, err := C.bpf_program__next(nil, o.obj)
	if bpfProgram == nil || err != nil {
		return nil, fmt.Errorf("error getting first map %w", err)
	}
	return &Program{bpfProgram: bpfProgram, bpfObj: o.obj}, nil
}

func (p *Program) Name() string {
	name := C.bpf_program__name(p.bpfProgram)
	if name == nil {
		return ""
	}
	return C.GoString(name)
}

// NextProgram returns the successive maps given the first map.
// Returns nil, no error at the end of the list.
func (p *Program) NextProgram() (*Program, error) {
	bpfProgram, err := C.bpf_program__next(p.bpfProgram, p.bpfObj)
	if err != nil {
		return nil, fmt.Errorf("error getting next map %w", err)
	}
	if bpfProgram == nil {
		return nil, nil
	}
	return &Program{bpfProgram: bpfProgram, bpfObj: p.bpfObj}, nil
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
func GetMapFDByID(mapID int) (uint32, error) {
	fd, err := C.bpf_map__get_map_fd_by_id(C.uint(mapID))
	if err != nil {
		return 0, err
	}

	return uint32(fd), nil
}

func GetMapInfo(fd uint32) (int, int, int, int, error) {
	var map_info C.struct_bpf_map_info
	// _, err := C.bpf_map_get_info(C.int(fd), (*C.struct_bpf_map_info)(unsafe.Pointer(&map_info)))
	_, err := C.bpf_map__get_info(C.uint(fd), &map_info)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("Error get map info with fd %d: %w", fd, err)
	}
	return int(map_info._type),
		int(map_info.key_size),
		int(map_info.value_size),
		int(map_info.max_entries),
		nil
}

// Enum defined in ebpf-for-windows/include/ebpf_structs.h
var TypeStringToMapType = map[string]int{
	"hash":            1,
	"array":           2,
	"prog_array":      3,
	"percpu_hash":     4,
	"percpu_array":    5,
	"hash_of_maps":    6,
	"array_of_maps":   7,
	"lru_hash":        8,
	"lpm_trie":        9,
	"queue":           10,
	"lru_percpu_hash": 11,
	"stack":           12,
	"ringbuf":         13,
}

func CreateMap(map_type string, key_size int, value_size int, max_entries int, map_flags uint32) (int, error) {
	mapType, exist := TypeStringToMapType[map_type]
	if !exist {
		return -1, fmt.Errorf("Invalid map type")
	}

	log.Infof("Create map before fixing for windows: mapType %d, key_size %d, value_size %d, max_entries %d, map_flags %d\n",
		mapType, key_size, value_size, max_entries, map_flags)

	// Have to set map flags to 0 for Windows.
	map_flags = 0

	log.Infof("Create map after fixing for windows: mapType %d, key_size %d, value_size %d, max_entries %d, map_flags %d\n",
		mapType, key_size, value_size, max_entries, map_flags)

	fd := C.bpf_map__create(
		C.enum_bpf_map_type(mapType),
		C.int(key_size),
		C.int(value_size),
		C.int(max_entries),
		C.uint(map_flags),
	)

	if int(fd) <= 0 {
		return -1, fmt.Errorf("Failed to create map")
	}
	return int(fd), nil
}

func dumpAsm(insns asm.Insns) {
	for i, bytes := range insns {
		oneline := fmt.Sprintf("%d -- ", i)
		for _, b := range bytes {
			oneline += fmt.Sprintf("%02x ", b)
		}
		log.Infof("%s", oneline)
	}
}

func LoadBPFProgramFromInsns(insns asm.Insns, license string, progType uint32) (uint32, error) {
	dumpAsm(insns)

	cInsnBytes := C.CBytes(insns.AsBytes())
	defer C.free(cInsnBytes)
	cLicense := C.CString(license)
	defer C.free(unsafe.Pointer(cLicense))

	var logBuf unsafe.Pointer
	logSize := 10000
	if logSize > 0 {
		logBuf = C.malloc((C.size_t)(logSize))
		defer C.free(logBuf)
	}

	fd, err := C.bpf_program__load_bytecode(C.enum_bpf_prog_type(progType), cInsnBytes, C.size_t(len(insns)), cLicense, 0, logBuf, C.size_t(logSize))

	log.Infof("load byte code returns %d, err %v", fd, err)
	if err != nil {
		goLog := strings.TrimSpace(C.GoString((*C.char)(logBuf)))
		fmt.Printf("BPF_PROG_LOAD failed %v\n", goLog)
		if len(goLog) > 0 {
			for _, l := range strings.Split(goLog, "\n") {
				fmt.Printf("BPF Verifier:    ", l)
			}
		} else if logSize > 0 {
			fmt.Printf("Verifier log was empty.")
		}
		fmt.Println("\n")
	}

	if err != nil {
		return 0, err
	}
	return uint32(fd), nil
}

func UpdateMapEntry(mapFD uint32, k, v []byte) error {
	cK := C.CBytes(k)
	defer C.free(cK)
	cV := C.CBytes(v)
	defer C.free(cV)

	_, err := C.bpf_map__update_elem(C.uint(mapFD), cK, cV, 0)
	if err != nil {
		return err
	}
	return nil
}

func GetMapEntry(mapFD uint32, k []byte, valueSize int) ([]byte, error) {
	log.Infof("GetMapEntry got mapFD %d, key %x", mapFD, k)
	val := make([]byte, valueSize)

	_, err := C.bpf_map__lookup_elem(C.uint(mapFD), unsafe.Pointer(&k[0]), unsafe.Pointer(&val[0]))
	if err != nil {
		return nil, err
	}

	return val, nil
}

func DeleteMapEntry(mapFD uint32, k []byte, valueSize int) error {
	_, err := C.bpf_map__delete_elem(C.uint(mapFD), unsafe.Pointer(&k[0]))
	return err
}

func ShowMapEntries(mapFD uint32, valueSize int) error {
	k := make([]byte, 4)
	index := 0
	binary.LittleEndian.PutUint32(k, uint32(index))
	for {
		readback, err := GetMapEntry(mapFD, k, valueSize)
		if err != nil {
			log.Errorf("GetMapEntry failed to get with err %v", err)
			return err
		}
		log.Infof("GetMapEntry got key %d, value %x", index, readback)
		break
	}
	return nil
}

//--------------------------------------
// The following is for ebpfwin functions

func RunProgram() int {
	id := C.run_load_program()
	return int(id)
}

func RunAnotherProgram() int {
	// id := C.xsk_prog_load()
	id := C.multiple_tail_calls_test()
	return int(id)
}

func ShowObjectDetails(obj *Obj) error {
	m0, err := obj.FirstMap()
	if err != nil {
		log.WithError(err).Errorf("Failed to get first map")
		return err
	}

	log.Infof("First map is %s, fd %d", m0.Name(), m0.Fd())

	m := m0
	for {
		m, err = m.NextMap()
		if err != nil {
			log.WithError(err).Errorf("Failed to get next map")
			return err
		}

		if m == nil {
			log.Info("No more map available\n\n")
			break
		}

		t, keySize, valueSize, maxEntries, err := GetMapInfo(uint32(m.Fd()))
		if err != nil {
			log.WithError(err).Errorf("Failed to get map info")
			return err
		}

		log.Infof("Next map is %s, fd %d -- type: %d, keySize %d, valueSize %d, maxEntries %d",
			m.Name(), m.Fd(), t, keySize, valueSize, maxEntries)
	}

	p0, err := obj.FirstProgram()
	if err != nil {
		log.WithError(err).Errorf("Failed to get first program")
		return err
	}

	log.Infof("First program is %s", p0.Name())

	p := p0
	for {
		p, err = p.NextProgram()
		if err != nil {
			log.WithError(err).Errorf("Failed to get next program")
			return err
		}

		if p == nil {
			log.Info("No more program available\n\n")
			break
		}

		log.Infof("Next program is %s", p.Name())
	}
	return nil
}

func ObjectTest(path string, progName string) error {
	obj, err := LoadObject(path)
	if err != nil {
		log.WithError(err).Errorf("Failed to open object file %s", path)
		return err
	}

	cProgName := C.CString(progName)
	defer C.free(unsafe.Pointer(cProgName))
	progFD := C.bpf_program__get_fd(obj.obj, cProgName)

	if progFD <= 0 {
		return fmt.Errorf("Failed to get progFD")
	}

	log.Infof("Get progFD %d for %s", progFD, progName)

	cMapName := C.CString("cali_jump")
	defer C.free(unsafe.Pointer(cMapName))
	mapFD := C.bpf_map__get_map_fd_by_name(obj.obj, cMapName)
	if mapFD <= 0 {
		return fmt.Errorf("Failed to get mapFD")
	}
	log.Infof("Get mapFD %d", mapFD)

	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))
	err = UpdateMapEntry(uint32(mapFD), k, v)
	if err != nil {
		log.WithError(err).Errorf("Failed to update jump map %s %s", path, progName)
		return err
	}

	// load sample program
	sample_id := C.run_load_sample_program()
	sampleID := int(sample_id)
	log.Infof("Get progFD %d for sample program", sampleID)

	sampleKey := 1
	binary.LittleEndian.PutUint32(k, uint32(sampleKey))
	binary.LittleEndian.PutUint32(v, uint32(sampleID))
	err = UpdateMapEntry(uint32(mapFD), k, v)
	if err != nil {
		log.WithError(err).Errorf("Failed to update jump map %s %s", path, progName)
		return err
	}

	time.Sleep(3 * time.Second)

	obj.Close()
	return nil
}
