// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
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

package bpf

// #include "bpf_syscall_windows.h"
import "C"
import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/libbpfwin"
)

func SyscallSupport() bool {
	return true
}

func GetMapFDByPin(filename string) (MapFD, error) {
	log.Debugf("GetMapFDByPin(%v)", filename)
	// TODO

	return 0, fmt.Errorf("TODO, not implemented.")
}

func GetMapFDByID(mapID int) (MapFD, error) {
	fd, err := libbpfwin.GetMapFDByID(mapID)
	return MapFD(fd), err
}

const defaultLogSize = 1024 * 1024
const maxLogSize = 128 * 1024 * 1024

func LoadBPFProgramFromInsns(insns asm.Insns, license string, progType uint32) (ProgFD, error) {
	log.Debugf("LoadBPFProgramFromInsns(%v, %v, %v)", insns, license, progType)
	fd, err := libbpfwin.LoadBPFProgramFromInsns(insns, license, progType)
	return ProgFD(fd), err
}

func RunBPFProgram(fd ProgFD, dataIn []byte, repeat int) (ProgResult, error) {
	log.Debugf("RunBPFProgram(%v, ..., %v)， not supported on Windows yet", fd, repeat)

	return ProgResult{}, nil
}

func UpdateMapEntry(mapFD MapFD, k, v []byte) error {
	log.Debugf("UpdateMapEntry(%v, %v, %v)", mapFD, k, v)

	err := checkMapIfDebug(mapFD, len(k), len(v))
	if err != nil {
		return err
	}

	return libbpfwin.UpdateMapEntry(uint32(mapFD), k, v)
}

func GetMapEntry(mapFD MapFD, k []byte, valueSize int) ([]byte, error) {
	log.Debugf("GetMapEntry(%v, %v, %v)", mapFD, k, valueSize)

	return libbpfwin.GetMapEntry(uint32(mapFD), k, valueSize)
}

func checkMapIfDebug(mapFD MapFD, keySize, valueSize int) error {
	// Do nothing at moment for Windows.
	return nil
}

func GetMapInfo(fd MapFD) (*MapInfo, error) {
	mapType, keySize, valueSize, maxEntries, err := libbpfwin.GetMapInfo(uint32(fd))
	if err != nil {
		return nil, err
	}
	return &MapInfo{
		Type:       mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}, nil
}

func DeleteMapEntry(mapFD MapFD, k []byte, valueSize int) error {
	log.Debugf("DeleteMapEntry(%v, %v, %v)", mapFD, k, valueSize)

	err := checkMapIfDebug(mapFD, len(k), valueSize)
	if err != nil {
		return err
	}

	return libbpfwin.DeleteMapEntry(uint32(mapFD), k, valueSize)
}

const ENOENT = 3025

func DeleteMapEntryIfExists(mapFD MapFD, k []byte, valueSize int) error {
	err := DeleteMapEntry(mapFD, k, valueSize)
	//if err == ENOENT {
	// Delete failed because entry did not exist.
	// err = nil
	// }

	return err
}

// Batch size established by trial and error; 8-32 seemed to be the sweet spot for the conntrack map.
const MapIteratorNumKeys = 16

// MapIterator handles one pass of iteration over the map.
type MapIterator struct {
	// Metadata about the map.
	mapFD      MapFD
	maxEntries int
	valueSize  int
	keySize    int

	// The values below point to the C heap.  We must allocate the key and value buffers on the C heap
	// because we pass them to the kernel as pointers contained in the bpf_attr union.  That extra level of
	// indirection defeats Go's special handling of pointers when passing them to the syscall.  If we allocated the
	// keys and values as slices and the garbage collector decided to move the backing memory of the slices then
	// the pointers we write to the bpf_attr union could end up being stale (since the union is opaque to the
	// garbage collector).

	// keyBeforeNextBatch is either nil at start of day or points to a buffer containing the key to pass to
	// bpf_map_load_multi.
	keyBeforeNextBatch unsafe.Pointer

	// keys points to a buffer containing up to MapIteratorNumKeys keys
	keys unsafe.Pointer
	// values points to a buffer containing up to MapIteratorNumKeys values
	values unsafe.Pointer

	// valueStride is the step through the values buffer.  I.e. the size of the value rounded up for alignment.
	valueStride int
	// keyStride is the step through the keys buffer.  I.e. the size of the key rounded up for alignment.
	keyStride int
	// numEntriesLoaded is the number of valid entries in the key and values buffers.
	numEntriesLoaded int
	// entryIdx is the index of the next key/value to return.
	entryIdx int
	// numEntriesVisited is incremented for each entry that we visit.  Used as a sanity check in case we go into an
	// infinite loop.
	numEntriesVisited int
}

// align64 rounds up the given size to the nearest 8-bytes.
func align64(size int) int {
	if size%8 == 0 {
		return size
	}
	return size + (8 - (size % 8))
}

func NewMapIterator(mapFD MapFD, keySize, valueSize, maxEntries int) (*MapIterator, error) {
	err := checkMapIfDebug(mapFD, keySize, valueSize)
	if err != nil {
		return nil, err
	}

	keyStride := align64(keySize)
	valueStride := align64(valueSize)

	keysBufSize := (C.size_t)(keyStride * MapIteratorNumKeys)
	valueBufSize := (C.size_t)(valueStride * MapIteratorNumKeys)

	m := &MapIterator{
		mapFD:       mapFD,
		maxEntries:  maxEntries,
		keySize:     keySize,
		valueSize:   valueSize,
		keyStride:   keyStride,
		valueStride: valueStride,
		keys:        C.malloc(keysBufSize),
		values:      C.malloc(valueBufSize),
	}

	C.memset(m.keys, 0, (C.size_t)(keysBufSize))
	C.memset(m.values, 0, (C.size_t)(valueBufSize))

	// Make sure the C buffers are cleaned up.
	runtime.SetFinalizer(m, func(m *MapIterator) {
		err := m.Close()
		if err != nil {
			log.WithError(err).Panic("Unexpected error from MapIterator.Close().")
		}
	})

	return m, nil
}

// Next gets the next key/value pair from the iteration.  The key and value []byte slices returned point to the
// MapIterator's internal buffers (which are allocated on the C heap); they should not be retained or modified.
// Returns ErrIterationFinished at the end of the iteration or ErrVisitedTooManyKeys if it visits considerably more
// keys than the maximum size of the map.
func (m *MapIterator) Next() (k, v []byte, err error) {
	if m.numEntriesLoaded == m.entryIdx {
		// Need to load a new batch of KVs from the kernel.
		var count C.int
		rc := C.bpf_map_load_multi(C.uint(m.mapFD), m.keyBeforeNextBatch, MapIteratorNumKeys, C.int(m.keyStride), m.keys, C.int(m.valueStride), m.values)
		if rc < 0 {
			// err = unix.Errno(-rc)
			return //TODO
		}
		count = rc
		if count == 0 {
			// No error but no keys either.  We're done.
			err = ErrIterationFinished
			return
		}

		m.numEntriesLoaded = int(count)
		m.entryIdx = 0
		if m.keyBeforeNextBatch == nil {
			m.keyBeforeNextBatch = C.malloc((C.size_t)(m.keySize))
		}
		C.memcpy(m.keyBeforeNextBatch, unsafe.Pointer(uintptr(m.keys)+uintptr(m.keyStride*(m.numEntriesLoaded-1))), (C.size_t)(m.keySize))
	}

	currentKeyPtr := unsafe.Pointer(uintptr(m.keys) + uintptr(m.keyStride*(m.entryIdx)))
	currentValPtr := unsafe.Pointer(uintptr(m.values) + uintptr(m.valueStride*(m.entryIdx)))

	k = ptrToSlice(currentKeyPtr, m.keySize)
	v = ptrToSlice(currentValPtr, m.valueSize)

	m.entryIdx++
	m.numEntriesVisited++

	if m.numEntriesVisited > m.maxEntries*10 {
		// Either a bug or entries are being created 10x faster than we're iterating through them?
		err = ErrVisitedTooManyKeys
		return
	}

	return
}

func ptrToSlice(ptr unsafe.Pointer, size int) (b []byte) {
	keySliceHdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	keySliceHdr.Data = uintptr(ptr)
	keySliceHdr.Cap = size
	keySliceHdr.Len = size
	return
}

func (m *MapIterator) Close() error {
	C.free(m.keyBeforeNextBatch)
	m.keyBeforeNextBatch = nil
	C.free(m.keys)
	m.keys = nil
	C.free(m.values)
	m.values = nil

	// Don't need the finalizer any more.
	runtime.SetFinalizer(m, nil)

	return nil
}
